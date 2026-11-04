use colored::Colorize;
use std::borrow::Cow;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use crate::detect::Privilege;
use crate::mounts::Mounts;

// ═══════════════════════════════════════════════════
//  Command Execution
// ═══════════════════════════════════════════════════

// ══════════════════════════════════════════════════
//  Trusted binary resolution
// ══════════════════════════════════════════════════

/// Directories a privileged command may come from. `$PATH` is deliberately not
/// consulted — every package manager and coreutil we escalate lives here on all
/// supported distros, and these are root-writable only.
///
/// `/nix/var/nix/profiles/default/bin` is the exception that proves the rule: Nix
/// installs its tools into the store and exposes them only through profile
/// symlinks, so `nix-collect-garbage` is never in `/usr/bin`. The default profile
/// is the *system* one, created and owned by root at install time — a user
/// profile (`~/.nix-profile`) is deliberately not listed.
const TRUSTED_BIN_DIRS: &[&str] = &[
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/nix/var/nix/profiles/default/bin",
];

/// NixOS keeps its tools where no other distribution does. The setuid wrappers
/// (`sudo`, `doas`) are in `/run/wrappers/bin`, which is a tmpfs set up at
/// boot, and everything else is reached through the system profile,
/// `/run/current-system/sw/bin`, a link into the immutable store. Neither
/// exists elsewhere, and neither is fixed by this list alone: they are used
/// only where [`only_root_can_change`] holds for them right now, so a machine
/// where one of them is something else (a directory that is not root's)
/// simply does not get it.
const NIXOS_WRAPPER_DIR: &str = "/run/wrappers/bin";
const NIXOS_SYSTEM_DIR: &str = "/run/current-system/sw/bin";

/// Whether a directory owned by `uid` with this `mode` can be changed by root
/// alone: root's, and writable by neither its group nor everyone.
fn only_root_can_change(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}

/// [`only_root_can_change`] for what `dir` is now. Links are followed, because
/// `/run/current-system` is one; the directory they lead to is what counts.
fn is_root_controlled(dir: &Path) -> bool {
    fs::metadata(dir).is_ok_and(|m| m.is_dir() && only_root_can_change(m.uid(), m.mode()))
}

/// The directories a privileged command may come from, in search order:
/// [`TRUSTED_BIN_DIRS`], with the NixOS ones added where `checked` accepts
/// them. The wrappers come first, as they do in a NixOS `PATH`, so that the
/// setuid `sudo` is the one found and not a plain copy of it further on.
fn trusted_dirs_with(checked: &dyn Fn(&Path) -> bool) -> Vec<&'static str> {
    let mut dirs = Vec::new();
    if checked(Path::new(NIXOS_WRAPPER_DIR)) {
        dirs.push(NIXOS_WRAPPER_DIR);
    }
    dirs.extend_from_slice(TRUSTED_BIN_DIRS);
    if checked(Path::new(NIXOS_SYSTEM_DIR)) {
        dirs.push(NIXOS_SYSTEM_DIR);
    }
    dirs
}

/// [`trusted_dirs_with`] for this machine.
fn trusted_dirs() -> Vec<&'static str> {
    trusted_dirs_with(&is_root_controlled)
}

/// Resolve `cmd` to an absolute path inside [`TRUSTED_BIN_DIRS`], ignoring
/// `$PATH`. Returns `None` when it isn't there, which callers treat as "not
/// available" — refusing beats running something unverified as root.
///
/// Handing a bare name to the privilege helper leaves the lookup to the helper.
/// `sudo` usually has `secure_path` to replace the caller's `$PATH`, but that is
/// admin-configurable and `doas` has no equivalent — so `doas pacman` would run a
/// `pacman` from `~/.local/bin` as root. `doas /usr/bin/pacman` cannot.
/// CWE-426; verified by exploit on Arch with `doas`.
pub fn resolve_trusted(cmd: &str) -> Option<String> {
    // Absolute paths come from our own code, never user input.
    if cmd.starts_with('/') {
        return Path::new(cmd).is_file().then(|| cmd.to_string());
    }
    if cmd.contains('/') {
        return None;
    }
    resolve_in(&trusted_dirs(), cmd)
}

/// The first of `dirs` that holds a file called `cmd`, as an absolute path.
fn resolve_in(dirs: &[&str], cmd: &str) -> Option<String> {
    dirs.iter()
        .map(|dir| Path::new(dir).join(cmd))
        .find(|p| p.is_file())
        .and_then(|p| p.to_str().map(|s| s.to_string()))
}

/// Hand every child the trusted `PATH` instead of the inherited one.
///
/// [`resolve_trusted`] fixes which binary we launch; this fixes what that binary
/// finds when it shells out itself — pacman runs hooks, emerge runs ebuilds, apk
/// runs triggers, all inheriting our environment. Only `PATH` is replaced; the
/// rest is needed (`HOME`, `XDG_CACHE_HOME`, locale).
///
/// `LD_PRELOAD` needs no handling: the loader ignores it across a setuid
/// boundary, and sudo and doas both strip it.
fn harden_env(cmd: &mut Command) -> &mut Command {
    cmd.env("PATH", trusted_path())
}

/// The `PATH` handed to every child: [`TRUSTED_BIN_DIRS`] only. Public so the
/// few call sites that build a `Command` directly can apply the same hardening.
pub fn trusted_path() -> String {
    trusted_dirs().join(":")
}

/// Cut `$PATH` down to what root can run tools from, when root is running, and
/// say which entries were left out that are worth naming.
///
/// The user tier ([`run_user`], [`capture`], [`which`]) finds a tool through the
/// caller's `$PATH` and runs it with the caller's rights, which gains nobody
/// anything while the caller is the user whose caches are being cleaned. A root
/// run is not that: `sudo` keeps the caller's `PATH` unless the sudoers file sets
/// `secure_path`, `sudo -E` always keeps it, and a `pip` that a process of the
/// user's own left in `~/.local/bin` is then started as root (seen with the real
/// root of a container: it printed `uid=0`). What a tool starts is found through
/// the same `PATH`, `#!/usr/bin/env node` among it, so the `PATH` the children
/// inherit is changed as well, here, once, before anything looks for a tool.
///
/// What stays is what [`only_root_can_change`] holds for the directory an entry
/// leads to, as it is for the NixOS ones among the trusted directories. What goes
/// without a word is what could not have held a tool: an entry that is not
/// absolute (a shell reads it as the current directory), one that is not there,
/// one that is not a directory. What goes and is named is a directory that
/// somebody other than root can change, or one that cannot be looked at. When
/// nothing is left the trusted directories are, not an empty `PATH`, which
/// anything that searches it reads as the current directory.
pub fn harden_path_for_root() -> Vec<PathBuf> {
    let Some(path) = env::var_os("PATH") else {
        return Vec::new();
    };
    match harden_path_with(is_root(), &path, look_at_dir) {
        Some((kept, left_out)) => {
            env::set_var("PATH", kept);
            left_out
        }
        None => Vec::new(),
    }
}

/// [`harden_path_for_root`] with what it asks of the machine handed in: whether
/// root is running, the `PATH`, and `look`, which says what a directory is. The
/// new `PATH` and the entries to name, or `None` when there is nothing to change.
fn harden_path_with(
    root: bool,
    path: &OsStr,
    look: impl Fn(&Path) -> io::Result<(bool, u32, u32)>,
) -> Option<(OsString, Vec<PathBuf>)> {
    if !root {
        return None;
    }
    let mut kept: Vec<PathBuf> = Vec::new();
    let mut left_out = Vec::new();
    for entry in env::split_paths(path) {
        if !entry.is_absolute() {
            continue;
        }
        match look(&entry) {
            Ok((true, uid, mode)) if only_root_can_change(uid, mode) => kept.push(entry),
            Ok((true, ..)) => left_out.push(entry),
            Ok((false, ..)) => {}
            Err(why) if why.kind() == io::ErrorKind::NotFound => {}
            Err(_) => left_out.push(entry),
        }
    }
    if kept.is_empty() {
        kept = trusted_dirs().into_iter().map(PathBuf::from).collect();
    }
    let new = env::join_paths(&kept).ok()?;
    (new != path).then_some((new, left_out))
}

/// Run a system tool with visible output (inherits stdio).
///
/// **System tier.** A bare `cmd` is looked up in the trusted directories only:
/// [`harden_env`] replaces the child's `PATH`, and that same `PATH` is where
/// `Command` searches for the program. So the name can resolve to a root-owned
/// directory and nowhere else. This is the tier for package managers,
/// `journalctl`, `flatpak` and the like.
///
/// It is the wrong tier for anything installed in the user's home (`uv` in
/// `~/.local/bin`, `cargo` in `~/.cargo/bin`): the trusted lookup cannot see
/// them, so the call returns `false` and nothing says why. Those go through
/// [`run_user`].
#[must_use = "a command that failed has to be reported, not assumed to have worked"]
pub fn run(cmd: &str, args: &[&str]) -> bool {
    let mut command = Command::new(cmd);
    command.args(args);
    harden_env(&mut command);
    keep_json_stdout_clean(&mut command);
    command.status().map(|s| s.success()).unwrap_or(false)
}

/// `--json` promises exactly one document on stdout, and a child that inherits
/// stdout is free to add lines of its own (`apt-get autoremove` certainly
/// does). So in JSON mode a visible command's stdout goes nowhere. Its stderr
/// is left alone: that is how a failure still reaches a person watching the
/// terminal, and no consumer parses it.
fn keep_json_stdout_clean(command: &mut Command) {
    if silent() {
        command.stdout(Stdio::null());
    }
}

/// Run a tool that belongs to the *user*, with visible output (inherits stdio).
///
/// **User tier**, the counterpart of [`run`]. `--dev` drives tools that their
/// installers put in the user's home (`~/.cargo/bin`, `~/.local/bin`, a version
/// manager's shims), so the trusted directories are the wrong place to look.
/// The name is resolved once, through the caller's own `$PATH`, to an absolute
/// path ([`which_path`]), and that path is what gets spawned.
///
/// The child keeps the caller's environment, `PATH` included. A shim or a
/// wrapper script finds the interpreter it needs only through the `PATH` it
/// was started with, and narrowing it is what made `--dev` lose track of
/// user-installed tools in 1.8.0. The one addition is [`TOOL_ENV_DEFAULTS`]:
/// switches that keep a tool's one-time setup out of a cleanup run, never
/// overriding a choice the caller has already made.
///
/// This is not an escalation: the tool runs with the caller's rights against
/// the caller's caches, so a binary the caller controls gains nothing. (Were the
/// caller root it would be one, and `main` has cut `$PATH` down to what root
/// alone controls first: [`harden_path_for_root`].) It must never be paired with
/// [`elevate`], which has its own trusted lookup.
#[must_use = "a command that failed has to be reported, not assumed to have worked"]
pub fn run_user(cmd: &str, args: &[&str]) -> bool {
    run_user_in(&env::var_os("PATH").unwrap_or_default(), cmd, args)
}

/// [`run_user`] with the search path passed in, so tests can aim it at a
/// scratch directory without touching the process environment.
fn run_user_in(paths: &OsStr, cmd: &str, args: &[&str]) -> bool {
    let Some(program) = which_path_in(cmd, paths) else {
        return false;
    };
    let mut command = user_command(&program, args);
    keep_json_stdout_clean(&mut command);
    command.status().map(|s| s.success()).unwrap_or(false)
}

/// [`run_user`] without letting the tool's own chatter into our report: the
/// user-tier counterpart of [`run_quiet`], on the same terms. Nothing is
/// printed on success, a failure replays what the tool said, `--verbose` opts
/// back into the raw output, and the tool gets a null stdin.
///
/// `--dev` needs this more than the package managers do. The tools it drives
/// print whatever they like: `pnpm` a prune report, `uv` a summary and, on the
/// first run after an SDK install or upgrade, `dotnet` a welcome banner with
/// documentation links and a telemetry notice. None of it is ours, and it all
/// lands in the middle of our report.
#[must_use = "a command that failed has to be reported, not assumed to have worked"]
pub fn run_user_quiet(cmd: &str, args: &[&str]) -> bool {
    if is_verbose() {
        return run_user(cmd, args);
    }
    run_user_quiet_in(&env::var_os("PATH").unwrap_or_default(), cmd, args)
}

/// [`run_user_quiet`] over an explicit search path (see [`run_user_in`]).
fn run_user_quiet_in(paths: &OsStr, cmd: &str, args: &[&str]) -> bool {
    let Some(program) = which_path_in(cmd, paths) else {
        return false;
    };
    match user_command(&program, args).output() {
        Ok(out) => {
            if !out.status.success() {
                replay_failure(&out);
            }
            out.status.success()
        }
        Err(_) => false,
    }
}

/// The command for a user-tier tool: the program at its resolved path, the
/// caller's environment, and the defaults from [`TOOL_ENV_DEFAULTS`].
fn user_command(program: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(program);
    command.args(args);
    apply_tool_env(&mut command, program);
    command
}

/// Environment a user-tier tool starts with unless the caller has already
/// chosen, keyed by the program's file name.
///
/// `dotnet` is the reason this exists. The first command after an SDK install
/// or upgrade runs one-time setup that nothing about clearing a cache asked
/// for, as a side effect of whatever command happened to come first:
///
/// * a welcome banner, with documentation links and a telemetry notice, on stdout;
/// * generating an ASP.NET Core HTTPS development certificate;
/// * adding the global-tools directory to the `PATH`;
/// * a workload integrity check, which may repair workloads over the network.
///
/// Each has its own switch, and `DOTNET_NOLOGO` covers only the first, which is
/// the cosmetic part. Hiding the banner while still generating a certificate
/// would be tidier, not better, so every switch is set. The telemetry opt-out
/// is here for the same reason: a cache cleaner should not report anything on
/// the user's behalf.
///
/// `DOTNET_SKIP_FIRST_TIME_EXPERIENCE` is the legacy first-run switch. Current
/// SDKs ignore it and older ones honoured it, so setting it costs nothing.
const TOOL_ENV_DEFAULTS: &[(&str, &[(&str, &str)])] = &[(
    "dotnet",
    &[
        ("DOTNET_NOLOGO", "1"),
        ("DOTNET_CLI_TELEMETRY_OPTOUT", "1"),
        ("DOTNET_GENERATE_ASPNET_CERTIFICATE", "false"),
        ("DOTNET_ADD_GLOBAL_TOOLS_TO_PATH", "false"),
        ("DOTNET_SKIP_WORKLOAD_INTEGRITY_CHECK", "1"),
        ("DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "1"),
    ],
)];

/// The [`TOOL_ENV_DEFAULTS`] that apply to `program` (matched on its file name
/// only, so a directory called `dotnet` does not make its contents dotnet),
/// minus any variable `is_set` says the caller already has.
fn tool_env_defaults(
    program: &Path,
    is_set: impl Fn(&str) -> bool,
) -> Vec<(&'static str, &'static str)> {
    let Some(name) = program.file_name().and_then(OsStr::to_str) else {
        return Vec::new();
    };
    TOOL_ENV_DEFAULTS
        .iter()
        .filter(|(tool, _)| *tool == name)
        .flat_map(|(_, vars)| vars.iter().copied())
        .filter(|(key, _)| !is_set(key))
        .collect()
}

/// Give `command` the defaults for `program`, leaving alone every variable the
/// caller's own environment already sets.
fn apply_tool_env(command: &mut Command, program: &Path) {
    for (key, value) in tool_env_defaults(program, |key| env::var_os(key).is_some()) {
        command.env(key, value);
    }
}

/// Run a command without letting its own chatter into our report.
///
/// The helpers we drive (`pacman -Sc`, `paru -Sc`, `flatpak uninstall`,
/// `journalctl --vacuum-size`) each print several lines of their own — on a
/// full `--all` run that was more foreign output than ours, which buried the
/// section results the user actually came for.
///
/// So we capture instead of inherit. On success nothing is printed: the
/// caller's own `✔` line is the report. On **failure** the captured stderr is
/// replayed under the caller's `✘` line, which is strictly better than before —
/// the error used to scroll past inside 30 lines of unrelated success chatter.
///
/// `--verbose` opts back into the raw firehose by delegating to [`run`].
///
/// `output()` gives the child a null stdin, which is the behaviour we want: a
/// helper that unexpectedly wants input fails fast with a captured message we
/// replay, instead of blocking forever. Inheriting stdin would be worse than it
/// sounds — the prompt itself goes to stderr, so we'd capture the question and
/// leave the terminal silently waiting for an answer nobody was asked for.
/// Privileged calls work because `main()` caches credentials up front via
/// `acquire_sudo`, which does inherit the terminal.
#[must_use = "a command that failed has to be reported, not assumed to have worked"]
pub fn run_quiet(cmd: &str, args: &[&str]) -> bool {
    if is_verbose() {
        return run(cmd, args);
    }
    match harden_env(Command::new(cmd).args(args)).output() {
        Ok(out) => {
            if !out.status.success() {
                replay_stderr(&out.stderr);
            }
            out.status.success()
        }
        Err(_) => false,
    }
}

/// Print a failed command's captured stderr, indented and dimmed to read as
/// context under the caller's error line rather than as report content.
/// Capped at 5 lines — a broken command can emit hundreds, and re-flooding the
/// report is the exact thing [`run_quiet`] exists to prevent.
fn replay_stderr(stderr: &[u8]) {
    if silent() {
        return;
    }
    let text = String::from_utf8_lossy(stderr);
    for line in text.lines().filter(|l| !l.trim().is_empty()).take(5) {
        println!("      {}", shown(line).dimmed());
    }
}

/// What to show for a captured command that failed. Most tools complain on
/// stderr, but some (MSBuild-based ones among them) report errors on stdout, so
/// when stderr has nothing to say the explanation is looked for there.
fn failure_detail(out: &Output) -> &[u8] {
    if out.stderr.iter().all(u8::is_ascii_whitespace) {
        &out.stdout
    } else {
        &out.stderr
    }
}

fn replay_failure(out: &Output) {
    replay_stderr(failure_detail(out));
}

/// [`run_quiet`] with privilege escalation. Resolves and dispatches exactly as
/// [`elevate`] does — see the rationale there.
#[must_use = "a command that failed has to be reported, not assumed to have worked"]
pub fn elevate_quiet(privilege: Privilege, cmd: &str, args: &[&str]) -> bool {
    let Some((program, argv)) = escalation(privilege, cmd, args, &resolve_trusted) else {
        explain_unavailable(privilege, cmd);
        return false;
    };
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    run_quiet(&program, &argv)
}

/// Quiet counterpart to [`sudo`], using the helper detected at startup.
#[must_use = "a command that failed has to be reported, not assumed to have worked"]
pub fn sudo_quiet(cmd: &str, args: &[&str]) -> bool {
    elevate_quiet(current_privilege(), cmd, args)
}

/// How a command ended and what it printed, for a caller whose question is
/// answered by more than "did it succeed".
#[derive(Debug)]
pub struct Captured {
    /// The exit status; `None` when a signal ended the command.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// [`elevate_quiet`] for a read-only question that the exit status alone does not
/// answer. `pgrep` exits 1 for "none found", and so does `sudo` for "I refused",
/// so a `bool` cannot tell a clean "no" from a question that was never put.
///
/// Resolved and run exactly as [`elevate`] runs a command. `None` is "not
/// started", and has been said, as there.
#[must_use = "None means the command never ran, and nothing was learnt"]
pub fn elevate_capture(privilege: Privilege, cmd: &str, args: &[&str]) -> Option<Captured> {
    let Some((program, argv)) = escalation(privilege, cmd, args, &resolve_trusted) else {
        explain_unavailable(privilege, cmd);
        return None;
    };
    let out = match harden_env(Command::new(&program).args(&argv)).output() {
        Ok(out) => out,
        Err(e) => {
            note(&format!("not run: {cmd} could not be started ({e})"));
            return None;
        }
    };
    Some(Captured {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

// ══════════════════════════════════════════════════
//  Privilege Escalation
// ══════════════════════════════════════════════════

/// The privilege helper detected at startup.
///
/// `main()` sets this once via [`set_privilege`]; everywhere else — including
/// the legacy [`sudo`] wrapper used by `clean.rs` — reads it through
/// [`current_privilege`]. We deliberately avoid threading a `Privilege`
/// argument through every cleanup function: it would touch ~30 call sites
/// with no behavioural benefit.
static PRIVILEGE: OnceLock<Privilege> = OnceLock::new();

/// Quiet-mode flag set by `--quiet` / `-q`. When true, [`info`] and [`skip`]
/// produce no output and the banner sub-lines are hidden. Action lines
/// (section, success, warning, error) always print — those are the bits the
/// user actually needs to see.
static QUIET: OnceLock<bool> = OnceLock::new();

/// JSON-mode flag set by `--json`. When true, ALL human-facing output helpers
/// (banner, section, success, warning, error, info, skip) are silenced so the
/// only thing on stdout is the final JSON object that `main()` prints. Also
/// forces [`confirm`] to decline, so a stray prompt can never block a
/// non-interactive run.
static JSON: OnceLock<bool> = OnceLock::new();

/// Verbose flag set by `--verbose` / `-v`. When true, [`run_quiet`] stops
/// capturing and inherits stdio again, so every helper's raw output is visible.
/// This is the escape hatch for debugging a misbehaving package manager: the
/// clean report is the default, the firehose is one flag away.
static VERBOSE: OnceLock<bool> = OnceLock::new();

/// Record the detected privilege helper. Called once from `main()`.
/// Subsequent calls are silently ignored — `OnceLock` semantics.
pub fn set_privilege(p: Privilege) {
    let _ = PRIVILEGE.set(p);
}

/// Enable quiet mode. Called once from `main()` when `--quiet` is passed.
pub fn set_quiet(q: bool) {
    let _ = QUIET.set(q);
}

/// Returns true if `--quiet` was passed at startup.
pub fn is_quiet() -> bool {
    *QUIET.get().unwrap_or(&false)
}

/// Enable JSON mode. Called once from `main()` when `--json` is passed.
pub fn set_json(j: bool) {
    let _ = JSON.set(j);
    if j {
        // A machine consumer wants plain text; strip ANSI colors everywhere.
        colored::control::set_override(false);
    }
}

/// Returns true if `--json` was passed at startup. In JSON mode every human
/// output helper is silenced and prompts auto-decline.
pub fn is_json() -> bool {
    *JSON.get().unwrap_or(&false)
}

/// True when no human-facing chatter should be printed at all (JSON mode).
fn silent() -> bool {
    is_json()
}

/// Enable verbose mode. Called once from `main()` when `--verbose` is passed.
/// JSON mode wins: a machine consumer must never get helper output on stdout,
/// so `main()` never enables verbose alongside `--json`.
pub fn set_verbose(v: bool) {
    let _ = VERBOSE.set(v);
}

/// Returns true if `--verbose` was passed at startup.
pub fn is_verbose() -> bool {
    *VERBOSE.get().unwrap_or(&false)
}

/// Current privilege helper, or `Privilege::Sudo` if `main()` never set one
/// (e.g. in unit tests that exercise [`elevate`] directly).
pub fn current_privilege() -> Privilege {
    *PRIVILEGE.get().unwrap_or(&Privilege::Sudo)
}

/// Run `cmd` with the requested privilege helper. `Privilege::Root` runs
/// the command directly because we are already uid 0. `Privilege::None` means
/// no escalation tool exists — there is nothing to run, so we report failure
/// without spawning anything (the caller should have already warned the user).
///
/// Both the helper and the target command are resolved through
/// [`resolve_trusted`] first, so neither is looked up in the caller's `$PATH`.
/// This is the single choke point for privileged execution — the ~40 call sites
/// in `clean.rs` keep passing bare names and inherit the guarantee for free.
#[must_use = "a command that failed has to be reported, not assumed to have worked"]
pub fn elevate(privilege: Privilege, cmd: &str, args: &[&str]) -> bool {
    let Some((program, argv)) = escalation(privilege, cmd, args, &resolve_trusted) else {
        explain_unavailable(privilege, cmd);
        return false;
    };
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    run(&program, &argv)
}

/// What to spawn to run `cmd args…` under `privilege`: a program and its
/// arguments, or `None` when it must not run at all. That is the case when no
/// escalation tool exists, and when the command or the tool is not found by
/// `resolve` ([`resolve_trusted`] outside of tests).
///
/// Refuse rather than fall back to a `$PATH` lookup: with root behind the call,
/// "not in a trusted directory" must never mean "try anywhere". The command is
/// handed to `sudo`/`doas` as the absolute path `resolve` found, so it can
/// neither be looked up again nor be taken for an option.
fn escalation(
    privilege: Privilege,
    cmd: &str,
    args: &[&str],
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Option<(String, Vec<String>)> {
    let target = resolve(cmd)?;
    let args = args.iter().map(|a| a.to_string());
    match privilege {
        Privilege::Root => Some((target, args.collect())),
        Privilege::Sudo | Privilege::Doas => {
            let helper = resolve(privilege.name())?;
            Some((helper, std::iter::once(target).chain(args).collect()))
        }
        Privilege::None => None,
    }
}

/// [`elevate`] with `input` fed to the command's stdin.
///
/// For handing root a payload without leaving it in a file first: a file in a
/// directory an unprivileged process can write to is a file that process can
/// swap between the moment it was checked and the moment root reads it. A pipe
/// has no such window.
///
/// Resolution and environment are exactly [`elevate`]'s. `true` means the
/// command exited 0 *and* every byte of `input` reached it: a command that
/// stopped reading early is a failure whatever its exit status says, since
/// what it did with a short input is not something to vouch for.
#[must_use = "a command that failed has to be reported, not assumed to have worked"]
pub fn elevate_with_input(privilege: Privilege, cmd: &str, args: &[&str], input: &[u8]) -> bool {
    let Some((program, argv)) = escalation(privilege, cmd, args, &resolve_trusted) else {
        explain_unavailable(privilege, cmd);
        return false;
    };
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    run_with_input(&program, &argv, input)
}

/// Spawn `cmd` with the hardened environment, write `input` to its stdin, and
/// wait for it. Stdout and stderr follow the usual rules for visible commands,
/// and a password prompt still reaches the terminal (sudo and doas ask on the
/// tty, not on stdin).
fn run_with_input(cmd: &str, args: &[&str], input: &[u8]) -> bool {
    let mut command = Command::new(cmd);
    command.args(args).stdin(Stdio::piped());
    harden_env(&mut command);
    keep_json_stdout_clean(&mut command);
    let Ok(mut child) = command.spawn() else {
        return false;
    };
    // A command that exits without reading (a refused password, a policy
    // denial) makes the write fail with a broken pipe. Rust ignores SIGPIPE, so
    // that arrives here as an error rather than killing us, and the exit
    // status below tells the rest. Dropping the handle sends EOF.
    let delivered = child
        .stdin
        .take()
        .map(|mut stdin| stdin.write_all(input).is_ok())
        .unwrap_or(false);
    let succeeded = child.wait().map(|s| s.success()).unwrap_or(false);
    delivered && succeeded
}

/// [`elevate_with_input`] for a command whose output is not ours to show: what
/// it prints is captured, and a failure replays what it said, as for
/// [`elevate_quiet`].
///
/// For the tools that can only be told "yes" at a prompt. `pacman -Scc` is the
/// one that matters: `--noconfirm` answers every question with its default, and
/// the default for "remove ALL files from cache?" is no, so the deep clean was
/// a command that succeeded at doing nothing.
///
/// `true` means the command exited 0 and every byte of `input` reached it.
#[must_use = "a command that failed has to be reported, not assumed to have worked"]
pub fn elevate_quiet_with_input(
    privilege: Privilege,
    cmd: &str,
    args: &[&str],
    input: &[u8],
) -> bool {
    let Some((program, argv)) = escalation(privilege, cmd, args, &resolve_trusted) else {
        explain_unavailable(privilege, cmd);
        return false;
    };
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    if is_verbose() {
        return run_with_input(&program, &argv, input);
    }
    run_quiet_with_input(&program, &argv, input)
}

/// [`elevate_quiet_with_input`] with the helper detected at startup.
#[must_use = "a command that failed has to be reported, not assumed to have worked"]
pub fn sudo_quiet_with_input(cmd: &str, args: &[&str], input: &[u8]) -> bool {
    elevate_quiet_with_input(current_privilege(), cmd, args, input)
}

/// [`run_with_input`] with stdout and stderr captured instead of inherited.
///
/// The input is written from a thread, because a command is free to fill its
/// output pipes before it reads a byte of ours, and a writer that waits for the
/// reader while the reader waits for the writer is a hang.
fn run_quiet_with_input(cmd: &str, args: &[&str], input: &[u8]) -> bool {
    let mut command = Command::new(cmd);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    harden_env(&mut command);
    let Ok(mut child) = command.spawn() else {
        return false;
    };
    let writer = child.stdin.take().map(|mut stdin| {
        let input = input.to_vec();
        std::thread::spawn(move || stdin.write_all(&input).is_ok())
    });
    let Ok(out) = child.wait_with_output() else {
        return false;
    };
    // Joined after the wait: the command has exited by now, so the writer has
    // either finished or failed on a pipe nobody reads.
    let delivered = writer
        .map(|handle| handle.join().unwrap_or(false))
        .unwrap_or(false);
    if !out.status.success() {
        replay_failure(&out);
    }
    delivered && out.status.success()
}

/// A dimmed line of explanation, indented like the lines [`run_quiet`] replays
/// from a failed command.
fn note(msg: &str) {
    if silent() {
        return;
    }
    println!("      {}", shown(msg).dimmed());
}

/// Say why a privileged command was not even started. Without this a `false`
/// from [`elevate`] reads as the command having failed, when what failed is
/// finding it.
fn explain_unavailable(privilege: Privilege, cmd: &str) {
    note(&unavailable(privilege, cmd, &resolve_trusted));
}

/// The sentence for [`explain_unavailable`], with the lookup passed in so a test
/// does not depend on what the machine has installed.
fn unavailable(
    privilege: Privilege,
    cmd: &str,
    resolve: &dyn Fn(&str) -> Option<String>,
) -> String {
    let dirs = trusted_dirs().join(", ");
    match privilege {
        Privilege::None => "not run: not root, and neither sudo nor doas was found".to_string(),
        _ if resolve(cmd).is_none() => {
            format!("not run: {cmd} is not in a directory trusted for root ({dirs})")
        }
        Privilege::Sudo | Privilege::Doas => format!(
            "not run: {} is not in a directory trusted for root ({dirs})",
            privilege.name()
        ),
        Privilege::Root => format!("not run: {cmd} could not be started"),
    }
}

/// Cache the user's password / authorisation for the chosen helper.
///
/// `sudo -v` extends the auth-cache; `doas` has no equivalent, so we send a
/// no-op command (`true`) that simply triggers the password prompt.
pub fn acquire_privilege(privilege: Privilege) -> bool {
    match privilege {
        Privilege::Root => true,
        // Resolved for the same reason as `elevate`: this is the call that
        // prompts for the password, so a shadowed `sudo`/`doas` here would
        // harvest it.
        Privilege::Sudo => match resolve_trusted("sudo") {
            Some(p) => run(&p, &["-v"]),
            None => false,
        },
        Privilege::Doas => match resolve_trusted("doas") {
            Some(p) => run(&p, &["true"]),
            None => false,
        },
        Privilege::None => false,
    }
}

/// Backwards-compatible wrapper. Delegates to [`elevate`] with the helper
/// detected at startup (set by `main()` via [`set_privilege`]).
#[must_use = "a command that failed has to be reported, not assumed to have worked"]
pub fn sudo(cmd: &str, args: &[&str]) -> bool {
    elevate(current_privilege(), cmd, args)
}

/// Capture stdout of a user-level tool (returns output regardless of exit code).
///
/// **User tier**, on the same terms as [`run_user`]. Not restricted to
/// [`TRUSTED_BIN_DIRS`], because `--dev` drives tools that legitimately live in
/// the user's home: rustup puts `cargo` in `~/.cargo/bin`, and the
/// `uv`/`deno`/`pnpm`/`bun` installers default to `~/.local/bin`. Those run with
/// the caller's own privileges against the caller's own cache, so a binary they
/// control is not an escalation. The name is resolved through the caller's
/// `$PATH` ([`which_path`]) and the child keeps the caller's environment; for
/// root that `$PATH` is the one [`harden_path_for_root`] left.
/// Privileged callers use [`capture_trusted`].
pub fn capture(cmd: &str, args: &[&str]) -> Option<String> {
    capture_in(&env::var_os("PATH").unwrap_or_default(), cmd, args)
}

/// [`capture`] over an explicit search path (see [`run_user_in`]).
fn capture_in(paths: &OsStr, cmd: &str, args: &[&str]) -> Option<String> {
    let program = which_path_in(cmd, paths)?;
    capture_program(&program, args, false)
}

/// Run `program` and return its trimmed stdout. `harden` picks the
/// environment the child gets: the trusted `PATH` (see [`harden_env`]) or the
/// caller's own.
fn capture_program(program: &Path, args: &[&str], harden: bool) -> Option<String> {
    let mut command = Command::new(program);
    command.args(args);
    if harden {
        harden_env(&mut command);
    } else {
        apply_tool_env(&mut command, program);
    }
    command
        .stderr(Stdio::null())
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// [`capture`] that also looks at how the tool ended: its output when it exited
/// 0, and `None` when it did not or could not be started.
///
/// **User tier**, like [`capture`]. For the runs whose output we read *and*
/// whose success we report, `nix-collect-garbage` among them: [`capture`] hands
/// back whatever the tool printed even when it failed, so a failure looked like
/// a quiet success. What a failed tool said is shown, as [`run_user_quiet`] does.
#[must_use = "None means the tool failed, and that has to be reported"]
pub fn capture_checked(cmd: &str, args: &[&str]) -> Option<String> {
    capture_checked_in(&env::var_os("PATH").unwrap_or_default(), cmd, args)
}

/// [`capture_checked`] over an explicit search path (see [`run_user_in`]).
fn capture_checked_in(paths: &OsStr, cmd: &str, args: &[&str]) -> Option<String> {
    let Some(program) = which_path_in(cmd, paths) else {
        note(&format!("{cmd} was not found in your PATH"));
        return None;
    };
    let out = user_command(&program, args).output().ok()?;
    if !out.status.success() {
        replay_failure(&out);
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// [`capture`] restricted to [`TRUSTED_BIN_DIRS`], for output we act on with
/// root behind it.
///
/// A tool whose output is handed to a privileged command must not be one a
/// user can shadow: it would not need to run as root itself, only to name the
/// things we then delete. Returns `None` when the tool is not in a trusted
/// directory, and the output whatever the tool's exit status was; a caller that
/// reads a list and acts on "nothing there" wants [`list_trusted`] instead.
pub fn capture_trusted(cmd: &str, args: &[&str]) -> Option<String> {
    let target = resolve_trusted(cmd)?;
    capture_program(Path::new(&target), args, true)
}

/// How a read-only listing came out.
#[derive(Debug, PartialEq, Eq)]
pub enum Listing {
    /// The tool printed a list.
    Found(String),
    /// It ran, and there is nothing to list.
    Nothing,
    /// It could not be run, or it ended the way a broken tool does. What it said
    /// has been shown.
    Failed,
}

/// What a tool that has nothing to list exits with.
#[derive(Clone, Copy, Debug)]
pub enum WhenEmpty {
    /// 0, like nearly everything.
    Exit0,
    /// 1, with no output: `pacman -Qdtq` (checked against pacman 7.1).
    Exit1,
}

/// What a finished listing means, decided apart from running it.
///
/// A tool that cannot look and a tool that looked and found nothing both print
/// nothing, and "nothing found" is a success line that must not be said of a
/// listing that never happened: a locked package database was reported as
/// "No orphans found". Where the exit status separates the two it is enough;
/// where a tool uses 1 for both (pacman), what separates them is that its
/// errors are the `error:` lines — its warnings, for instance about sync
/// databases that were never downloaded, come with a harmless run too.
fn classify_listing(code: Option<i32>, stdout: &str, stderr: &str, empty: WhenEmpty) -> Listing {
    let stdout = stdout.trim();
    match code {
        Some(0) => {}
        Some(1)
            if matches!(empty, WhenEmpty::Exit1)
                && stdout.is_empty()
                && !stderr.lines().any(|l| l.trim_start().starts_with("error:")) =>
        {
            return Listing::Nothing;
        }
        _ => return Listing::Failed,
    }
    if stdout.is_empty() {
        Listing::Nothing
    } else {
        Listing::Found(stdout.to_string())
    }
}

/// Run a read-only listing from a [`TRUSTED_BIN_DIRS`] tool and say what it
/// came to ([`Listing`]); a failure explains itself, as for [`run_quiet`].
pub fn list_trusted(cmd: &str, args: &[&str], empty: WhenEmpty) -> Listing {
    let Some(target) = resolve_trusted(cmd) else {
        note(&format!(
            "{cmd} is not in a directory trusted for root ({})",
            trusted_dirs().join(", ")
        ));
        return Listing::Failed;
    };
    let mut command = Command::new(&target);
    command.args(args);
    harden_env(&mut command);
    let Ok(out) = command.output() else {
        note(&format!("{cmd} could not be started"));
        return Listing::Failed;
    };
    let listing = classify_listing(
        out.status.code(),
        &String::from_utf8_lossy(&out.stdout),
        &String::from_utf8_lossy(&out.stderr),
        empty,
    );
    if listing == Listing::Failed {
        replay_failure(&out);
    }
    listing
}

/// Check if a command exists in PATH, as something [`run_user`] could start.
///
/// Same lookup as [`which_path`]: an executable file in an absolute `$PATH`
/// entry, not merely any file of that name.
///
/// Walks $PATH directly instead of spawning a `which` subprocess —
/// faster, more reliable, and works on systems where `which` itself
/// is not installed (e.g. minimal Alpine containers).
pub fn which(cmd: &str) -> bool {
    which_path(cmd).is_some()
}

/// Find `cmd` the way a shell would, but safely: the first *executable file*
/// reachable through an *absolute* `$PATH` entry.
///
/// This is how the user tier ([`run_user`], [`capture`]) turns a bare name into
/// the program to spawn. Resolving it here, once, instead of leaving it to
/// `Command` keeps the answer independent of whatever environment the child is
/// later given, and makes [`which`] and the launch agree on what "installed"
/// means.
///
/// * Relative and empty entries are skipped. To a shell an empty entry means
///   "the current directory", so `PATH=:/usr/bin` would let a file dropped into
///   whatever directory we happen to run from be started: the planted-binary
///   problem [`resolve_trusted`] closes for privileged commands.
/// * A name containing `/` is not searched for. It is accepted only as an
///   absolute path to an executable file.
/// * Directories and files without an execute bit are skipped, so a data file
///   called `go` early on the path does not shadow the real tool behind it.
pub fn which_path(cmd: &str) -> Option<PathBuf> {
    which_path_in(cmd, &env::var_os("PATH").unwrap_or_default())
}

/// [`which_path`] over an explicit search path (see [`run_user_in`]).
fn which_path_in(cmd: &str, paths: &OsStr) -> Option<PathBuf> {
    if cmd.is_empty() {
        return None;
    }
    if cmd.contains('/') {
        let path = Path::new(cmd);
        return (path.is_absolute() && is_executable_file(path)).then(|| path.to_path_buf());
    }
    env::split_paths(paths)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(cmd))
        .find(|candidate| is_executable_file(candidate))
}

/// A regular file (symlinks followed) with at least one execute bit set.
fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Availability check for a command we intend to run with privileges. Must agree
/// with what [`elevate`] accepts — gating on the looser [`which`] would pick a
/// branch (e.g. a planted `dnf`) that then refuses to execute.
pub fn which_trusted(cmd: &str) -> bool {
    resolve_trusted(cmd).is_some()
}

/// Check if running as root (uid 0)
pub fn is_root() -> bool {
    // From /proc, not `id -u`: a shadowed `id` printing "0" would convince us we
    // are already root, so we would skip escalation and every privileged step
    // would fail. Format: `Uid:\t<real>\t<effective>\t<saved>\t<fs>`.
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                let mut f = rest.split_whitespace();
                let _real = f.next();
                if let Some(effective) = f.next() {
                    return effective == "0";
                }
            }
        }
    }
    // No /proc (unusual container or chroot).
    capture_trusted("id", &["-u"])
        .map(|id| id == "0")
        .unwrap_or(false)
}

/// Acquire sudo privileges (prompts for password).
///
/// Kept as a thin wrapper so the legacy `main.rs` path keeps working until
/// it is converted to call [`acquire_privilege`] directly.
pub fn acquire_sudo() -> bool {
    let p = current_privilege();
    if p == Privilege::Root {
        return true;
    }
    if !silent() {
        println!();
        println!(
            "  {}",
            format!("🔐 Requesting privileges ({})...", p.name()).yellow()
        );
    }
    acquire_privilege(p)
}

// ═══════════════════════════════════════════════════
//  File Operations
// ═══════════════════════════════════════════════════

/// What a file occupies on disk: the blocks its filesystem gave it (`st_blocks`,
/// always counted in 512-byte units), not the length of what it holds.
///
/// The two differ both ways. A sparse file, or one the filesystem compresses,
/// takes less than its length, and a small file takes a whole block. Everything
/// reported as freed is about the disk, so this is the one that counts, as it
/// is for `du`. (On a filesystem that shares extents between files, a snapshot
/// or a reflink, it is still an upper bound: what another file shares stays.)
pub fn allocated(md: &fs::Metadata) -> u64 {
    md.blocks().saturating_mul(512)
}

/// What removing a set of files frees: their [`allocated`] blocks, except that a
/// file with more than one name frees nothing until its last name is gone. Only
/// files are added (a directory's own count of links is its subdirectories). So
/// such a file counts once, and only when every one of its names is in the set;
/// a pnpm store whose files are also linked into projects is worth nothing
/// until those projects go, and says so.
#[derive(Default)]
struct Footprint {
    /// Files with a single name.
    whole: u64,
    /// Files with several, by device and inode.
    shared: std::collections::HashMap<(u64, u64), Shared>,
}

struct Shared {
    bytes: u64,
    /// Names the filesystem says it has, and names met so far.
    links: u64,
    seen: u64,
}

impl Footprint {
    fn add(&mut self, md: &fs::Metadata) {
        let bytes = allocated(md);
        if md.nlink() <= 1 {
            self.whole += bytes;
            return;
        }
        let entry = self.shared.entry((md.dev(), md.ino())).or_insert(Shared {
            bytes,
            links: md.nlink(),
            seen: 0,
        });
        entry.seen += 1;
    }

    fn total(&self) -> u64 {
        self.whole
            + self
                .shared
                .values()
                .filter(|f| f.seen >= f.links)
                .map(|f| f.bytes)
                .sum::<u64>()
    }
}

/// What removing the one directory entry described by `md` frees (see
/// [`Footprint`]): for a file, its blocks when it has no other name. A directory
/// is [`dir_size`]'s business, and a link is its own few bytes.
pub fn footprint_of(md: &fs::Metadata) -> u64 {
    let mut footprint = Footprint::default();
    footprint.add(md);
    footprint.total()
}

/// What removing `path` frees: the disk space ([`allocated`]) of the files in
/// it, skipping symlinks, with the rule for files that have other names (see
/// [`Footprint`]). Directories are not counted, so a tree of empty directories
/// is 0, as "nothing to clean" needs. Neither is what is on another file system
/// mounted inside the tree: it is not removed with the tree (see
/// [`remove_entry`]), so it is not freed either.
///
/// `path` is spelled the way the mounts are, a real path; [`dir_size`] takes any.
///
/// Reads type and size from the `DirEntry` the directory scan already produced.
/// The `is_symlink()` / `is_dir()` / `metadata()` chain this replaced re-resolved
/// each path three times; on a 40 000-file tree that was 88 ms versus `du`'s 34.
/// `~/.cache` is the deepest tree the tool touches, and on a spinning disk the
/// syscall count is the runtime.
///
/// Iterative so a deep tree cannot overflow the stack.
pub fn dir_size_in(path: &Path, mounts: &Mounts) -> u64 {
    let Ok(top) = fs::symlink_metadata(path) else {
        return 0;
    };
    if top.is_symlink() {
        return 0;
    }
    let mut footprint = Footprint::default();
    if !top.is_dir() {
        footprint.add(&top);
        return footprint.total();
    }

    // Almost no tree has a mount inside it, and then there is nothing to compare
    // each entry with. In path order, which is how `below` hands them over.
    let apart: Vec<&Path> = mounts.below(path).collect();
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            // A mount point is left as it is, a file too: a file can be
            // bind-mounted over a file.
            if !apart.is_empty() && apart.binary_search(&entry.path().as_path()).is_ok() {
                continue;
            }
            if ft.is_dir() {
                stack.push(entry.path());
            } else if let Ok(md) = entry.metadata() {
                footprint.add(&md);
            }
        }
    }
    footprint.total()
}

/// [`dir_size_in`] for a path spelled any way, against the mounts there are now.
/// A list of mounts that cannot be read leaves the figure as it would be
/// without mounts: it only says what a run would free, and a run does not go on
/// without the list.
pub fn dir_size(path: &Path) -> u64 {
    dir_size_against(path, &Mounts::read().unwrap_or_default())
}

/// [`dir_size`] with the mounts handed in, so that a test can say what is mounted where.
fn dir_size_against(path: &Path, mounts: &Mounts) -> u64 {
    // A link is not followed (see `dir_size_in`), so it is looked at before it is resolved.
    if fs::symlink_metadata(path).is_ok_and(|md| md.is_symlink()) {
        return 0;
    }
    let real = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    dir_size_in(&real, mounts)
}

/// What emptying a directory came to.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Emptied {
    /// Bytes of what is gone.
    pub freed: u64,
    /// Entries tried, and how many of those are still there.
    pub tried: usize,
    pub failed: usize,
    /// The first that is still there, and why.
    pub first_failure: Option<String>,
    /// Mount points that were not entered, and are as they were: another file
    /// system is not part of a cache, whatever it is mounted on.
    pub left: Vec<PathBuf>,
}

impl Emptied {
    /// Note what became of one entry of `size` bytes (see [`remove_entry`]).
    pub fn add(&mut self, path: &Path, size: u64, result: io::Result<Removal>) {
        self.tried += 1;
        match result {
            Ok(removal) => {
                // What was gone before we got to it freed nothing of ours, and
                // left nothing behind.
                if removal.removed {
                    self.freed += size;
                }
                self.left.extend(removal.left);
            }
            Err(why) => {
                self.failed += 1;
                if self.first_failure.is_none() {
                    self.first_failure = Some(format!("{}: {why}", path.display()));
                }
            }
        }
    }

    /// Say which mount points were left alone, and why. Not a failure: leaving
    /// them is the job, but a directory that does not end up empty deserves
    /// its explanation.
    pub fn mention_left(&self) {
        for note in self.left_notes() {
            warning(&note);
        }
    }

    /// One line for each mount point that was left, in the order of the paths and
    /// not of the directory listings they came from.
    fn left_notes(&self) -> Vec<String> {
        let mut left: Vec<&PathBuf> = self.left.iter().collect();
        left.sort();
        left.into_iter()
            .map(|mount| {
                format!(
                    "Kept {}: another file system is mounted there",
                    mount.display()
                )
            })
            .collect()
    }

    /// The error to report for emptying `dir`, when anything is still there.
    pub fn complaint(&self, dir: &Path) -> Option<String> {
        let first = self.first_failure.as_deref()?;
        Some(format!(
            "Could not remove {} of {} item(s) in {}: {first}",
            self.failed,
            self.tried,
            dir.display()
        ))
    }
}

/// What became of one entry of a cache directory (see [`remove_entry`]).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Removal {
    /// Whether it was removed or, for a tree with a mount point inside it, all
    /// of it that is not on another file system. False when it was gone before
    /// we got to it, and when it is a mount point itself.
    pub removed: bool,
    /// The mount points that were not entered, and are as they were.
    pub left: Vec<PathBuf>,
}

/// Remove one entry of a cache directory: a file, a symlink (the link, never
/// what it points to) or a directory tree. [`Removal::removed`] is false when it
/// was already gone, which is as good.
///
/// What most often stops an owner from removing a tree is a directory that has
/// lost its write bit. Go makes its module cache read-only on purpose; an AUR
/// build that fetched modules without `-modcacherw` leaves exactly that in the
/// helper's cache; and whatever was trashed from such a tree arrives in the
/// trash the same way. `rm -rf` fails on it too. Giving the owner back access to
/// the tree's directories and trying once more is the `chmod -R u+w` that
/// clearing it by hand takes, and it only touches what is being deleted. What
/// still cannot be removed after that — another user's files — comes back as
/// the error, for the caller to report.
///
/// A mount point is neither removed nor entered: another file system is not part
/// of a cache, whatever it is mounted on, and `remove_dir_all` would go in and
/// empty it. A tree with one inside it is removed around it, and the directories
/// on the way to it stay. `path` is spelled the way the mounts are (see
/// [`Mounts`]).
pub fn remove_entry(path: &Path, is_real_dir: bool, mounts: &Mounts) -> io::Result<Removal> {
    if mounts.is_mount_point(path) {
        return Ok(Removal {
            removed: false,
            left: vec![path.to_path_buf()],
        });
    }
    if is_real_dir && mounts.below(path).next().is_some() {
        return remove_around_mounts(path, mounts);
    }
    let attempt = || -> io::Result<bool> {
        let removed = if is_real_dir {
            fs::remove_dir_all(path)
        } else {
            fs::remove_file(path)
        };
        match removed {
            Ok(()) => Ok(true),
            Err(why) if why.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(why) => Err(why),
        }
    };
    let removed = match attempt() {
        Err(why) if is_real_dir && why.kind() == io::ErrorKind::PermissionDenied => {
            make_dirs_accessible(path);
            attempt()
        }
        outcome => outcome,
    }?;
    Ok(Removal {
        removed,
        left: Vec::new(),
    })
}

/// Remove what is in `dir` and not on another file system: mount points are
/// left as they are, and so are the directories on the way to them. What cannot
/// be removed does not stop the rest, and the first such error is the one
/// returned.
fn remove_around_mounts(dir: &Path, mounts: &Mounts) -> io::Result<Removal> {
    // A directory that cannot be listed is not one that can be opened either, so
    // there is no access to give back: it is reported (see `grant_if_unchanged`).
    let entries = match fs::read_dir(dir) {
        Err(why) if why.kind() == io::ErrorKind::NotFound => return Ok(Removal::default()),
        other => other?,
    };
    let mut removal = Removal {
        removed: true,
        left: Vec::new(),
    };
    let mut first_error = None;
    for entry in entries {
        let outcome = entry.and_then(|entry| {
            let path = entry.path();
            let is_real_dir = match entry.metadata() {
                Ok(md) => md.is_dir() && !md.is_symlink(),
                Err(why) if why.kind() == io::ErrorKind::NotFound => return Ok(Removal::default()),
                Err(why) => return Err(why),
            };
            let mut outcome = remove_entry(&path, is_real_dir, mounts);
            // `dir` stays, so it is given back no more than the write access
            // that taking something out of it needs, and only when that was the
            // reason it could not be done.
            if matches!(&outcome, Err(why) if why.kind() == io::ErrorKind::PermissionDenied) {
                grant_owner_access(dir);
                outcome = remove_entry(&path, is_real_dir, mounts);
            }
            outcome
        });
        match outcome {
            Ok(inner) => removal.left.extend(inner.left),
            Err(why) => {
                first_error.get_or_insert(why);
            }
        }
    }
    match first_error {
        Some(why) => Err(why),
        None => Ok(removal),
    }
}

/// Give the owner read, write and search permission on `root` and on every
/// directory below it. Symlinks are never entered and nothing outside the tree
/// is touched. Best effort: what cannot be changed is not ours to change.
fn make_dirs_accessible(root: &Path) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        // This one first: without search permission nothing below it is reachable.
        grant_owner_access(&dir);
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            // `DirEntry::file_type` does not follow a link.
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push(entry.path());
            }
        }
    }
}

/// `chmod u+rwx` on `dir`, and only on a real directory: it is looked at
/// without following links, opened, and the opened thing must be the same
/// inode, so a link put in its place after the look is not changed through.
fn grant_owner_access(dir: &Path) {
    if let Ok(seen) = fs::symlink_metadata(dir) {
        grant_if_unchanged(dir, &seen);
    }
}

/// The second half of [`grant_owner_access`], with the first look (`seen`)
/// handed in so that a test can put something else in the path's place.
fn grant_if_unchanged(dir: &Path, seen: &fs::Metadata) {
    // Only a directory is ever opened: opening a FIFO would wait for a writer
    // and opening a device can have effects of its own.
    if !seen.is_dir() {
        return;
    }
    // A directory the owner cannot even read cannot be opened here, and is
    // left alone: it is reported rather than changed through a path that a
    // link could be put in the way of.
    let Ok(file) = fs::File::open(dir) else {
        return;
    };
    let Ok(opened) = file.metadata() else {
        return;
    };
    if !is_same_directory(seen, &opened) {
        return;
    }
    let mode = opened.permissions().mode() & 0o7777;
    if mode & 0o700 != 0o700 {
        let _ = file.set_permissions(fs::Permissions::from_mode(mode | 0o700));
    }
}

/// Whether `opened`, what opening a path reached, is a directory and the very
/// one that `seen`, a look at the same path that did not follow links, found:
/// the same device and inode. Anything else, a link or another directory or a
/// file that took its place in between, is not something to change.
fn is_same_directory(seen: &fs::Metadata, opened: &fs::Metadata) -> bool {
    opened.is_dir() && opened.dev() == seen.dev() && opened.ino() == seen.ino()
}

/// Empty a directory, keeping the directory itself. `Err` only when it exists
/// and cannot be read; what could not be removed is in the [`Emptied`], and so
/// are the mount points that were left alone. `path` is spelled the way the
/// mounts are (see [`Mounts`]).
fn empty_dir(path: &Path, mounts: &Mounts) -> io::Result<Emptied> {
    let mut emptied = Emptied::default();
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(why) if why.kind() == io::ErrorKind::NotFound => return Ok(emptied),
        Err(why) => return Err(why),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(why) => {
                emptied.add(path, 0, Err(why));
                continue;
            }
        };
        let p = entry.path();
        // `DirEntry::metadata` is an lstat: one call gives symlink, dir and size.
        let md = match entry.metadata() {
            Ok(md) => md,
            Err(why) if why.kind() == io::ErrorKind::NotFound => continue,
            Err(why) => {
                emptied.add(&p, 0, Err(why));
                continue;
            }
        };
        let is_real_dir = md.is_dir() && !md.is_symlink();
        let size = if mounts.is_mount_point(&p) {
            0
        } else if is_real_dir {
            dir_size_in(&p, mounts)
        } else {
            footprint_of(&md)
        };
        emptied.add(&p, size, remove_entry(&p, is_real_dir, mounts));
    }
    Ok(emptied)
}

/// Remove all contents inside a directory (keeps the dir itself).
/// Returns total bytes freed. What could not be removed is reported as an error,
/// once for the directory: a "freed" figure that quietly leaves out what stayed
/// behind is how a cache that never shrinks goes unnoticed. What is mounted
/// inside the directory is left as it is, with a note, and is not an error.
pub fn rm_contents(path: &Path) -> u64 {
    rm_contents_with(path, Mounts::read())
}

/// [`rm_contents`] with the list of mounts handed in, so that a test can say
/// what is mounted where.
fn rm_contents_with(path: &Path, mounts: io::Result<Mounts>) -> u64 {
    // The mounts are listed by their real paths, so the paths below must be real
    // too: `/home` is a link to `/var/home` on Fedora Silverblue.
    let root = match fs::canonicalize(path) {
        Ok(root) => root,
        // Nothing there, nothing to empty.
        Err(why) if why.kind() == io::ErrorKind::NotFound => return 0,
        Err(why) => {
            error(&format!("Could not read {}: {why}", path.display()));
            return 0;
        }
    };
    let mounts = match mounts {
        Ok(mounts) => mounts,
        Err(why) => {
            // Emptying a tree without knowing what is mounted in it is how a
            // cache run empties something that is not a cache.
            error(&format!(
                "Could not read the list of mounts ({why}), so {} was left alone",
                path.display()
            ));
            return 0;
        }
    };
    match empty_dir(&root, &mounts) {
        Ok(emptied) => {
            emptied.mention_left();
            if let Some(complaint) = emptied.complaint(path) {
                error(&complaint);
            }
            emptied.freed
        }
        Err(why) => {
            error(&format!("Could not read {}: {why}", path.display()));
            0
        }
    }
}

/// What [`sudo_sweep`] removes from a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sweep {
    /// Every regular file below it. The directories stay.
    Files,
    /// All that is in it, directories too. The directory itself stays.
    Contents,
}

/// The `find` that makes a sweep, for the real path of the directory.
///
/// `-xdev` comes first, as a global option: GNU find warns about one that
/// follows a test. It keeps `find` out of another file system mounted inside the
/// tree. `find` empties what it goes into: with a tmpfs mounted inside, both
/// `-mindepth 1 -delete` and `-type f -delete` removed what was in it (GNU find
/// 4.11, and BusyBox's).
fn sweep_args(dir: &str, what: Sweep) -> Vec<&str> {
    let mut args = vec![dir, "-xdev"];
    match what {
        Sweep::Files => args.extend(["-type", "f"]),
        Sweep::Contents => args.extend(["-mindepth", "1"]),
    }
    args.push("-delete");
    args
}

/// Empty a directory that only root may, as `find` run through [`sudo_quiet`]
/// does: `true` when it was done.
///
/// Not when another file system is mounted inside the directory, which is left
/// alone and said to be: what is not mounted is not worth the chance of what is.
/// `-xdev` keeps `find` out of a file system of its own, but a bind mount is the
/// same file system on both sides of it, and only the kernel's list shows it (see
/// [`Mounts`]). A list that cannot be read is no answer, and the directory is
/// left alone then too. The directory itself being a mount point is ordinary
/// (`/var/tmp/portage` on a tmpfs): it is what is mounted inside it that counts.
///
/// `find` is given the real path, the one that list uses. A link as the place
/// to start from is not followed by `find`, which then removes nothing and says
/// that it did.
pub fn sudo_sweep(dir: &str, what: Sweep) -> bool {
    sweep_with(dir, what, Mounts::read(), &|args| sudo_quiet("find", args))
}

/// [`sudo_sweep`] with the list of mounts and the `find` handed in, so that a
/// test can say what is mounted where and see what would be run.
fn sweep_with(
    dir: &str,
    what: Sweep,
    mounts: io::Result<Mounts>,
    find: &dyn Fn(&[&str]) -> bool,
) -> bool {
    let real = match fs::canonicalize(dir) {
        Ok(real) => real,
        // Nothing there, nothing to empty.
        Err(why) if why.kind() == io::ErrorKind::NotFound => return true,
        Err(why) => {
            warning(&format!(
                "Could not resolve {dir} ({why}), so it was left alone"
            ));
            return false;
        }
    };
    let mounts = match mounts {
        Ok(mounts) => mounts,
        Err(why) => {
            warning(&format!(
                "Could not read the list of mounts ({why}), so {dir} was left alone"
            ));
            return false;
        }
    };
    if let Some(inside) = mounts.below(&real).next() {
        warning(&format!(
            "Left {dir} alone: another file system is mounted at {}",
            inside.display()
        ));
        return false;
    }
    let Some(real) = real.to_str() else {
        warning(&format!(
            "{dir} is not a name that can be passed on, so it was left alone"
        ));
        return false;
    };
    find(&sweep_args(real, what))
}

/// Format bytes to human-readable string
pub fn format_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.2} MB", b / MB)
    } else if b >= KB {
        format!("{:.2} KB", b / KB)
    } else {
        format!("{} B", bytes)
    }
}

/// The user's home directory, from `$HOME`.
///
/// Only a usable value counts: absolute and non-empty. An empty `$HOME` would
/// turn `~/.cache` into `.cache` in whatever directory the tool happened to be
/// started from, and a relative one does the same; both are treated as unset,
/// so the callers' "cannot determine HOME" paths run instead of a cleanup of the
/// wrong place.
pub fn home_dir() -> Option<String> {
    usable_home(env::var("HOME").ok())
}

fn usable_home(home: Option<String>) -> Option<String> {
    home.filter(|h| Path::new(h).is_absolute())
}

/// `$HOME`, when root is running and that directory is not root's to clean.
///
/// `sudo -E`, a sudoers file that keeps `HOME`, and older releases of some
/// distributions start root with the home directory of whoever ran sudo. The
/// user-level steps (`--cache`, `--trash`, `--dev`, ...) would then run as root
/// inside a tree that user controls, and where a removal ends up is theirs to
/// say: a link they left as `~/.cache`, or put there during the run, makes root
/// remove whatever it leads to. Nothing below the start path is followed, but
/// where the start path itself leads cannot be told by looking at it.
///
/// So those steps are not run as root in such a home, and `main` says so. A home
/// is root's when [`only_root_can_change`] holds for the directory it leads to
/// now. The directories above it are not looked at (root's home is not put below
/// something somebody else can rename). A user in their own home, the ordinary
/// case, gets `None` without a look.
pub fn foreign_home() -> Option<String> {
    foreign_home_of(is_root(), home_dir(), look_at_home)
}

/// [`foreign_home`] with what it asks of the machine handed in: whether root is
/// running, `$HOME`, and `look`, which says what a path is.
fn foreign_home_of(
    root: bool,
    home: Option<String>,
    look: impl FnOnce(&str) -> io::Result<(bool, u32, u32)>,
) -> Option<String> {
    if !root {
        return None;
    }
    let home = home?;
    is_someone_elses(look(&home)).then_some(home)
}

/// What a home directory is now, as `(a directory, owner, mode)`. A link is
/// followed, as the steps that work in it will follow it.
fn look_at_home(home: &str) -> io::Result<(bool, u32, u32)> {
    look_at_dir(Path::new(home))
}

/// [`look_at_home`] for any path.
fn look_at_dir(dir: &Path) -> io::Result<(bool, u32, u32)> {
    fs::metadata(dir).map(|m| (m.is_dir(), m.uid(), m.mode()))
}

/// Whether what was found about a home directory makes it somebody else's, for
/// root. A directory is root's when root alone can change it. One that is not
/// there is nothing to clean, and what is not a directory has nothing in it to
/// clean: neither is a reason to say no. One that cannot be looked at is
/// refused, because nothing is known about it.
fn is_someone_elses(found: io::Result<(bool, u32, u32)>) -> bool {
    match found {
        Ok((true, uid, mode)) => !only_root_can_change(uid, mode),
        Ok((false, ..)) => false,
        Err(why) => why.kind() != io::ErrorKind::NotFound,
    }
}

/// Ask user for yes/no confirmation. In JSON mode there is no interactive
/// terminal, so we decline by default rather than block on stdin — callers
/// that must proceed non-interactively pass `--yes`, which short-circuits
/// before reaching here.
pub fn confirm(msg: &str) -> bool {
    if silent() {
        return false;
    }
    print!("  {} {} ", "?".cyan().bold(), shown(msg));
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}

// ═══════════════════════════════════════════════════
//  UI Helpers
// ═══════════════════════════════════════════════════

/// Characters that make a terminal do something other than show text, or show
/// text as something it is not: every control character (ESC begins the escape
/// sequences, and the C1 range holds the one-byte CSI), the bidirectional
/// overrides and isolates behind "Trojan Source", the line/paragraph
/// separators and the byte-order mark.
pub fn is_terminal_hazard(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

/// Text from outside, made safe to print: whatever a terminal would act on is
/// shown as the escape that names it (`\u{1b}`, `\n`), so the reader sees what
/// is there and the terminal does nothing about it.
///
/// File names are the reason. Linux allows any byte in one but `/` and NUL, so
/// a file in a cache can be called ESC `[2J` (clear the screen), ESC `]0;...`
/// BEL (retitle the window), or a name, a newline and `✔ Freed 4 GB` (a line
/// that looks like one of ours); and a tool's complaint, replayed under a
/// failure, can quote such a name. Every helper that prints a message passes it
/// through here, so what builds a message does not have to remember to.
///
/// One thing is let through: a color sequence, ESC `[`, digits and `;`, `m`,
/// which is what `colored` writes into our own messages. Text that carries one
/// can change colors and nothing else.
pub fn shown(text: &str) -> Cow<'_, str> {
    if !text.chars().any(is_terminal_hazard) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 16);
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        if c == '\u{1b}' {
            if let Some(len) = color_sequence_len(rest) {
                out.push_str(&rest[..len]);
                rest = &rest[len..];
                continue;
            }
        }
        if is_terminal_hazard(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
        rest = &rest[c.len_utf8()..];
    }
    Cow::Owned(out)
}

/// The length of the color sequence at the start of `s`, if there is one: ESC
/// `[`, up to 64 digits and semicolons, `m`. Anything longer is not a color
/// `colored` would write, and is not let through as one.
fn color_sequence_len(s: &str) -> Option<usize> {
    let params = s.strip_prefix("\u{1b}[")?;
    let n = params
        .bytes()
        .take_while(|b| b.is_ascii_digit() || *b == b';')
        .count();
    (n <= 64 && params.as_bytes().get(n) == Some(&b'm')).then_some(2 + n + 1)
}

pub fn banner(version: &str) {
    if is_quiet() || silent() {
        // Quiet mode: skip the banner entirely. Most automated/scripted
        // users want plain output they can pipe somewhere. JSON mode: nothing
        // but the final object may hit stdout.
        return;
    }
    println!();
    println!(
        "    {} {}  {}",
        "⚡ Oxi".cyan().bold(),
        "Clean".white().bold(),
        format!("v{}", version).dimmed()
    );
    println!(
        "    {}",
        "Fast Cross-Distribution Linux System Cleaner".white()
    );
    println!(
        "    {}",
        "──────────────────────────────────────────────"
            .cyan()
            .dimmed()
    );
    println!();
}

pub fn section(title: &str) {
    if silent() {
        return;
    }
    println!();
    println!("  {} {}", "━━▶".cyan().bold(), shown(title).white().bold());
}

pub fn success(msg: &str) {
    if silent() {
        return;
    }
    println!("    {} {}", "✔".green().bold(), shown(msg));
}

/// Whether a cleanup that freed `freed` bytes ends with a "Freed …" line.
///
/// `failed` says that something went wrong on the way, and was reported then. A
/// "Freed 0 B" beneath that red line reads as a success for work that did not
/// happen, so the line is kept for what was actually freed, or for a step with
/// nothing to complain about, where "0 B" is the honest result.
fn freed_line_wanted(freed: u64, failed: bool) -> bool {
    freed > 0 || !failed
}

/// Close a cleanup with what it freed, unless it freed nothing and failed (see
/// [`freed_line_wanted`]). `mark` is a [`failure_count`] taken when the step
/// began, which is how a step says "something failed" without having to track
/// every call that could fail.
pub fn say_freed(freed: u64, mark: usize) {
    if freed_line_wanted(freed, failure_count() > mark) {
        success(&format!("Freed {}", format_size(freed).green()));
    }
}

pub fn warning(msg: &str) {
    if silent() {
        return;
    }
    println!("    {} {}", "⚠".yellow().bold(), shown(msg));
}

/// What went wrong in this run, so the exit status and the `--json` report can
/// say so as well as the terminal.
///
/// Everything printed through [`error`] lands here, and nothing else does. That
/// is the contract the rest of the code is written to: a step that did not do
/// what it was asked reports itself with `error`, and whatever goes through
/// `error` is a failure by definition. [`warning`] is for what deserves a look
/// without making the run a failure.
#[derive(Default)]
struct Failures {
    /// Every failure reported, however many messages are kept.
    count: usize,
    messages: Vec<String>,
}

/// Messages kept for the report. A run that fails this many times has nothing
/// to add that the first few have not said; the count stays exact.
const KEPT_FAILURES: usize = 100;

impl Failures {
    fn record(&mut self, message: &str) {
        self.count += 1;
        if self.messages.len() < KEPT_FAILURES {
            self.messages.push(message.to_string());
        }
    }

    /// The messages of the failures after the first `mark`.
    fn since(&self, mark: usize) -> Vec<String> {
        self.messages.iter().skip(mark).cloned().collect()
    }
}

static FAILURES: Mutex<Failures> = Mutex::new(Failures {
    count: 0,
    messages: Vec::new(),
});

fn failures() -> MutexGuard<'static, Failures> {
    // Nothing here can leave the list half-updated, so a panic elsewhere is no
    // reason to stop reporting.
    FAILURES.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How many failures this run has reported so far. `main()` turns a non-zero
/// answer into the exit status; taken before a step and handed to
/// [`failures_since`] afterwards, it says which failures the step caused.
pub fn failure_count() -> usize {
    failures().count
}

/// The messages of the failures reported after the first `mark`, where `mark`
/// came from an earlier [`failure_count`].
pub fn failures_since(mark: usize) -> Vec<String> {
    failures().since(mark)
}

/// Report that something did not work. Printed in red, and recorded: this is the
/// one way to make the run end with a failing exit status, and `--json` mode,
/// which prints nothing here, still carries the message in its report.
pub fn error(msg: &str) {
    failures().record(msg);
    if silent() {
        return;
    }
    println!("    {} {}", "✘".red().bold(), shown(msg));
}

/// Informational line. Suppressed by `--quiet` (noisiest lines) and by JSON
/// mode. The user can survive without them.
pub fn info(msg: &str) {
    if is_quiet() || silent() {
        return;
    }
    println!("    {} {}", "ℹ".blue(), shown(msg));
}

/// "Skipped" line. Suppressed by `--quiet` and JSON mode; nothing to act on.
pub fn skip(msg: &str) {
    if is_quiet() || silent() {
        return;
    }
    println!("    {} {}", "⊘".dimmed(), shown(msg).dimmed());
}

/// A line of report content with no marker of its own: a table row, a package
/// in a list. Silent in JSON mode like every other helper here. `--quiet` keeps
/// it, because unlike [`info`] it is the content the user asked for rather than
/// commentary on it.
///
/// Anything a report prints goes through one of these helpers, never straight
/// to `println!`: one stray line is enough to corrupt a `--json` consumer's
/// input, and nothing else would notice.
pub fn plain(msg: &str) {
    if silent() {
        return;
    }
    println!("{}", shown(msg));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    // ── The closing "Freed" line ──

    #[test]
    fn test_a_freed_line_needs_something_freed_or_nothing_wrong() {
        // Done, and something to show for it.
        assert!(freed_line_wanted(4096, false));
        // Partly done: the failure has its own line, and the progress is real.
        assert!(freed_line_wanted(4096, true));
        // Nothing to free and nothing wrong: "0 B" is the answer.
        assert!(freed_line_wanted(0, false));
        // Nothing freed and a failure above it: no success line.
        assert!(!freed_line_wanted(0, true));
    }

    // ── CWE-426: untrusted search path ──

    #[test]
    fn test_resolve_trusted_ignores_path_entirely() {
        // The exploit this guards: a `pacman` planted in ~/.local/bin ran as root
        // because we handed the bare name to `doas`, which searches the caller's
        // $PATH. An executable outside TRUSTED_BIN_DIRS must never resolve, even
        // when $PATH points straight at it.
        let dir = std::env::temp_dir().join(format!("oxi_pathtest_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let evil = dir.join("oxiclean-fake-pkgmanager");
        fs::write(&evil, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut p = fs::metadata(&evil).unwrap().permissions();
            p.set_mode(0o755);
            fs::set_permissions(&evil, p).unwrap();
        }
        assert!(evil.is_file(), "fixture must be a real executable file");

        assert_eq!(
            resolve_trusted("oxiclean-fake-pkgmanager"),
            None,
            "an executable outside TRUSTED_BIN_DIRS must never resolve"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_resolve_trusted_finds_real_system_binaries() {
        // The hardening must not break normal operation: the coreutils we drive
        // live in trusted directories on every supported distro.
        let sh = resolve_trusted("sh").expect("sh must resolve");
        assert!(sh.starts_with('/'), "must be an absolute path, got {sh}");
        assert!(
            TRUSTED_BIN_DIRS.iter().any(|d| sh.starts_with(d)),
            "{sh} resolved outside the trusted set"
        );
    }

    #[test]
    fn test_resolve_trusted_rejects_paths_and_missing() {
        // A name with a separator is not a bare command; refuse rather than guess.
        assert_eq!(resolve_trusted("../../bin/sh"), None);
        assert_eq!(resolve_trusted("subdir/tool"), None);
        // Nonexistent commands resolve to None, not to a bogus path.
        assert_eq!(resolve_trusted("oxiclean_no_such_binary_xyz"), None);
        // An absolute path that does not exist must not be trusted either.
        assert_eq!(resolve_trusted("/nonexistent/oxiclean_xyz"), None);
    }

    #[test]
    fn test_trusted_bin_dirs_are_root_owned_only() {
        // Every trusted directory must be a system location. A user-writable
        // entry here would reopen the hole this list exists to close.
        for d in TRUSTED_BIN_DIRS {
            assert!(d.starts_with('/'), "{d} is not absolute");
            assert!(
                !d.contains("/home/") && !d.contains("/tmp"),
                "{d} is user-writable territory"
            );
            // `~` never expands in these strings, and a per-user Nix profile
            // (`~/.nix-profile/bin`, or `/nix/var/nix/profiles/per-user/...`) is
            // writable by its owner — only the root-owned default profile
            // qualifies.
            assert!(!d.contains('~'), "{d} relies on shell expansion");
            assert!(
                !d.contains("per-user") && !d.contains(".nix-profile"),
                "{d} is a per-user Nix profile, which its owner can write to"
            );
        }
    }

    #[test]
    fn test_only_a_directory_root_alone_can_change_is_trusted() {
        // (owner, mode, trusted). The mode a stat reports carries the file
        // type too; it must not matter.
        let cases = [
            (0, 0o755, true),
            (0, 0o555, true),
            (0, 0o700, true),
            (0, 0o040_755, true),
            (0, 0o775, false),
            (0, 0o757, false),
            (0, 0o777, false),
            (0, 0o041_777, false),
            (1000, 0o755, false),
            (1000, 0o555, false),
        ];
        for (uid, mode, want) in cases {
            assert_eq!(only_root_can_change(uid, mode), want, "uid {uid} {mode:o}");
        }
    }

    #[test]
    fn test_a_directory_is_judged_by_what_it_is_now() {
        let base = scratch("root-controlled");
        fs::write(base.join("file"), b"x").unwrap();
        std::os::unix::fs::symlink("/usr/bin", base.join("link-to-usr-bin")).unwrap();
        std::os::unix::fs::symlink(&base, base.join("link-to-mine")).unwrap();

        // A system directory, and a link that leads to one, as `/run/current-system` does.
        assert!(is_root_controlled(Path::new("/usr/bin")));
        assert!(is_root_controlled(&base.join("link-to-usr-bin")));
        // Something that is not a directory, or is not there, never is, not
        // even a file of root's.
        assert!(!is_root_controlled(&base.join("file")));
        if Path::new("/etc/passwd").is_file() {
            assert!(!is_root_controlled(Path::new("/etc/passwd")));
        }
        assert!(!is_root_controlled(&base.join("missing")));
        // The user's own directory, and a link to it, are not (root can be
        // anyone's owner, so a test run as root cannot say).
        if !is_root() {
            assert!(!is_root_controlled(&base));
            assert!(!is_root_controlled(&base.join("link-to-mine")));
        }
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_the_nixos_directories_are_trusted_one_by_one_and_only_when_checked() {
        use std::cell::RefCell;

        // Nothing passes: the list is what it always was.
        assert_eq!(trusted_dirs_with(&|_| false), TRUSTED_BIN_DIRS);

        // Everything passes: the wrappers lead, as in a NixOS PATH, so the
        // setuid `sudo` is found before any plain copy; the system profile ends.
        let all = trusted_dirs_with(&|_| true);
        assert_eq!(all.len(), TRUSTED_BIN_DIRS.len() + 2);
        assert_eq!(all.first(), Some(&"/run/wrappers/bin"));
        assert_eq!(all.last(), Some(&"/run/current-system/sw/bin"));
        assert_eq!(&all[1..all.len() - 1], TRUSTED_BIN_DIRS);

        // Each is judged on its own.
        let wrappers = trusted_dirs_with(&|d| d == Path::new("/run/wrappers/bin"));
        assert_eq!(wrappers.first(), Some(&"/run/wrappers/bin"));
        assert!(!wrappers.contains(&"/run/current-system/sw/bin"));
        let system = trusted_dirs_with(&|d| d == Path::new("/run/current-system/sw/bin"));
        assert_eq!(system.last(), Some(&"/run/current-system/sw/bin"));
        assert!(!system.contains(&"/run/wrappers/bin"));

        // And only those two are ever put to the check: the standard
        // directories are root's by convention on every distribution.
        let asked = RefCell::new(Vec::new());
        let _ = trusted_dirs_with(&|d| {
            asked.borrow_mut().push(d.to_path_buf());
            false
        });
        assert_eq!(
            asked.into_inner(),
            [
                PathBuf::from("/run/wrappers/bin"),
                PathBuf::from("/run/current-system/sw/bin")
            ]
        );
    }

    #[test]
    fn test_the_first_directory_that_has_the_command_wins() {
        let base = scratch("resolve-in");
        let (a, b) = (base.join("a"), base.join("b"));
        for d in [&a, &b] {
            fs::create_dir_all(d).unwrap();
            fs::write(d.join("tool"), b"x").unwrap();
        }
        fs::write(b.join("only-b"), b"x").unwrap();
        let (sa, sb) = (a.to_str().unwrap(), b.to_str().unwrap());

        assert_eq!(resolve_in(&[sa, sb], "tool"), Some(format!("{sa}/tool")));
        assert_eq!(resolve_in(&[sb, sa], "tool"), Some(format!("{sb}/tool")));
        assert_eq!(
            resolve_in(&[sa, sb], "only-b"),
            Some(format!("{sb}/only-b"))
        );
        assert_eq!(resolve_in(&[sa, sb], "nothing"), None);
        assert_eq!(resolve_in(&[], "tool"), None);
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_children_get_the_same_directories_the_lookup_uses() {
        assert_eq!(trusted_path(), trusted_dirs().join(":"));
    }

    #[test]
    fn test_trusted_path_is_what_children_get() {
        // Children must receive our chosen PATH, not the inherited one.
        let p = trusted_path();
        for d in TRUSTED_BIN_DIRS {
            assert!(p.contains(d), "trusted PATH is missing {d}");
        }
        assert!(!p.is_empty());
    }

    #[test]
    fn test_elevate_none_never_spawns_even_for_trusted_binary() {
        // Privilege::None means no helper exists. Even a perfectly trusted
        // command must not run — there is nothing to escalate with.
        assert!(!elevate(Privilege::None, "sh", &["-c", "exit 0"]));
    }

    #[test]
    fn test_elevate_refuses_untrusted_command() {
        // With no helper needed (Root), a command outside the trusted set must
        // still be refused rather than resolved through $PATH.
        assert!(!elevate(
            Privilege::Root,
            "oxiclean_no_such_binary_xyz",
            &[]
        ));
    }

    #[test]
    fn test_is_root_matches_the_kernel() {
        // is_root reads /proc/self/status instead of trusting an `id` binary that
        // could be shadowed to print "0" — which would make us skip escalation.
        // Cross-check against the real euid.
        let expected = fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines().find_map(|l| {
                    l.strip_prefix("Uid:")
                        .and_then(|r| r.split_whitespace().nth(1).map(|e| e == "0"))
                })
            })
            .expect("/proc/self/status must expose Uid");
        assert_eq!(is_root(), expected);
    }

    #[test]
    fn test_format_size_bytes() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
    }

    #[test]
    fn test_format_size_kb() {
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1536), "1.50 KB");
    }

    #[test]
    fn test_format_size_mb() {
        assert_eq!(format_size(1_048_576), "1.00 MB");
    }

    #[test]
    fn test_format_size_gb() {
        assert_eq!(format_size(1_073_741_824), "1.00 GB");
    }

    #[test]
    fn test_format_size_boundary_kb_mb() {
        // 1024 * 1024 - 1 must stay in KB, not flip to MB
        assert_eq!(format_size(1_048_575), "1024.00 KB");
        assert_eq!(format_size(1_048_576), "1.00 MB");
    }

    #[test]
    fn test_format_size_boundary_mb_gb() {
        // 1024 * 1024 * 1024 - 1 must stay in MB, not flip to GB
        assert_eq!(format_size(1_073_741_823), "1024.00 MB");
        assert_eq!(format_size(1_073_741_824), "1.00 GB");
    }

    #[test]
    fn test_which_exists() {
        assert!(which("ls"));
        assert!(which("echo"));
    }

    #[test]
    fn test_which_not_exists() {
        assert!(!which("nonexistent_command_xyz_12345"));
    }

    #[test]
    fn test_only_an_absolute_home_is_usable() {
        let some = |s: &str| Some(s.to_string());
        assert_eq!(usable_home(some("/home/u")), some("/home/u"));
        assert_eq!(usable_home(some("/")), some("/"), "root in a container");
        assert_eq!(usable_home(some("")), None, "empty would mean the cwd");
        assert_eq!(usable_home(some("home/u")), None, "relative would too");
        assert_eq!(usable_home(some(".")), None);
        assert_eq!(usable_home(None), None);
    }

    // ── Root in a home directory that is not root's ──

    fn found(is_dir: bool, uid: u32, mode: u32) -> io::Result<(bool, u32, u32)> {
        Ok((is_dir, uid, mode))
    }

    #[test]
    fn test_a_home_directory_is_roots_when_only_root_can_change_it() {
        // Root's own, as systems make it.
        for mode in [0o700, 0o750, 0o755, 0o550] {
            assert!(!is_someone_elses(found(true, 0, mode)), "{mode:o}");
        }
        // Another account's, however closed it is.
        for uid in [1, 1000, 65534] {
            assert!(is_someone_elses(found(true, uid, 0o700)), "uid {uid}");
        }
        // Root's, but open to its group or to everyone; a sticky bit changes
        // nothing about what can be put in it.
        for mode in [0o720, 0o702, 0o775, 0o757, 0o777, 0o1777, 0o2775] {
            assert!(is_someone_elses(found(true, 0, mode)), "{mode:o}");
        }
    }

    #[test]
    fn test_what_cannot_be_cleaned_anyway_is_no_reason_to_refuse() {
        let missing: io::Result<(bool, u32, u32)> = Err(io::ErrorKind::NotFound.into());
        assert!(!is_someone_elses(missing), "there is nothing to clean");
        // A file has nothing in it, whoever it belongs to.
        assert!(!is_someone_elses(found(false, 1000, 0o644)));
        // What cannot be looked at is not known to be root's.
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::Other,
        ] {
            assert!(is_someone_elses(Err(kind.into())), "{kind:?}");
        }
    }

    #[test]
    fn test_only_root_in_a_home_that_is_not_roots_is_in_a_foreign_one() {
        let home = || Some("/home/u".to_string());
        let theirs = |_: &str| found(true, 1000, 0o755);
        let roots = |_: &str| found(true, 0, 0o700);
        let never = |_: &str| -> io::Result<(bool, u32, u32)> {
            panic!("a home directory was looked at that nothing was asked about")
        };

        // A user in their own home is what the tool is for, and it is not looked at.
        assert_eq!(foreign_home_of(false, home(), never), None);
        // Root in somebody else's home, and in its own.
        assert_eq!(
            foreign_home_of(true, home(), theirs),
            Some("/home/u".to_string())
        );
        assert_eq!(foreign_home_of(true, home(), roots), None);
        // With no usable HOME there is nothing to refuse: the steps say what
        // they say about it themselves.
        assert_eq!(foreign_home_of(true, None, never), None);
    }

    #[test]
    fn test_a_home_directory_is_looked_at_as_the_steps_will_reach_it() {
        let dir = real_scratch("look_at_home");
        let md = fs::metadata(&dir).unwrap();
        let at = |p: &Path| look_at_home(p.to_str().unwrap());
        assert_eq!(at(&dir).unwrap(), (true, md.uid(), md.mode()));

        // A link is followed, as the steps follow it.
        let link = dir.join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert_eq!(at(&link).unwrap(), (true, md.uid(), md.mode()));
        // A file is not a directory.
        let file = dir.join("file");
        fs::write(&file, "x").unwrap();
        assert!(!at(&file).unwrap().0);
        // And what is not there says so, which is what makes it nothing to clean.
        let gone = dir.join("gone");
        assert_eq!(at(&gone).unwrap_err().kind(), io::ErrorKind::NotFound);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_a_user_is_never_in_somebody_elses_home() {
        // Only for root does the answer depend on whose HOME it has.
        if !is_root() {
            assert_eq!(foreign_home(), None);
        }
    }

    // ── Root and $PATH ──

    #[test]
    fn test_root_keeps_only_the_path_entries_that_root_alone_can_change() {
        let look = |dir: &Path| match dir.to_str().unwrap() {
            "/usr/bin" | "/usr/local/bin" => found(true, 0, 0o755),
            "/home/u/.local/bin" => found(true, 1000, 0o755),
            "/opt/shared/bin" => found(true, 0, 0o775),
            "/opt/open/bin" => found(true, 0, 0o777),
            "/srv/tool" => found(false, 0, 0o755),
            "/gone/bin" => Err(io::ErrorKind::NotFound.into()),
            "/locked/bin" => Err(io::ErrorKind::PermissionDenied.into()),
            other => panic!("{other} is not an absolute entry, and was looked at"),
        };
        let path = OsStr::new(
            "/home/u/.local/bin:/usr/local/bin:/opt/shared/bin:/usr/bin:/opt/open/bin:\
             /srv/tool:/gone/bin:/locked/bin:.::relative/bin",
        );
        let (new, left_out) = harden_path_with(true, path, look).unwrap();
        // Root's own stay, in the order they were in.
        assert_eq!(new, OsString::from("/usr/local/bin:/usr/bin"));
        // What is named is what is there and that somebody else can change, or
        // cannot be looked at; not what could never have held a tool.
        let named: Vec<&str> = left_out.iter().map(|p| p.to_str().unwrap()).collect();
        assert_eq!(
            named,
            [
                "/home/u/.local/bin",
                "/opt/shared/bin",
                "/opt/open/bin",
                "/locked/bin"
            ]
        );
    }

    #[test]
    fn test_a_users_path_is_not_touched_and_a_safe_one_is_not_rewritten() {
        let never =
            |_: &Path| -> io::Result<(bool, u32, u32)> { panic!("a user's PATH was looked at") };
        let path = OsStr::new("/home/u/.local/bin:/usr/bin");
        assert_eq!(harden_path_with(false, path, never), None);

        let roots = |_: &Path| found(true, 0, 0o755);
        let safe = OsStr::new("/usr/local/bin:/usr/bin:/bin");
        assert_eq!(harden_path_with(true, safe, roots), None);
    }

    #[test]
    fn test_root_with_nothing_left_gets_the_trusted_directories() {
        let theirs = |_: &Path| found(true, 1000, 0o755);
        let path = OsStr::new("/home/u/bin:/home/u/.local/bin");
        let (new, left_out) = harden_path_with(true, path, theirs).unwrap();
        assert_eq!(new, OsString::from(trusted_path()));
        assert_eq!(left_out.len(), 2);

        // An empty PATH is the current directory to whatever searches it.
        let never = |_: &Path| -> io::Result<(bool, u32, u32)> {
            panic!("an entry that is not absolute was looked at")
        };
        let (new, left_out) = harden_path_with(true, OsStr::new(""), never).unwrap();
        assert_eq!(new, OsString::from(trusted_path()));
        assert!(left_out.is_empty());
    }

    #[test]
    fn test_home_dir_exists() {
        let home = home_dir();
        assert!(home.is_some());
        assert!(!home.unwrap().is_empty());
    }

    #[test]
    fn test_capture_echo() {
        let result = capture("echo", &["hello"]);
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn test_capture_nonexistent() {
        let result = capture("nonexistent_cmd_xyz", &[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_dir_size_nonexistent() {
        let path = PathBuf::from("/tmp/oxiclean_test_nonexistent");
        assert_eq!(dir_size(&path), 0);
    }

    #[test]
    fn test_dir_size_and_rm() {
        let test_dir = PathBuf::from("/tmp/oxiclean_test_size");
        let _ = fs::remove_dir_all(&test_dir);
        fs::create_dir_all(&test_dir).unwrap();
        fs::write(test_dir.join("a.txt"), "hello").unwrap();
        fs::write(test_dir.join("b.txt"), "world!!!").unwrap();
        let sub = test_dir.join("subdir");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("c.txt"), "test data").unwrap();

        let size = dir_size(&test_dir);
        assert!(size > 0);

        let freed = rm_contents(&test_dir);
        assert!(freed > 0);
        assert!(test_dir.exists());
        assert_eq!(dir_size(&test_dir), 0);
        let _ = fs::remove_dir_all(&test_dir);
    }

    /// `len` bytes that no filesystem can compress or share, so that a size
    /// means the same on every one of them (a cheap xorshift stream).
    fn noise(len: usize) -> Vec<u8> {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15 ^ len as u64;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    /// What the filesystem says `path` occupies.
    fn on_disk(path: &Path) -> u64 {
        allocated(&fs::symlink_metadata(path).unwrap())
    }

    #[test]
    fn test_dir_size_and_rm_handle_symlinks() {
        // dir_size and rm_contents take type and size from the DirEntry rather
        // than re-stat each path. The subtle part is that DirEntry::metadata is
        // an lstat: it must report the *link*, never follow it. Getting that
        // wrong would count a symlink target's bytes (inflating the freed
        // figure) or, worse, descend out of the tree being cleaned.
        use std::os::unix::fs::symlink;
        let base = scratch("lnk");

        let outside = base.join("outside");
        let tree = base.join("tree");
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(tree.join("sub")).unwrap();

        // A big file OUTSIDE the tree, and a big directory outside it.
        fs::write(outside.join("big.bin"), noise(1 << 20)).unwrap();
        // Real content inside the tree.
        fs::write(tree.join("real.bin"), noise(64 << 10)).unwrap();
        fs::write(tree.join("sub/inner.bin"), noise(48 << 10)).unwrap();
        let real = on_disk(&tree.join("real.bin")) + on_disk(&tree.join("sub/inner.bin"));
        // Links that must contribute their own (tiny) size, never the target's.
        symlink(outside.join("big.bin"), tree.join("link_to_big")).unwrap();
        symlink(&outside, tree.join("link_to_dir")).unwrap();
        symlink("/nonexistent/xyz", tree.join("broken")).unwrap();

        // The real content only: symlinks are skipped by dir_size, and the
        // megabyte they lead to is not counted through either of them.
        assert_eq!(
            dir_size(&tree),
            real,
            "symlinks must be skipped and never followed"
        );

        let freed = rm_contents(&tree);
        assert!(tree.is_dir(), "the directory itself must survive");
        assert_eq!(dir_size(&tree), 0, "contents must be gone");
        // The link target must still exist: we unlinked the links, not the files.
        assert!(
            outside.join("big.bin").is_file(),
            "rm_contents followed a symlink and deleted outside the tree"
        );
        // Freed is the real content, plus at most a block for each link's own
        // entry (a filesystem may give a long link target one); never the megabyte.
        assert!(
            (real..real + 3 * 4096 + 1).contains(&freed),
            "freed should be about {real}, got {freed}"
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_dir_size_on_a_symlink_is_zero() {
        // A symlink handed in directly must report 0, not the target's size.
        use std::os::unix::fs::symlink;
        let base = scratch("lnktop");
        fs::write(base.join("target.bin"), noise(50_000)).unwrap();
        let link = base.join("thelink");
        symlink(base.join("target.bin"), &link).unwrap();

        assert_eq!(dir_size(&link), 0);
        let target = dir_size(&base.join("target.bin"));
        assert_eq!(target, on_disk(&base.join("target.bin")));
        assert!(target >= 50_000, "{target}");

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_a_file_counts_what_it_occupies_on_disk() {
        let base = scratch("on-disk");
        // A small file takes a block, not its length.
        fs::write(base.join("small"), b"x").unwrap();
        let small = dir_size(&base.join("small"));
        assert_eq!(small, on_disk(&base.join("small")));
        assert!(small >= 512, "{small}");
        // In whole blocks, and in the right unit: 70 000 bytes of noise take
        // 70 000 rounded up to a block, give or take what a filesystem adds.
        fs::write(base.join("big"), noise(70_000)).unwrap();
        let big = dir_size(&base.join("big"));
        assert!((70_000..70_000 + 16_384).contains(&big), "{big}");

        // A sparse file takes what was written, not what it spans.
        let sparse = base.join("sparse");
        let file = fs::File::create(&sparse).unwrap();
        file.set_len(8 << 20).unwrap();
        drop(file);
        {
            use std::io::{Seek, SeekFrom};
            let mut f = fs::OpenOptions::new().write(true).open(&sparse).unwrap();
            f.seek(SeekFrom::Start(4 << 20)).unwrap();
            f.write_all(&noise(4096)).unwrap();
        }
        let span = fs::metadata(&sparse).unwrap().len();
        let used = dir_size(&sparse);
        assert_eq!(used, on_disk(&sparse));
        // (A filesystem that cannot make holes would give the span back.)
        if used < span {
            assert!(used < 1 << 20, "a sparse file counted as {used} of {span}");
        }
        // Inside a tree it is the same.
        fs::create_dir(base.join("tree")).unwrap();
        fs::rename(&sparse, base.join("tree/sparse")).unwrap();
        assert_eq!(dir_size(&base.join("tree")), used);
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_empty_directories_are_not_something_to_clean() {
        // "Nothing to clean" is a size of 0; the blocks a directory itself
        // occupies must not turn an empty skeleton into one.
        let base = scratch("skeleton");
        fs::create_dir_all(base.join("a/b/c")).unwrap();
        fs::create_dir_all(base.join("d")).unwrap();
        assert_eq!(dir_size(&base), 0);
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_a_file_with_two_names_counts_once_and_only_when_both_are_going() {
        let base = scratch("links");
        let tree = base.join("tree");
        let outside = base.join("outside");
        fs::create_dir_all(tree.join("sub")).unwrap();
        fs::create_dir_all(&outside).unwrap();

        // Both names in the tree: counted once, at its size.
        fs::write(tree.join("a"), noise(64 << 10)).unwrap();
        fs::hard_link(tree.join("a"), tree.join("sub/a2")).unwrap();
        let a = on_disk(&tree.join("a"));
        assert!(a >= 64 << 10);
        assert_eq!(dir_size(&tree), a, "two names of one file are one file");

        // A name outside the tree: removing the tree frees nothing for it.
        fs::write(outside.join("x"), noise(64 << 10)).unwrap();
        fs::hard_link(outside.join("x"), tree.join("x-in-tree")).unwrap();
        assert_eq!(dir_size(&tree), a, "a file that stays is not freed");
        assert_eq!(dir_size(&tree.join("x-in-tree")), 0);

        // Three names, two of them in the tree and one outside: it stays.
        fs::write(outside.join("y"), noise(64 << 10)).unwrap();
        fs::hard_link(outside.join("y"), tree.join("y1")).unwrap();
        fs::hard_link(outside.join("y"), tree.join("sub/y2")).unwrap();
        assert_eq!(dir_size(&tree), a);

        // And the file without other names is counted in full beside them.
        fs::write(tree.join("z"), noise(32 << 10)).unwrap();
        assert_eq!(dir_size(&tree), a + on_disk(&tree.join("z")));
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_emptying_a_directory_frees_nothing_for_a_file_that_stays() {
        let base = scratch("links-rm");
        let tree = base.join("tree");
        let outside = base.join("outside");
        fs::create_dir_all(&tree).unwrap();
        fs::create_dir_all(&outside).unwrap();
        // Sizes that are not a multiple of a block, so that a length is not
        // mistaken for what the file occupies.
        fs::write(outside.join("shared"), noise(70_000)).unwrap();
        fs::hard_link(outside.join("shared"), tree.join("shared")).unwrap();
        fs::write(tree.join("own"), noise(70_001)).unwrap();
        let own = on_disk(&tree.join("own"));

        let freed = rm_contents(&tree);

        assert_eq!(freed, own, "only the file that had no other name was freed");
        // The data is still there, under its other name.
        assert_eq!(fs::read(outside.join("shared")).unwrap(), noise(70_000));
        // Under that name alone it is now the file's to free.
        let md = fs::symlink_metadata(outside.join("shared")).unwrap();
        assert_eq!(footprint_of(&md), on_disk(&outside.join("shared")));
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_what_one_entry_frees_is_its_blocks_unless_it_has_another_name() {
        let base = scratch("footprint");
        fs::write(base.join("one"), noise(64 << 10)).unwrap();
        let alone = footprint_of(&fs::symlink_metadata(base.join("one")).unwrap());
        assert_eq!(alone, on_disk(&base.join("one")));
        assert!(alone >= 64 << 10);

        fs::hard_link(base.join("one"), base.join("two")).unwrap();
        for name in ["one", "two"] {
            let md = fs::symlink_metadata(base.join(name)).unwrap();
            assert_eq!(footprint_of(&md), 0, "{name} has another name");
        }
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_rm_contents_empty() {
        let test_dir = PathBuf::from("/tmp/oxiclean_test_empty");
        let _ = fs::remove_dir_all(&test_dir);
        fs::create_dir_all(&test_dir).unwrap();
        assert_eq!(rm_contents(&test_dir), 0);
        let _ = fs::remove_dir_all(&test_dir);
    }

    // ── Privilege escalation ──

    #[test]
    fn test_elevate_root_runs_directly() {
        // Privilege::Root must invoke the command directly, with no wrapper.
        // `true` exits 0 — it succeeds only if we did NOT prepend `sudo `/`doas `
        // (which would resolve to non-existent binaries in some environments
        // and would either fail outright or prompt for a password).
        assert!(elevate(Privilege::Root, "true", &[]));
    }

    #[test]
    fn test_elevate_root_propagates_failure() {
        // `false` exits non-zero; elevate must surface that.
        assert!(!elevate(Privilege::Root, "false", &[]));
    }

    #[test]
    fn test_elevate_none_never_spawns() {
        // Privilege::None means no escalation tool exists. elevate must return
        // false WITHOUT trying to run anything — even a command that would
        // otherwise succeed (`true`) must not run, because there's no helper.
        assert!(!elevate(Privilege::None, "true", &[]));
        // acquire_privilege must likewise refuse rather than "succeed".
        assert!(!acquire_privilege(Privilege::None));
    }

    // ── Escalation: what runs, and with what ──

    #[test]
    fn test_escalation_builds_the_command_line_for_each_helper() {
        let resolve = |name: &str| match name {
            "sh" => Some("/usr/bin/sh".to_string()),
            "sudo" => Some("/usr/bin/sudo".to_string()),
            "doas" => Some("/usr/bin/doas".to_string()),
            _ => None,
        };
        let args = ["-c", "echo $0 'quoted'", "with space"];
        let owned = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        // Root runs the resolved path directly.
        assert_eq!(
            escalation(Privilege::Root, "sh", &args, &resolve),
            Some(("/usr/bin/sh".to_string(), owned(&args)))
        );
        // sudo and doas are handed the resolved absolute path of the command,
        // then its arguments untouched.
        let through = owned(&["/usr/bin/sh", "-c", "echo $0 'quoted'", "with space"]);
        assert_eq!(
            escalation(Privilege::Sudo, "sh", &args, &resolve),
            Some(("/usr/bin/sudo".to_string(), through.clone()))
        );
        assert_eq!(
            escalation(Privilege::Doas, "sh", &args, &resolve),
            Some(("/usr/bin/doas".to_string(), through))
        );
        // Nothing to escalate with, or nothing to run.
        assert_eq!(escalation(Privilege::None, "sh", &args, &resolve), None);
        assert_eq!(
            escalation(Privilege::Sudo, "unknown", &args, &resolve),
            None
        );
    }

    #[test]
    fn test_escalation_never_runs_without_the_tool_it_needs() {
        let only_sh = |name: &str| (name == "sh").then(|| "/usr/bin/sh".to_string());
        assert_eq!(escalation(Privilege::Sudo, "sh", &[], &only_sh), None);
        assert_eq!(escalation(Privilege::Doas, "sh", &[], &only_sh), None);
        // Root needs no helper.
        assert!(escalation(Privilege::Root, "sh", &[], &only_sh).is_some());
        // And a helper is never put in front of a command that was not found.
        let only_sudo = |name: &str| (name == "sudo").then(|| "/usr/bin/sudo".to_string());
        assert_eq!(escalation(Privilege::Sudo, "sh", &[], &only_sudo), None);
    }

    #[test]
    fn test_escalation_resolves_through_the_trusted_directories() {
        let (program, _) = escalation(Privilege::Root, "sh", &[], &resolve_trusted).unwrap();
        assert!(program.starts_with('/'), "{program}");
        assert!(
            TRUSTED_BIN_DIRS.iter().any(|d| program.starts_with(d)),
            "{program}"
        );
        assert_eq!(
            escalation(Privilege::Root, "./sh", &[], &resolve_trusted),
            None
        );
        assert_eq!(
            escalation(
                Privilege::Root,
                "oxiclean_no_such_binary_xyz",
                &[],
                &resolve_trusted
            ),
            None
        );
    }

    // ── elevate_with_input ──

    /// `sh -c script out` with `input` on stdin, as `Privilege::Root` would run
    /// it; `$0` in the script is the path of the output file.
    fn root_sh_with_input(script: &str, out: &Path, input: &[u8]) -> bool {
        let out = out.to_str().unwrap();
        elevate_with_input(Privilege::Root, "sh", &["-c", script, out], input)
    }

    /// Not one repeated byte, so a dropped or reordered chunk shows.
    fn patterned(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn test_elevate_with_input_hands_over_every_byte() {
        let dir = scratch("input_all");
        let out = dir.join("out");
        // Many times a pipe buffer: the writer has to keep going while the
        // command reads.
        let input = patterned(3 << 20);
        assert!(root_sh_with_input("cat > \"$0\"", &out, &input));
        assert_eq!(fs::read(&out).unwrap(), input);
        // An empty input is a valid input.
        assert!(root_sh_with_input("cat > \"$0\"", &out, b""));
        assert_eq!(fs::read(&out).unwrap(), b"");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_elevate_with_input_reports_a_command_that_fails() {
        let dir = scratch("input_fails");
        let out = dir.join("out");
        assert!(!root_sh_with_input(
            "cat > \"$0\"; exit 1",
            &out,
            b"payload"
        ));
        // It did receive the input; the failure is its own.
        assert_eq!(fs::read(&out).unwrap(), b"payload");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_elevate_with_input_is_a_failure_when_the_command_stops_reading() {
        // Exits 0 without reading a byte of 4 MiB. Whatever it did with what it
        // never saw is not something to vouch for, and the writer must not hang
        // on a pipe nobody reads.
        let dir = scratch("input_early");
        let out = dir.join("out");
        let started = std::time::Instant::now();
        assert!(!root_sh_with_input("exit 0", &out, &patterned(4 << 20)));
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_elevate_with_input_runs_nothing_it_may_not() {
        let dir = scratch("input_refused");
        let marker = dir.join("ran");
        let marker = marker.to_str().unwrap();
        let script = "touch \"$0\"";
        // No escalation tool exists.
        assert!(!elevate_with_input(
            Privilege::None,
            "sh",
            &["-c", script, marker],
            b"x"
        ));
        // A command outside the trusted directories, by name or by path.
        assert!(!elevate_with_input(
            Privilege::Root,
            "oxiclean_no_such_binary_xyz",
            &[marker],
            b"x"
        ));
        assert!(!elevate_with_input(
            Privilege::Root,
            "./sh",
            &["-c", script, marker],
            b"x"
        ));
        assert!(!Path::new(marker).exists(), "something ran");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_elevate_with_input_gives_the_child_the_trusted_path() {
        let dir = scratch("input_path");
        let out = dir.join("out");
        assert!(root_sh_with_input(
            "printf %s \"$PATH\" > \"$0\"",
            &out,
            b""
        ));
        assert_eq!(fs::read_to_string(&out).unwrap(), trusted_path());
        fs::remove_dir_all(&dir).unwrap();
    }

    // ── A question put to a command: its status is part of the answer ──

    #[test]
    fn test_elevate_capture_hands_back_the_status_and_both_streams() {
        let c = elevate_capture(
            Privilege::Root,
            "sh",
            &["-c", "printf 0; printf 'sudo: no' >&2; exit 1"],
        )
        .expect("sh is in a trusted directory");
        assert_eq!(c.code, Some(1));
        assert_eq!(c.stdout, "0");
        assert_eq!(c.stderr, "sudo: no");
    }

    #[test]
    fn test_elevate_capture_of_a_command_a_signal_ended_has_no_status() {
        let c = elevate_capture(Privilege::Root, "sh", &["-c", "kill -9 $$"]).unwrap();
        assert_eq!(c.code, None);
    }

    #[test]
    fn test_elevate_capture_runs_nothing_it_may_not() {
        let dir = scratch("capture_refused");
        let marker = dir.join("ran");
        let marker = marker.to_str().unwrap();
        let script = "touch \"$0\"";
        // No escalation tool exists.
        assert!(elevate_capture(Privilege::None, "sh", &["-c", script, marker]).is_none());
        // A command outside the trusted directories, by name or by path.
        assert!(
            elevate_capture(Privilege::Root, "oxiclean_no_such_binary_xyz", &[marker]).is_none()
        );
        assert!(elevate_capture(Privilege::Root, "./sh", &["-c", script, marker]).is_none());
        assert!(!Path::new(marker).exists(), "something ran");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_elevate_capture_gives_the_child_the_trusted_path() {
        let c = elevate_capture(Privilege::Root, "sh", &["-c", "printf %s \"$PATH\""]).unwrap();
        assert_eq!(c.stdout, trusted_path());
    }

    #[test]
    fn test_current_privilege_default_is_sudo() {
        // Until main() sets PRIVILEGE, current_privilege() falls back to Sudo.
        // We can't assert equality reliably across the whole test suite
        // (any earlier test that calls set_privilege would change it), so we
        // just assert that the call returns *some* valid variant and does not
        // panic.
        let p = current_privilege();
        let _ = p.name();
    }

    // ── Two tiers of trust: system tools vs. the user's own ──
    //
    // 1.8.0 narrowed the child's PATH for *every* command, which also narrowed
    // where `Command` looks for the program: `--dev` quietly stopped finding
    // `uv`, `pnpm` and `deno` in the user's home. These tests pin the contract
    // of each tier so that cannot come back unnoticed.
    //
    // The tools they start are symlinks to `/bin/sh`, never scripts written on
    // the spot: executing a file this thread has only just written races with
    // every other test thread that forks ("Text file busy"), and a test that
    // flakes one run in fifteen is worse than no test.

    /// A fresh, empty directory unique to this test (and to this process).
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("oxi_{name}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// `remove_entry` with nothing mounted anywhere, answering as it did before
    /// mounts were looked at: whether the entry was removed.
    fn remove_plain(path: &Path, is_real_dir: bool) -> io::Result<bool> {
        remove_entry(path, is_real_dir, &Mounts::default()).map(|removal| removal.removed)
    }

    /// Put a tool called `name` in `dir`: a symlink that behaves like `sh`.
    fn sh_as(dir: &Path, name: &str) -> PathBuf {
        let link = dir.join(name);
        std::os::unix::fs::symlink("/bin/sh", &link).unwrap();
        link
    }

    /// `dir` spelled relative to the current directory, so a test can build
    /// relative paths that really do lead somewhere.
    fn relative_to_cwd(dir: &Path) -> PathBuf {
        let cwd = env::current_dir().unwrap();
        let up = "../".repeat(cwd.components().count() - 1);
        Path::new(&up).join(dir.strip_prefix("/").unwrap())
    }

    #[test]
    fn test_which_path_finds_tools_the_trusted_resolver_refuses() {
        // The 1.8.0 regression in two lines: a tool installed under the user's
        // home is invisible to the trusted resolver by design, yet `--dev` has
        // to be able to reach it.
        let dir = scratch("which_user_tool");
        let tool = sh_as(&dir, "oxiclean-user-tool");

        assert_eq!(resolve_trusted("oxiclean-user-tool"), None);
        assert_eq!(
            which_path_in("oxiclean-user-tool", dir.as_os_str()),
            Some(tool)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_which_path_skips_non_executables_and_directories() {
        // Only something we could actually start counts, and the first runnable
        // match wins: `a` holds a data file of that name, `b` a directory, `c`
        // the real tool.
        let root = scratch("which_skips");
        let (a, b, c) = (root.join("a"), root.join("b"), root.join("c"));
        for dir in [&a, &b, &c] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(a.join("tool"), "not a program").unwrap();
        fs::create_dir(b.join("tool")).unwrap();
        sh_as(&c, "tool");

        let all = env::join_paths([&a, &b, &c]).unwrap();
        assert_eq!(which_path_in("tool", &all), Some(c.join("tool")));
        let without_the_tool = env::join_paths([&a, &b]).unwrap();
        assert_eq!(which_path_in("tool", &without_the_tool), None);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_which_path_ignores_relative_and_empty_path_entries() {
        // To a shell an empty `$PATH` entry means "the current directory", and a
        // relative one is whatever the cwd makes it. Starting a tool found that
        // way runs a file the caller never chose (CWE-426, the same hole
        // TRUSTED_BIN_DIRS closes for privileged commands), so neither counts.
        let dir = scratch("which_relative");
        sh_as(&dir, "oxiclean-rel-tool");

        // The very same directory, spelled relative to wherever the tests run.
        let relative = relative_to_cwd(&dir);
        assert!(
            is_executable_file(&relative.join("oxiclean-rel-tool")),
            "fixture: the relative spelling must lead to the tool"
        );

        let paths = env::join_paths([PathBuf::new(), relative, PathBuf::from(".")]).unwrap();
        assert_eq!(which_path_in("oxiclean-rel-tool", &paths), None);
        // The absolute spelling of that same directory is found.
        assert!(which_path_in("oxiclean-rel-tool", dir.as_os_str()).is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_which_path_with_a_slash_accepts_only_absolute_executables() {
        let dir = scratch("which_slash");
        let tool = sh_as(&dir, "tool");
        let data = dir.join("data");
        fs::write(&data, "x").unwrap();
        let no_path = OsStr::new("");

        // Absolute: used as given, `$PATH` is irrelevant.
        assert_eq!(
            which_path_in(tool.to_str().unwrap(), no_path),
            Some(tool.clone())
        );
        assert_eq!(which_path_in(data.to_str().unwrap(), no_path), None);
        // Relative with a separator: its meaning depends on the cwd, so it is
        // refused rather than guessed at, even when it really does lead to the
        // tool and even when `$PATH` could resolve it.
        let relative_tool = relative_to_cwd(&dir).join("tool");
        assert!(
            is_executable_file(&relative_tool),
            "fixture: the relative spelling must lead to the tool"
        );
        assert_eq!(
            which_path_in(relative_tool.to_str().unwrap(), no_path),
            None
        );
        assert_eq!(which_path_in("./tool", dir.as_os_str()), None);
        assert_eq!(which_path_in("sub/tool", dir.as_os_str()), None);
        // Degenerate names never match.
        assert_eq!(which_path_in("", dir.as_os_str()), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_run_user_starts_the_tool_which_found() {
        // `run_user_in` searches only the directory it is given, so the marker
        // can only appear if the `sh` in `dir` was the one started.
        let dir = scratch("run_user_ok");
        sh_as(&dir, "sh");
        let marker = dir.join("ran");

        assert!(run_user_in(
            dir.as_os_str(),
            "sh",
            &["-c", ": > \"$1\"", "sh", marker.to_str().unwrap()]
        ));
        assert!(marker.exists(), "the tool was found but never ran");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_run_user_child_inherits_the_callers_path() {
        // The user tier hands the child the environment it was started with: a
        // version manager's shim or a wrapper script finds the interpreter it
        // needs through that very `$PATH`.
        let dir = scratch("run_user_path");
        sh_as(&dir, "sh");
        let seen = dir.join("seen");

        assert!(run_user_in(
            dir.as_os_str(),
            "sh",
            &[
                "-c",
                "printf %s \"$PATH\" > \"$1\"",
                "sh",
                seen.to_str().unwrap()
            ]
        ));
        assert_eq!(
            fs::read_to_string(&seen).unwrap(),
            env::var("PATH").unwrap()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_run_user_reports_failure_honestly() {
        let dir = scratch("run_user_fail");
        sh_as(&dir, "sh");

        assert!(!run_user_in(dir.as_os_str(), "sh", &["-c", "exit 3"]));
        // Not found at all is `false` too: no panic, and no second attempt
        // through some other, wider lookup.
        assert!(!run_user_in(dir.as_os_str(), "oxiclean-no-such-tool", &[]));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_capture_hands_the_child_the_callers_path() {
        // User tier: found through the search path it is given, run with the
        // caller's own environment untouched.
        let dir = scratch("capture_user");
        sh_as(&dir, "sh");

        let seen = capture_in(dir.as_os_str(), "sh", &["-c", "printf %s \"$PATH\""]);
        assert_eq!(seen.unwrap(), env::var("PATH").unwrap());
        // A tool that is not on the search path is "not available", not an error.
        assert_eq!(
            capture_in(dir.as_os_str(), "oxiclean-no-such-tool", &[]),
            None
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_capture_trusted_hands_the_child_only_the_trusted_path() {
        // System tier: resolved in the trusted directories, and the child gets
        // those directories as its whole PATH.
        let seen = capture_trusted("sh", &["-c", "printf %s \"$PATH\""]);
        assert_eq!(seen.unwrap(), trusted_path());
        assert_eq!(capture_trusted("oxiclean-no-such-tool", &[]), None);
    }

    #[test]
    fn test_command_resolves_bare_names_through_the_childs_own_path() {
        // The assumption behind the 1.8.0 regression, pinned so a change in std
        // cannot hide it again: when `PATH` is set on a `Command`, a bare program
        // name is looked up in *that* value, not in ours. `harden_env` therefore
        // narrows the lookup as well as the environment, which is exactly what the
        // system tier wants and exactly what the user tier must avoid.
        let dir = scratch("child_path_lookup");
        sh_as(&dir, "sh");

        let through_the_childs_path = Command::new("sh")
            .args(["-c", "exit 0"])
            .env("PATH", &dir)
            .status();
        assert!(
            through_the_childs_path
                .map(|s| s.success())
                .unwrap_or(false),
            "a bare name must resolve through the child's PATH"
        );
        // `sh` is on *our* PATH. Had the lookup used ours, this would succeed.
        let nowhere = Command::new("sh")
            .args(["-c", "exit 0"])
            .env("PATH", "/nonexistent")
            .status();
        assert!(nowhere.is_err(), "...and only through the child's PATH");
        let _ = fs::remove_dir_all(&dir);
    }

    // ── Per-tool environment ──

    #[test]
    fn test_tool_env_defaults_for_dotnet_switch_off_every_first_run_side_effect() {
        let defaults = tool_env_defaults(Path::new("dotnet"), |_| false);
        for pair in [
            ("DOTNET_NOLOGO", "1"),
            ("DOTNET_CLI_TELEMETRY_OPTOUT", "1"),
            ("DOTNET_GENERATE_ASPNET_CERTIFICATE", "false"),
            ("DOTNET_ADD_GLOBAL_TOOLS_TO_PATH", "false"),
            ("DOTNET_SKIP_WORKLOAD_INTEGRITY_CHECK", "1"),
        ] {
            assert!(
                defaults.contains(&pair),
                "{pair:?} missing from {defaults:?}"
            );
        }
    }

    #[test]
    fn test_tool_env_defaults_match_the_tool_by_file_name_only() {
        let has_defaults = |p: &str| !tool_env_defaults(Path::new(p), |_| false).is_empty();
        assert!(has_defaults("dotnet"));
        assert!(has_defaults("/usr/share/dotnet/dotnet"));
        assert!(!has_defaults("uv"));
        assert!(!has_defaults("dotnetx"));
        assert!(!has_defaults("not-dotnet"));
        // A directory called `dotnet` does not make everything inside it dotnet.
        assert!(!has_defaults("/home/u/dotnet/uv"));
    }

    #[test]
    fn test_tool_env_defaults_never_override_what_the_caller_set() {
        let defaults = tool_env_defaults(Path::new("dotnet"), |key| {
            key == "DOTNET_CLI_TELEMETRY_OPTOUT"
        });
        assert!(defaults
            .iter()
            .all(|(k, _)| *k != "DOTNET_CLI_TELEMETRY_OPTOUT"));
        assert!(
            defaults.iter().any(|(k, _)| *k == "DOTNET_NOLOGO"),
            "the choices the caller did not make still apply"
        );
    }

    #[test]
    fn test_user_tier_child_gets_the_tool_defaults_and_other_tools_none() {
        // Through a real child, so the whole chain from lookup to environment
        // is covered. The host may have chosen already (a .NET developer often
        // has), and then its choice is what the child must see.
        let dir = scratch("tool_env");
        sh_as(&dir, "dotnet");
        sh_as(&dir, "uv");
        let show = ["-c", "printf %s \"$DOTNET_GENERATE_ASPNET_CERTIFICATE\""];
        let host = env::var("DOTNET_GENERATE_ASPNET_CERTIFICATE");

        let dotnet = capture_in(dir.as_os_str(), "dotnet", &show).unwrap();
        assert_eq!(dotnet, host.clone().unwrap_or_else(|_| "false".into()));
        let uv = capture_in(dir.as_os_str(), "uv", &show).unwrap();
        assert_eq!(uv, host.unwrap_or_default());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_run_user_quiet_reports_the_tools_status() {
        let dir = scratch("quiet_status");
        sh_as(&dir, "sh");

        assert!(run_user_quiet_in(dir.as_os_str(), "sh", &["-c", "exit 0"]));
        assert!(!run_user_quiet_in(dir.as_os_str(), "sh", &["-c", "exit 3"]));
        assert!(!run_user_quiet_in(
            dir.as_os_str(),
            "oxiclean-no-such-tool",
            &[]
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_failure_detail_prefers_stderr_and_falls_back_to_stdout() {
        use std::os::unix::process::ExitStatusExt;
        let failed = |stdout: &str, stderr: &str| Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        };

        let both = failed("on stdout", "on stderr");
        assert_eq!(failure_detail(&both), b"on stderr");
        // Some tools report errors on stdout and leave stderr empty or blank.
        let only_stdout = failed("error: on stdout", " \n");
        assert_eq!(failure_detail(&only_stdout), b"error: on stdout");
    }

    // ── Output discipline ──
    //
    // Whether a tool's chatter reaches stdout, and whether JSON mode silences
    // the helpers, are properties of the whole process: JSON mode is a switch
    // that can be set once. So these tests run themselves again as a child
    // process (`OXI_CHILD` set), where they may flip it, and inspect what the
    // child printed.

    const CHILD_ENV: &str = "OXI_CHILD";

    /// Re-run the one test `name` of this binary in a child process.
    fn run_as_child(name: &str) -> Output {
        Command::new(env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap()
    }

    /// What the child printed, after checking that it ran and passed.
    fn child_stdout(name: &str) -> String {
        let out = run_as_child(name);
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "child failed:\n{stdout}\n{stderr}");
        assert!(stdout.contains("CHILD-RAN"), "child never ran:\n{stdout}");
        stdout
    }

    #[test]
    fn test_quiet_run_keeps_the_tools_chatter_off_stdout() {
        const ME: &str = "utils::tests::test_quiet_run_keeps_the_tools_chatter_off_stdout";
        if env::var_os(CHILD_ENV).is_none() {
            let stdout = child_stdout(ME);
            assert!(
                !stdout.contains("TOOL-CHATTER"),
                "chatter leaked:\n{stdout}"
            );
            assert!(
                stdout.contains("TOOL-COMPLAINT"),
                "a failing tool's complaint must be replayed:\n{stdout}"
            );
            return;
        }
        let dir = scratch("quiet_chatter");
        sh_as(&dir, "sh");
        let noisy = "echo TOOL-CHATTER; echo TOOL-CHATTER >&2";
        assert!(run_user_quiet_in(dir.as_os_str(), "sh", &["-c", noisy]));
        let failing = "echo TOOL-COMPLAINT >&2; exit 1";
        assert!(!run_user_quiet_in(dir.as_os_str(), "sh", &["-c", failing]));
        println!("CHILD-RAN");
    }

    #[test]
    fn test_json_mode_children_cannot_write_to_stdout() {
        const ME: &str = "utils::tests::test_json_mode_children_cannot_write_to_stdout";
        if env::var_os(CHILD_ENV).is_none() {
            let stdout = child_stdout(ME);
            for leak in ["TOOL-CHATTER", "HELPER-LINE"] {
                assert!(
                    !stdout.contains(leak),
                    "{leak} leaked into JSON mode:\n{stdout}"
                );
            }
            return;
        }
        set_json(true);
        let dir = scratch("json_chatter");
        sh_as(&dir, "sh");
        // Both tiers, visible runs: the tool inherits stdout unless we stop it.
        assert!(run_user_in(
            dir.as_os_str(),
            "sh",
            &["-c", "echo TOOL-CHATTER"]
        ));
        assert!(run("sh", &["-c", "echo TOOL-CHATTER"]));
        // And every human-facing helper goes quiet.
        plain("HELPER-LINE plain");
        success("HELPER-LINE success");
        info("HELPER-LINE info");
        println!("CHILD-RAN");
    }

    #[test]
    fn test_report_modules_print_only_through_the_output_helpers() {
        // `--json` promises exactly one document on stdout, so every
        // human-facing line has to go through the helpers that go quiet in JSON
        // mode. A direct `println!` in a report module is invisible until a
        // machine consumer chokes on it (clean.rs once listed orphaned packages
        // that way). main.rs is exempt: it owns the banner and the final
        // report, and branches on `--json` itself.
        let modules = [
            ("clean.rs", include_str!("clean.rs")),
            ("dev.rs", include_str!("dev.rs")),
            ("detect.rs", include_str!("detect.rs")),
            ("roots.rs", include_str!("roots.rs")),
            ("update.rs", include_str!("update.rs")),
        ];
        for (name, source) in modules {
            for (number, line) in source.lines().enumerate() {
                let code = line.trim_start();
                if code.starts_with("//") {
                    continue;
                }
                let code = code.replace("eprintln!(", "").replace("eprint!(", "");
                assert!(
                    !code.contains("println!(") && !code.contains("print!("),
                    "{name}:{} prints straight to stdout, use the helpers in utils: {code}",
                    number + 1
                );
            }
        }
    }

    // ── Text from outside ──

    #[test]
    fn test_ordinary_text_is_shown_as_it_is() {
        for text in [
            "",
            "plain ascii: /home/me/.cache/pip (3 items)",
            "héllo wörld — ✔ ⚠ ✘",
            "مرحبا بالعالم",
            "日本語のファイル名.txt",
            "emoji 📋 and a joiner 👩‍💻",
        ] {
            assert!(
                matches!(shown(text), Cow::Borrowed(_)),
                "{text:?} was copied"
            );
            assert_eq!(shown(text), text);
        }
    }

    #[test]
    fn test_what_a_terminal_would_act_on_is_spelled_out_instead() {
        let cases = [
            // Cursor movement and "clear the screen".
            ("a\u{1b}[2Jb", r"a\u{1b}[2Jb"),
            ("a\u{1b}[1;31Hb", r"a\u{1b}[1;31Hb"),
            // OSC: window title, clipboard, hyperlinks.
            ("x\u{1b}]0;pwned\u{7}y", r"x\u{1b}]0;pwned\u{7}y"),
            // The one-byte CSI of the C1 range.
            ("x\u{9b}2Jy", r"x\u{9b}2Jy"),
            // A name that starts a line that looks like ours.
            ("n\n    ✔ Freed 9 GB", r"n\n    ✔ Freed 9 GB"),
            ("a\rb", r"a\rb"),
            ("a\tb", r"a\tb"),
            ("a\u{7f}b\0c", r"a\u{7f}b\u{0}c"),
            // Text that reads backwards, or is not there.
            ("gnp.\u{202e}exe", r"gnp.\u{202e}exe"),
            ("a\u{2067}b\u{2069}", r"a\u{2067}b\u{2069}"),
            ("\u{feff}x", r"\u{feff}x"),
            ("a\u{2028}b", r"a\u{2028}b"),
        ];
        for (hostile, expected) in cases {
            assert_eq!(shown(hostile), expected, "{hostile:?}");
            assert!(
                !shown(hostile).chars().any(is_terminal_hazard),
                "{hostile:?}"
            );
        }
    }

    #[test]
    fn test_our_own_colors_pass_and_nothing_that_looks_like_them_does() {
        // What `colored` writes into our messages.
        for ours in [
            "\u{1b}[32mgreen\u{1b}[0m",
            "\u{1b}[1;32mbold green\u{1b}[0m",
            "\u{1b}[2mdim\u{1b}[0m",
            "\u{1b}[m",
            "\u{1b}[38;2;10;20;30mtruecolor\u{1b}[0m",
        ] {
            assert_eq!(shown(ours), ours);
        }
        // Close, and not colors.
        for (hostile, expected) in [
            ("\u{1b}[2J", r"\u{1b}[2J"),
            ("\u{1b}[?25l", r"\u{1b}[?25l"),
            ("\u{1b}[31", r"\u{1b}[31"),
            ("\u{1b}[3 1m", r"\u{1b}[3 1m"),
            ("\u{1b}[38:2::1:2:3m", r"\u{1b}[38:2::1:2:3m"),
            ("\u{1b}[", r"\u{1b}["),
            ("\u{1b}", r"\u{1b}"),
        ] {
            assert_eq!(shown(hostile), expected, "{hostile:?}");
        }
        // Too long to be one.
        let long = format!("\u{1b}[{}m", "1;".repeat(40));
        assert!(shown(&long).starts_with(r"\u{1b}["), "{long:?}");
        // A color beside a hostile sequence: only the color survives.
        assert_eq!(
            shown("\u{1b}[31mred\u{1b}[2J\u{1b}[0m"),
            "\u{1b}[31mred\\u{1b}[2J\u{1b}[0m"
        );
    }

    #[test]
    fn test_showing_text_twice_changes_nothing() {
        for text in [
            "a\u{1b}[2Jb",
            "\u{1b}[32mok\u{1b}[0m \u{1b}[2J",
            "n\nm",
            "gnp.\u{202e}exe",
        ] {
            let once = shown(text).into_owned();
            assert_eq!(shown(&once), once, "{text:?}");
        }
    }

    #[test]
    fn test_every_helper_that_prints_a_message_shows_hostile_text() {
        const ME: &str = "utils::tests::test_every_helper_that_prints_a_message_shows_hostile_text";
        const TAGS: [&str; 10] = [
            "section", "success", "warning", "error", "info", "skip", "plain", "note", "replay",
            "confirm",
        ];
        // A message that is a file name, or quotes one. The newline is left out
        // for `replay`, whose input is lines already.
        let hostile = |tag: &str, newline: &str| {
            format!("TAG-{tag} A\u{1b}[2JB\u{1b}]0;pwned\u{7}C{newline}    ✔ Freed 99 GB")
        };
        if env::var_os(CHILD_ENV).is_none() {
            let stdout = child_stdout(ME);
            assert!(
                !stdout.contains('\u{1b}') && !stdout.contains('\u{7}'),
                "an escape sequence reached the terminal:\n{stdout:?}"
            );
            assert!(
                !stdout
                    .lines()
                    .any(|l| l.trim_start().starts_with("✔ Freed 99 GB")),
                "a name forged a line of ours:\n{stdout}"
            );
            for tag in TAGS {
                let marker = format!("TAG-{tag} ");
                let lines: Vec<&str> = stdout.lines().filter(|l| l.contains(&marker)).collect();
                assert_eq!(lines.len(), 1, "{tag}: {lines:?}\n{stdout}");
                assert!(
                    lines[0].contains(r"\u{1b}[2J"),
                    "{tag} did not show the escape: {}",
                    lines[0]
                );
            }
            return;
        }
        colored::control::set_override(false);
        section(&hostile("section", "\n"));
        success(&hostile("success", "\n"));
        warning(&hostile("warning", "\n"));
        error(&hostile("error", "\n"));
        info(&hostile("info", "\n"));
        skip(&hostile("skip", "\n"));
        plain(&hostile("plain", "\n"));
        note(&hostile("note", "\n"));
        replay_stderr(hostile("replay", "").as_bytes());
        // The child has no stdin, so the answer is no.
        assert!(!confirm(&hostile("confirm", "\n")));
        println!();
        println!("CHILD-RAN");
    }

    // ── Failures ──

    #[test]
    fn test_failures_are_counted_and_listed_in_order() {
        let mut failures = Failures::default();
        failures.record("first");
        failures.record("second");
        failures.record("third");
        assert_eq!(failures.count, 3);
        assert_eq!(failures.since(0), ["first", "second", "third"]);
    }

    #[test]
    fn test_failures_since_a_mark_are_only_the_later_ones() {
        let mut failures = Failures::default();
        failures.record("before");
        let mark = failures.count;
        failures.record("after one");
        failures.record("after two");
        assert_eq!(failures.since(mark), ["after one", "after two"]);
        assert!(failures.since(failures.count).is_empty());
        assert!(failures.since(usize::MAX).is_empty());
    }

    #[test]
    fn test_a_flood_of_failures_keeps_the_count_exact_and_the_list_bounded() {
        let mut failures = Failures::default();
        for n in 0..KEPT_FAILURES + 25 {
            failures.record(&format!("failure {n}"));
        }
        assert_eq!(failures.count, KEPT_FAILURES + 25);
        assert_eq!(failures.messages.len(), KEPT_FAILURES);
        assert_eq!(failures.messages[0], "failure 0");
        assert_eq!(failures.since(KEPT_FAILURES + 5), Vec::<String>::new());
    }

    #[test]
    fn test_error_records_even_when_json_mode_prints_nothing() {
        const ME: &str = "utils::tests::test_error_records_even_when_json_mode_prints_nothing";
        if env::var_os(CHILD_ENV).is_none() {
            let stdout = child_stdout(ME);
            assert!(
                !stdout.contains('\u{2718}'),
                "JSON mode must not print the line:\n{stdout}"
            );
            assert!(
                stdout.contains("COUNT=2"),
                "both failures must be counted:\n{stdout}"
            );
            assert!(
                stdout.contains("SINCE-1=[\"second: DISK-ON-FIRE\"]"),
                "the list must be what came after the mark:\n{stdout}"
            );
            return;
        }
        set_json(true);
        assert_eq!(failure_count(), 0, "a run starts with no failures");
        error("first");
        let mark = failure_count();
        error("second: DISK-ON-FIRE");
        // Warnings are for what deserves a look; they are not failures.
        warning("just a remark");
        println!("COUNT={}", failure_count());
        println!("SINCE-1={:?}", failures_since(mark));
        println!("CHILD-RAN");
    }

    // ── Commands that are told "yes", and commands that cannot be started ──

    /// `sh -c script out` with `input` on stdin, run quietly as `Privilege::Root`
    /// would run it; `$0` in the script is the path of the output file.
    fn root_quiet_sh_with_input(script: &str, out: &Path, input: &[u8]) -> bool {
        let out = out.to_str().unwrap();
        elevate_quiet_with_input(Privilege::Root, "sh", &["-c", script, out], input)
    }

    #[test]
    fn test_a_quiet_command_with_input_gets_every_byte() {
        let dir = scratch("quiet_input_all");
        let out = dir.join("out");
        // Many times a pipe buffer: the writer has to keep going while the
        // command reads.
        let input = patterned(3 << 20);
        assert!(root_quiet_sh_with_input("cat > \"$0\"", &out, &input));
        assert_eq!(fs::read(&out).unwrap(), input);
        assert!(root_quiet_sh_with_input("cat > \"$0\"", &out, b""));
        assert_eq!(fs::read(&out).unwrap(), b"");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_a_quiet_command_may_fill_its_output_before_it_reads() {
        // Hundreds of KB on stdout and on stderr, several pipe buffers each,
        // before the first byte of input is read. A writer that did not run
        // alongside the reader would wait for a command that is waiting for it.
        let dir = scratch("quiet_input_noisy");
        let out = dir.join("out");
        let input = patterned(1 << 20);
        let script = "yes out | head -c 300000; yes err | head -c 300000 >&2; cat > \"$0\"";
        let started = std::time::Instant::now();
        assert!(root_quiet_sh_with_input(script, &out, &input));
        assert!(started.elapsed() < std::time::Duration::from_secs(20));
        assert_eq!(fs::read(&out).unwrap(), input);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_a_quiet_command_with_input_reports_its_own_failure() {
        let dir = scratch("quiet_input_fails");
        let out = dir.join("out");
        assert!(!root_quiet_sh_with_input(
            "cat > \"$0\"; exit 1",
            &out,
            b"payload"
        ));
        // It did receive the input; the failure is its own.
        assert_eq!(fs::read(&out).unwrap(), b"payload");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_a_quiet_command_that_stops_reading_is_a_failure() {
        // Exits 0 without reading a byte of 4 MiB: what it did with what it
        // never saw is not something to vouch for, and the writer must not hang
        // on a pipe nobody reads.
        let dir = scratch("quiet_input_early");
        let out = dir.join("out");
        let started = std::time::Instant::now();
        assert!(!root_quiet_sh_with_input(
            "exit 0",
            &out,
            &patterned(4 << 20)
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_each_answer_reaches_its_own_prompt() {
        // The shape of `pacman -Scc`: one question for the cache and one for
        // the sync databases, answered in that order.
        let dir = scratch("quiet_input_prompts");
        let out = dir.join("out");
        let script = "read first; read second; printf '%s,%s' \"$first\" \"$second\" > \"$0\"";
        assert!(root_quiet_sh_with_input(script, &out, b"y\nn\n"));
        assert_eq!(fs::read_to_string(&out).unwrap(), "y,n");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_a_quiet_command_with_input_runs_nothing_it_may_not() {
        let dir = scratch("quiet_input_refused");
        let marker = dir.join("ran");
        let marker = marker.to_str().unwrap();
        let script = "touch \"$0\"";
        assert!(!elevate_quiet_with_input(
            Privilege::None,
            "sh",
            &["-c", script, marker],
            b"x"
        ));
        assert!(!elevate_quiet_with_input(
            Privilege::Root,
            "oxiclean_no_such_binary_xyz",
            &[marker],
            b"x"
        ));
        assert!(!elevate_quiet_with_input(
            Privilege::Root,
            "./sh",
            &["-c", script, marker],
            b"x"
        ));
        assert!(!Path::new(marker).exists(), "something ran");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_a_quiet_command_with_input_keeps_its_chatter_off_stdout() {
        const ME: &str =
            "utils::tests::test_a_quiet_command_with_input_keeps_its_chatter_off_stdout";
        if env::var_os(CHILD_ENV).is_none() {
            let stdout = child_stdout(ME);
            assert!(
                !stdout.contains("TOOL-CHATTER"),
                "chatter leaked:\n{stdout}"
            );
            assert!(
                stdout.contains("TOOL-COMPLAINT"),
                "a failing tool's complaint must be replayed:\n{stdout}"
            );
            return;
        }
        let noisy = "echo TOOL-CHATTER; echo TOOL-CHATTER >&2; cat > /dev/null";
        assert!(elevate_quiet_with_input(
            Privilege::Root,
            "sh",
            &["-c", noisy],
            b"x"
        ));
        let failing = "echo TOOL-COMPLAINT >&2; cat > /dev/null; exit 1";
        assert!(!elevate_quiet_with_input(
            Privilege::Root,
            "sh",
            &["-c", failing],
            b"x"
        ));
        println!("CHILD-RAN");
    }

    #[test]
    fn test_capture_checked_tells_a_failure_from_an_answer() {
        let dir = scratch("capture_checked");
        sh_as(&dir, "sh");
        let paths = dir.as_os_str();

        assert_eq!(
            capture_checked_in(paths, "sh", &["-c", "echo '  freed 5  '"]),
            Some("freed 5".to_string())
        );
        // `capture` hands back what a tool printed even when it failed...
        assert_eq!(
            capture_in(paths, "sh", &["-c", "echo partial; exit 3"]),
            Some("partial".to_string())
        );
        // ...and this one does not.
        assert_eq!(
            capture_checked_in(paths, "sh", &["-c", "echo partial; exit 3"]),
            None
        );
        assert_eq!(
            capture_checked_in(paths, "oxiclean-no-such-tool", &[]),
            None
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_the_reason_a_command_was_not_started_names_what_is_missing() {
        let nothing = |_: &str| -> Option<String> { None };
        let only = |found: &'static str| {
            move |c: &str| -> Option<String> { (c == found).then(|| format!("/usr/bin/{c}")) }
        };

        let msg = unavailable(Privilege::None, "pacman", &only("pacman"));
        assert!(msg.contains("neither sudo nor doas"), "{msg}");

        // Root with a command that is nowhere trusted: the command is named, and
        // so are the places that were looked in.
        let msg = unavailable(Privilege::Root, "nix-collect-garbage", &nothing);
        assert!(msg.contains("nix-collect-garbage"), "{msg}");
        assert!(msg.contains("/usr/bin"), "{msg}");
        assert!(msg.contains("/nix/var/nix/profiles/default/bin"), "{msg}");

        // The command is there; it is the helper that is not.
        let msg = unavailable(Privilege::Doas, "pacman", &only("pacman"));
        assert!(msg.contains("doas"), "{msg}");
        assert!(!msg.contains("pacman"), "{msg}");
        let msg = unavailable(Privilege::Sudo, "pacman", &only("pacman"));
        assert!(msg.contains("sudo"), "{msg}");
    }

    #[test]
    fn test_every_privileged_entry_point_says_why_it_did_not_run() {
        const ME: &str = "utils::tests::test_every_privileged_entry_point_says_why_it_did_not_run";
        if env::var_os(CHILD_ENV).is_none() {
            let stdout = child_stdout(ME);
            // One sentence from each of the four ways in.
            assert_eq!(
                stdout.matches("neither sudo nor doas was found").count(),
                4,
                "every entry point must say why it did nothing:\n{stdout}"
            );
            return;
        }
        // `Privilege::None` runs nothing, so nothing here can touch the machine.
        assert!(!elevate(Privilege::None, "true", &[]));
        assert!(!elevate_quiet(Privilege::None, "true", &[]));
        assert!(!elevate_with_input(Privilege::None, "true", &[], b"x"));
        assert!(!elevate_quiet_with_input(
            Privilege::None,
            "true",
            &[],
            b"x"
        ));
        println!("CHILD-RAN");
    }

    #[test]
    fn test_the_reason_a_command_did_not_run_is_not_printed_in_json_mode() {
        const ME: &str =
            "utils::tests::test_the_reason_a_command_did_not_run_is_not_printed_in_json_mode";
        if env::var_os(CHILD_ENV).is_none() {
            let stdout = child_stdout(ME);
            assert!(
                !stdout.contains("not run:"),
                "--json must keep stdout to the one document:\n{stdout}"
            );
            return;
        }
        set_json(true);
        assert!(!elevate_quiet(Privilege::None, "true", &[]));
        println!("CHILD-RAN");
    }

    #[test]
    fn test_a_listing_tells_nothing_to_list_from_a_broken_tool() {
        use WhenEmpty::{Exit0, Exit1};
        let found = |s: &str| Listing::Found(s.to_string());
        // A list.
        assert_eq!(
            classify_listing(Some(0), "a\nb\n", "", Exit0),
            found("a\nb")
        );
        assert_eq!(
            classify_listing(Some(0), "a\n", "warning: x", Exit1),
            found("a")
        );
        // Nothing to list: exit 0 and no output (a tool may say so on stderr)...
        assert_eq!(classify_listing(Some(0), "", "", Exit0), Listing::Nothing);
        assert_eq!(
            classify_listing(Some(0), " \n", "No snaps are installed yet", Exit0),
            Listing::Nothing
        );
        // ...or, for pacman, exit 1 and no output, warnings or not.
        assert_eq!(classify_listing(Some(1), "", "", Exit1), Listing::Nothing);
        let unsynced = "warning: database file for 'core' does not exist (use '-Sy' to download)";
        assert_eq!(
            classify_listing(Some(1), "", unsynced, Exit1),
            Listing::Nothing
        );
        // Broken: an `error:` line, any other status, a signal, or an exit 1
        // from a tool that does not use it for "nothing".
        let broken = "error: failed to initialize alpm library";
        assert_eq!(
            classify_listing(Some(1), "", broken, Exit1),
            Listing::Failed
        );
        assert_eq!(
            classify_listing(Some(1), "", &format!("{unsynced}\n{broken}"), Exit1),
            Listing::Failed
        );
        assert_eq!(classify_listing(Some(1), "", "", Exit0), Listing::Failed);
        assert_eq!(classify_listing(Some(2), "", "", Exit1), Listing::Failed);
        assert_eq!(
            classify_listing(Some(1), "partial", "", Exit1),
            Listing::Failed
        );
        assert_eq!(classify_listing(None, "a", "", Exit0), Listing::Failed);
    }

    #[test]
    fn test_list_trusted_runs_the_tool_and_classifies_what_it_did() {
        use WhenEmpty::{Exit0, Exit1};
        let run = |script: &str, empty| list_trusted("sh", &["-c", script], empty);
        assert_eq!(
            run("echo one; echo two", Exit0),
            Listing::Found("one\ntwo".to_string())
        );
        assert_eq!(run("exit 0", Exit0), Listing::Nothing);
        assert_eq!(
            run("echo 'warning: x' >&2; exit 1", Exit1),
            Listing::Nothing
        );
        assert_eq!(
            run("echo 'error: broken' >&2; exit 1", Exit1),
            Listing::Failed
        );
        assert_eq!(run("exit 3", Exit0), Listing::Failed);
        // Not a tool that is trusted at all: a failure, not an empty answer.
        assert_eq!(
            list_trusted("oxiclean_no_such_binary_xyz", &[], Exit0),
            Listing::Failed
        );
    }

    #[test]
    fn test_a_failed_listing_says_what_the_tool_said() {
        const ME: &str = "utils::tests::test_a_failed_listing_says_what_the_tool_said";
        if env::var_os(CHILD_ENV).is_none() {
            let stdout = child_stdout(ME);
            assert!(
                stdout.contains("TOOL-COMPLAINT"),
                "a failed listing must explain itself:\n{stdout}"
            );
            assert!(
                !stdout.contains("TOOL-FINE"),
                "a listing that worked has nothing to explain:\n{stdout}"
            );
            return;
        }
        let fine = list_trusted(
            "sh",
            &["-c", "echo TOOL-FINE >&2; echo item"],
            WhenEmpty::Exit0,
        );
        assert_eq!(fine, Listing::Found("item".to_string()));
        let broken = list_trusted(
            "sh",
            &["-c", "echo TOOL-COMPLAINT >&2; exit 2"],
            WhenEmpty::Exit0,
        );
        assert_eq!(broken, Listing::Failed);
        println!("CHILD-RAN");
    }

    // ── Removing what cannot be removed as it stands ──

    fn chmod(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn mode_of(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    /// A tree like Go's module cache: nobody may write to its directories or files.
    fn read_only_tree(root: &Path) {
        let deep = root.join("a/b/c");
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("file"), b"payload").unwrap();
        fs::write(root.join("a/top"), b"payload").unwrap();
        chmod(&deep.join("file"), 0o444);
        chmod(&root.join("a/top"), 0o444);
        for dir in [deep, root.join("a/b"), root.join("a"), root.to_path_buf()] {
            chmod(&dir, 0o555);
        }
    }

    #[test]
    fn test_a_tree_of_read_only_directories_is_removed() {
        let base = scratch("ro_tree");
        let tree = base.join("tree");
        read_only_tree(&tree);
        if !is_root() {
            // The reason this exists: as it stands, plain removal gets nowhere,
            // and it used to be left at that without a word.
            assert!(fs::remove_dir_all(&tree).is_err());
            assert!(tree.join("a/b/c/file").exists());
        }
        let removed = remove_plain(&tree, true);
        assert!(matches!(removed, Ok(true)), "{removed:?}");
        assert!(!tree.exists());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_only_the_very_directory_that_was_looked_at_is_changed() {
        let base = scratch("same-directory");
        let one = base.join("one");
        let two = base.join("two");
        fs::create_dir_all(&one).unwrap();
        fs::create_dir_all(&two).unwrap();
        fs::write(base.join("file"), b"x").unwrap();

        let meta = |p: &Path| fs::metadata(p).unwrap();
        let lmeta = |p: &Path| fs::symlink_metadata(p).unwrap();

        // The same directory, looked at twice.
        assert!(is_same_directory(&lmeta(&one), &meta(&one)));
        // Another directory in its place.
        assert!(!is_same_directory(&lmeta(&one), &meta(&two)));
        // A file is not a directory, even when it is the very thing looked at.
        let file = base.join("file");
        assert!(!is_same_directory(&lmeta(&file), &meta(&file)));

        // The device is part of the identity: the roots of /proc and /sys are
        // both inode 1, on different devices. (Only checked where the machine
        // has two such directories.)
        if let (Ok(a), Ok(b)) = (fs::metadata("/proc"), fs::metadata("/sys")) {
            if a.ino() == b.ino() && a.dev() != b.dev() {
                assert!(!is_same_directory(&a, &b));
            }
        }
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_nothing_is_changed_when_the_path_no_longer_leads_to_what_was_seen() {
        let base = scratch("swapped");
        let make = |name: &str| {
            let dir = base.join(name);
            fs::create_dir_all(&dir).unwrap();
            chmod(&dir, 0o555);
            dir
        };
        let seen = make("seen");
        let other = make("other");
        let target = make("target");
        let link = base.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let file = base.join("file");
        fs::write(&file, b"x").unwrap();
        chmod(&file, 0o444);
        let first_look = fs::symlink_metadata(&seen).unwrap();

        // The path now leads to another directory, to a link to one, or to a
        // file: none of them is what was looked at.
        grant_if_unchanged(&other, &first_look);
        grant_if_unchanged(&link, &first_look);
        grant_if_unchanged(&file, &first_look);
        assert_eq!(mode_of(&other), 0o555);
        assert_eq!(mode_of(&target), 0o555);
        assert_eq!(mode_of(&file), 0o444);

        // What was looked at, and still is there, is given access.
        grant_if_unchanged(&seen, &first_look);
        assert_eq!(mode_of(&seen), 0o755);
        // A look at a link is never followed, whatever it leads to.
        grant_if_unchanged(&link, &fs::symlink_metadata(&link).unwrap());
        assert_eq!(mode_of(&target), 0o555);

        for dir in [&seen, &other, &target] {
            chmod(dir, 0o755);
        }
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_an_entry_that_is_already_gone_is_not_an_error() {
        let base = scratch("gone");
        assert!(matches!(remove_plain(&base.join("nope"), false), Ok(false)));
        assert!(matches!(remove_plain(&base.join("nope"), true), Ok(false)));
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_removing_a_tree_never_changes_what_a_link_in_it_points_to() {
        use std::os::unix::fs::symlink;
        let base = scratch("ro_link");
        let outside = base.join("outside");
        let outside_sub = outside.join("sub");
        fs::create_dir_all(&outside_sub).unwrap();
        fs::write(outside.join("keep"), b"keep").unwrap();
        chmod(&outside_sub, 0o555);
        chmod(&outside, 0o555);
        let tree = base.join("tree");
        fs::create_dir_all(tree.join("a")).unwrap();
        symlink(&outside, tree.join("a/link_to_dir")).unwrap();
        symlink(outside.join("keep"), tree.join("a/link_to_file")).unwrap();
        read_only_tree(&tree);

        let removed = remove_plain(&tree, true);
        assert!(matches!(removed, Ok(true)), "{removed:?}");
        assert!(!tree.exists());
        // Neither the directory a link points to nor anything inside it.
        assert_eq!(
            mode_of(&outside),
            0o555,
            "a link was followed and what it points to was changed"
        );
        assert_eq!(mode_of(&outside_sub), 0o555, "a link was entered");
        assert!(outside.join("keep").is_file());

        // A link handed in directly is removed as the link it is.
        let link = base.join("direct");
        symlink(&outside, &link).unwrap();
        assert!(matches!(remove_plain(&link, false), Ok(true)));
        assert!(outside.join("keep").is_file());
        chmod(&outside, 0o755);
        chmod(&outside_sub, 0o755);
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_access_is_only_given_to_a_directory_that_is_one() {
        use std::os::unix::fs::symlink;
        let base = scratch("grant");
        let dir = base.join("dir");
        fs::create_dir_all(&dir).unwrap();
        chmod(&dir, 0o500);
        grant_owner_access(&dir);
        assert_eq!(mode_of(&dir), 0o700);
        // Group and others keep what they had; nothing is taken away.
        chmod(&dir, 0o750);
        grant_owner_access(&dir);
        assert_eq!(mode_of(&dir), 0o750);
        // Through a link, nothing changes.
        let link = base.join("link");
        symlink(&dir, &link).unwrap();
        chmod(&dir, 0o500);
        grant_owner_access(&link);
        assert_eq!(mode_of(&dir), 0o500);
        // Nor on a file.
        let file = base.join("file");
        fs::write(&file, b"x").unwrap();
        chmod(&file, 0o400);
        grant_owner_access(&file);
        assert_eq!(mode_of(&file), 0o400);
        chmod(&dir, 0o755);
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_what_cannot_be_removed_is_an_error_not_a_success() {
        if is_root() {
            return; // root can remove anything
        }
        let base = scratch("ro_parent");
        let parent = base.join("parent");
        fs::create_dir_all(parent.join("tree")).unwrap();
        fs::write(parent.join("file"), b"x").unwrap();
        // The entries of `parent` cannot be unlinked, whatever is done to them.
        chmod(&parent, 0o555);
        let file = remove_plain(&parent.join("file"), false);
        let tree = remove_plain(&parent.join("tree"), true);
        chmod(&parent, 0o755);
        assert_eq!(file.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(tree.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert!(parent.join("file").exists() && parent.join("tree").exists());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_emptying_a_directory_counts_what_went_and_what_stayed() {
        let base = scratch("empty_count");
        fs::write(base.join("a"), vec![0u8; 100]).unwrap();
        fs::create_dir_all(base.join("d")).unwrap();
        fs::write(base.join("d/b"), vec![0u8; 200]).unwrap();
        let emptied = empty_dir(&base, &Mounts::default()).unwrap();
        assert_eq!((emptied.tried, emptied.failed), (2, 0));
        assert!(emptied.freed >= 300, "{emptied:?}");
        assert!(emptied.complaint(&base).is_none());
        assert_eq!(fs::read_dir(&base).unwrap().count(), 0);

        // A directory that is not there has nothing to empty.
        assert_eq!(
            empty_dir(&base.join("nope"), &Mounts::default()).unwrap(),
            Emptied::default()
        );

        if !is_root() {
            fs::write(base.join("x"), b"1").unwrap();
            fs::write(base.join("y"), b"2").unwrap();
            chmod(&base, 0o555);
            let emptied = empty_dir(&base, &Mounts::default());
            chmod(&base, 0o755);
            let emptied = emptied.unwrap();
            assert_eq!((emptied.freed, emptied.tried, emptied.failed), (0, 2, 2));
            let complaint = emptied.complaint(&base).unwrap();
            assert!(
                complaint.starts_with("Could not remove 2 of 2 item(s) in "),
                "{complaint}"
            );
            assert!(complaint.contains("ermission denied"), "{complaint}");

            // One that exists and cannot be read is an error of its own.
            chmod(&base, 0o000);
            let unreadable = empty_dir(&base, &Mounts::default());
            chmod(&base, 0o755);
            assert!(unreadable.is_err());
        }
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_the_complaint_names_the_count_the_first_entry_and_the_reason() {
        let mut emptied = Emptied::default();
        emptied.add(
            Path::new("/c/a"),
            10,
            Ok(Removal {
                removed: true,
                left: Vec::new(),
            }),
        );
        emptied.add(
            Path::new("/c/b"),
            20,
            Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        );
        emptied.add(Path::new("/c/c"), 30, Err(io::Error::other("busy")));
        emptied.add(Path::new("/c/d"), 40, Ok(Removal::default()));
        assert_eq!((emptied.freed, emptied.tried, emptied.failed), (10, 4, 2));
        assert_eq!(
            emptied.complaint(Path::new("/c")).unwrap(),
            "Could not remove 2 of 4 item(s) in /c: /c/b: permission denied"
        );
        let clean = Emptied::default();
        assert_eq!(clean.complaint(Path::new("/c")), None);
    }

    #[test]
    fn test_rm_contents_reports_what_it_could_not_remove() {
        const ME: &str = "utils::tests::test_rm_contents_reports_what_it_could_not_remove";
        if env::var_os(CHILD_ENV).is_none() {
            if is_root() {
                return; // root can remove anything
            }
            let stdout = child_stdout(ME);
            assert!(
                stdout.contains("Could not remove 2 of 2 item(s) in "),
                "{stdout}"
            );
            assert!(stdout.contains("Could not read "), "{stdout}");
            assert!(stdout.contains("FREED=0 NEW-FAILURES=2"), "{stdout}");
            return;
        }
        let base = scratch("rm_reports");
        let stuck = base.join("stuck");
        let locked = base.join("locked");
        fs::create_dir_all(&stuck).unwrap();
        fs::create_dir_all(&locked).unwrap();
        fs::write(stuck.join("x"), b"1").unwrap();
        fs::write(stuck.join("y"), b"2").unwrap();
        chmod(&stuck, 0o555);
        chmod(&locked, 0o000);
        let before = failure_count();
        let freed = rm_contents(&stuck) + rm_contents(&locked);
        chmod(&stuck, 0o755);
        chmod(&locked, 0o755);
        println!("FREED={freed} NEW-FAILURES={}", failure_count() - before);
        fs::remove_dir_all(&base).unwrap();
        println!("CHILD-RAN");
    }

    // ── Mounts: another file system is not part of the tree that holds it ──
    //
    // Nothing here mounts anything: a directory a test calls a mount point is an
    // ordinary directory that the list of mounts it hands over names. If the
    // code went in anyway, it would remove what is in it, and the test would see.

    /// A scratch directory spelled the way the kernel lists mounts: a real path.
    fn real_scratch(name: &str) -> PathBuf {
        fs::canonicalize(scratch(name)).unwrap()
    }

    /// Write `len` bytes to `path`, making its directories.
    fn put(path: &Path, len: usize) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, vec![1u8; len]).unwrap();
    }

    /// A tree with ordinary files and two directories that count as mount points,
    /// `m1` straight in it and `d/inner/m2` further down, each with a file or two.
    fn tree_with_two_mounts(root: &Path) -> Mounts {
        put(&root.join("f"), 5000);
        put(&root.join("d/g"), 5000);
        put(&root.join("d/inner/j"), 5000);
        put(&root.join("m1/keep1"), 70_000);
        put(&root.join("m1/sub/more"), 5000);
        put(&root.join("d/inner/m2/keep2"), 90_000);
        let (m1, m2) = (root.join("m1"), root.join("d/inner/m2"));
        Mounts::of(&[&m1, &m2])
    }

    #[test]
    fn test_what_is_mounted_inside_a_tree_is_not_counted_in_it() {
        let base = real_scratch("mount_size");
        let mounts = tree_with_two_mounts(&base);
        let outside = on_disk(&base.join("f"))
            + on_disk(&base.join("d/g"))
            + on_disk(&base.join("d/inner/j"));
        let inside = on_disk(&base.join("m1/keep1"))
            + on_disk(&base.join("m1/sub/more"))
            + on_disk(&base.join("d/inner/m2/keep2"));
        assert_eq!(dir_size_in(&base, &mounts), outside);
        assert_eq!(
            dir_size_in(&base, &Mounts::default()),
            outside + inside,
            "with nothing mounted it is all of it"
        );
        // Asked for by its own name, a mounted tree is counted: whoever asks wants it.
        assert_eq!(
            dir_size_in(&base.join("m1"), &mounts),
            on_disk(&base.join("m1/keep1")) + on_disk(&base.join("m1/sub/more"))
        );
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_a_tree_reached_through_a_link_is_measured_around_its_mounts() {
        use std::os::unix::fs::symlink;
        let base = real_scratch("mount_size_link");
        put(&base.join("real/cache/own"), 5000);
        put(&base.join("real/cache/mnt/theirs"), 90_000);
        symlink(base.join("real"), base.join("link")).unwrap();
        // The kernel lists the real path, the tree is asked for by the link.
        let mnt = base.join("real/cache/mnt");
        let mounts = Mounts::of(&[&mnt]);
        let own = on_disk(&base.join("real/cache/own"));
        assert_eq!(dir_size_against(&base.join("link/cache"), &mounts), own);
        // A link itself is not followed: nothing is counted for it.
        assert_eq!(dir_size_against(&base.join("link"), &mounts), 0);
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_a_file_mounted_over_a_file_is_left_and_not_counted_either() {
        let base = real_scratch("mount_file");
        put(&base.join("plain"), 5000);
        put(&base.join("sub/bound"), 70_000);
        let bound = base.join("sub/bound");
        let mounts = Mounts::of(&[&bound]);
        let plain = on_disk(&base.join("plain"));
        assert_eq!(dir_size_in(&base, &mounts), plain);
        let emptied = empty_dir(&base, &mounts).unwrap();
        assert_eq!(emptied.freed, plain, "{emptied:?}");
        assert_eq!(emptied.left, vec![bound.clone()]);
        assert_eq!(emptied.failed, 0, "{emptied:?}");
        assert!(bound.is_file() && !base.join("plain").exists());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_a_mount_point_is_neither_removed_nor_entered() {
        let base = real_scratch("mount_entry");
        let mounts = tree_with_two_mounts(&base);
        let m1 = base.join("m1");
        let removal = remove_entry(&m1, true, &mounts).unwrap();
        assert_eq!(
            removal,
            Removal {
                removed: false,
                left: vec![m1.clone()]
            }
        );
        assert!(m1.join("keep1").is_file() && m1.join("sub/more").is_file());

        // A file can be one: a bind mount over a file.
        let file = base.join("f");
        let removal = remove_entry(&file, false, &Mounts::of(&[&file])).unwrap();
        assert!(!removal.removed);
        assert_eq!(removal.left, vec![file.clone()]);
        assert!(file.is_file());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_a_tree_is_removed_around_the_mounts_inside_it() {
        let base = real_scratch("mount_around");
        let mounts = tree_with_two_mounts(&base);
        let removal = remove_entry(&base.join("d"), true, &mounts).unwrap();
        assert!(removal.removed);
        assert_eq!(removal.left, vec![base.join("d/inner/m2")]);
        assert!(!base.join("d/g").exists() && !base.join("d/inner/j").exists());
        assert!(
            base.join("d/inner/m2/keep2").is_file(),
            "what is mounted is as it was"
        );
        // The directories on the way to it stay, and so does everything else.
        assert!(base.join("d/inner").is_dir());
        assert!(base.join("f").is_file() && base.join("m1/keep1").is_file());

        // The whole tree as one entry, both mounts inside it.
        let removal = remove_entry(&base, true, &mounts).unwrap();
        let mut left = removal.left;
        left.sort();
        assert_eq!(left, vec![base.join("d/inner/m2"), base.join("m1")]);
        assert!(!base.join("f").exists());
        assert!(base.join("m1/keep1").is_file() && base.join("m1/sub/more").is_file());
        assert!(base.join("d/inner/m2/keep2").is_file());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_only_what_was_removed_counts_as_freed_and_what_failed_is_counted() {
        let mut emptied = Emptied::default();
        // Gone before we got to it: it freed nothing of ours, and nothing is left.
        emptied.add(Path::new("/c/gone"), 500, Ok(Removal::default()));
        // A mount point: left as it is, so nothing is freed either.
        let mnt = PathBuf::from("/c/mnt");
        let kept = Removal {
            removed: false,
            left: vec![mnt.clone()],
        };
        emptied.add(&mnt, 900, Ok(kept));
        emptied.add(
            Path::new("/c/file"),
            700,
            Ok(Removal {
                removed: true,
                left: Vec::new(),
            }),
        );
        assert_eq!(emptied.freed, 700, "{emptied:?}");
        assert_eq!((emptied.tried, emptied.failed), (3, 0), "{emptied:?}");
        assert_eq!(emptied.left, vec![mnt]);
        assert!(emptied.complaint(Path::new("/c")).is_none());

        emptied.add(
            Path::new("/c/stuck"),
            100,
            Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        );
        assert_eq!((emptied.tried, emptied.failed, emptied.freed), (4, 1, 700));
        let complaint = emptied.complaint(Path::new("/c")).unwrap();
        assert!(
            complaint.starts_with("Could not remove 1 of 4 item(s) in /c: /c/stuck: "),
            "{complaint}"
        );
    }

    #[test]
    fn test_the_mounts_that_were_left_are_named_in_the_order_of_their_paths() {
        let emptied = Emptied {
            left: vec![
                PathBuf::from("/c/m"),
                PathBuf::from("/a/z"),
                PathBuf::from("/a/b/c"),
            ],
            ..Emptied::default()
        };
        assert_eq!(
            emptied.left_notes(),
            [
                "Kept /a/b/c: another file system is mounted there",
                "Kept /a/z: another file system is mounted there",
                "Kept /c/m: another file system is mounted there",
            ]
        );
        assert!(Emptied::default().left_notes().is_empty());
    }

    #[test]
    fn test_a_name_that_begins_like_a_mount_point_is_not_one() {
        let base = real_scratch("mount_prefix");
        put(&base.join("m/keep"), 5000);
        put(&base.join("mm/x"), 5000);
        put(&base.join("m.c"), 5000);
        let m = base.join("m");
        let emptied = empty_dir(&base, &Mounts::of(&[&m])).unwrap();
        assert_eq!(emptied.left, vec![m.clone()]);
        assert_eq!(emptied.failed, 0, "{emptied:?}");
        assert!(m.join("keep").is_file());
        assert!(!base.join("mm").exists() && !base.join("m.c").exists());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_emptying_around_mounts_frees_what_the_preview_said() {
        let base = real_scratch("mount_empty");
        let mounts = tree_with_two_mounts(&base);
        let preview = dir_size_in(&base, &mounts);
        assert!(preview > 0);
        let emptied = empty_dir(&base, &mounts).unwrap();
        assert_eq!(emptied.freed, preview, "{emptied:?}");
        // Leaving a mount alone is the job, not a failure.
        assert_eq!((emptied.tried, emptied.failed), (3, 0), "{emptied:?}");
        assert!(emptied.complaint(&base).is_none());
        let mut left = emptied.left.clone();
        left.sort();
        assert_eq!(left, vec![base.join("d/inner/m2"), base.join("m1")]);
        let mut remaining: Vec<String> = fs::read_dir(&base)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        remaining.sort();
        assert_eq!(remaining, ["d", "m1"]);
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_a_cache_reached_through_a_link_is_still_emptied_around_its_mounts() {
        use std::os::unix::fs::symlink;
        let base = real_scratch("mount_link");
        put(&base.join("real/cache/file"), 5000);
        put(&base.join("real/cache/mnt/keep"), 5000);
        symlink(base.join("real"), base.join("link")).unwrap();
        // The kernel lists the real path; the cache is asked for by the link, as
        // `/home/me/.cache` is on a system where `/home` is `/var/home`.
        let mnt = base.join("real/cache/mnt");
        let freed = rm_contents_with(&base.join("link/cache"), Ok(Mounts::of(&[&mnt])));
        assert!(freed > 0);
        assert!(!base.join("real/cache/file").exists());
        assert!(base.join("real/cache/mnt/keep").is_file());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_a_directory_on_the_way_to_a_mount_is_opened_just_enough_to_empty_it() {
        if is_root() {
            return; // root can remove anything
        }
        let base = real_scratch("mount_perm");
        put(&base.join("top/f"), 5000);
        put(&base.join("top/m/keep"), 5000);
        let m = base.join("top/m");
        chmod(&base.join("top"), 0o555);
        let removal = remove_entry(&base.join("top"), true, &Mounts::of(&[&m]));
        let mode = mode_of(&base.join("top"));
        chmod(&base.join("top"), 0o755);
        let removal = removal.unwrap();
        assert!(removal.removed);
        assert!(!base.join("top/f").exists());
        assert!(base.join("top/m/keep").is_file());
        // It stays, so it got the owner's write access back and nothing else.
        assert_eq!(mode, 0o755);
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_without_the_list_of_mounts_nothing_is_removed() {
        const ME: &str = "utils::tests::test_without_the_list_of_mounts_nothing_is_removed";
        if env::var_os(CHILD_ENV).is_none() {
            let stdout = child_stdout(ME);
            assert!(
                stdout.contains("Could not read the list of mounts (no /proc here), so "),
                "{stdout}"
            );
            assert!(
                stdout.contains("FREED=0 STILL-THERE=true NEW-FAILURES=1"),
                "{stdout}"
            );
            return;
        }
        let base = real_scratch("mount_nolist");
        put(&base.join("cache/file"), 5000);
        let before = failure_count();
        let freed = rm_contents_with(&base.join("cache"), Err(io::Error::other("no /proc here")));
        println!(
            "FREED={freed} STILL-THERE={} NEW-FAILURES={}",
            base.join("cache/file").exists(),
            failure_count() - before
        );
        fs::remove_dir_all(&base).unwrap();
        println!("CHILD-RAN");
    }

    #[test]
    fn test_what_is_left_alone_is_said_and_is_not_a_failure() {
        const ME: &str = "utils::tests::test_what_is_left_alone_is_said_and_is_not_a_failure";
        if env::var_os(CHILD_ENV).is_none() {
            let stdout = child_stdout(ME);
            assert!(
                stdout.contains("another file system is mounted there"),
                "{stdout}"
            );
            assert!(stdout.contains("/cache/mnt"), "{stdout}");
            assert!(stdout.contains("NEW-FAILURES=0"), "{stdout}");
            return;
        }
        let base = real_scratch("mount_said");
        put(&base.join("cache/file"), 5000);
        put(&base.join("cache/mnt/keep"), 5000);
        let before = failure_count();
        let mnt = base.join("cache/mnt");
        let freed = rm_contents_with(&base.join("cache"), Ok(Mounts::of(&[&mnt])));
        println!(
            "FREED={} NEW-FAILURES={}",
            freed > 0,
            failure_count() - before
        );
        fs::remove_dir_all(&base).unwrap();
        println!("CHILD-RAN");
    }

    // ── Sweeps: what root empties with `find` ──

    /// What `sweep_with` ran, one entry per call, and what it answered when the
    /// `find` it was handed answered `outcome`.
    fn sweep_run(
        dir: &Path,
        what: Sweep,
        mounts: io::Result<Mounts>,
        outcome: bool,
    ) -> (bool, Vec<Vec<String>>) {
        let calls = std::cell::RefCell::new(Vec::new());
        let done = sweep_with(dir.to_str().unwrap(), what, mounts, &|args| {
            calls
                .borrow_mut()
                .push(args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>());
            outcome
        });
        (done, calls.into_inner())
    }

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(|word| word.to_string()).collect()
    }

    #[test]
    fn test_a_sweep_is_find_on_the_real_path_that_stays_in_its_file_system() {
        use std::os::unix::fs::symlink;
        let base = real_scratch("sweep_args");
        fs::create_dir_all(base.join("real/sub")).unwrap();
        symlink(base.join("real"), base.join("link")).unwrap();
        let real = base.join("real");
        let real = real.to_str().unwrap();
        for (what, tail) in [
            (Sweep::Contents, ["-mindepth", "1"]),
            (Sweep::Files, ["-type", "f"]),
        ] {
            // Asked for by the link; `find` does not follow one to start with.
            for outcome in [true, false] {
                let (done, calls) =
                    sweep_run(&base.join("link"), what, Ok(Mounts::default()), outcome);
                assert_eq!(done, outcome, "the answer is find's");
                assert_eq!(
                    calls,
                    [words(&[real, "-xdev", tail[0], tail[1], "-delete"])]
                );
            }
        }
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_a_directory_with_a_file_system_mounted_inside_it_is_not_swept() {
        let base = real_scratch("sweep_inside");
        fs::create_dir_all(base.join("tree/deep/mnt")).unwrap();
        fs::create_dir_all(base.join("tree2")).unwrap();
        let (tree, deep, tree2) = (
            base.join("tree"),
            base.join("tree/deep/mnt"),
            base.join("tree2"),
        );
        for what in [Sweep::Files, Sweep::Contents] {
            let (done, calls) = sweep_run(&tree, what, Ok(Mounts::of(&[&deep])), true);
            assert!(!done && calls.is_empty(), "{what:?}: {calls:?}");
        }
        // The directory itself being a mount point is ordinary, and a neighbour whose
        // name begins the same is not inside it.
        let (done, calls) = sweep_run(
            &tree,
            Sweep::Contents,
            Ok(Mounts::of(&[&tree, &tree2])),
            true,
        );
        assert!(done && calls.len() == 1, "{calls:?}");
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_a_sweep_needs_the_list_of_mounts_but_not_for_what_is_not_there() {
        let base = real_scratch("sweep_edge");
        fs::create_dir_all(base.join("tree")).unwrap();
        let no_list = || Err(io::Error::other("no /proc here"));
        // No list is no answer: nothing is run, and it was not done.
        let (done, calls) = sweep_run(&base.join("tree"), Sweep::Files, no_list(), true);
        assert!(!done && calls.is_empty(), "{calls:?}");
        // Nothing there: nothing to empty, and no list or `find` is needed for that.
        let (done, calls) = sweep_run(&base.join("gone"), Sweep::Files, no_list(), false);
        assert!(done && calls.is_empty(), "{calls:?}");
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_a_directory_whose_real_name_cannot_be_passed_on_is_not_swept() {
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::symlink;
        let base = real_scratch("sweep_name");
        let odd = base.join(std::ffi::OsString::from_vec(b"odd-\xff".to_vec()));
        fs::create_dir_all(&odd).unwrap();
        symlink(&odd, base.join("link")).unwrap();
        let (done, calls) = sweep_run(
            &base.join("link"),
            Sweep::Files,
            Ok(Mounts::default()),
            true,
        );
        assert!(!done && calls.is_empty(), "{calls:?}");
        fs::remove_dir_all(&base).unwrap();
    }

    /// Whether a real file system can be mounted here, in a namespace that goes
    /// with the child: what it takes to try `find` on one without touching the
    /// machine.
    fn can_mount_privately(dir: &Path) -> bool {
        Command::new("unshare")
            .args(["-Urm", "sh", "-c", "mount -t tmpfs tmpfs \"$0\""])
            .arg(dir)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .output()
            .is_ok_and(|out| out.status.success())
    }

    #[test]
    fn test_find_with_these_arguments_stays_out_of_another_file_system() {
        let base = real_scratch("sweep_real_find");
        if !can_mount_privately(&base) {
            eprintln!("skipped: this machine gives no private mount namespace");
            fs::remove_dir_all(&base).unwrap();
            return;
        }
        // A tmpfs is mounted inside the tree, with what must survive in it. Run as
        // the arguments say, `find` empties the rest and leaves what is mounted.
        const SCRIPT: &str = r#"
            T=$1
            mkdir -p "$T/sub" "$T/mnt"
            echo a > "$T/f1"; echo b > "$T/sub/f2"
            mount -t tmpfs tmpfs "$T/mnt" || exit 90
            echo precious > "$T/mnt/precious"
            find "$@" > /dev/null 2>&1
            find "$T" -mindepth 1 | sort
        "#;
        let tree = base.join("tree");
        let tree = tree.to_str().unwrap();
        for (what, left) in [
            (Sweep::Contents, vec!["/mnt", "/mnt/precious"]),
            (Sweep::Files, vec!["/mnt", "/mnt/precious", "/sub"]),
        ] {
            let out = Command::new("unshare")
                .args(["-Urm", "sh", "-c", SCRIPT, "sh"])
                .args(sweep_args(tree, what))
                .env_clear()
                .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                .env("LC_ALL", "C")
                .output()
                .unwrap();
            let shown = String::from_utf8_lossy(&out.stdout).into_owned();
            let want: Vec<String> = left.iter().map(|rest| format!("{tree}{rest}")).collect();
            assert_eq!(shown.lines().collect::<Vec<_>>(), want, "{what:?}: {out:?}");
            // The mount was made in the child's namespace, so none of it is here.
            let _ = fs::remove_dir_all(tree);
        }
        let _ = fs::remove_dir_all(&base);
    }
}
