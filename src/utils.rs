use colored::Colorize;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;

use crate::detect::Privilege;

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
    TRUSTED_BIN_DIRS
        .iter()
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
    TRUSTED_BIN_DIRS.join(":")
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
/// the caller's caches, so a binary the caller controls gains nothing. It must
/// never be paired with [`elevate`], which has its own trusted lookup.
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
        println!("      {}", line.dimmed());
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

/// [`run_quiet`] with privilege escalation. Mirrors [`elevate`]'s dispatch.
pub fn elevate_quiet(privilege: Privilege, cmd: &str, args: &[&str]) -> bool {
    // Same trusted-path resolution as [`elevate`] — see the rationale there.
    let Some(target) = resolve_trusted(cmd) else {
        return false;
    };
    match privilege {
        Privilege::Root => run_quiet(&target, args),
        Privilege::Sudo | Privilege::Doas => {
            let Some(helper) = resolve_trusted(privilege.name()) else {
                return false;
            };
            let mut a = vec![target.as_str()];
            a.extend_from_slice(args);
            run_quiet(&helper, &a)
        }
        Privilege::None => false,
    }
}

/// Quiet counterpart to [`sudo`], using the helper detected at startup.
pub fn sudo_quiet(cmd: &str, args: &[&str]) -> bool {
    elevate_quiet(current_privilege(), cmd, args)
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
pub fn elevate(privilege: Privilege, cmd: &str, args: &[&str]) -> bool {
    let Some((program, argv)) = escalation(privilege, cmd, args, &resolve_trusted) else {
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
pub fn elevate_with_input(privilege: Privilege, cmd: &str, args: &[&str], input: &[u8]) -> bool {
    let Some((program, argv)) = escalation(privilege, cmd, args, &resolve_trusted) else {
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
/// `$PATH` ([`which_path`]) and the child keeps the caller's environment.
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

/// [`capture`] restricted to [`TRUSTED_BIN_DIRS`], for output we act on with
/// root behind it.
///
/// `pacman -Qdtq` and `zypper packages --orphaned` produce the package list that
/// is then fed to a privileged removal command, so a shadowed binary here does
/// not need to run as root itself — it just has to name packages, and we delete
/// them. Returns `None` when the tool is not in a trusted directory, which
/// callers already treat as "not available".
pub fn capture_trusted(cmd: &str, args: &[&str]) -> Option<String> {
    let target = resolve_trusted(cmd)?;
    capture_program(Path::new(&target), args, true)
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

/// Recursively calculate directory size, skipping symlinks.
///
/// Reads type and size from the `DirEntry` the directory scan already produced.
/// The `is_symlink()` / `is_dir()` / `metadata()` chain this replaced re-resolved
/// each path three times; on a 40 000-file tree that was 88 ms versus `du`'s 34.
/// `~/.cache` is the deepest tree the tool touches, and on a spinning disk the
/// syscall count is the runtime.
///
/// Iterative so a deep tree cannot overflow the stack.
pub fn dir_size(path: &Path) -> u64 {
    let Ok(top) = fs::symlink_metadata(path) else {
        return 0;
    };
    if top.is_symlink() {
        return 0;
    }
    if !top.is_dir() {
        return top.len();
    }

    let mut total = 0u64;
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
            if ft.is_dir() {
                stack.push(entry.path());
            } else if let Ok(md) = entry.metadata() {
                total += md.len();
            }
        }
    }
    total
}

/// Remove all contents inside a directory (keeps the dir itself)
/// Returns total bytes freed
pub fn rm_contents(path: &Path) -> u64 {
    let mut freed = 0u64;
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        // `DirEntry::metadata` is an lstat: one call gives symlink, dir and size.
        let Ok(md) = entry.metadata() else {
            continue;
        };
        let is_real_dir = md.is_dir() && !md.is_symlink();

        let size = if is_real_dir { dir_size(&p) } else { md.len() };

        let ok = if is_real_dir {
            fs::remove_dir_all(&p).is_ok()
        } else {
            fs::remove_file(&p).is_ok()
        };

        if ok {
            freed += size;
        }
    }
    freed
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

/// Ask user for yes/no confirmation. In JSON mode there is no interactive
/// terminal, so we decline by default rather than block on stdin — callers
/// that must proceed non-interactively pass `--yes`, which short-circuits
/// before reaching here.
pub fn confirm(msg: &str) -> bool {
    if silent() {
        return false;
    }
    print!("  {} {} ", "?".cyan().bold(), msg);
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}

// ═══════════════════════════════════════════════════
//  UI Helpers
// ═══════════════════════════════════════════════════

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
    println!("  {} {}", "━━▶".cyan().bold(), title.white().bold());
}

pub fn success(msg: &str) {
    if silent() {
        return;
    }
    println!("    {} {}", "✔".green().bold(), msg);
}

pub fn warning(msg: &str) {
    if silent() {
        return;
    }
    println!("    {} {}", "⚠".yellow().bold(), msg);
}

pub fn error(msg: &str) {
    if silent() {
        return;
    }
    println!("    {} {}", "✘".red().bold(), msg);
}

/// Informational line. Suppressed by `--quiet` (noisiest lines) and by JSON
/// mode. The user can survive without them.
pub fn info(msg: &str) {
    if is_quiet() || silent() {
        return;
    }
    println!("    {} {}", "ℹ".blue(), msg);
}

/// "Skipped" line. Suppressed by `--quiet` and JSON mode; nothing to act on.
pub fn skip(msg: &str) {
    if is_quiet() || silent() {
        return;
    }
    println!("    {} {}", "⊘".dimmed(), msg.dimmed());
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
    println!("{msg}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

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

    #[test]
    fn test_dir_size_and_rm_handle_symlinks() {
        // dir_size and rm_contents were rewritten to take type and size from the
        // DirEntry rather than re-stat each path. The subtle part is that
        // DirEntry::metadata is an lstat: it must report the *link*, never follow
        // it. Getting that wrong would count a symlink target's bytes (inflating
        // the freed figure) or, worse, descend out of the tree being cleaned.
        use std::os::unix::fs::symlink;
        let base = std::env::temp_dir().join(format!("oxi_lnk_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);

        let outside = base.join("outside");
        let tree = base.join("tree");
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(tree.join("sub")).unwrap();

        // A big file OUTSIDE the tree, and a big directory outside it.
        fs::write(outside.join("big.bin"), vec![0u8; 100_000]).unwrap();
        // Real content inside the tree: 500 + 300 bytes.
        fs::write(tree.join("real.txt"), vec![0u8; 500]).unwrap();
        fs::write(tree.join("sub/inner.txt"), vec![0u8; 300]).unwrap();
        // Links that must contribute their own (tiny) size, never the target's.
        symlink(outside.join("big.bin"), tree.join("link_to_big")).unwrap();
        symlink(&outside, tree.join("link_to_dir")).unwrap();
        symlink("/nonexistent/xyz", tree.join("broken")).unwrap();

        // 800 bytes of real content. Symlinks are skipped entirely by dir_size,
        // and the 100 KB target must not be counted through either link.
        assert_eq!(
            dir_size(&tree),
            800,
            "symlinks must be skipped and never followed"
        );

        let freed = rm_contents(&tree);
        assert!(tree.is_dir(), "the directory itself must survive");
        assert_eq!(dir_size(&tree), 0, "contents must be gone");
        // The link target must still exist — we unlinked the links, not the files.
        assert!(
            outside.join("big.bin").is_file(),
            "rm_contents followed a symlink and deleted outside the tree"
        );
        // Freed counts the real bytes plus the links' own entries, never 100 KB.
        assert!(
            (800..2_000).contains(&freed),
            "freed should be ~800 B of real content, got {freed}"
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_dir_size_on_a_symlink_is_zero() {
        // A symlink handed in directly must report 0, not the target's size.
        use std::os::unix::fs::symlink;
        let base = std::env::temp_dir().join(format!("oxi_lnktop_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("target.bin"), vec![0u8; 50_000]).unwrap();
        let link = base.join("thelink");
        symlink(base.join("target.bin"), &link).unwrap();

        assert_eq!(dir_size(&link), 0);
        assert_eq!(dir_size(&base.join("target.bin")), 50_000);

        let _ = fs::remove_dir_all(&base);
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
}
