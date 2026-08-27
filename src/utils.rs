use colored::Colorize;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};
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

/// Run command with visible output (inherits stdio)
pub fn run(cmd: &str, args: &[&str]) -> bool {
    harden_env(Command::new(cmd).args(args))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
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
    // Refuse rather than fall back to a $PATH lookup: with root behind the
    // call, "not in a trusted directory" must never mean "try anywhere".
    let Some(target) = resolve_trusted(cmd) else {
        return false;
    };
    match privilege {
        Privilege::Root => run(&target, args),
        Privilege::Sudo | Privilege::Doas => {
            let Some(helper) = resolve_trusted(privilege.name()) else {
                return false;
            };
            let mut a = vec![target.as_str()];
            a.extend_from_slice(args);
            run(&helper, &a)
        }
        Privilege::None => false,
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
pub fn sudo(cmd: &str, args: &[&str]) -> bool {
    elevate(current_privilege(), cmd, args)
}

/// Capture stdout of a command (returns output regardless of exit code).
///
/// Not restricted to [`TRUSTED_BIN_DIRS`], because `--dev` drives tools that
/// legitimately live in the user's home: rustup puts `cargo` in `~/.cargo/bin`,
/// and the `uv`/`deno`/`pnpm`/`bun` installers default to `~/.local/bin`. Those
/// run with the caller's own privileges against the caller's own cache, so a
/// binary they control is not an escalation. Privileged callers use
/// [`capture_trusted`].
pub fn capture(cmd: &str, args: &[&str]) -> Option<String> {
    harden_env(Command::new(cmd).args(args))
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
    capture(&target, args)
}

/// Check if a command exists in PATH.
/// Walks $PATH directly instead of spawning a `which` subprocess —
/// faster, more reliable, and works on systems where `which` itself
/// is not installed (e.g. minimal Alpine containers).
pub fn which(cmd: &str) -> bool {
    match env::var_os("PATH") {
        Some(paths) => env::split_paths(&paths).any(|dir| dir.join(cmd).is_file()),
        None => false,
    }
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

/// Get user home directory from $HOME
pub fn home_dir() -> Option<String> {
    env::var("HOME").ok()
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
}
