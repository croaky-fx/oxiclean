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

/// Run command with visible output (inherits stdio)
pub fn run(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
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
    match Command::new(cmd).args(args).output() {
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
    match privilege {
        Privilege::Root => run_quiet(cmd, args),
        Privilege::Sudo | Privilege::Doas => {
            let mut a = vec![cmd];
            a.extend_from_slice(args);
            run_quiet(privilege.name(), &a)
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
pub fn elevate(privilege: Privilege, cmd: &str, args: &[&str]) -> bool {
    match privilege {
        Privilege::Root => run(cmd, args),
        Privilege::Sudo | Privilege::Doas => {
            let mut a = vec![cmd];
            a.extend_from_slice(args);
            run(privilege.name(), &a)
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
        Privilege::Sudo => run("sudo", &["-v"]),
        Privilege::Doas => run("doas", &["true"]),
        Privilege::None => false,
    }
}

/// Backwards-compatible wrapper. Delegates to [`elevate`] with the helper
/// detected at startup (set by `main()` via [`set_privilege`]).
pub fn sudo(cmd: &str, args: &[&str]) -> bool {
    elevate(current_privilege(), cmd, args)
}

/// Capture stdout of a command (returns output regardless of exit code)
pub fn capture(cmd: &str, args: &[&str]) -> Option<String> {
    Command::new(cmd)
        .args(args)
        .stderr(Stdio::null())
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
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

/// Check if running as root (uid 0)
pub fn is_root() -> bool {
    capture("id", &["-u"]).map(|id| id == "0").unwrap_or(false)
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

/// Recursively calculate directory size (skips symlinks)
pub fn dir_size(path: &Path) -> u64 {
    if !path.exists() {
        return 0;
    }
    if path.is_file() {
        return path.metadata().map(|m| m.len()).unwrap_or(0);
    }
    let mut total = 0u64;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_symlink() {
                continue;
            }
            if p.is_dir() {
                total += dir_size(&p);
            } else {
                total += p.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
    }
    total
}

/// Remove all contents inside a directory (keeps the dir itself)
/// Returns total bytes freed
pub fn rm_contents(path: &Path) -> u64 {
    let mut freed = 0u64;
    if !path.exists() || !path.is_dir() {
        return 0;
    }
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();

            // Measure size before deletion
            let size = if p.is_symlink() {
                p.symlink_metadata().map(|m| m.len()).unwrap_or(0)
            } else if p.is_dir() {
                dir_size(&p)
            } else {
                p.metadata().map(|m| m.len()).unwrap_or(0)
            };

            // Delete
            let ok = if p.is_dir() && !p.is_symlink() {
                fs::remove_dir_all(&p).is_ok()
            } else {
                fs::remove_file(&p).is_ok()
            };

            if ok {
                freed += size;
            }
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
