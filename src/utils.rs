use colored::Colorize;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};

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

/// Run command silently (suppress all output)
pub fn run_silent(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
    .args(args)
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .status()
    .map(|s| s.success())
    .unwrap_or(false)
}

/// Run command with sudo, falls back to direct if already root
pub fn sudo(cmd: &str, args: &[&str]) -> bool {
    if is_root() {
        return run(cmd, args);
    }
    let mut a = vec![cmd];
    a.extend_from_slice(args);
    run("sudo", &a)
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

/// Check if a command exists in PATH
pub fn which(cmd: &str) -> bool {
    run_silent("which", &[cmd])
}

/// Check if running as root (uid 0)
pub fn is_root() -> bool {
    capture("id", &["-u"])
    .map(|id| id == "0")
    .unwrap_or(false)
}

/// Acquire sudo privileges (prompts for password)
pub fn acquire_sudo() -> bool {
    if is_root() {
        return true;
    }
    println!();
    println!("  {}", "🔐 Requesting sudo privileges...".yellow());
    Command::new("sudo")
    .arg("-v")
    .status()
    .map(|s| s.success())
    .unwrap_or(false)
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

/// Ask user for yes/no confirmation
pub fn confirm(msg: &str) -> bool {
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
    println!();
    println!("  {} {}", "━━▶".cyan().bold(), title.white().bold());
}

pub fn success(msg: &str) {
    println!("    {} {}", "✔".green().bold(), msg);
}

pub fn warning(msg: &str) {
    println!("    {} {}", "⚠".yellow().bold(), msg);
}

pub fn error(msg: &str) {
    println!("    {} {}", "✘".red().bold(), msg);
}

pub fn info(msg: &str) {
    println!("    {} {}", "ℹ".blue(), msg);
}

pub fn skip(msg: &str) {
    println!("    {} {}", "⊘".dimmed(), msg.dimmed());
}
