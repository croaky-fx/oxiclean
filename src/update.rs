// ═══════════════════════════════════════════════════
//  Self-update — `oxiclean --update`
// ═══════════════════════════════════════════════════
//
// Checks GitHub for a newer release, shows its notes, and (with consent)
// swaps the running binary for the new one.
//
// Hard rules baked in here:
//
// * **Never self-update a package-manager install.** If pacman/dpkg owns the
//   binary, updating in place corrupts their file database and gets clobbered
//   on the next system upgrade. We detect this and point at the right command.
// * **Atomic replacement, ETXTBSY-safe.** You cannot open a *running*
//   executable for writing (Linux returns ETXTBSY), so `cp`/`install` would
//   fail. The only safe swap is `rename(2)` over the target — we copy the new
//   binary to a temp file *in the same directory* and rename it into place.
// * **Verify before trusting.** The download must be a real ELF and must run
//   `--version` reporting the expected release, which also proves the libc
//   flavour matched.

use std::path::Path;
use std::process::{Command, Stdio};

use colored::Colorize;
use serde::Deserialize;

use crate::utils;

const REPO: &str = "croaky-fx/oxiclean";
const API_LATEST: &str = "https://api.github.com/repos/croaky-fx/oxiclean/releases/latest";

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    body: Option<String>,
}

// ── pure, testable helpers ──────────────────────────

/// Parse `1.4.2` or `v1.4.2` into `(major, minor, patch)`.
fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim().trim_start_matches('v');
    let mut it = s.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    let patch = it
        .next()
        .unwrap_or("0")
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0);
    Some((major, minor, patch))
}

/// True only if `latest` is strictly newer than `current`.
fn is_newer(current: &str, latest: &str) -> bool {
    match (parse_version(current), parse_version(latest)) {
        (Some(c), Some(l)) => l > c,
        _ => false,
    }
}

/// Map the compile-time target arch to a release-asset token, or `None` for
/// architectures we don't publish prebuilt binaries for.
fn asset_arch() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Some("x86_64"),
        "aarch64" => Some("aarch64"),
        _ => None,
    }
}

/// Detect libc by looking for the musl loader file — pure `std::fs`, no shell,
/// nothing non-POSIX. Defaults to `gnu` when no musl loader is present.
fn detect_libc() -> &'static str {
    if let Ok(entries) = std::fs::read_dir("/lib") {
        for e in entries.flatten() {
            if let Some(name) = e.file_name().to_str() {
                if name.starts_with("libc.musl-") || name.starts_with("ld-musl-") {
                    return "musl";
                }
            }
        }
    }
    "gnu"
}

/// The first four bytes of every ELF file are `0x7F E L F`.
fn is_elf(path: &Path) -> bool {
    use std::io::Read;
    let mut buf = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .map(|_| buf == [0x7f, b'E', b'L', b'F'])
        .unwrap_or(false)
}

/// Result of asking a package manager whether it owns a path.
enum Ownership {
    /// The package manager owns this file — do not self-update.
    Owned,
    /// The package manager is installed and cleanly reports it does not own it.
    NotOwned,
    /// The tool isn't installed at all — it simply can't own anything here.
    Absent,
    /// The tool is installed but the query errored (locked/corrupt DB,
    /// unexpected exit) — we genuinely can't tell, so fail closed.
    Errored,
}

/// Ask `tool` (with `args`) whether it owns `exe`. `pacman -Qo` and `dpkg -S`
/// both exit 0 when owned and exit 1 when they cleanly don't own the path.
/// An installed tool exiting some other way is `Errored` (fail closed); a tool
/// that isn't installed is `Absent` (it can't be managing this binary).
fn query_owner(tool: &str, args: &[&str], exe: &Path) -> Ownership {
    if !utils::which(tool) {
        return Ownership::Absent;
    }
    match Command::new(tool)
        .args(args)
        .arg(exe)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(s) if s.success() => Ownership::Owned,
        Ok(s) if s.code() == Some(1) => Ownership::NotOwned,
        _ => Ownership::Errored,
    }
}

/// If a system package manager owns `exe` — or is installed but its query
/// failed — return the command the user should run instead. `None` means every
/// package manager present cleanly disowned the binary, so self-update is safe.
fn managed_by(exe: &Path) -> Option<String> {
    let probes: &[(&str, &[&str], &str)] = &[
        (
            "pacman",
            &["-Qo"],
            "paru -Syu oxiclean   (or: sudo pacman -Syu)",
        ),
        (
            "dpkg",
            &["-S"],
            "sudo apt update && sudo apt install --only-upgrade oxiclean",
        ),
    ];
    for (tool, args, cmd) in probes {
        match query_owner(tool, args, exe) {
            Ownership::Owned => return Some(cmd.to_string()),
            Ownership::Errored => {
                return Some(format!(
                    "your package manager ({tool} query failed — refusing to overwrite a possibly-managed binary)"
                ))
            }
            Ownership::NotOwned | Ownership::Absent => {}
        }
    }
    None
}

// ── networking ──────────────────────────────────────

fn user_agent() -> String {
    format!("oxiclean/{}", env!("CARGO_PKG_VERSION"))
}

fn fetch_latest() -> Result<Release, String> {
    let mut resp = ureq::get(API_LATEST)
        .header("User-Agent", &user_agent())
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| e.to_string())?;
    resp.body_mut()
        .read_json::<Release>()
        .map_err(|e| e.to_string())
}

fn download(url: &str, dest: &Path) -> Result<(), String> {
    let mut resp = ureq::get(url)
        .header("User-Agent", &user_agent())
        .call()
        .map_err(|e| e.to_string())?;
    let mut file = std::fs::File::create(dest).map_err(|e| e.to_string())?;
    let mut reader = resp.body_mut().as_reader();
    std::io::copy(&mut reader, &mut file).map_err(|e| e.to_string())?;
    Ok(())
}

fn set_exec(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)
}

/// True if we can create files in `dir` (probe rather than parse mode bits, so
/// root and ACLs are handled correctly).
fn dir_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".oxiclean.wtest.{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Replace `target` with `new_bin` atomically and ETXTBSY-safe: copy into a
/// sibling temp file in `target`'s own directory, then `rename` over the
/// target. When the directory needs root, do the same three steps in one
/// privileged shell call so the swap is still a single atomic rename.
fn replace_binary(new_bin: &Path, target: &Path) -> Result<(), String> {
    let dir = target.parent().unwrap_or_else(|| Path::new("/"));
    let tmp = dir.join(format!(".oxiclean.new.{}", std::process::id()));

    if dir_writable(dir) {
        std::fs::copy(new_bin, &tmp).map_err(|e| e.to_string())?;
        set_exec(&tmp).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, target).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            e.to_string()
        })?;
        return Ok(());
    }

    let priv_ = crate::detect::find_privilege();
    let tmp_q = shell_quote(&tmp.to_string_lossy());
    // `trap ... EXIT` removes the temp file even if `mv` fails, so a failed
    // privileged install never leaves a root-owned leftover next to the target.
    let script = format!(
        "trap 'rm -f {tmp}' EXIT; cp -f {src} {tmp} && chmod 755 {tmp} && mv -f {tmp} {dst}",
        src = shell_quote(&new_bin.to_string_lossy()),
        tmp = tmp_q,
        dst = shell_quote(&target.to_string_lossy()),
    );
    if utils::elevate(priv_, "sh", &["-c", &script]) {
        Ok(())
    } else {
        Err("privileged install failed".to_string())
    }
}

/// Single-quote a path for safe use inside the privileged `sh -c` string.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ── entry point ─────────────────────────────────────

/// Run the `--update` flow. Returns a process exit code.
pub fn run(yes: bool) -> i32 {
    let current = env!("CARGO_PKG_VERSION");

    let exe = match std::env::current_exe().and_then(|p| p.canonicalize()) {
        Ok(p) => p,
        Err(e) => {
            utils::error(&format!("cannot locate own binary: {e}"));
            return 1;
        }
    };

    if let Some(cmd) = managed_by(&exe) {
        utils::section("Update");
        utils::info(&format!(
            "Installed by a package manager ({})",
            exe.display()
        ));
        utils::info(&format!("Update it with:  {}", cmd.bold()));
        return 0;
    }

    utils::section("Update");
    let release = match fetch_latest() {
        Ok(r) => r,
        Err(e) => {
            utils::error(&format!("couldn't check for updates ({e})"));
            return 1;
        }
    };
    let latest = release.tag_name.trim_start_matches('v').to_string();

    if !is_newer(current, &latest) {
        utils::success(&format!("You're on the latest version ({current})"));
        return 0;
    }

    println!(
        "  {} {} {} {}",
        "Update available:".bold(),
        current.yellow(),
        "→".dimmed(),
        latest.green().bold()
    );
    let notes = release.body.as_deref().unwrap_or("").trim();
    if !notes.is_empty() && !utils::is_quiet() {
        println!();
        for line in notes.lines() {
            println!("  {line}");
        }
        println!();
    }

    if !yes && !utils::confirm(&format!("Upgrade to {latest}? [y/N]:")) {
        utils::info("Update cancelled");
        return 0;
    }

    let arch = match asset_arch() {
        Some(a) => a,
        None => {
            utils::error(&format!(
                "no prebuilt binary for {} — build from source: cargo install --git https://github.com/{REPO}",
                std::env::consts::ARCH
            ));
            return 1;
        }
    };
    let libc = detect_libc();
    let asset = format!("oxiclean-{arch}-linux-{libc}");
    let url = format!(
        "https://github.com/{REPO}/releases/download/{}/{asset}",
        release.tag_name
    );

    let tmp = std::env::temp_dir().join(format!("oxiclean-update.{}", std::process::id()));
    struct Cleanup<'a>(&'a Path);
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0);
        }
    }
    let _cleanup = Cleanup(&tmp);

    utils::info(&format!("Downloading {asset}..."));
    if let Err(e) = download(&url, &tmp) {
        utils::error(&format!("download failed ({e})"));
        return 1;
    }
    if !is_elf(&tmp) {
        utils::error("downloaded file is not a valid Linux binary");
        return 1;
    }
    let _ = set_exec(&tmp);

    let got = Command::new(&tmp)
        .arg("--version")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    if !got.contains(&latest) {
        utils::error(&format!(
            "downloaded binary failed its self-check (expected {latest}, got '{got}') — libc mismatch?"
        ));
        return 1;
    }
    utils::success(&format!("Verified {latest}"));

    utils::info(&format!("Installing to {}...", exe.display()));
    if let Err(e) = replace_binary(&tmp, &exe) {
        utils::error(&format!("install failed ({e})"));
        return 1;
    }

    utils::success(&format!("Updated {current} → {latest}"));
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("1.4.2"), Some((1, 4, 2)));
        assert_eq!(parse_version("v1.4.2"), Some((1, 4, 2)));
        assert_eq!(parse_version(" 1.4.2 "), Some((1, 4, 2)));
        assert_eq!(parse_version("1.4"), Some((1, 4, 0)));
        assert_eq!(parse_version("2.0.0"), Some((2, 0, 0)));
        assert_eq!(parse_version("garbage"), None);
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn test_is_newer() {
        assert!(is_newer("1.4.1", "1.4.2"));
        assert!(is_newer("1.4.2", "1.5.0"));
        assert!(is_newer("1.9.9", "2.0.0"));
        assert!(!is_newer("1.4.2", "1.4.2"));
        assert!(!is_newer("1.4.2", "1.4.1"));
        assert!(!is_newer("2.0.0", "1.9.9"));
        // Unparseable input must never claim an update is available.
        assert!(!is_newer("1.4.2", "garbage"));
    }

    #[test]
    fn test_asset_arch_is_supported_on_this_host() {
        // CI and dev machines are x86_64 or aarch64 — both must map.
        assert!(asset_arch().is_some());
    }

    #[test]
    fn test_detect_libc_is_stable() {
        let a = detect_libc();
        assert!(a == "musl" || a == "gnu");
        assert_eq!(a, detect_libc());
    }

    #[test]
    fn test_is_elf() {
        let dir = std::env::temp_dir();
        let good = dir.join(format!("oxiclean_elf_good.{}", std::process::id()));
        let bad = dir.join(format!("oxiclean_elf_bad.{}", std::process::id()));
        std::fs::write(&good, [0x7f, b'E', b'L', b'F', 0, 0]).unwrap();
        std::fs::write(&bad, b"#!/bin/sh\n").unwrap();
        assert!(is_elf(&good));
        assert!(!is_elf(&bad));
        let _ = std::fs::remove_file(&good);
        let _ = std::fs::remove_file(&bad);
    }

    #[test]
    fn test_shell_quote_escapes() {
        assert_eq!(shell_quote("/usr/local/bin/x"), "'/usr/local/bin/x'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn test_query_owner_absent_tool() {
        // A tool that isn't installed can't own anything — Absent, so
        // managed_by skips it rather than blocking self-update.
        let r = query_owner(
            "definitely-not-a-real-pm-xyz",
            &["-Qo"],
            Path::new("/bin/sh"),
        );
        assert!(matches!(r, Ownership::Absent));
    }

    #[test]
    fn test_query_owner_clean_not_owned() {
        // `false` exits 1 for any args — stands in for a package manager
        // cleanly reporting "no package owns this". Must be NotOwned, not
        // Errored, so a genuinely-unmanaged binary can still self-update.
        if utils::which("false") {
            let r = query_owner("false", &[], Path::new("/tmp/whatever"));
            assert!(matches!(r, Ownership::NotOwned));
        }
    }

    #[test]
    fn test_query_owner_unexpected_exit_is_errored() {
        // An installed tool exiting with neither 0 (owned) nor 1 (cleanly
        // not-owned) must be Errored, so managed_by fails closed.
        if utils::which("sh") {
            let r = query_owner("sh", &["-c", "exit 2 #"], Path::new("/tmp/x"));
            assert!(matches!(r, Ownership::Errored));
        }
    }
}
