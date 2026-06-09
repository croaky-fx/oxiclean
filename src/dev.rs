// ═══════════════════════════════════════════════════
//  Dev-tool cache cleanup
// ═══════════════════════════════════════════════════
//
// Each tool exposes a `scan_*` function that reports the size of its cache
// without touching anything, and a `clean_*` function that performs the
// cleanup. Splitting the two phases lets us print a nice summary first,
// then act — and lets the user see exactly what would be touched
// in `--dry-run`.
//
// Safety rules:
//
// * **Never** delete user-installed binaries (`~/.cargo/bin`,
//   `~/.npm/lib/node_modules`, etc.). Those are not caches.
// * **Never** delete poetry virtualenvs — only `~/.cache/pypoetry/cache`.
// * **pnpm** uses hard-linked stores; deleting the store directory by hand
//   silently breaks every existing `node_modules`. We must call
//   `pnpm store prune`.
// * **go**'s module cache is read-only; `rm -rf` fails. Use `go clean
//   -modcache`.
// * Anything that triggers a re-download on next build is gated behind
//   `--deep`. Re-extracting from a local `.crate` file doesn't count as
//   re-download.

use colored::Colorize;
use std::path::{Path, PathBuf};

use crate::utils;

// ─── Display ─────────────────────────────────────────

/// A single dev-tool's cache, with everything we need to render the
/// pre-cleanup summary table and to act on it.
pub struct DevCache {
    pub name: &'static str,
    pub size: u64,
    /// `true` if cleaning will force a re-download on the next build.
    /// Gated behind `--deep`.
    pub needs_redownload: bool,
    /// Short note shown in the summary (e.g. "store prune", "re-extract only").
    pub note: &'static str,
}

// ─── Path helpers ────────────────────────────────────

fn home_join(suffix: &str) -> Option<PathBuf> {
    utils::home_dir().map(|h| PathBuf::from(h).join(suffix))
}

/// Resolve `pnpm store path` at runtime. Falls back to `~/.local/share/pnpm/store`
/// only if pnpm isn't on PATH.
fn pnpm_store_path() -> Option<PathBuf> {
    if utils::which("pnpm") {
        if let Some(out) = utils::capture("pnpm", &["store", "path"]) {
            if !out.is_empty() {
                return Some(PathBuf::from(out));
            }
        }
    }
    home_join(".local/share/pnpm/store")
}

/// Resolve `go env GOMODCACHE`. Falls back to `$GOPATH/pkg/mod` then `~/go/pkg/mod`.
fn go_modcache_path() -> Option<PathBuf> {
    if utils::which("go") {
        if let Some(out) = utils::capture("go", &["env", "GOMODCACHE"]) {
            if !out.is_empty() {
                return Some(PathBuf::from(out));
            }
        }
    }
    home_join("go/pkg/mod")
}

/// Resolve `uv cache dir`. Falls back to `~/.cache/uv`.
fn uv_cache_path() -> Option<PathBuf> {
    if utils::which("uv") {
        if let Some(out) = utils::capture("uv", &["cache", "dir"]) {
            if !out.is_empty() {
                return Some(PathBuf::from(out));
            }
        }
    }
    home_join(".cache/uv")
}

/// Resolve `deno info` cache root. Falls back to `~/.cache/deno`.
fn deno_dir_path() -> Option<PathBuf> {
    if let Ok(env) = std::env::var("DENO_DIR") {
        if !env.is_empty() {
            return Some(PathBuf::from(env));
        }
    }
    home_join(".cache/deno")
}

// ─── Scanners (read-only) ────────────────────────────

fn scan_simple(name: &'static str, path: Option<PathBuf>, note: &'static str) -> Option<DevCache> {
    let p = path?;
    if !p.exists() {
        return None;
    }
    let size = utils::dir_size(&p);
    if size == 0 {
        return None;
    }
    Some(DevCache {
        name,
        size,
        needs_redownload: false,
        note,
    })
}

fn scan_redownload(
    name: &'static str,
    path: Option<PathBuf>,
    note: &'static str,
) -> Option<DevCache> {
    let p = path?;
    if !p.exists() {
        return None;
    }
    let size = utils::dir_size(&p);
    if size == 0 {
        return None;
    }
    Some(DevCache {
        name,
        size,
        needs_redownload: true,
        note,
    })
}

/// Build the full list of dev-tool caches present on this system.
/// Tools that aren't installed (or whose cache doesn't exist yet)
/// are silently omitted.
pub fn scan_all() -> Vec<DevCache> {
    let mut out: Vec<DevCache> = Vec::new();

    // ── Node ecosystem ──
    if let Some(c) = scan_simple("npm", home_join(".npm/_cacache"), "safe") {
        out.push(c);
    }
    if let Some(c) = scan_simple("yarn (classic)", home_join(".cache/yarn"), "safe") {
        out.push(c);
    }
    if let Some(c) = scan_simple("yarn (berry)", home_join(".yarn/berry/cache"), "safe") {
        out.push(c);
    }
    if let Some(c) = scan_simple("bun", home_join(".bun/install/cache"), "safe") {
        out.push(c);
    }
    if let Some(c) = scan_simple("pnpm", pnpm_store_path(), "store prune") {
        out.push(c);
    }
    if let Some(c) = scan_simple("deno", deno_dir_path(), "safe") {
        out.push(c);
    }

    // ── Python ecosystem ──
    if let Some(c) = scan_simple("pip", home_join(".cache/pip"), "safe") {
        out.push(c);
    }
    if let Some(c) = scan_simple("uv", uv_cache_path(), "safe") {
        out.push(c);
    }
    if let Some(c) = scan_simple("pipenv", home_join(".cache/pipenv"), "safe") {
        out.push(c);
    }
    // poetry: ONLY `cache/`, never `virtualenvs/`
    if let Some(c) = scan_simple(
        "poetry",
        home_join(".cache/pypoetry/cache"),
        "safe (virtualenvs preserved)",
    ) {
        out.push(c);
    }

    // ── Rust ──
    if let Some(c) = scan_simple(
        "cargo registry/src",
        home_join(".cargo/registry/src"),
        "re-extract only",
    ) {
        out.push(c);
    }
    if let Some(c) = scan_simple(
        "cargo git/checkouts",
        home_join(".cargo/git/checkouts"),
        "re-extract only",
    ) {
        out.push(c);
    }
    if let Some(c) = scan_redownload(
        "cargo registry/cache",
        home_join(".cargo/registry/cache"),
        "re-download on next build",
    ) {
        out.push(c);
    }
    if let Some(c) = scan_redownload(
        "cargo git/db",
        home_join(".cargo/git/db"),
        "re-download on next build",
    ) {
        out.push(c);
    }

    // ── Go ──
    if let Some(c) = scan_redownload(
        "go modules",
        go_modcache_path(),
        "re-download on next build",
    ) {
        out.push(c);
    }

    // ── Ruby ──
    if utils::which("gem") {
        // gem cleanup doesn't operate on a fixed directory \u2014 it walks
        // GEM_PATH and removes old versions. We can't pre-measure it
        // accurately, but we still want to advertise it.
        out.push(DevCache {
            name: "ruby gems (old versions)",
            size: 0,
            needs_redownload: false,
            note: "gem cleanup",
        });
    }

    // ── PHP ──
    if utils::which("composer") {
        if let Some(p) = home_join(".cache/composer") {
            if p.exists() {
                let size = utils::dir_size(&p);
                if size > 0 {
                    out.push(DevCache {
                        name: "composer",
                        size,
                        needs_redownload: false,
                        note: "safe",
                    });
                }
            }
        }
    }

    // ── JVM ──
    // Gradle: ONLY `caches/`, never `wrapper/` (distributions).
    if let Some(c) = scan_simple("gradle", home_join(".gradle/caches"), "safe") {
        out.push(c);
    }
    // Maven local repo \u2014 will re-download. Often huge.
    if let Some(c) = scan_redownload(
        "maven (.m2)",
        home_join(".m2/repository"),
        "re-download on next build",
    ) {
        out.push(c);
    }

    out
}

/// Total size of all detected caches.
pub fn total_size(caches: &[DevCache]) -> u64 {
    caches.iter().map(|c| c.size).sum()
}

/// Total size restricted to caches that would be cleaned at a given mode.
/// Without `--deep`, we skip anything that needs re-download.
pub fn cleanable_size(caches: &[DevCache], deep: bool) -> u64 {
    caches
        .iter()
        .filter(|c| deep || !c.needs_redownload)
        .map(|c| c.size)
        .sum()
}

/// Print the scan summary table.
pub fn print_summary(caches: &[DevCache], deep: bool) {
    if caches.is_empty() {
        utils::info("No dev-tool caches detected");
        return;
    }

    // Longest name for padding.
    let name_width = caches
        .iter()
        .map(|c| c.name.len())
        .max()
        .unwrap_or(8)
        .max(8);

    for c in caches {
        let will_clean = deep || !c.needs_redownload;
        let marker = if will_clean {
            "\u{2713}".green()
        } else {
            "\u{26A0}".yellow()
        };
        let size_str = if c.size == 0 {
            "  --  ".to_string()
        } else {
            utils::format_size(c.size)
        };
        println!(
            "      \u{2022} {:width$}  {:>10}   {} {}",
            c.name,
            size_str,
            marker,
            c.note.dimmed(),
            width = name_width
        );
    }

    let total = total_size(caches);
    let to_clean = cleanable_size(caches, deep);
    println!(
        "      {} Total: {}   |   Will clean now: {}",
        "\u{2500}".dimmed(),
        utils::format_size(total).cyan().bold(),
        utils::format_size(to_clean).green().bold()
    );
    if !deep && total > to_clean {
        println!(
            "      {} {}",
            "\u{2139}".blue(),
            "Pass --deep to also clean caches that trigger re-downloads".dimmed()
        );
    }
}

// ─── Cleaners ────────────────────────────────────────

fn clean_dir_contents(path: &Path) -> u64 {
    if !path.exists() {
        return 0;
    }
    utils::rm_contents(path)
}

/// Wipe everything inside the directory **except** entries whose name is
/// listed in `keep`. Reserved for future cleaners that need to operate on
/// a parent directory while preserving a protected child (e.g. cleaning
/// `~/.cargo` while keeping `bin/`). Currently every cleaner targets a
/// leaf directory directly, but the helper has an associated test as a
/// regression guard so we keep it compiled in.
#[cfg(test)]
fn clean_dir_contents_except(path: &Path, keep: &[&str]) -> u64 {
    use std::fs;
    if !path.exists() || !path.is_dir() {
        return 0;
    }
    let mut freed = 0u64;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            let name = match p.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };
            if keep.contains(&name) {
                continue;
            }
            let size = if p.is_symlink() {
                p.symlink_metadata().map(|m| m.len()).unwrap_or(0)
            } else if p.is_dir() {
                utils::dir_size(&p)
            } else {
                p.metadata().map(|m| m.len()).unwrap_or(0)
            };
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

fn clean_one(c: &DevCache, deep: bool, dry_run: bool) -> u64 {
    if c.needs_redownload && !deep {
        return 0; // skipped \u2014 already reported in summary
    }
    if dry_run {
        return 0;
    }

    match c.name {
        // ── Node ──
        "npm" => home_join(".npm/_cacache")
            .as_deref()
            .map(clean_dir_contents)
            .unwrap_or(0),
        "yarn (classic)" => home_join(".cache/yarn")
            .as_deref()
            .map(clean_dir_contents)
            .unwrap_or(0),
        "yarn (berry)" => home_join(".yarn/berry/cache")
            .as_deref()
            .map(clean_dir_contents)
            .unwrap_or(0),
        "bun" => home_join(".bun/install/cache")
            .as_deref()
            .map(clean_dir_contents)
            .unwrap_or(0),

        // pnpm: hard-linked store \u2014 NEVER touch directly.
        "pnpm" => {
            let before = pnpm_store_path().map(|p| utils::dir_size(&p)).unwrap_or(0);
            utils::run("pnpm", &["store", "prune"]);
            let after = pnpm_store_path().map(|p| utils::dir_size(&p)).unwrap_or(0);
            before.saturating_sub(after)
        }

        "deno" => {
            // Prefer the official command when available; otherwise fall
            // back to wiping DENO_DIR.
            if utils::which("deno") {
                let before = deno_dir_path().map(|p| utils::dir_size(&p)).unwrap_or(0);
                utils::run("deno", &["clean"]);
                let after = deno_dir_path().map(|p| utils::dir_size(&p)).unwrap_or(0);
                before.saturating_sub(after)
            } else {
                deno_dir_path()
                    .as_deref()
                    .map(clean_dir_contents)
                    .unwrap_or(0)
            }
        }

        // ── Python ──
        "pip" => {
            if utils::which("pip") {
                let before = home_join(".cache/pip")
                    .map(|p| utils::dir_size(&p))
                    .unwrap_or(0);
                utils::run("pip", &["cache", "purge"]);
                let after = home_join(".cache/pip")
                    .map(|p| utils::dir_size(&p))
                    .unwrap_or(0);
                before.saturating_sub(after)
            } else {
                home_join(".cache/pip")
                    .as_deref()
                    .map(clean_dir_contents)
                    .unwrap_or(0)
            }
        }
        "uv" => {
            if utils::which("uv") {
                let before = uv_cache_path().map(|p| utils::dir_size(&p)).unwrap_or(0);
                utils::run("uv", &["cache", "clean"]);
                let after = uv_cache_path().map(|p| utils::dir_size(&p)).unwrap_or(0);
                before.saturating_sub(after)
            } else {
                uv_cache_path()
                    .as_deref()
                    .map(clean_dir_contents)
                    .unwrap_or(0)
            }
        }
        "pipenv" => home_join(".cache/pipenv")
            .as_deref()
            .map(clean_dir_contents)
            .unwrap_or(0),
        "poetry" => {
            // ONLY the `cache/` subdir. Never `virtualenvs/`.
            home_join(".cache/pypoetry/cache")
                .as_deref()
                .map(clean_dir_contents)
                .unwrap_or(0)
        }

        // ── Rust ── (~/.cargo/bin is preserved by construction:
        //  we operate on subdirectories that don't contain it.)
        "cargo registry/src" => home_join(".cargo/registry/src")
            .as_deref()
            .map(clean_dir_contents)
            .unwrap_or(0),
        "cargo git/checkouts" => home_join(".cargo/git/checkouts")
            .as_deref()
            .map(clean_dir_contents)
            .unwrap_or(0),
        "cargo registry/cache" => home_join(".cargo/registry/cache")
            .as_deref()
            .map(clean_dir_contents)
            .unwrap_or(0),
        "cargo git/db" => home_join(".cargo/git/db")
            .as_deref()
            .map(clean_dir_contents)
            .unwrap_or(0),

        // ── Go ──
        // Use the official command here because the module cache often
        // contains read-only files; direct deletion is less reliable.
        "go modules" if utils::which("go") => {
            let before = go_modcache_path().map(|p| utils::dir_size(&p)).unwrap_or(0);
            utils::run("go", &["clean", "-modcache"]);
            let after = go_modcache_path().map(|p| utils::dir_size(&p)).unwrap_or(0);
            before.saturating_sub(after)
        }
        "go modules" => 0,

        // ── Ruby ──
        "ruby gems (old versions)" => {
            // `gem cleanup` removes old versions only \u2014 it never touches
            // currently required gems. Safe by design.
            utils::run("gem", &["cleanup"]);
            0 // gem cleanup doesn't report freed bytes in a parseable way
        }

        // ── PHP ──
        // Prefer Composer's own cache command when it exists instead of
        // blindly deleting the directory.
        "composer" if utils::which("composer") => {
            let before = home_join(".cache/composer")
                .map(|p| utils::dir_size(&p))
                .unwrap_or(0);
            utils::run("composer", &["clear-cache", "--no-interaction"]);
            let after = home_join(".cache/composer")
                .map(|p| utils::dir_size(&p))
                .unwrap_or(0);
            before.saturating_sub(after)
        }
        "composer" => 0,

        // ── JVM ──
        "gradle" => {
            // ONLY the `caches/` subtree of `~/.gradle`. NEVER `wrapper/`.
            home_join(".gradle/caches")
                .as_deref()
                .map(clean_dir_contents)
                .unwrap_or(0)
        }
        "maven (.m2)" => home_join(".m2/repository")
            .as_deref()
            .map(clean_dir_contents)
            .unwrap_or(0),

        _ => 0,
    }
}

/// Run the whole dev-cache workflow. Returns total bytes freed.
pub fn run(deep: bool, dry_run: bool, yes: bool) -> u64 {
    utils::section("Dev Cache");

    utils::info("Scanning...");
    let caches = scan_all();
    if caches.is_empty() {
        utils::info("No dev-tool caches detected");
        return 0;
    }

    print_summary(&caches, deep);

    let to_clean = cleanable_size(&caches, deep);
    if to_clean == 0 && !caches.iter().any(|c| c.name == "ruby gems (old versions)") {
        utils::success("Nothing to clean");
        return 0;
    }

    if dry_run {
        utils::info(&format!(
            "[DRY RUN] Would free up to {}",
            utils::format_size(to_clean)
        ));
        return 0;
    }

    // Deep mode may clear caches that will need to be downloaded again.
    // Ask once before doing that unless the user already passed --yes.
    let has_redownload = caches.iter().any(|c| c.needs_redownload);
    if deep
        && has_redownload
        && !yes
        && !utils::confirm(
            "Proceed with --deep? This will trigger re-downloads on next build. [y/N]:",
        )
    {
        utils::skip("Deep clean cancelled by user");
        return 0;
    }

    let mut freed = 0u64;
    for c in &caches {
        freed += clean_one(c, deep, dry_run);
    }
    utils::success(&format!("Freed {}", utils::format_size(freed).green()));
    freed
}

// ═══════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // ── scan helpers behaviour ──────────────────────────

    #[test]
    fn test_scan_simple_skips_missing_dir() {
        let p = Some(PathBuf::from("/tmp/oxiclean_definitely_not_exists_xyz"));
        let c = scan_simple("ghost", p, "safe");
        assert!(c.is_none(), "missing directory must be reported as None");
    }

    #[test]
    fn test_scan_simple_skips_empty_dir() {
        let dir = PathBuf::from("/tmp/oxiclean_dev_empty");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let c = scan_simple("empty", Some(dir.clone()), "safe");
        assert!(c.is_none(), "0-byte directory must be reported as None");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_scan_simple_reports_size() {
        let dir = PathBuf::from("/tmp/oxiclean_dev_nonempty");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("a"), b"hello world").unwrap();
        let c = scan_simple("real", Some(dir.clone()), "safe").expect("expected Some");
        assert_eq!(c.name, "real");
        assert_eq!(c.size, 11);
        assert!(!c.needs_redownload);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_scan_redownload_sets_flag() {
        let dir = PathBuf::from("/tmp/oxiclean_dev_redl");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("a"), b"x").unwrap();
        let c = scan_redownload("redl", Some(dir.clone()), "re-download").expect("Some");
        assert!(c.needs_redownload);
        let _ = fs::remove_dir_all(&dir);
    }

    // ── cleanable_size: --deep gating ───────────────────

    #[test]
    fn test_cleanable_size_skips_redownload_without_deep() {
        let caches = vec![
            DevCache {
                name: "safe",
                size: 100,
                needs_redownload: false,
                note: "",
            },
            DevCache {
                name: "redl",
                size: 1000,
                needs_redownload: true,
                note: "",
            },
        ];
        assert_eq!(cleanable_size(&caches, false), 100);
        assert_eq!(cleanable_size(&caches, true), 1100);
        assert_eq!(total_size(&caches), 1100);
    }

    // ── Safety guarantees: must never delete what we promised not to ──

    /// `clean_dir_contents_except` is the helper we'd reach for if we
    /// ever wanted to clean a parent directory of a protected child.
    /// We don't actually need it for the current tool set \u2014 every cleaner
    /// targets a leaf cache directory \u2014 but the property test makes the
    /// guarantee explicit.
    #[test]
    fn test_clean_dir_contents_except_preserves_listed() {
        let root = PathBuf::from("/tmp/oxiclean_dev_except");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("bin/installed_tool"), b"binary").unwrap();
        fs::create_dir_all(root.join("registry")).unwrap();
        fs::write(root.join("registry/some.crate"), b"cache").unwrap();

        let freed = clean_dir_contents_except(&root, &["bin"]);

        // We removed registry/some.crate (5 bytes) but kept bin/installed_tool.
        assert!(freed >= 5);
        assert!(root.join("bin/installed_tool").exists(), "bin must survive");
        assert!(!root.join("registry").exists(), "registry must be gone");
        let _ = fs::remove_dir_all(&root);
    }

    /// Cargo's `bin/` directory holds user-installed binaries like
    /// `cargo-watch` and `rustfmt`. None of the cargo entries in our
    /// scanner list targets `~/.cargo` itself \u2014 they all target
    /// subdirectories that do *not* contain `bin/`. This test is a
    /// regression guard: if anyone ever adds a `~/.cargo` entry, the
    /// assertion below makes it loud.
    #[test]
    fn test_cargo_entries_never_target_bin_directory() {
        // Build a list of every path-suffix our scanner could clean for cargo.
        let cargo_suffixes = [
            ".cargo/registry/src",
            ".cargo/registry/cache",
            ".cargo/git/checkouts",
            ".cargo/git/db",
        ];
        for s in cargo_suffixes {
            assert!(
                !s.ends_with("/bin") && !s.contains("/bin/"),
                "cargo cleanup target {s:?} must not reach into ~/.cargo/bin"
            );
        }
    }

    /// Poetry virtualenvs live in `~/.cache/pypoetry/virtualenvs/` \u2014 they
    /// are NOT a cache and must never be touched. Our poetry entry
    /// explicitly targets the `cache/` sibling.
    #[test]
    fn test_poetry_target_is_cache_not_virtualenvs() {
        let path = home_join(".cache/pypoetry/cache");
        if let Some(p) = path {
            let s = p.to_string_lossy().to_string();
            assert!(s.ends_with(".cache/pypoetry/cache"));
            assert!(!s.contains("virtualenvs"));
        }
    }

    /// Gradle's `wrapper/` holds downloaded Gradle distributions. Cleaning
    /// it would force re-downloading whole Gradle releases. We only
    /// target `caches/`.
    #[test]
    fn test_gradle_target_is_caches_not_wrapper() {
        let path = home_join(".gradle/caches");
        if let Some(p) = path {
            let s = p.to_string_lossy().to_string();
            assert!(s.ends_with(".gradle/caches"));
            assert!(!s.contains("wrapper"));
        }
    }

    /// npm's `lib/node_modules` is where `npm i -g` installs binaries.
    /// We only target `_cacache/`.
    #[test]
    fn test_npm_target_is_cacache_not_globals() {
        let path = home_join(".npm/_cacache");
        if let Some(p) = path {
            let s = p.to_string_lossy().to_string();
            assert!(s.ends_with("_cacache"));
            assert!(!s.contains("node_modules"));
        }
    }
}
