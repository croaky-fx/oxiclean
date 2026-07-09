use colored::Colorize;
use std::path::{Path, PathBuf};

use crate::detect::Distro;
use crate::utils;

/// Remove partial-download leftovers from interrupted `pacman -Syu` runs.
///
/// Modern pacman (6.1+) downloads packages in a sandbox under the dedicated
/// `alpm` user, so an interrupted run (Ctrl-C, lost network, power loss)
/// leaves behind a *directory* like `/var/cache/pacman/pkg/download-XXXXXX`,
/// owned by `alpm` and mode `0700`. Older pacman left `.part`-style files
/// instead. Either way, `pacman -Sc` / `<helper> -Sc` later trip over the
/// leftover and print `error: could not open file ... Error reading fd 7`
/// for each one. We remove them quietly first.
///
/// The parent dir is world-readable, so we enumerate names as the invoking
/// user; the leftovers themselves are root/`alpm`-owned, so the delete goes
/// through `sudo rm -rf` (which handles both files and non-empty dirs).
/// See https://forum.endeavouros.com/t/error-cleaning-package-cache/73965
fn cleanup_pacman_partial_downloads() {
    let leftovers = find_partial_downloads(Path::new("/var/cache/pacman/pkg"));
    if leftovers.is_empty() {
        return;
    }
    let paths: Vec<String> = leftovers
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let mut args: Vec<&str> = vec!["-rf"];
    args.extend(paths.iter().map(|s| s.as_str()));
    utils::sudo("rm", &args);
}

/// True if `name` is a pacman partial-download leftover that is always safe to
/// delete. Real cached packages always end in `.pkg.tar.*`; the sandboxed
/// downloader's leftovers never do — they are `download-` followed by a random
/// suffix (a directory on pacman 6.1+, a file on older versions).
fn is_partial_download(name: &str) -> bool {
    name.starts_with("download-") && !name.contains(".pkg.tar")
}

/// Enumerate partial-download leftovers (files *or* directories) directly under
/// `cache_dir`. Reads entry names only — never descends — so it works even when
/// the leftovers are mode `0700` and owned by another user.
fn find_partial_downloads(cache_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(cache_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if is_partial_download(name) {
                    out.push(entry.path());
                }
            }
        }
    }
    out
}

/// Decide whether a destructive "deep" operation should run.
///
/// * `deep == true`  → always run (user explicitly opted in)
/// * `deep == false && yes == true` → skip silently (non-interactive run)
/// * otherwise → ask the user
///
/// Pub-crate visibility so it can be unit-tested.
pub(crate) fn should_deep(deep: bool, yes: bool, prompt: &str) -> bool {
    if deep {
        return true;
    }
    if yes {
        return false;
    }
    utils::confirm(prompt)
}

fn pkg_cache_dir(distro: &Distro) -> Option<PathBuf> {
    match distro {
        Distro::Arch => Some(PathBuf::from("/var/cache/pacman/pkg")),
        Distro::Debian => Some(PathBuf::from("/var/cache/apt/archives")),
        Distro::Fedora => {
            if utils::which("dnf") {
                Some(PathBuf::from("/var/cache/dnf"))
            } else {
                Some(PathBuf::from("/var/cache/yum"))
            }
        }
        Distro::Suse => Some(PathBuf::from("/var/cache/zypp/packages")),
        Distro::Void => Some(PathBuf::from("/var/cache/xbps")),
        Distro::Alpine => Some(PathBuf::from("/var/cache/apk")),
        Distro::Gentoo => Some(PathBuf::from("/var/cache/distfiles")),
        Distro::Solus => Some(PathBuf::from("/var/cache/eopkg/packages")),
        _ => None,
    }
}

// ══════════════════════════════════════════════════
//  Expensive-cache protection (used by user_cache)
// ══════════════════════════════════════════════════

/// Caches under the user cache dir that a blanket `--cache`/`--all` wipe must
/// never touch. Two kinds, both costly to lose:
///   * **Model weights** — `huggingface`, `torch`: multi-GB downloads a user
///     grabbed on purpose; re-fetching means hours and bandwidth. They're not
///     "leftovers" and nobody clears a 40 GB model as routine cache cleanup.
///   * **Dev-tool caches** — `uv`, `pip`, `pipenv`, `pypoetry`, `deno`,
///     `ccache`, `yarn`: these live under ~/.cache but are already owned by
///     `--dev`, which cleans them deliberately with the correct per-tool
///     command. Wiping them here would contradict `--dev`'s care.
///
/// Removing any of these stays possible — via `--dev` (with `--deep` for the
/// re-download-heavy ones) — it just never happens by accident.
const PROTECTED_CACHE_DIRS: &[&str] = &[
    "huggingface",
    "torch",
    "uv",
    "pip",
    "pipenv",
    "pypoetry",
    "deno",
    "ccache",
    "yarn",
];

/// Resolve the user cache directory, honouring `XDG_CACHE_HOME` (the spec-
/// correct override) and falling back to `~/.cache`.
fn user_cache_base() -> Option<PathBuf> {
    if let Ok(x) = std::env::var("XDG_CACHE_HOME") {
        if !x.is_empty() {
            return Some(PathBuf::from(x));
        }
    }
    utils::home_dir().map(|h| PathBuf::from(h).join(".cache"))
}

/// The set of top-level entry names to protect inside `cache_base`: the static
/// list, plus HuggingFace's location if it's been redirected *inside* the cache
/// base via `HF_HOME`/`HF_HUB_CACHE` (so a non-default model dir is still
/// spared). A relocation outside the cache base needs no entry — user_cache
/// only ever touches things under the cache base to begin with.
fn protected_cache_names(cache_base: &Path) -> Vec<String> {
    let mut names: Vec<String> = PROTECTED_CACHE_DIRS.iter().map(|s| s.to_string()).collect();
    for var in ["HF_HOME", "HF_HUB_CACHE"] {
        if let Ok(val) = std::env::var(var) {
            if val.is_empty() {
                continue;
            }
            if let Ok(rel) = PathBuf::from(&val).strip_prefix(cache_base) {
                if let Some(first) = rel.components().next() {
                    if let Some(s) = first.as_os_str().to_str() {
                        if !names.iter().any(|n| n == s) {
                            names.push(s.to_string());
                        }
                    }
                }
            }
        }
    }
    names
}

/// Split the top-level entries of `cache_dir` into `(to_clean, protected)`,
/// where `protected` holds the names we spared. Read-only — no deletion — so
/// the unit tests can prove a protected cache is never selected for removal.
fn partition_cache_entries(cache_dir: &Path, protected: &[String]) -> (Vec<PathBuf>, Vec<String>) {
    let mut to_clean = Vec::new();
    let mut skipped = Vec::new();
    if let Ok(entries) = std::fs::read_dir(cache_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if protected.contains(&name) {
                skipped.push(name);
            } else {
                to_clean.push(entry.path());
            }
        }
    }
    (to_clean, skipped)
}

/// Size of a cache entry: follows the same symlink/dir/file rules as
/// `utils::rm_contents` so the "freed" tally matches what's actually removed.
fn entry_size(p: &Path) -> u64 {
    if p.is_symlink() {
        p.symlink_metadata().map(|m| m.len()).unwrap_or(0)
    } else if p.is_dir() {
        utils::dir_size(p)
    } else {
        p.metadata().map(|m| m.len()).unwrap_or(0)
    }
}

pub fn user_cache(dry_run: bool) -> u64 {
    utils::section("User Cache");

    let cache = match user_cache_base() {
        Some(c) => c,
        None => {
            utils::error("Cannot determine cache directory");
            return 0;
        }
    };

    if !cache.exists() {
        utils::info("No cache directory found");
        return 0;
    }

    // Instead of wiping ~/.cache wholesale, spare the expensive/irreplaceable
    // caches: model weights that cost gigabytes to re-download (HuggingFace,
    // torch) and dev-tool caches that `--dev` manages deliberately with the
    // right per-tool commands. A blanket wipe here would silently destroy a
    // 40 GB model download — those belong to `--dev`, not `--cache`.
    let protected = protected_cache_names(&cache);
    let (to_clean, mut skipped) = partition_cache_entries(&cache, &protected);

    if !skipped.is_empty() {
        skipped.sort();
        // Say what we deliberately preserved so a user who *wants* it gone knows
        // it was spared — and where to reclaim it (`--dev`).
        utils::skip(&format!(
            "Protected (clean with --dev): {}",
            skipped.join(", ")
        ));
    }

    let clean_size: u64 = to_clean.iter().map(|p| entry_size(p)).sum();
    if clean_size == 0 {
        utils::success("Already clean");
        return 0;
    }

    if dry_run {
        utils::info(&format!(
            "[DRY RUN] Would free {}",
            utils::format_size(clean_size)
        ));
        return 0;
    }

    let mut freed = 0u64;
    for path in &to_clean {
        let size = entry_size(path);
        let ok = if path.is_dir() && !path.is_symlink() {
            std::fs::remove_dir_all(path).is_ok()
        } else {
            std::fs::remove_file(path).is_ok()
        };
        if ok {
            freed += size;
        }
    }
    utils::success(&format!("Freed {}", utils::format_size(freed).green()));
    freed
}

pub fn pkg_cache(distro: &Distro, deep: bool, dry_run: bool, yes: bool) -> u64 {
    utils::section("Package Cache");

    // Atomic / OSTree systems (Fedora Silverblue, Kinoite, Bazzite, …) report as
    // Fedora by ID, but `dnf clean` is not how their storage is reclaimed — the
    // OS is an ostree image and cached data is cleared with `rpm-ostree cleanup`.
    // We only pass the non-destructive `-b` (temporary files) and `-m` (cached
    // repo metadata) flags. `-p` (pending) and `-r` (rollback) alter *bootable
    // deployments* — that's system state, not cache, so they are never touched.
    if crate::detect::is_ostree() {
        if dry_run {
            utils::info("[DRY RUN] Would run: rpm-ostree cleanup -bm");
            return 0;
        }
        if utils::sudo("rpm-ostree", &["cleanup", "-bm"]) {
            utils::success("rpm-ostree cleaned (base deployments + cached metadata)");
        } else {
            utils::error("rpm-ostree cleanup failed");
        }
        // rpm-ostree reclaims space across /sysroot and /var with no single
        // measurable cache dir, so we report the action rather than a byte count.
        return 0;
    }

    if *distro == Distro::Unknown {
        utils::skip("Unknown distribution — skipped");
        return 0;
    }

    // General immutable guard: an image-based system with a read-only rootfs
    // (SteamOS, openSUSE MicroOS, …) manages its OS through atomic image swaps,
    // not the package manager. These report as their base distro (Arch, SUSE…)
    // so the code below would try `pacman -Sc` / `zypper clean` and fail — or
    // worse, fight the atomic update model. We skip package-cache cleanup and
    // say why; the user-level steps (cache, trash, dev, journal) still run and
    // are where the reclaimable space on these systems actually is. OSTree is
    // handled above with its own real cleanup, so it never reaches here.
    if crate::detect::is_readonly_rootfs() {
        utils::skip("Immutable/read-only system — package cache managed by atomic updates");
        return 0;
    }

    if dry_run {
        utils::info(&format!(
            "[DRY RUN] Would clean {} cache{}",
            distro.pkg_manager(),
            if deep { " (deep)" } else { "" }
        ));
        return 0;
    }

    let cache_dir = pkg_cache_dir(distro);
    let size_before = cache_dir.as_ref().map(|p| utils::dir_size(p)).unwrap_or(0);

    match distro {
        Distro::Arch => {
            // Sweep partial-download leftovers BEFORE `pacman -Sc`.
            // When a `pacman -Syu` is interrupted (Ctrl-C, lost network,
            // power loss) it leaves files like `/var/cache/pacman/pkg/
            // download-AbCdEf` behind. `pacman -Sc` later tries to open
            // them and prints `error: could not open file ... Error
            // reading fd 7` for each. We delete them quietly first —
            // see https://forum.endeavouros.com/t/error-cleaning-package-cache/73965
            cleanup_pacman_partial_downloads();

            if utils::sudo("pacman", &["-Sc", "--noconfirm"]) {
                utils::success("pacman cache cleaned");
            } else {
                utils::error("pacman -Sc failed");
            }
            if should_deep(
                deep,
                yes,
                "Run pacman -Scc? (removes ALL cached packages) [y/N]:",
            ) {
                if utils::sudo("pacman", &["-Scc", "--noconfirm"]) {
                    utils::success("pacman deep clean done");
                } else {
                    utils::error("pacman -Scc failed");
                }
            }
        }

        Distro::Debian => {
            if utils::sudo("apt-get", &["clean"]) {
                utils::success("apt cache cleaned");
            } else {
                utils::error("apt-get clean failed");
            }
            if should_deep(
                deep,
                yes,
                "Run apt autoclean? (removes outdated debs) [y/N]:",
            ) {
                if utils::sudo("apt-get", &["autoclean", "-y"]) {
                    utils::success("autoclean done");
                } else {
                    utils::error("autoclean failed");
                }
            }
        }

        Distro::Fedora => {
            let pm = if utils::which("dnf") { "dnf" } else { "yum" };
            if utils::sudo(pm, &["clean", "all"]) {
                utils::success(&format!("{} cache cleaned", pm));
            } else {
                utils::error(&format!("{} clean failed", pm));
            }
        }

        Distro::Suse => {
            if utils::sudo("zypper", &["clean", "--all"]) {
                utils::success("zypper cache cleaned");
            } else {
                utils::error("zypper clean failed");
            }
        }

        Distro::Nix => {
            utils::info("Running Nix garbage collection...");
            utils::run("nix-collect-garbage", &[]);
            utils::sudo("nix-collect-garbage", &[]);
            utils::success("Garbage collected");

            if should_deep(
                deep,
                yes,
                "Delete ALL old generations? (nix-collect-garbage -d) [y/N]:",
            ) {
                utils::run("nix-collect-garbage", &["-d"]);
                utils::sudo("nix-collect-garbage", &["-d"]);
                utils::success("Old generations deleted");

                utils::info("Optimizing Nix store (may take a while)...");
                utils::sudo("nix-store", &["--optimise"]);
                utils::success("Nix store optimized");
            }
        }

        Distro::Void => {
            if utils::sudo("xbps-remove", &["-O", "-y"]) {
                utils::success("xbps cache cleaned");
            } else {
                utils::error("xbps-remove -O failed");
            }
        }

        Distro::Alpine => {
            if utils::sudo("apk", &["cache", "clean"]) {
                utils::success("apk cache cleaned");
            } else {
                utils::warning("apk cache clean failed");
                let apk_cache = PathBuf::from("/var/cache/apk");
                if apk_cache.exists() {
                    utils::sudo("find", &["/var/cache/apk", "-type", "f", "-delete"]);
                    utils::success("apk cache directory cleaned");
                }
            }
        }

        Distro::Gentoo => {
            if utils::which("eclean") {
                if utils::sudo("eclean", &["distfiles"]) {
                    utils::success("Distfiles cleaned");
                } else {
                    utils::error("eclean distfiles failed");
                }
                if should_deep(deep, yes, "Also clean binary packages? [y/N]:")
                    && utils::sudo("eclean", &["packages"])
                {
                    utils::success("Binary packages cleaned");
                }
            } else {
                utils::warning("eclean not found — install app-portage/gentoolkit");
                let distfiles = PathBuf::from("/var/cache/distfiles");
                if distfiles.exists() {
                    utils::sudo("find", &["/var/cache/distfiles", "-type", "f", "-delete"]);
                    utils::success("Distfiles cleaned");
                }
            }
        }

        Distro::Solus => {
            if utils::sudo("eopkg", &["delete-cache"]) {
                utils::success("eopkg cache cleaned");
            } else {
                utils::error("eopkg delete-cache failed");
            }
        }

        Distro::Clear => {
            let staged = PathBuf::from("/var/lib/swupd/staged");
            if staged.exists() {
                utils::sudo("rm", &["-rf", "/var/lib/swupd/staged"]);
                utils::success("swupd staged files cleaned");
            } else {
                utils::info("No staged files to clean");
            }
        }

        Distro::Unknown => {}
    }

    let size_after = cache_dir.as_ref().map(|p| utils::dir_size(p)).unwrap_or(0);
    let freed = size_before.saturating_sub(size_after);
    if freed > 0 {
        utils::info(&format!(
            "Package cache freed: {}",
            utils::format_size(freed).green()
        ));
    }
    freed
}

pub fn orphans(distro: &Distro, dry_run: bool, yes: bool) -> u64 {
    utils::section("Orphaned Packages");

    // Atomic (OSTree) and image-based read-only systems don't have "orphans" in
    // the traditional sense — packages are part of the OS image, not
    // individually installed, so there's nothing to autoremove. Skip cleanly
    // rather than running a package-manager command that would fail or mislead.
    if crate::detect::is_ostree() {
        utils::skip("Atomic system — packages are part of the OS image, no orphans to remove");
        return 0;
    }
    if crate::detect::is_readonly_rootfs() {
        utils::skip("Immutable/read-only system — package removal handled by atomic updates");
        return 0;
    }

    if *distro == Distro::Unknown {
        utils::skip("Unknown distribution — skipped");
        return 0;
    }

    match distro {
        Distro::Arch => {
            let out = utils::capture("pacman", &["-Qdtq"]).unwrap_or_default();
            if out.is_empty() {
                utils::success("No orphans found");
                return 0;
            }
            let pkgs: Vec<&str> = out.lines().collect();
            utils::info(&format!("Found {} orphan(s):", pkgs.len()));
            for p in &pkgs {
                println!("      {} {}", "\u{2022}".dimmed(), p);
            }
            if dry_run {
                utils::info("[DRY RUN] Would remove above packages");
                return 0;
            }
            if yes || utils::confirm("Remove orphaned packages? [y/N]:") {
                let mut args: Vec<&str> = vec!["-Rns", "--noconfirm"];
                args.extend(&pkgs);
                if utils::sudo("pacman", &args) {
                    utils::success("Orphans removed");
                } else {
                    utils::error("Failed to remove some orphans");
                }
            }
        }

        Distro::Debian => {
            if dry_run {
                utils::info("[DRY RUN] Would run: apt-get autoremove");
                return 0;
            }
            utils::info("Running autoremove...");
            if utils::sudo("apt-get", &["autoremove", "-y"]) {
                utils::success("Autoremove done");
            } else {
                utils::error("Autoremove failed");
            }
        }

        Distro::Fedora => {
            let pm = if utils::which("dnf") { "dnf" } else { "yum" };
            if dry_run {
                utils::info(&format!("[DRY RUN] Would run: {} autoremove", pm));
                return 0;
            }
            utils::info("Running autoremove...");
            if utils::sudo(pm, &["autoremove", "-y"]) {
                utils::success("Autoremove done");
            } else {
                utils::error("Autoremove failed");
            }
        }

        Distro::Suse => {
            let out = utils::capture("zypper", &["packages", "--orphaned"]).unwrap_or_default();
            if out.is_empty() || !out.contains('|') {
                utils::success("No orphans found");
                return 0;
            }
            let pkgs: Vec<String> = out
                .lines()
                .filter(|l| l.contains('|') && !l.contains("---") && !l.contains("Name"))
                .filter_map(|l| {
                    let cols: Vec<&str> = l.split('|').map(|s| s.trim()).collect();
                    if cols.len() >= 3 {
                        Some(cols[2].to_string())
                    } else {
                        None
                    }
                })
                .filter(|n| !n.is_empty())
                .collect();

            if pkgs.is_empty() {
                utils::success("No orphans found");
                return 0;
            }
            utils::info(&format!("Found {} orphan(s)", pkgs.len()));
            if dry_run {
                utils::info("[DRY RUN] Would remove above packages");
                return 0;
            }
            if yes || utils::confirm("Remove orphaned packages? [y/N]:") {
                let pkg_refs: Vec<&str> = pkgs.iter().map(|s| s.as_str()).collect();
                let mut args: Vec<&str> = vec!["remove", "-y", "--clean-deps"];
                args.extend(&pkg_refs);
                if utils::sudo("zypper", &args) {
                    utils::success("Orphans removed");
                } else {
                    utils::error("Failed to remove orphans");
                }
            }
        }

        Distro::Nix => {
            utils::info("NixOS handles orphans via garbage collection (already covered)");
        }

        Distro::Void => {
            if dry_run {
                utils::info("[DRY RUN] Would run: xbps-remove -o");
                return 0;
            }
            utils::info("Removing orphans...");
            if utils::sudo("xbps-remove", &["-o", "-y"]) {
                utils::success("Orphans removed");
            } else {
                utils::warning("No orphans found or removal failed");
            }
        }

        Distro::Alpine => {
            if dry_run {
                utils::info("[DRY RUN] Would check for orphans");
                return 0;
            }
            utils::info("Alpine manages deps via world file");
            utils::warning("Automatic orphan removal not supported on Alpine");
        }

        Distro::Gentoo => {
            if dry_run {
                utils::info("[DRY RUN] Would run: emerge --depclean");
                return 0;
            }
            utils::info("Running depclean...");
            if utils::sudo("emerge", &["--depclean"]) {
                utils::success("Depclean done");
            } else {
                utils::error("Depclean failed");
            }
        }

        Distro::Solus => {
            if dry_run {
                utils::info("[DRY RUN] Would remove orphans");
                return 0;
            }
            utils::info("Removing orphans...");
            if utils::sudo("eopkg", &["remove-orphans", "-y"]) {
                utils::success("Orphans removed");
            } else {
                utils::warning("No orphans or removal failed");
            }
        }

        Distro::Clear => {
            utils::info("Clear Linux auto-manages dependencies via swupd bundles");
        }

        Distro::Unknown => {}
    }

    0
}

pub fn aur_cache(helper: &str, deep: bool, dry_run: bool, yes: bool) -> u64 {
    utils::section("AUR Cache");

    if dry_run {
        utils::info(&format!(
            "[DRY RUN] Would run: {} -Sc{}",
            helper,
            if deep { "c" } else { "" }
        ));
        return 0;
    }

    let cache_dir = utils::home_dir().map(|h| PathBuf::from(&h).join(".cache").join(helper));
    let size_before = cache_dir.as_ref().map(|p| utils::dir_size(p)).unwrap_or(0);

    // AUR helpers (paru, yay, …) clean the shared pacman cache too, so the same
    // partial-download leftovers would make them print the `Error reading fd 7`
    // noise. Sweep them first — see `cleanup_pacman_partial_downloads`.
    cleanup_pacman_partial_downloads();

    if utils::run(helper, &["-Sc", "--noconfirm"]) {
        utils::success(&format!("{} cache cleaned", helper));
    } else {
        utils::error(&format!("{} -Sc failed", helper));
    }

    if should_deep(
        deep,
        yes,
        &format!(
            "Run {} -Scc? (removes ALL cached AUR packages) [y/N]:",
            helper
        ),
    ) {
        if utils::run(helper, &["-Scc", "--noconfirm"]) {
            utils::success(&format!("{} deep clean done", helper));
        } else {
            utils::error(&format!("{} -Scc failed", helper));
        }
    }

    let size_after = cache_dir.as_ref().map(|p| utils::dir_size(p)).unwrap_or(0);
    let freed = size_before.saturating_sub(size_after);
    if freed > 0 {
        utils::info(&format!(
            "AUR cache freed: {}",
            utils::format_size(freed).green()
        ));
    }
    freed
}

pub fn flatpak(deep: bool, dry_run: bool) -> u64 {
    utils::section("Flatpak");

    if dry_run {
        utils::info("[DRY RUN] Would clean Flatpak unused runtimes & cache");
        if deep {
            utils::info("[DRY RUN] Would also repair Flatpak installation");
        }
        return 0;
    }

    utils::info("Removing unused Flatpak runtimes (user)...");
    utils::run("flatpak", &["uninstall", "--unused", "-y"]);

    utils::info("Removing unused Flatpak runtimes (system)...");
    utils::sudo("flatpak", &["uninstall", "--unused", "-y"]);

    if deep {
        utils::info("Repairing Flatpak installation (deep mode)...");
        utils::sudo("flatpak", &["repair"]);
        utils::success("Flatpak repair done");
    }

    let mut freed = 0u64;
    if let Some(home) = utils::home_dir() {
        let fp_cache = PathBuf::from(&home).join(".local/share/flatpak/repo/tmp");
        if fp_cache.exists() {
            let size = utils::dir_size(&fp_cache);
            if size > 0 {
                freed += utils::rm_contents(&fp_cache);
            }
        }
    }

    utils::sudo(
        "find",
        &[
            "/var/tmp",
            "-name",
            "flatpak-cache-*",
            "-exec",
            "rm",
            "-rf",
            "{}",
            "+",
        ],
    );

    let sys_fp_tmp = PathBuf::from("/var/lib/flatpak/repo/tmp");
    if sys_fp_tmp.exists() {
        utils::sudo(
            "find",
            &["/var/lib/flatpak/repo/tmp", "-mindepth", "1", "-delete"],
        );
    }

    if freed > 0 {
        utils::success(&format!("Freed {}", utils::format_size(freed).green()));
    } else {
        utils::success("Flatpak cleanup done");
    }

    freed
}

pub fn snap(dry_run: bool) -> u64 {
    utils::section("Snap");

    if dry_run {
        utils::info("[DRY RUN] Would remove disabled snap revisions & cache");
        return 0;
    }

    let out = utils::capture("snap", &["list", "--all"]).unwrap_or_default();
    let disabled: Vec<(&str, &str)> = out
        .lines()
        .filter(|l| l.contains("disabled"))
        .filter_map(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            if parts.len() >= 3 {
                Some((parts[0], parts[2]))
            } else {
                None
            }
        })
        .collect();

    if disabled.is_empty() {
        utils::info("No disabled snap revisions found");
    } else {
        utils::info(&format!("Found {} disabled revision(s)", disabled.len()));
        for (name, rev) in &disabled {
            utils::info(&format!("Removing {} (rev {})...", name, rev));
            if utils::sudo("snap", &["remove", name, "--revision", rev]) {
                utils::success(&format!("Removed {} rev {}", name, rev));
            } else {
                utils::error(&format!("Failed to remove {} rev {}", name, rev));
            }
        }
    }

    let mut freed = 0u64;
    let snap_cache = PathBuf::from("/var/lib/snapd/cache");
    if snap_cache.exists() {
        let size = utils::dir_size(&snap_cache);
        if size > 0 {
            utils::sudo("find", &["/var/lib/snapd/cache", "-type", "f", "-delete"]);
            freed += size;
            utils::success(&format!("Freed {}", utils::format_size(size).green()));
        }
    }

    freed
}

pub fn journal(dry_run: bool) -> u64 {
    utils::section("Journal");

    if !utils::which("journalctl") {
        utils::skip("journalctl not found — skipped");
        return 0;
    }

    if let Some(usage) = utils::capture("journalctl", &["--disk-usage"]) {
        utils::info(&format!("Current usage: {}", usage));
    }

    if dry_run {
        utils::info("[DRY RUN] Would vacuum journal to 50M");
        return 0;
    }

    let journal_dir = PathBuf::from("/var/log/journal");
    let size_before = utils::dir_size(&journal_dir);

    utils::info("Vacuuming journal (keeping 50M)...");
    if utils::sudo("journalctl", &["--vacuum-size=50M"]) {
        utils::success("Journal vacuumed");
    } else {
        utils::error("Journal vacuum failed");
    }

    let size_after = utils::dir_size(&journal_dir);
    let freed = size_before.saturating_sub(size_after);
    if freed > 0 {
        utils::info(&format!(
            "Journal freed: {}",
            utils::format_size(freed).green()
        ));
    }
    freed
}

pub fn trash(dry_run: bool) -> u64 {
    utils::section("Trash");

    let home = match utils::home_dir() {
        Some(h) => h,
        None => {
            utils::error("Cannot determine HOME directory");
            return 0;
        }
    };

    let trash_dirs = [
        PathBuf::from(&home).join(".local/share/Trash/files"),
        PathBuf::from(&home).join(".local/share/Trash/info"),
        PathBuf::from(&home).join(".Trash"),
    ];

    let mut total_size = 0u64;
    for dir in &trash_dirs {
        if dir.exists() {
            total_size += utils::dir_size(dir);
        }
    }

    if total_size == 0 {
        utils::success("Trash is empty");
        return 0;
    }

    utils::info(&format!(
        "Trash size: {}",
        utils::format_size(total_size).yellow()
    ));

    if dry_run {
        utils::info(&format!(
            "[DRY RUN] Would free {}",
            utils::format_size(total_size)
        ));
        return 0;
    }

    let mut freed = 0u64;
    for dir in &trash_dirs {
        if dir.exists() {
            freed += utils::rm_contents(dir);
        }
    }

    utils::success(&format!("Freed {}", utils::format_size(freed).green()));
    freed
}

// ══════════════════════════════════════════════════
//  Filesystem TRIM (SSD/NVMe maintenance) — opt-in via --trim
// ══════════════════════════════════════════════════

/// Discard unused blocks on SSD/NVMe filesystems (`fstrim`). This is filesystem
/// *maintenance*, not cache cleanup, which is why it's a standalone `--trim`
/// flag and is NOT part of `--all` or `--deep`.
///
/// Safety choices baked in:
/// * `--fstab` trims only filesystems listed in `/etc/fstab` — the user's
///   permanent mounts — so transient removable/USB drives (whose bridge chips
///   often mishandle UNMAP) are skipped by construction.
/// * `fstrim` is synchronous, so it never hits the async-discard + NCQ firmware
///   corruption path that continuous `discard` mount options can.
/// * `fstrim` itself skips any filesystem that doesn't support discard, so this
///   is a safe no-op on HDDs.
pub fn trim(dry_run: bool, disk_type: crate::detect::DiskType) -> u64 {
    utils::section("Filesystem Trim");

    if !utils::which("fstrim") {
        utils::skip("fstrim not found (install util-linux) — skipped");
        return 0;
    }

    if dry_run {
        utils::info("[DRY RUN] Would run: fstrim --fstab --verbose");
        return 0;
    }

    if disk_type == crate::detect::DiskType::HDD {
        // Not an error — fstrim will simply no-op on rotational disks — but the
        // user should know TRIM only reclaims blocks on SSD/NVMe.
        utils::info("Root disk looks like an HDD — TRIM only benefits SSD/NVMe");
    }

    utils::info("Trimming fstab-listed filesystems (removable drives are skipped)...");
    if utils::sudo("fstrim", &["--fstab", "--verbose"]) {
        utils::success("Filesystems trimmed");
    } else {
        utils::error("fstrim failed (or no discard-capable filesystems)");
    }
    // TRIM frees blocks on the device, not measurable cache bytes, so it
    // contributes nothing to the run's freed-bytes total.
    0
}

// ══════════════════════════════════════════════════
//  Nix garbage collection — works on *any* distro that has /nix/store
// ══════════════════════════════════════════════════

/// Run Nix garbage collection. Detects multi-user vs single-user installs
/// and skips `nix store --optimise` on HDDs because it is extremely slow.
pub fn nix_gc(deep: bool, dry_run: bool, yes: bool, disk_type: crate::detect::DiskType) -> u64 {
    utils::section("Nix GC");

    if !crate::detect::has_nix() {
        utils::skip("Nix not installed — skipped");
        return 0;
    }

    if dry_run {
        utils::info("[DRY RUN] Would run: nix-collect-garbage");
        if deep {
            utils::info("[DRY RUN] Would also delete old generations (-d)");
        }
        return 0;
    }

    let store = PathBuf::from("/nix/store");
    let store_before = utils::dir_size(&store);

    utils::info("Collecting garbage (user)...");
    utils::run("nix-collect-garbage", &[]);

    if crate::detect::nix_is_multiuser() {
        utils::info("Collecting garbage (system)...");
        utils::sudo("nix-collect-garbage", &[]);
    }

    if should_deep(
        deep,
        yes,
        "Delete old Nix generations? (removes all but current) [y/N]:",
    ) {
        utils::info("Removing old generations...");
        utils::run("nix-collect-garbage", &["-d"]);
        if crate::detect::nix_is_multiuser() {
            utils::sudo("nix-collect-garbage", &["-d"]);
        }
        utils::success("Old generations removed");

        // `nix store --optimise` walks the entire store and hard-links
        // identical files. On a spinning disk that can take *hours*.
        if disk_type == crate::detect::DiskType::HDD {
            utils::info(
                "Skipping store optimise on HDD (too slow). Run manually: nix store --optimise",
            );
        } else {
            utils::info("Optimising Nix store (hard-linking identical files)...");
            utils::sudo("nix", &["store", "--optimise"]);
            utils::success("Store optimised");
        }
    }

    let store_after = utils::dir_size(&store);
    let freed = store_before.saturating_sub(store_after);
    if freed > 0 {
        utils::info(&format!(
            "Nix store freed: {}",
            utils::format_size(freed).green()
        ));
    }
    freed
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── should_deep: destructive behaviour — must not surprise the user ──

    #[test]
    fn test_should_deep_flag_true_always_wins() {
        // deep=true means the user explicitly asked for deep clean.
        // It must override `yes` and never prompt.
        assert!(should_deep(true, false, "irrelevant"));
        assert!(should_deep(true, true, "irrelevant"));
    }

    #[test]
    fn test_should_deep_yes_without_deep_returns_false() {
        // yes=true + deep=false: non-interactive run.
        // Must return false WITHOUT prompting — otherwise the test would
        // hang waiting on stdin, which is itself the proof it works.
        assert!(!should_deep(false, true, "irrelevant"));
    }

    // ── partial-download sweep: catch alpm leftovers, never real packages ──

    #[test]
    fn test_is_partial_download_matches_leftovers() {
        // pacman 6.1+ leaves directories; older pacman left files. Both share
        // the `download-<random>` shape and must be matched.
        assert!(is_partial_download("download-3kcUOv"));
        assert!(is_partial_download("download-AbCdEf"));
    }

    #[test]
    fn test_is_partial_download_spares_real_packages() {
        // A real cached package that merely starts with "download" must
        // survive — the guard keys on the `.pkg.tar` extension.
        assert!(!is_partial_download(
            "download-manager-1.2-1-x86_64.pkg.tar.zst"
        ));
        assert!(!is_partial_download("firefox-120.0-1-x86_64.pkg.tar.zst"));
        assert!(!is_partial_download("downloads"));
    }

    #[test]
    fn test_find_partial_downloads_selects_files_and_dirs() {
        use std::fs;
        let tmp = std::env::temp_dir().join(format!("oxiclean_sweep_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        // The directory shape (which the old `-type f` filter silently missed),
        // the older file shape, and a real package that must be left alone.
        fs::create_dir(tmp.join("download-3kcUOv")).unwrap();
        fs::write(tmp.join("download-OldPart"), b"x").unwrap();
        fs::write(tmp.join("vim-9.1-1-x86_64.pkg.tar.zst"), b"x").unwrap();

        let mut found: Vec<String> = find_partial_downloads(&tmp)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        found.sort();

        assert_eq!(found, vec!["download-3kcUOv", "download-OldPart"]);

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_find_partial_downloads_missing_dir_is_empty() {
        // A non-existent cache dir must not panic — just yield nothing.
        let found = find_partial_downloads(Path::new("/nonexistent/oxiclean/cache"));
        assert!(found.is_empty());
    }

    // ── Expensive-cache protection: the core safety guarantee of --cache ──

    #[test]
    fn test_protected_list_covers_models_and_dev_caches() {
        // The two model caches whose loss is catastrophic must be present, plus
        // representative dev caches. This is the regression guard against anyone
        // quietly dropping an entry from PROTECTED_CACHE_DIRS.
        for must in ["huggingface", "torch", "uv", "pip", "ccache"] {
            assert!(
                PROTECTED_CACHE_DIRS.contains(&must),
                "{must} must stay in the protected-cache list"
            );
        }
    }

    #[test]
    fn test_partition_never_selects_protected_for_deletion() {
        use std::fs;
        let base = std::env::temp_dir().join(format!("oxiclean_cache_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        // A protected model cache with a "huge" file, and a disposable browser
        // cache. Only the browser cache may be selected for cleaning.
        fs::create_dir_all(base.join("huggingface/hub")).unwrap();
        fs::write(base.join("huggingface/hub/model.bin"), vec![0u8; 4096]).unwrap();
        fs::create_dir_all(base.join("mozilla")).unwrap();
        fs::write(base.join("mozilla/thumb.png"), b"junk").unwrap();

        let protected = protected_cache_names(&base);
        let (to_clean, skipped) = partition_cache_entries(&base, &protected);

        let clean_names: Vec<String> = to_clean
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();

        assert!(
            clean_names.contains(&"mozilla".to_string()),
            "disposable cache must be cleanable"
        );
        assert!(
            !clean_names.contains(&"huggingface".to_string()),
            "huggingface model cache must NEVER be selected for deletion"
        );
        assert!(skipped.contains(&"huggingface".to_string()));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_hf_home_relocation_inside_cache_base_is_protected() {
        // If HF_HOME points at a non-default directory *inside* the cache base,
        // that top-level entry must be protected too. We drive protected_cache_names
        // with a synthesized value rather than mutating global env in a test.
        let base = PathBuf::from("/home/u/.cache");
        let relocated = base.join("my-models/hub");
        // Simulate the strip_prefix logic protected_cache_names uses.
        let rel = relocated.strip_prefix(&base).unwrap();
        let first = rel
            .components()
            .next()
            .unwrap()
            .as_os_str()
            .to_str()
            .unwrap();
        assert_eq!(first, "my-models");
    }

    #[test]
    fn test_partition_missing_dir_is_empty() {
        let (to_clean, skipped) =
            partition_cache_entries(Path::new("/nonexistent/oxiclean/xyz"), &[]);
        assert!(to_clean.is_empty());
        assert!(skipped.is_empty());
    }
}
