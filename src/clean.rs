use colored::Colorize;
use std::path::PathBuf;

use crate::detect::Distro;
use crate::utils;

fn should_deep(deep: bool, yes: bool, prompt: &str) -> bool {
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

pub fn user_cache(dry_run: bool) -> u64 {
    utils::section("User Cache (~/.cache)");

    let home = match utils::home_dir() {
        Some(h) => h,
        None => {
            utils::error("Cannot determine HOME directory");
            return 0;
        }
    };

    let cache = PathBuf::from(&home).join(".cache");
    if !cache.exists() {
        utils::info("No cache directory found");
        return 0;
    }

    let size = utils::dir_size(&cache);
    utils::info(&format!("Cache size: {}", utils::format_size(size).yellow()));

    if size == 0 {
        utils::success("Already clean");
        return 0;
    }

    if dry_run {
        utils::info(&format!("[DRY RUN] Would free {}", utils::format_size(size)));
        return 0;
    }

    let freed = utils::rm_contents(&cache);
    utils::success(&format!("Freed {}", utils::format_size(freed).green()));
    freed
}

pub fn pkg_cache(distro: &Distro, deep: bool, dry_run: bool, yes: bool) -> u64 {
    utils::section(&format!("Package Cache ({})", distro.pkg_manager()));

    if *distro == Distro::Unknown {
        utils::skip("Unknown distribution — skipped");
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
            utils::info("Cleaning pacman cache (keeping latest version)...");
            if utils::sudo("pacman", &["-Sc", "--noconfirm"]) {
                utils::success("pacman cache cleaned");
            } else {
                utils::error("pacman -Sc failed");
            }
            if should_deep(deep, yes, "Run pacman -Scc? (removes ALL cached packages) [y/N]:") {
                if utils::sudo("pacman", &["-Scc", "--noconfirm"]) {
                    utils::success("pacman deep clean done");
                } else {
                    utils::error("pacman -Scc failed");
                }
            }
        }

        Distro::Debian => {
            utils::info("Cleaning apt cache...");
            if utils::sudo("apt-get", &["clean"]) {
                utils::success("apt cache cleaned");
            } else {
                utils::error("apt-get clean failed");
            }
            if should_deep(deep, yes, "Run apt autoclean? (removes outdated debs) [y/N]:") {
                if utils::sudo("apt-get", &["autoclean", "-y"]) {
                    utils::success("autoclean done");
                } else {
                    utils::error("autoclean failed");
                }
            }
        }

        Distro::Fedora => {
            let pm = if utils::which("dnf") { "dnf" } else { "yum" };
            utils::info(&format!("Cleaning {} cache...", pm));
            if utils::sudo(pm, &["clean", "all"]) {
                utils::success(&format!("{} cache cleaned", pm));
            } else {
                utils::error(&format!("{} clean failed", pm));
            }
        }

        Distro::Suse => {
            utils::info("Cleaning zypper cache...");
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

            if should_deep(deep, yes, "Delete ALL old generations? (nix-collect-garbage -d) [y/N]:") {
                utils::run("nix-collect-garbage", &["-d"]);
                utils::sudo("nix-collect-garbage", &["-d"]);
                utils::success("Old generations deleted");

                utils::info("Optimizing Nix store (may take a while)...");
                utils::sudo("nix-store", &["--optimise"]);
                utils::success("Nix store optimized");
            }
        }

        Distro::Void => {
            utils::info("Cleaning xbps cache...");
            if utils::sudo("xbps-remove", &["-O", "-y"]) {
                utils::success("xbps cache cleaned");
            } else {
                utils::error("xbps-remove -O failed");
            }
        }

        Distro::Alpine => {
            utils::info("Cleaning apk cache...");
            if utils::sudo("apk", &["cache", "clean"]) {
                utils::success("apk cache cleaned");
            } else {
                utils::warning("apk cache clean failed");
                let apk_cache = PathBuf::from("/var/cache/apk");
                if apk_cache.exists() {
                    utils::info("Cleaning /var/cache/apk manually...");
                    utils::sudo("find", &["/var/cache/apk", "-type", "f", "-delete"]);
                    utils::success("apk cache directory cleaned");
                }
            }
        }

        Distro::Gentoo => {
            if utils::which("eclean") {
                utils::info("Cleaning distfiles...");
                if utils::sudo("eclean", &["distfiles"]) {
                    utils::success("Distfiles cleaned");
                } else {
                    utils::error("eclean distfiles failed");
                }
                if should_deep(deep, yes, "Also clean binary packages? [y/N]:") {
                    if utils::sudo("eclean", &["packages"]) {
                        utils::success("Binary packages cleaned");
                    }
                }
            } else {
                utils::warning("eclean not found — install app-portage/gentoolkit");
                let distfiles = PathBuf::from("/var/cache/distfiles");
                if distfiles.exists() {
                    utils::info("Cleaning /var/cache/distfiles manually...");
                    utils::sudo("find", &["/var/cache/distfiles", "-type", "f", "-delete"]);
                    utils::success("Distfiles cleaned");
                }
            }
        }

        Distro::Solus => {
            utils::info("Cleaning eopkg cache...");
            if utils::sudo("eopkg", &["delete-cache"]) {
                utils::success("eopkg cache cleaned");
            } else {
                utils::error("eopkg delete-cache failed");
            }
        }

        Distro::Clear => {
            utils::info("Cleaning swupd state...");
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
        utils::info(&format!("Package cache freed: {}", utils::format_size(freed).green()));
    }
    freed
}

pub fn orphans(distro: &Distro, dry_run: bool, yes: bool) -> u64 {
    utils::section("Orphaned Packages");

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
            let pkgs: Vec<String> = out.lines()
                .filter(|l| l.contains('|') && !l.contains("---") && !l.contains("Name"))
                .filter_map(|l| {
                    let cols: Vec<&str> = l.split('|').map(|s| s.trim()).collect();
                    if cols.len() >= 3 { Some(cols[2].to_string()) } else { None }
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
    utils::section(&format!("AUR Cache ({})", helper));

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

    utils::info(&format!("Cleaning {} cache...", helper));
    if utils::run(helper, &["-Sc", "--noconfirm"]) {
        utils::success(&format!("{} cache cleaned", helper));
    } else {
        utils::error(&format!("{} -Sc failed", helper));
    }

    if should_deep(deep, yes, &format!("Run {} -Scc? (removes ALL cached AUR packages) [y/N]:", helper)) {
        if utils::run(helper, &["-Scc", "--noconfirm"]) {
            utils::success(&format!("{} deep clean done", helper));
        } else {
            utils::error(&format!("{} -Scc failed", helper));
        }
    }

    let size_after = cache_dir.as_ref().map(|p| utils::dir_size(p)).unwrap_or(0);
    let freed = size_before.saturating_sub(size_after);
    if freed > 0 {
        utils::info(&format!("AUR cache freed: {}", utils::format_size(freed).green()));
    }
    freed
}

pub fn flatpak(deep: bool, dry_run: bool) -> u64 {
    utils::section("Flatpak Cleanup");

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

    utils::sudo("find", &["/var/tmp", "-name", "flatpak-cache-*", "-exec", "rm", "-rf", "{}", "+"]);

    let sys_fp_tmp = PathBuf::from("/var/lib/flatpak/repo/tmp");
    if sys_fp_tmp.exists() {
        utils::sudo("find", &["/var/lib/flatpak/repo/tmp", "-mindepth", "1", "-delete"]);
    }

    if freed > 0 {
        utils::success(&format!("Freed {}", utils::format_size(freed).green()));
    } else {
        utils::success("Flatpak cleanup done");
    }

    freed
}

pub fn snap(dry_run: bool) -> u64 {
    utils::section("Snap Cleanup");

    if dry_run {
        utils::info("[DRY RUN] Would remove disabled snap revisions & cache");
        return 0;
    }

    let out = utils::capture("snap", &["list", "--all"]).unwrap_or_default();
    let disabled: Vec<(&str, &str)> = out.lines()
        .filter(|l| l.contains("disabled"))
        .filter_map(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            if parts.len() >= 3 { Some((parts[0], parts[2])) } else { None }
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
            utils::info("Cleaning snap cache...");
            utils::sudo("find", &["/var/lib/snapd/cache", "-type", "f", "-delete"]);
            freed += size;
            utils::success(&format!("Freed {}", utils::format_size(size).green()));
        }
    }

    freed
}

pub fn journal(dry_run: bool) -> u64 {
    utils::section("Systemd Journal");

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
        utils::info(&format!("Journal freed: {}", utils::format_size(freed).green()));
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

    utils::info(&format!("Trash size: {}", utils::format_size(total_size).yellow()));

    if dry_run {
        utils::info(&format!("[DRY RUN] Would free {}", utils::format_size(total_size)));
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
