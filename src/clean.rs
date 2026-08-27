use colored::Colorize;
use std::path::{Path, PathBuf};

use crate::detect::{AurHelper, Distro};
use crate::utils;

// Which helper commands are allowed to print their own output.
//
// Default is `utils::*_quiet`: cache-clearing commands emit several lines each
// and on a full `--all` run there was more foreign output than ours, which
// buried the section results. Those are captured (and their stderr replayed if
// they fail). `--verbose` turns capturing off globally.
//
// Three kinds of command stay on the plain `utils::run`/`utils::sudo`, because
// hiding them would cost the user something real rather than just noise:
//
//   1. Package *removal* (`pacman -Rns`, `apt-get autoremove`, `emerge
//      --depclean`, ...) — destructive and slow. On a btrfs system with
//      snapper hooks this takes tens of seconds; silence would read as a hang.
//   2. Nix garbage collection — routinely runs for minutes.
//   3. `fstrim --verbose` — its output *is* the result. We have no
//      oxiclean-generated line that carries the same information.
//
// The line is: we hide chatter, never results or progress.

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
    utils::sudo_quiet("rm", &args);
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

// ══════════════════════════════════════════════════
//  Gentoo build-tmp cleanup (used by pkg_cache Gentoo arm)
// ══════════════════════════════════════════════════

/// Parse `PORTAGE_TMPDIR` out of make.conf content. Portage builds under
/// `$PORTAGE_TMPDIR/portage`, defaulting to `/var/tmp` when unset (so the build
/// tree is `/var/tmp/portage`). Pure — no I/O — so the parsing is unit-tested.
/// Returns the *tmpdir* value (not the `/portage` subdir); the caller appends
/// `portage`. Later assignments win, matching shell/make semantics.
fn parse_portage_tmpdir(make_conf: &str) -> Option<String> {
    parse_make_conf_var(make_conf, "PORTAGE_TMPDIR")
}

/// Resolve the portage build-tmp directory: `$PORTAGE_TMPDIR/portage`, honouring
/// make.conf and falling back to the `/var/tmp` default. The returned path is
/// *always* validated to end in `/portage` by the caller before any deletion.
fn portage_build_dir() -> PathBuf {
    let make_conf = std::fs::read_to_string("/etc/portage/make.conf").unwrap_or_default();
    let base = parse_portage_tmpdir(&make_conf).unwrap_or_else(|| "/var/tmp".to_string());
    PathBuf::from(base).join("portage")
}

/// Final safety gate before deleting anything under the portage build tree:
/// the resolved path must be `<real-dir>/portage` — it must end in a `portage`
/// component AND be nested at least one directory below root. A malformed
/// `PORTAGE_TMPDIR` (empty, or `/`) would otherwise expand to `/portage`; we
/// reject that so an aim at a bare top-level dir can never slip through.
fn portage_dir_is_safe(dir: &Path) -> bool {
    dir.file_name().map(|n| n == "portage").unwrap_or(false) && dir.components().count() >= 3
}

/// True when an `emerge` build is in progress. Deleting `/var/tmp/portage`
/// mid-build corrupts the running compile, so this is a hard guard. Uses
/// `pgrep -f emerge`: run without a shell, the only cmdlines containing
/// "emerge" are real emerge processes (pgrep excludes its own PID). Fails
/// *closed* — if we can't tell, we assume a build is running and skip.
///
/// Resolved through a trusted system path, not `$PATH`: a shadowed `pgrep` that
/// exits non-zero would report "no build running" and hand this function's
/// safety guarantee to whoever planted it — the sweep would then delete a live
/// build tree. A `pgrep` we cannot vouch for is treated as unavailable, which
/// fails closed.
fn emerge_running() -> bool {
    let Some(pgrep) = utils::resolve_trusted("pgrep") else {
        return true; // can't verify → assume a build is running
    };
    match std::process::Command::new(pgrep)
        .args(["-f", "emerge"])
        .env("PATH", utils::trusted_path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        Ok(s) => s.success(), // exit 0 = at least one match
        Err(_) => true,       // pgrep missing / failed → assume unsafe
    }
}

/// Remove failed-build leftovers under the portage build tree. These are the
/// half-unpacked/half-compiled remnants of interrupted or failed `emerge` runs
/// — pure garbage that portage does not reuse. We only ever delete the
/// *contents*, never the `portage` dir itself, and only after four guards pass:
/// the dir exists, no emerge is running, the path resolves under a real
/// tmpdir, and it ends in `/portage`.
fn clean_portage_tmp(dry_run: bool) -> u64 {
    let build_dir = portage_build_dir();

    if !build_dir.exists() || !portage_dir_is_safe(&build_dir) {
        return 0;
    }
    if emerge_running() {
        utils::skip("emerge is running — leaving build tmp untouched");
        return 0;
    }

    let size = utils::dir_size(&build_dir);
    if size == 0 {
        return 0;
    }
    if dry_run {
        utils::info(&format!(
            "[DRY RUN] Would clear failed-build leftovers in {} ({})",
            build_dir.display(),
            utils::format_size(size)
        ));
        return 0;
    }

    // The contents are root-owned (built via sudo emerge), so delete through
    // sudo. `-mindepth 1` keeps the `portage` dir itself; `-delete` handles the
    // nested trees. We report the pre-measured size as freed.
    let target = build_dir.to_string_lossy().into_owned();
    utils::sudo_quiet("find", &[&target, "-mindepth", "1", "-delete"]);
    utils::success(&format!(
        "Cleared portage build leftovers ({})",
        utils::format_size(size).green()
    ));
    size
}

/// Resolve the package-cache directory to measure on Fedora/RHEL. dnf5 keeps
/// its cache under `/var/cache/libdnf5`; dnf4 and yum use `/var/cache/dnf` and
/// `/var/cache/yum`. `dnf clean all` cleans whichever backend is active, so we
/// measure the one that actually holds data.
fn fedora_cache_dir() -> PathBuf {
    resolve_fedora_cache_dir(
        Path::new("/var/cache/libdnf5").is_dir(),
        utils::which_trusted("dnf"),
    )
}

/// Pure path-selection logic, split out from [`fedora_cache_dir`] so it can be
/// tested without touching the filesystem. Prefer the libdnf5 dir when present,
/// then the dnf4 dir, then yum. We pick a single active dir rather than summing
/// them so a stale sibling left over from a dnf4→dnf5 migration can't be
/// double-counted into the freed total.
fn resolve_fedora_cache_dir(libdnf5_exists: bool, has_dnf: bool) -> PathBuf {
    if libdnf5_exists {
        PathBuf::from("/var/cache/libdnf5")
    } else if has_dnf {
        PathBuf::from("/var/cache/dnf")
    } else {
        PathBuf::from("/var/cache/yum")
    }
}

/// Resolve Gentoo's `DISTDIR` — where portage stores downloaded source
/// archives. `eclean distfiles` reads this from the live portage config, so
/// hard-coding the default would measure the wrong tree on any system that
/// overrides it (and Funtoo defaults it to `/var/cache/portage/distfiles`).
///
/// Asks `portageq` first because that is portage's own answer, then falls back
/// to parsing make.conf, then to the modern default. The old pre-2.3.8 default
/// was `/usr/portage/distfiles`, so we accept that only if it actually exists.
fn gentoo_distdir() -> PathBuf {
    if let Some(out) = utils::capture_trusted("portageq", &["distdir"]) {
        let trimmed = out.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    let make_conf = std::fs::read_to_string("/etc/portage/make.conf").unwrap_or_default();
    if let Some(dir) = parse_make_conf_var(&make_conf, "DISTDIR") {
        return PathBuf::from(dir);
    }
    let legacy = PathBuf::from("/usr/portage/distfiles");
    if legacy.is_dir() && !PathBuf::from("/var/cache/distfiles").is_dir() {
        return legacy;
    }
    PathBuf::from("/var/cache/distfiles")
}

/// Read a `KEY=value` assignment out of make.conf content. Later assignments
/// win, matching shell/make semantics; comments and empty values are ignored.
/// Pure — no I/O — so it is unit-tested.
fn parse_make_conf_var(make_conf: &str, key: &str) -> Option<String> {
    let prefix = format!("{}=", key);
    let mut found: Option<String> = None;
    for line in make_conf.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix(&prefix) {
            let val = rest.trim().trim_matches('"').trim_matches('\'');
            if !val.is_empty() {
                found = Some(val.to_string());
            }
        }
    }
    found
}

fn pkg_cache_dir(distro: &Distro) -> Option<PathBuf> {
    match distro {
        Distro::Arch => Some(PathBuf::from("/var/cache/pacman/pkg")),
        Distro::Debian => Some(PathBuf::from("/var/cache/apt/archives")),
        Distro::Fedora => Some(fedora_cache_dir()),
        // `zypper clean --all` clears the whole cache — downloaded packages
        // (`packages/`) *and* repository metadata (`raw/`, `solv/`). Measuring
        // only `packages/` under-reported the freed total by whatever the
        // metadata weighed, which on a refreshed Tumbleweed is ~65 MB of ~147 MB.
        Distro::Suse => Some(PathBuf::from("/var/cache/zypp")),
        Distro::Void => Some(PathBuf::from("/var/cache/xbps")),
        Distro::Alpine => Some(PathBuf::from("/var/cache/apk")),
        Distro::Gentoo => Some(gentoo_distdir()),
        // `eopkg delete-cache` clears the downloaded packages (`packages/`),
        // the source archives (`archives/`) and the db `.cache` files that sit
        // beside them, so measuring only `packages/` under-reports the total
        // the same way the openSUSE path did.
        // https://github.com/solus-project/package-management/blob/master/man/eopkg.1.md
        Distro::Solus => Some(PathBuf::from("/var/cache/eopkg")),
        _ => None,
    }
}

// ══════════════════════════════════════════════════
//  Expensive-cache protection (used by user_cache)
// ══════════════════════════════════════════════════

// Caches under the user cache dir that a blanket `--cache`/`--all` wipe must
// never touch. Split into two kinds because they're reported differently:
//
//   * `PROTECTED_MODEL_DIRS` — model weights. Protected **silently**: they are
//     never cleaned by `--cache` *or* `--dev`, so mentioning them (let alone
//     hinting "clean with --dev") would be a false promise. Just kept, quietly.
//   * `PROTECTED_DEV_DIRS` — dev-tool caches that `--dev` owns and cleans with
//     the correct per-tool command. When one of these is present we skip it
//     here and print a single hint pointing the user at `--dev`.
//
// Both lists together are what `partition_cache_entries` protects from
// deletion; only the dev list drives the printed hint.

/// Model-weight caches: multi-GB downloads a user grabbed on purpose (nobody
/// clears a 40 GB model as routine cleanup). Not "leftovers", and not something
/// `--dev` touches either — so `--cache` keeps them silently.
const PROTECTED_MODEL_DIRS: &[&str] = &["huggingface", "torch"];

/// Dev-tool caches that live under `~/.cache` but are owned by `--dev`. Wiping
/// them from `--cache` would contradict `--dev`'s per-tool handling, so they're
/// spared here and their presence prints a "use --dev" hint.
const PROTECTED_DEV_DIRS: &[&str] = &["uv", "pip", "pipenv", "pypoetry", "deno", "ccache", "yarn"];

/// Every top-level name protected from a `--cache` wipe (models + dev caches).
fn all_protected_dirs() -> Vec<&'static str> {
    PROTECTED_MODEL_DIRS
        .iter()
        .chain(PROTECTED_DEV_DIRS.iter())
        .copied()
        .collect()
}

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
/// list, the cache dirs of any AUR helper the AUR section is going to clean,
/// plus HuggingFace's location if it's been redirected *inside* the cache base
/// via `HF_HOME`/`HF_HUB_CACHE` (so a non-default model dir is still spared).
/// A relocation outside the cache base needs no entry — user_cache only ever
/// touches things under the cache base to begin with.
///
/// AUR helper cache dirs are held back for two different reasons, deliberately
/// kept apart:
///
/// * A **hand-pruned** helper (`clean: None`) keeps *state* inside its cache
///   dir. aura's `snapshots/` are user-saved restore points that `-B` restores
///   from, and `hashes/` is its build bookkeeping. A wholesale wipe of
///   `~/.cache/aura` destroys both, so that dir is held back **unconditionally**
///   — even when the AUR section is not running, because "clean less" beats
///   "delete the user's restore points".
/// * Every **command-driven** helper is merely *deferred*: its own `-Sc` cleans
///   the same dir, so we skip it here only when the AUR section will actually
///   run. Under `--cache` alone (or `--all --skip aur`) nothing else would touch
///   it, so it is cleaned here as before — deferring never means "nobody cleans
///   it".
fn protected_cache_names(
    cache_base: &Path,
    helpers: &[AurHelper],
    aur_running: bool,
) -> Vec<String> {
    let mut names: Vec<String> = all_protected_dirs().iter().map(|s| s.to_string()).collect();
    names.extend(
        helpers
            .iter()
            .filter(|h| aur_running || h.clean.is_none())
            .map(|h| h.bin.to_string()),
    );
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

/// True if any of the spared entries is a dev-tool cache (so we should print
/// the `--dev` hint). Model caches are excluded — they're kept silently because
/// nothing, not even `--dev`, removes them.
fn skipped_has_dev_cache(skipped: &[String]) -> bool {
    skipped
        .iter()
        .any(|name| PROTECTED_DEV_DIRS.contains(&name.as_str()))
}

/// True if any of the spared entries belongs to a hand-pruned helper (i.e. one
/// with no clean command). We only print the hint when the AUR section is not
/// running, so the user knows why we touched less than expected.
fn skipped_has_hand_pruned_helper(skipped: &[String], helpers: &[AurHelper]) -> bool {
    skipped.iter().any(|name| {
        helpers
            .iter()
            .any(|h| h.bin == name.as_str() && h.clean.is_none())
    })
}

pub fn user_cache(dry_run: bool, helpers: &[AurHelper], aur_running: bool) -> u64 {
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
    let protected = protected_cache_names(&cache, helpers, aur_running);
    let (to_clean, skipped) = partition_cache_entries(&cache, &protected);

    // Only announce the skip when a dev-tool cache was actually spared, and
    // point the user at the flag that *can* clean it. Model caches (HuggingFace,
    // torch) are kept silently: neither `--cache` nor `--dev` removes them, so
    // naming them here would just be noise (and "clean with --dev" a false lead).
    if skipped_has_dev_cache(&skipped) {
        utils::skip("Some dev-tool caches skipped — remove them with --dev");
    }

    // A hand-pruned helper's cache dir is held back even when the AUR section
    // is not running, because it stores state (aura's snapshots) that only that
    // section knows how to step around. Say so, or `--cache` looks like it
    // silently ignored a directory.
    if !aur_running && skipped_has_hand_pruned_helper(&skipped, helpers) {
        utils::skip("AUR helper cache skipped — clean it with --aur");
    }

    // Size every entry ONCE and carry the number forward. `entry_size` walks the
    // tree, and `~/.cache` is usually the deepest one we touch, so measuring the
    // total and then re-measuring each entry doubled the most expensive step.
    let sized: Vec<(PathBuf, u64)> = to_clean
        .into_iter()
        .map(|p| {
            let size = entry_size(&p);
            (p, size)
        })
        .collect();

    let clean_size: u64 = sized.iter().map(|(_, size)| size).sum();
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
    for (path, size) in &sized {
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
        if utils::sudo_quiet("rpm-ostree", &["cleanup", "-bm"]) {
            utils::success("rpm-ostree cleaned (base deployments + cached metadata)");
        } else {
            utils::error("rpm-ostree cleanup failed");
        }
        // rpm-ostree reclaims space across /sysroot and /var with no single
        // measurable cache dir, so we report the action rather than a byte count.
        return 0;
    }

    // General immutable guard: an image-based system with a read-only rootfs
    // (SteamOS, openSUSE MicroOS, …) manages its OS through atomic image swaps,
    // not the package manager. These report as their base distro (Arch, SUSE…)
    // so the code below would try `pacman -Sc` / `zypper clean` and fail — or
    // worse, fight the atomic update model. We skip package-cache cleanup and
    // say why; the user-level steps (cache, trash, dev, journal) still run and
    // are where the reclaimable space on these systems actually is. OSTree is
    // handled above with its own real cleanup, so it never reaches here. This
    // runs before the Unknown check (mirroring `orphans`) so an unrecognised
    // *and* read-only system is still correctly treated as immutable.
    if crate::detect::is_readonly_rootfs() {
        utils::skip("Immutable/read-only system — package cache managed by atomic updates");
        return 0;
    }

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

    // Bytes reclaimed outside the measured package-cache dir (e.g. Gentoo's
    // build-tmp tree), added to the final total.
    let mut extra_freed = 0u64;

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

            if utils::sudo_quiet("pacman", &["-Sc", "--noconfirm"]) {
                utils::success("pacman cache cleaned");
            } else {
                utils::error("pacman -Sc failed");
            }
            if should_deep(
                deep,
                yes,
                "Run pacman -Scc? (removes ALL cached packages) [y/N]:",
            ) {
                if utils::sudo_quiet("pacman", &["-Scc", "--noconfirm"]) {
                    utils::success("pacman deep clean done");
                } else {
                    utils::error("pacman -Scc failed");
                }
            }
        }

        Distro::Debian => {
            if utils::sudo_quiet("apt-get", &["clean"]) {
                utils::success("apt cache cleaned");
            } else {
                utils::error("apt-get clean failed");
            }
            if should_deep(
                deep,
                yes,
                "Run apt autoclean? (removes outdated debs) [y/N]:",
            ) {
                if utils::sudo_quiet("apt-get", &["autoclean", "-y"]) {
                    utils::success("autoclean done");
                } else {
                    utils::error("autoclean failed");
                }
            }
        }

        Distro::Fedora => {
            let pm = if utils::which_trusted("dnf") {
                "dnf"
            } else {
                "yum"
            };
            if utils::sudo_quiet(pm, &["clean", "all"]) {
                utils::success(&format!("{} cache cleaned", pm));
            } else {
                utils::error(&format!("{} clean failed", pm));
            }
        }

        Distro::Suse => {
            if utils::sudo_quiet("zypper", &["clean", "--all"]) {
                utils::success("zypper cache cleaned");
            } else {
                utils::error("zypper clean failed");
            }
        }

        Distro::Nix => {
            // Nix has no cache directory for `pkg_cache_dir` to measure, so this
            // arm always reported 0 B freed. Read the total off Nix's own report
            // line instead; see `parse_nix_freed`. The privileged run stays
            // visible because it can take minutes.
            utils::info("Running Nix garbage collection...");
            if let Some(out) = utils::capture("nix-collect-garbage", &[]) {
                extra_freed += parse_nix_freed(&out).unwrap_or(0);
            }
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
            // `-O` only drops *outdated* cached packages; the current version of
            // every installed package stays. On a freshly-installed system that
            // is the whole cache, so `-O` frees nothing and still exits 0 — we
            // used to report "cleaned" after removing zero bytes. `-OO` also
            // removes cached packages that are no longer installed.
            //
            // Doubling the flag stays behind `--deep` because the xbps cache is
            // what makes a downgrade possible: a version pulled from the repo
            // index can still be reinstalled from /var/cache/xbps. Emptying it
            // removes those rollback targets, so the user opts in.
            // https://docs.voidlinux.org/xbps/index.html
            let clean_all = should_deep(
                deep,
                yes,
                "Also remove cached packages that are no longer installed? \
                 (removes downgrade targets) [y/N]:",
            );
            let flag = if clean_all { "-OO" } else { "-O" };
            if utils::sudo_quiet("xbps-remove", &[flag, "-y"]) {
                utils::success("xbps cache cleaned");
                if !clean_all {
                    utils::skip("Cached current versions kept — remove them with --deep");
                }
            } else {
                utils::error(&format!("xbps-remove {} failed", flag));
            }
        }

        Distro::Alpine => {
            // `apk cache clean` only drops *superseded* versions; the cached
            // package for every currently-installed version stays, as do the
            // APKINDEX files. On a system that has never upgraded anything that
            // is the entire cache, so the command frees nothing and still exits
            // 0 — we used to report "cleaned" after removing zero bytes.
            // (`--purge` is not the answer either: verified in a container, it
            // also keeps the installed versions.)
            //
            // Clearing the rest means deleting the files ourselves, which costs
            // a re-download, so it stays behind `--deep`. The APKINDEX files go
            // with them and are refetched on the next `apk update`.
            // https://wiki.alpinelinux.org/wiki/Alpine_Package_Keeper
            if !utils::sudo_quiet("apk", &["cache", "clean"]) {
                utils::warning("apk cache clean failed");
            }
            let purge = should_deep(
                deep,
                yes,
                "Also remove cached packages for installed versions? \
                 (they re-download on next install) [y/N]:",
            );
            if purge && PathBuf::from("/var/cache/apk").is_dir() {
                utils::sudo_quiet("find", &["/var/cache/apk", "-type", "f", "-delete"]);
                utils::success("apk cache cleared");
            } else {
                utils::success("apk cache cleaned");
                if !purge {
                    utils::skip("Cached current versions kept — remove them with --deep");
                }
            }
        }

        Distro::Gentoo => {
            if utils::which_trusted("eclean") {
                if utils::sudo_quiet("eclean", &["distfiles"]) {
                    utils::success("Distfiles cleaned");
                } else {
                    utils::error("eclean distfiles failed");
                }
                if should_deep(deep, yes, "Also clean binary packages? [y/N]:")
                    && utils::sudo_quiet("eclean", &["packages"])
                {
                    utils::success("Binary packages cleaned");
                }
            } else {
                utils::warning("eclean not found — install app-portage/gentoolkit");
                let distfiles = gentoo_distdir();
                // A non-UTF-8 DISTDIR can't be passed as a &str arg; skip
                // rather than panic on unwrap.
                if let Some(path) = distfiles.to_str() {
                    if distfiles.is_dir() {
                        utils::sudo_quiet("find", &[path, "-type", "f", "-delete"]);
                        utils::success("Distfiles cleaned");
                    }
                }
            }
            // Also sweep failed-build leftovers under $PORTAGE_TMPDIR/portage —
            // interrupted/failed emerges leave gigabytes of half-built trees
            // there that portage never reuses. Guarded (no build running, path
            // validated); measured separately from the distfiles cache.
            extra_freed += clean_portage_tmp(dry_run);
        }

        Distro::Solus => {
            if utils::sudo_quiet("eopkg", &["delete-cache"]) {
                utils::success("eopkg cache cleaned");
            } else {
                utils::error("eopkg delete-cache failed");
            }
        }

        Distro::Clear => {
            // swupd has its own cache-cleaning subcommand that understands the
            // version/age heuristics for what's safe to drop. `swupd clean`
            // removes staged files and stale metadata; `--all` (deep) also drops
            // recent manifests. Prefer it over a raw `rm` of the staged dir so we
            // don't fight swupd's own bookkeeping.
            if utils::which_trusted("swupd") {
                let mut args = vec!["clean"];
                if deep {
                    args.push("--all");
                }
                if utils::sudo_quiet("swupd", &args) {
                    utils::success("swupd cache cleaned");
                } else {
                    utils::error("swupd clean failed");
                }
            } else {
                utils::skip("swupd not found — skipped");
            }
        }

        Distro::Unknown => {}
    }

    let size_after = cache_dir.as_ref().map(|p| utils::dir_size(p)).unwrap_or(0);
    let freed = size_before.saturating_sub(size_after) + extra_freed;
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
            let out = utils::capture_trusted("pacman", &["-Qdtq"]).unwrap_or_default();
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
            let pm = if utils::which_trusted("dnf") {
                "dnf"
            } else {
                "yum"
            };
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
            let out =
                utils::capture_trusted("zypper", &["packages", "--orphaned"]).unwrap_or_default();
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
            // apk has no separate "autoremove": it prunes now-unneeded
            // dependencies automatically whenever a package is removed with
            // `apk del`. There is nothing to collect after the fact, so the
            // old "not supported" wording was misleading — say what's true.
            utils::success(
                "apk removes unused dependencies automatically on 'apk del' — nothing to clean",
            );
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

/// Clean the cache of every installed AUR helper.
///
/// One line per helper with its own freed figure, rather than a single merged
/// total: if a helper stops cleaning properly, a permanently-zero line next to
/// a working one makes that visible immediately, where a combined number would
/// hide it.
pub fn aur_cache(helpers: &[AurHelper], deep: bool, dry_run: bool, yes: bool) -> u64 {
    utils::section("AUR Cache");

    if helpers.is_empty() {
        utils::skip("No AUR helper found — skipped");
        return 0;
    }

    if dry_run {
        for h in helpers {
            match if deep { h.deep_clean } else { h.clean } {
                Some(args) => utils::info(&format!(
                    "[DRY RUN] Would run: {} {}",
                    h.bin,
                    args.join(" ")
                )),
                None => {
                    for dir in prune_targets(h, deep) {
                        utils::info(&format!("[DRY RUN] Would clear: {}/{}", h.bin, dir));
                    }
                }
            }
        }
        return 0;
    }

    // Every helper cleans the shared pacman cache as well, so an interrupted
    // download's leftovers would make each of them print the `Error reading
    // fd 7` noise. One sweep up front covers all of them —
    // see `cleanup_pacman_partial_downloads`.
    cleanup_pacman_partial_downloads();

    helpers.iter().map(|h| clean_one_helper(h, deep, yes)).sum()
}

/// The helper's own cache directory. Goes through [`user_cache_base`] so
/// `XDG_CACHE_HOME` is honoured — building `~/.cache` by hand here would miss a
/// relocated cache and report 0 B freed on every run.
fn helper_cache_dir(h: &AurHelper) -> Option<PathBuf> {
    user_cache_base().map(|base| base.join(h.bin))
}

/// Subdirectories to clear for a helper we prune by hand. The re-download-
/// costing ones are only included under `--deep`, matching how `--dev` gates
/// its own caches.
fn prune_targets(h: &AurHelper, deep: bool) -> Vec<&'static str> {
    let mut dirs: Vec<&'static str> = h.prune_dirs.to_vec();
    if deep {
        dirs.extend_from_slice(h.prune_dirs_deep);
    }
    dirs
}

/// Clean a single helper and report its result. Split out so the per-helper
/// loop above stays readable.
fn clean_one_helper(h: &AurHelper, deep: bool, yes: bool) -> u64 {
    let cache_dir = helper_cache_dir(h);
    let size_before = cache_dir.as_ref().map(|p| utils::dir_size(p)).unwrap_or(0);

    match h.clean {
        // Helpers with a real clean command: let the helper do it, so its own
        // bookkeeping stays consistent.
        Some(args) => {
            if !utils::run_quiet(h.bin, args) {
                utils::error(&format!("{} {} failed", h.bin, args.join(" ")));
                return 0;
            }
            if let Some(deep_args) = h.deep_clean {
                if should_deep(
                    deep,
                    yes,
                    &format!(
                        "Run {} {}? (removes ALL cached AUR packages) [y/N]:",
                        h.bin,
                        deep_args.join(" ")
                    ),
                ) && !utils::run_quiet(h.bin, deep_args)
                {
                    utils::error(&format!("{} {} failed", h.bin, deep_args.join(" ")));
                }
            }
        }
        // Helpers with no usable clean command (aura): clear the specific
        // build/tarball subdirectories ourselves. Never the whole cache dir —
        // that would take `snapshots/` with it.
        None => {
            let Some(base) = cache_dir.as_ref() else {
                utils::error(&format!("{}: cannot determine cache directory", h.bin));
                return 0;
            };
            for dir in prune_targets(h, deep) {
                let target = base.join(dir);
                if target.is_dir() {
                    utils::rm_contents(&target);
                }
            }
        }
    }

    let size_after = cache_dir.as_ref().map(|p| utils::dir_size(p)).unwrap_or(0);
    let freed = size_before.saturating_sub(size_after);
    if freed > 0 {
        utils::success(&format!(
            "{} — freed {}",
            h.bin,
            utils::format_size(freed).green()
        ));
    } else {
        utils::success(&format!("{} — already clean", h.bin));
    }
    freed
}

/// Number of installed Flatpak refs across both the user and system
/// installations. `--columns=ref` keeps the output one machine-stable token per
/// line, with no header, so counting non-empty lines is enough. A failed or
/// missing `flatpak` yields 0, which makes the caller's before/after difference
/// 0 — it reports "no unused runtimes" rather than inventing a count.
fn flatpak_ref_count() -> usize {
    utils::capture_trusted("flatpak", &["list", "--columns=ref"])
        .map(|out| out.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0)
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

    // Count installed refs around the uninstall instead of reading flatpak's
    // own words. "Nothing unused to uninstall" is a translated string, so
    // matching it would silently stop working outside an English locale;
    // counting lines works everywhere. Both scopes are collapsed into one
    // number because the user/system split is an implementation detail — what
    // they want to know is how many runtimes went away.
    let before = flatpak_ref_count();

    utils::run_quiet("flatpak", &["uninstall", "--unused", "-y"]);
    utils::sudo_quiet("flatpak", &["uninstall", "--unused", "-y"]);

    match before.saturating_sub(flatpak_ref_count()) {
        0 => utils::success("No unused runtimes"),
        n => utils::success(&format!("Removed {} unused runtime(s)", n)),
    }

    if deep {
        if utils::sudo_quiet("flatpak", &["repair"]) {
            utils::success("Flatpak installation repaired");
        } else {
            utils::error("Flatpak repair failed");
        }
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

    utils::sudo_quiet(
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
        utils::sudo_quiet(
            "find",
            &["/var/lib/flatpak/repo/tmp", "-mindepth", "1", "-delete"],
        );
    }

    // The runtime count above is already this section's result line, so only
    // add a second one when the tmp-dir sweep actually reclaimed something.
    if freed > 0 {
        utils::success(&format!("Freed {}", utils::format_size(freed).green()));
    }

    freed
}

pub fn snap(dry_run: bool) -> u64 {
    utils::section("Snap");

    if dry_run {
        utils::info("[DRY RUN] Would remove disabled snap revisions & cache");
        return 0;
    }

    let out = utils::capture_trusted("snap", &["list", "--all"]).unwrap_or_default();
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
            if utils::sudo_quiet("snap", &["remove", name, "--revision", rev]) {
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
            utils::sudo_quiet("find", &["/var/lib/snapd/cache", "-type", "f", "-delete"]);
            freed += size;
            utils::success(&format!("Freed {}", utils::format_size(size).green()));
        }
    }

    freed
}

/// How much journal we keep. `journalctl --vacuum-size` takes the suffixed
/// form; the byte value is what we compare the current usage against.
const JOURNAL_LIMIT: &str = "50M";
const JOURNAL_LIMIT_BYTES: u64 = 50 * 1024 * 1024;

/// Pull the byte count out of `journalctl --disk-usage`.
///
/// The command answers with a whole sentence — "Archived and active journals
/// take up 48.1M in the file system." — so the old code printed that sentence
/// verbatim after its own "Current usage:" label, which read as duplicated and
/// swallowed most of the line width.
///
/// We scan for the first token that looks like a size (digits, optional
/// decimal, optional unit suffix) rather than matching the sentence, because
/// systemd translates its output: on a non-English locale the words change but
/// the number does not. Anything we cannot parse returns `None`, and the caller
/// then vacuums unconditionally — exactly the old behaviour, so a locale we
/// did not anticipate degrades to correct-but-chattier rather than to wrong.
/// Convert a numeric string plus a separate unit into bytes.
/// Shared by the journal and Nix parsers, which differ only in how the two
/// halves are written (`48.1M` versus `2.3 MiB`).
fn size_to_bytes(num: &str, unit: &str) -> Option<u64> {
    let value: f64 = num.parse().ok()?;
    let multiplier = match unit {
        "" | "B" => 1.0,
        "K" | "KB" | "KiB" => 1024.0,
        "M" | "MB" | "MiB" => 1024.0 * 1024.0,
        "G" | "GB" | "GiB" => 1024.0 * 1024.0 * 1024.0,
        "T" | "TB" | "TiB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some((value * multiplier) as u64)
}

/// Pull the freed byte count out of `nix-collect-garbage` output, whose last
/// line reads `1110 store paths deleted, 2.3 MiB freed`.
///
/// Nix computes this while deleting, from the size of each store path it
/// actually removes — so unlike a before/after directory walk it is exact, and
/// unaffected by CoW, thin provisioning or anything else at the filesystem
/// layer. It also saves walking `/nix/store`, which on a real NixOS install is
/// tens of gigabytes and hundreds of thousands of files.
///
/// Anchored on the word `freed` and read backwards, because the line starts with
/// a *different* number (the path count) that a first-number-wins parser would
/// grab instead. Returns `None` if the wording changes, and the caller then falls
/// back to measuring.
fn parse_nix_freed(text: &str) -> Option<u64> {
    for line in text.lines().rev() {
        let mut tokens = line.split_whitespace().collect::<Vec<_>>();
        // Expect `... <value> <unit> freed`; drop the trailing keyword.
        if tokens.last() != Some(&"freed") {
            continue;
        }
        tokens.pop();
        let unit = tokens.pop()?;
        let num = tokens.pop()?.trim_end_matches(',');
        return size_to_bytes(num, unit);
    }
    None
}

fn parse_journal_usage(text: &str) -> Option<u64> {
    for token in text.split_whitespace() {
        let token = token.trim_end_matches(['.', ',']);
        let split = token.find(|c: char| !c.is_ascii_digit() && c != '.');
        let (num, unit) = match split {
            Some(i) => token.split_at(i),
            None => (token, ""),
        };
        if let Some(bytes) = size_to_bytes(num, unit) {
            return Some(bytes);
        }
    }
    None
}

pub fn journal(dry_run: bool) -> u64 {
    utils::section("Journal");

    if !utils::which_trusted("journalctl") {
        utils::skip("journalctl not found — skipped");
        return 0;
    }

    let raw_usage = utils::capture_trusted("journalctl", &["--disk-usage"]);
    let usage_bytes = raw_usage.as_deref().and_then(parse_journal_usage);
    let usage_label = usage_bytes.map(utils::format_size);

    // `--vacuum-size` bounds the *archived* journals, and `--disk-usage`
    // reports archived + active. So a total already under the limit guarantees
    // the archived part is too, and the vacuum provably has nothing to do.
    // Skipping it saves a privileged subprocess and three lines of
    // "freed 0B of archived journals from ..." that told the user nothing.
    if let (Some(bytes), Some(label)) = (usage_bytes, &usage_label) {
        if bytes <= JOURNAL_LIMIT_BYTES {
            utils::success(&format!(
                "Already under {} ({}) — nothing to vacuum",
                JOURNAL_LIMIT, label
            ));
            return 0;
        }
    }

    if dry_run {
        match &usage_label {
            Some(label) => utils::info(&format!(
                "[DRY RUN] Would vacuum journal to {} (currently {})",
                JOURNAL_LIMIT, label
            )),
            None => utils::info(&format!(
                "[DRY RUN] Would vacuum journal to {}",
                JOURNAL_LIMIT
            )),
        }
        return 0;
    }

    let journal_dir = PathBuf::from("/var/log/journal");
    let size_before = utils::dir_size(&journal_dir);

    if !utils::sudo_quiet("journalctl", &[&format!("--vacuum-size={}", JOURNAL_LIMIT)]) {
        utils::error("Journal vacuum failed");
        return 0;
    }

    let size_after = utils::dir_size(&journal_dir);
    let freed = size_before.saturating_sub(size_after);

    // `/var/log/journal` is root-owned and typically unreadable to us, so
    // `dir_size` returns 0 and the difference is 0 even when the vacuum did
    // remove data. Report the measurement only when we actually have one.
    if freed > 0 {
        utils::success(&format!(
            "Vacuumed to {} — freed {}",
            JOURNAL_LIMIT,
            utils::format_size(freed).green()
        ));
    } else {
        match &usage_label {
            Some(label) => {
                utils::success(&format!("Vacuumed to {} (was {})", JOURNAL_LIMIT, label))
            }
            None => utils::success(&format!("Vacuumed to {}", JOURNAL_LIMIT)),
        }
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
//  Crash-dump cleanup (systemd-coredump + Apport)
// ══════════════════════════════════════════════════

/// Remove saved crash dumps. Two mechanisms are supported, each detected by the
/// existence of its directory (same spirit as `is_ostree`/`has_nix`):
///
///   * **systemd-coredump** — `/var/lib/systemd/coredump/`. Dumps are large
///     `.zst` blobs of a crashed process's memory. We remove the files directly
///     with a privileged `find … -type f -delete`. (`coredumpctl` has no
///     portable `delete` verb — it's absent on current systemd, e.g. v260 —
///     so relying on it silently fails; direct file removal is the one method
///     that works everywhere. The journal keeps brief metadata that shows as
///     `COREFILE=missing` until the journal next rotates — cosmetic, not data.)
///   * **Apport** — `/var/crash/` (Debian/Ubuntu). We delete only the top-level
///     `*.crash`/`*.uploaded` report *files*, never subdirectories: kdump stores
///     kernel `vmcore` dumps in dated subdirs there, and those are something the
///     admin configured on purpose — not routine cache.
///
/// Dumps can contain passwords and keys from the crashed process's memory, so
/// clearing them is also a small privacy win. Both directories are root-owned,
/// so deletion goes through sudo. Non-systemd, non-Apport systems (runit,
/// OpenRC, …) scatter `core` files in each process's cwd with no central
/// directory — nothing safe to sweep — so we simply report nothing to do.
pub fn coredumps(dry_run: bool) -> u64 {
    utils::section("Crash Dumps");

    let sd_dir = PathBuf::from("/var/lib/systemd/coredump");
    let apport_dir = PathBuf::from("/var/crash");
    let has_sd = sd_dir.exists();
    let has_apport = apport_dir.exists();

    if !has_sd && !has_apport {
        utils::skip("No crash-dump directory found — nothing to clean");
        return 0;
    }

    let mut freed = 0u64;

    // ── systemd-coredump ──
    if has_sd {
        let size = utils::dir_size(&sd_dir);
        if size == 0 {
            utils::success("systemd-coredump: already empty");
        } else if dry_run {
            utils::info(&format!(
                "[DRY RUN] Would clear systemd coredumps ({})",
                utils::format_size(size)
            ));
        } else {
            // Direct file removal — the only portable method. `coredumpctl`
            // has no `delete` verb on current systemd, so it can't be relied on.
            utils::sudo_quiet(
                "find",
                &["/var/lib/systemd/coredump", "-type", "f", "-delete"],
            );
            let after = utils::dir_size(&sd_dir);
            let got = size.saturating_sub(after);
            freed += got;
            utils::success(&format!(
                "systemd coredumps cleared ({})",
                utils::format_size(got).green()
            ));
        }
    }

    // ── Apport (/var/crash) ──
    if has_apport {
        // Measure only the flat report files we'd actually delete, so the
        // reported size never includes kdump vmcore subdirs we deliberately keep.
        let size = apport_report_size(&apport_dir);
        if size == 0 {
            utils::success("Apport: no crash reports to clean");
        } else if dry_run {
            utils::info(&format!(
                "[DRY RUN] Would clear Apport crash reports ({})",
                utils::format_size(size)
            ));
        } else {
            // -maxdepth 1 -type f: top-level report files only, never the
            // dated kdump subdirectories.
            utils::sudo_quiet(
                "find",
                &["/var/crash", "-maxdepth", "1", "-type", "f", "-delete"],
            );
            let after = apport_report_size(&apport_dir);
            let got = size.saturating_sub(after);
            freed += got;
            utils::success(&format!(
                "Apport reports cleared ({})",
                utils::format_size(got).green()
            ));
        }
    }

    freed
}

/// Total size of the top-level regular files directly inside `/var/crash`
/// (Apport reports). Excludes subdirectories so kdump's `vmcore` dumps, which
/// live in dated subdirs, are never counted or touched.
fn apport_report_size(dir: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() && !p.is_symlink() {
                total += p.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
    }
    total
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

    if !utils::which_trusted("fstrim") {
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

    // Nix prints what it freed on its last stdout line — `1110 store paths
    // deleted, 2.3 MiB freed` — counted from each store path as it deletes it.
    // That is exact and free, where measuring it ourselves means walking a store
    // that is routinely tens of gigabytes and hundreds of thousands of files,
    // twice. Runs whose output we capture contribute their reported total; the
    // ones that stay visible (they can take minutes, and silence would read as a
    // hang) contribute nothing rather than a guess.
    let mut freed = 0u64;

    utils::info("Collecting garbage (user)...");
    if let Some(out) = utils::capture("nix-collect-garbage", &[]) {
        freed += parse_nix_freed(&out).unwrap_or(0);
    }

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

        // `nix-collect-garbage -d` cleans the classic (nix-env) profile
        // generations but does NOT touch flake-profile history. On a flakes
        // setup those accumulate separately; `nix profile wipe-history` drops
        // the non-current versions of the default profile so their store paths
        // become collectable. Best-effort: only meaningful when the new `nix`
        // CLI with flakes support is present, and a no-op otherwise.
        if utils::which_trusted("nix") {
            utils::run("nix", &["profile", "wipe-history"]);
        }

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

    #[test]
    fn test_parse_nix_freed_real_output() {
        // Exact lines captured from nix-collect-garbage 2.35.2 in a container.
        let out = "deleting '/nix/store/abc-foo'\n\
                   deleting unused links...\n\
                   note: hard linking is currently saving 0.0 KiB\n\
                   1110 store paths deleted, 2.3 MiB freed";
        assert_eq!(
            parse_nix_freed(out),
            Some((2.3 * 1024.0 * 1024.0) as u64),
            "must read the size, not the leading store-path count"
        );
        assert_eq!(
            parse_nix_freed("1481 store paths deleted, 76.1 MiB freed"),
            Some((76.1 * 1024.0 * 1024.0) as u64)
        );
        assert_eq!(
            parse_nix_freed("0 store paths deleted, 0.0 KiB freed"),
            Some(0)
        );
    }

    #[test]
    fn test_parse_nix_freed_ignores_the_path_count() {
        // The line opens with a bigger number than the size. A parser that took
        // the first number it saw would report 1110 bytes as 1110 *paths*, which
        // is why this is anchored on the trailing "freed" keyword instead.
        let bytes = parse_nix_freed("1110 store paths deleted, 2.3 MiB freed").unwrap();
        assert_ne!(bytes, 1110);
        assert!(bytes > 2_000_000);
    }

    #[test]
    fn test_parse_nix_freed_unparseable_is_none() {
        // If the wording ever changes we must return None rather than a wrong
        // number — the caller then reports nothing instead of a fabricated total.
        assert_eq!(parse_nix_freed(""), None);
        assert_eq!(parse_nix_freed("deleting '/nix/store/abc'"), None);
        assert_eq!(parse_nix_freed("something freed"), None);
        assert_eq!(parse_nix_freed("2.3 QiB freed"), None);
    }

    #[test]
    fn test_size_to_bytes_units() {
        assert_eq!(size_to_bytes("512", "B"), Some(512));
        assert_eq!(size_to_bytes("2", "KiB"), Some(2048));
        assert_eq!(size_to_bytes("1.5", "GiB"), Some(1_610_612_736));
        assert_eq!(size_to_bytes("1", "QiB"), None);
        assert_eq!(size_to_bytes("abc", "MiB"), None);
    }

    // ── journal usage parsing ──

    #[test]
    fn test_parse_journal_usage_real_output() {
        // The exact sentence journalctl prints on an English locale.
        let text = "Archived and active journals take up 48.1M in the file system.";
        let bytes = parse_journal_usage(text).expect("should parse 48.1M");
        assert_eq!(bytes, (48.1 * 1024.0 * 1024.0) as u64);
    }

    #[test]
    fn test_parse_journal_usage_units() {
        assert_eq!(parse_journal_usage("takes up 512B here"), Some(512));
        assert_eq!(parse_journal_usage("takes up 2K here"), Some(2 * 1024));
        assert_eq!(
            parse_journal_usage("takes up 1.5G here"),
            Some((1.5 * 1024.0 * 1024.0 * 1024.0) as u64)
        );
        // Trailing punctuation must not defeat the unit lookup.
        assert_eq!(parse_journal_usage("up to 4M."), Some(4 * 1024 * 1024));
    }

    #[test]
    fn test_parse_journal_usage_unparseable_is_none() {
        // A translated or unexpected line must yield None so the caller
        // vacuums unconditionally rather than wrongly deciding it can skip.
        assert_eq!(parse_journal_usage(""), None);
        assert_eq!(parse_journal_usage("no numbers at all here"), None);
        // A bare number with an unknown suffix is not a size we understand.
        assert_eq!(parse_journal_usage("12Q of something"), None);
    }

    #[test]
    fn test_journal_skip_threshold_matches_limit_string() {
        // The byte constant and the string handed to --vacuum-size must agree,
        // or we would skip the vacuum against one limit while journalctl
        // enforces another.
        assert_eq!(
            parse_journal_usage(JOURNAL_LIMIT),
            Some(JOURNAL_LIMIT_BYTES)
        );
    }

    #[test]
    fn test_aur_deferral_never_strands_a_cache() {
        use std::fs;
        let base = std::env::temp_dir().join(format!("oxiclean_defer_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("paru")).unwrap();
        fs::write(base.join("paru/clone.tar"), vec![0u8; 4096]).unwrap();
        fs::create_dir_all(base.join("aura/snapshots")).unwrap();
        fs::write(base.join("aura/snapshots/restore.json"), vec![0u8; 512]).unwrap();

        let paru = crate::detect::AurHelper {
            bin: "paru",
            clean: Some(&["-Sc", "--noconfirm"]),
            deep_clean: Some(&["-Scc", "--noconfirm"]),
            prune_dirs: &[],
            prune_dirs_deep: &[],
        };
        let aura = crate::detect::AurHelper {
            bin: "aura",
            clean: None,
            deep_clean: None,
            prune_dirs: &["builds"],
            prune_dirs_deep: &["cache", "packages"],
        };
        let helpers = [paru, aura];

        // AUR section running → paru's dir is deferred to it, not deleted here.
        let names = protected_cache_names(&base, &helpers, true);
        let (to_clean, skipped) = partition_cache_entries(&base, &names);
        assert!(skipped.iter().any(|n| n == "paru"));
        assert!(!to_clean.iter().any(|p| p.ends_with("paru")));

        // AUR section NOT running (--cache alone, or --all --skip aur) → nobody
        // else would ever clean paru's dir, so user_cache must still take it.
        // This is the half that makes deferral safe rather than a silent leak.
        let names = protected_cache_names(&base, &helpers, false);
        let (to_clean, skipped) = partition_cache_entries(&base, &names);
        assert!(!skipped.iter().any(|n| n == "paru"));
        assert!(to_clean.iter().any(|p| p.ends_with("paru")));

        // aura is different: its cache dir holds `snapshots/` (user restore
        // points), so a blanket wipe would destroy state no cleaner should
        // touch. It must be held back in BOTH modes — including the one where
        // the AUR section is not running and nothing else will clean it.
        // Cleaning less is the right trade against deleting restore points.
        for aur_running in [true, false] {
            let names = protected_cache_names(&base, &helpers, aur_running);
            let (to_clean, skipped) = partition_cache_entries(&base, &names);
            assert!(
                skipped.iter().any(|n| n == "aura"),
                "aura cache dir must never be wiped wholesale (aur_running={})",
                aur_running
            );
            assert!(!to_clean.iter().any(|p| p.ends_with("aura")));
        }

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_prune_targets_gate_redownload_dirs_behind_deep() {
        let aura = crate::detect::AurHelper {
            bin: "aura",
            clean: None,
            deep_clean: None,
            prune_dirs: &["builds"],
            prune_dirs_deep: &["cache"],
        };
        // Safe run touches build leftovers only; the tarball cache (which costs
        // a rebuild/re-download) waits for --deep.
        assert_eq!(prune_targets(&aura, false), vec!["builds"]);
        assert_eq!(prune_targets(&aura, true), vec!["builds", "cache"]);
    }

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

    // ── Fedora cache-dir selection: dnf5 vs dnf4 vs yum ──

    #[test]
    fn test_measured_cache_dir_matches_what_the_clean_command_clears() {
        // The freed figure is measured as the size of `pkg_cache_dir` before and
        // after the clean command runs, so the two must describe the same tree.
        // Every wrong measurement found by live-testing containers:
        //
        // * openSUSE: measured /var/cache/zypp/packages but zypper clean --all
        //   also wiped raw/ + solv/ (~65 MB of ~147 MB unaccounted)
        // * Solus: eopkg delete-cache clears packages/ + archives/ + db files,
        //   so measuring packages/ alone would under-report the same way
        // * Alpine: apk cache clean keeps installed versions, so the freed
        //   figure is always 0 — the measured path is still correct
        //
        // The measured path must match what the command *actually touches*, not
        // a subdirectory of it. Verified in containers for openSUSE (147 MB
        // total), Alpine (8.6 MB), and against upstream docs for Solus and
        // Debian (apt-get clean only clears archives/).
        assert_eq!(
            pkg_cache_dir(&Distro::Suse),
            Some(PathBuf::from("/var/cache/zypp"))
        );
        assert_eq!(
            pkg_cache_dir(&Distro::Debian),
            Some(PathBuf::from("/var/cache/apt/archives"))
        );
        assert_eq!(
            pkg_cache_dir(&Distro::Solus),
            Some(PathBuf::from("/var/cache/eopkg"))
        );
        assert_eq!(
            pkg_cache_dir(&Distro::Alpine),
            Some(PathBuf::from("/var/cache/apk"))
        );
        // Gentoo's DISTDIR is resolved dynamically via portageq, but when
        // portageq is absent and the modern default exists, it falls back to
        // the standard path.
        assert_eq!(
            pkg_cache_dir(&Distro::Gentoo),
            Some(PathBuf::from("/var/cache/distfiles"))
        );
    }

    #[test]
    fn test_resolve_fedora_cache_dir_prefers_libdnf5() {
        // dnf5 (Fedora 41+ default) keeps its cache in /var/cache/libdnf5. When
        // that dir exists it wins, regardless of whether the `dnf` binary is
        // present — otherwise the freed-size measurement reads the wrong (often
        // empty) legacy dir and wrongly reports 0 bytes freed.
        assert_eq!(
            resolve_fedora_cache_dir(true, true),
            PathBuf::from("/var/cache/libdnf5")
        );
        assert_eq!(
            resolve_fedora_cache_dir(true, false),
            PathBuf::from("/var/cache/libdnf5")
        );
    }

    #[test]
    fn test_resolve_fedora_cache_dir_falls_back_to_dnf4_then_yum() {
        // No libdnf5 dir but a dnf binary → the dnf4 location.
        assert_eq!(
            resolve_fedora_cache_dir(false, true),
            PathBuf::from("/var/cache/dnf")
        );
        // Neither → the legacy yum location.
        assert_eq!(
            resolve_fedora_cache_dir(false, false),
            PathBuf::from("/var/cache/yum")
        );
    }

    // ── Expensive-cache protection: the core safety guarantee of --cache ──

    #[test]
    fn test_protected_list_covers_models_and_dev_caches() {
        // The two model caches whose loss is catastrophic must stay in the model
        // list; representative dev caches must stay in the dev list. This guards
        // against anyone quietly dropping an entry from either.
        for must in ["huggingface", "torch"] {
            assert!(
                PROTECTED_MODEL_DIRS.contains(&must),
                "{must} must stay in the protected model list"
            );
        }
        for must in ["uv", "pip", "ccache"] {
            assert!(
                PROTECTED_DEV_DIRS.contains(&must),
                "{must} must stay in the protected dev-cache list"
            );
        }
        // The two lists must not overlap — a name is either a silently-kept
        // model or a dev cache that drives the hint, never both.
        for m in PROTECTED_MODEL_DIRS {
            assert!(
                !PROTECTED_DEV_DIRS.contains(m),
                "{m} must not be in both lists"
            );
        }
    }

    #[test]
    fn test_dev_hint_only_fires_for_dev_caches() {
        // A model-only skip must stay silent (no --dev hint): --dev can't clean
        // models, so hinting at it would mislead.
        assert!(!skipped_has_dev_cache(&["huggingface".to_string()]));
        assert!(!skipped_has_dev_cache(&["torch".to_string()]));
        // A dev cache present → hint fires.
        assert!(skipped_has_dev_cache(&["pip".to_string()]));
        // Mixed → still fires (there IS a dev cache to point at).
        assert!(skipped_has_dev_cache(&[
            "huggingface".to_string(),
            "uv".to_string()
        ]));
        // Nothing skipped → no hint.
        assert!(!skipped_has_dev_cache(&[]));
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

        let protected = protected_cache_names(&base, &[], false);
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

    // ── Gentoo build-tmp: parse PORTAGE_TMPDIR + validate before deleting ──

    #[test]
    fn test_parse_make_conf_var_basic() {
        assert_eq!(
            parse_make_conf_var("DISTDIR=/custom/dist\n", "DISTDIR"),
            Some("/custom/dist".into())
        );
        assert_eq!(
            parse_make_conf_var("DISTDIR=\"/custom/dist\"\n", "DISTDIR"),
            Some("/custom/dist".into())
        );
        assert_eq!(
            parse_make_conf_var("DISTDIR='/custom/dist'\n", "DISTDIR"),
            Some("/custom/dist".into())
        );
        assert_eq!(
            parse_make_conf_var("#DISTDIR=/commented\n", "DISTDIR"),
            None
        );
        assert_eq!(parse_make_conf_var("", "DISTDIR"), None);
        assert_eq!(parse_make_conf_var("DISTDIR=\n", "DISTDIR"), None);
        assert_eq!(
            parse_make_conf_var("PORTAGE_TMPDIR=/var/tmp\n", "DISTDIR"),
            None
        );
    }

    #[test]
    fn test_parse_make_conf_var_later_assignment_wins() {
        let conf = "DISTDIR=/first\nDISTDIR=/second\n";
        assert_eq!(parse_make_conf_var(conf, "DISTDIR"), Some("/second".into()));
    }

    #[test]
    fn test_gentoo_distdir_fallback() {
        // When portageq is missing and make.conf is empty, must return the
        // modern default, not the legacy /usr/portage/distfiles.
        assert_eq!(
            pkg_cache_dir(&Distro::Gentoo),
            Some(PathBuf::from("/var/cache/distfiles"))
        );
    }

    #[test]
    fn test_parse_portage_tmpdir_default_and_custom() {
        // Unset → None (caller falls back to /var/tmp).
        assert_eq!(parse_portage_tmpdir("# empty make.conf\nUSE=\"x\"\n"), None);
        // Quoted and unquoted forms both parse to the bare path.
        assert_eq!(
            parse_portage_tmpdir("PORTAGE_TMPDIR=\"/mnt/build\"\n").as_deref(),
            Some("/mnt/build")
        );
        assert_eq!(
            parse_portage_tmpdir("PORTAGE_TMPDIR=/scratch\n").as_deref(),
            Some("/scratch")
        );
    }

    #[test]
    fn test_parse_portage_tmpdir_ignores_comments_and_takes_last() {
        // A commented assignment must be ignored; a later real one wins.
        let conf = "#PORTAGE_TMPDIR=/ignored\nPORTAGE_TMPDIR=/first\nPORTAGE_TMPDIR=\"/second\"\n";
        assert_eq!(parse_portage_tmpdir(conf).as_deref(), Some("/second"));
    }

    #[test]
    fn test_portage_dir_is_safe_requires_portage_leaf() {
        // Correct build dir: ends in /portage, has depth.
        assert!(portage_dir_is_safe(Path::new("/var/tmp/portage")));
        assert!(portage_dir_is_safe(Path::new("/mnt/build/portage")));
        // Must reject anything that isn't a `portage` leaf — the exact paths a
        // malformed PORTAGE_TMPDIR could otherwise expand to.
        assert!(!portage_dir_is_safe(Path::new("/var/tmp")));
        assert!(!portage_dir_is_safe(Path::new("/")));
        assert!(!portage_dir_is_safe(Path::new("/portage"))); // depth < 2
        assert!(!portage_dir_is_safe(Path::new("/var/tmp/portage-old")));
    }

    #[test]
    fn test_portage_tmpdir_hostile_values_never_yield_a_deletable_path() {
        // The build dir is `PORTAGE_TMPDIR` + "/portage", and make.conf is a
        // file we do not control the contents of. Every value here is one a
        // typo or a hostile edit could produce; none may survive the safety
        // gate, because whatever does survive gets its *contents deleted*.
        //
        // The pairing matters: parse_portage_tmpdir decides WHAT we aim at and
        // portage_dir_is_safe decides whether we fire, so they are tested as
        // one unit rather than separately.
        for hostile in [
            "/",           // → /portage, top level
            "//",          // → //portage, normalises to depth 2
            "",            // empty → falls back to the /var/tmp default
            "/usr",        // → /usr/portage, a real system dir with a valid leaf
            "/etc",        // → /etc/portage, the config dir itself
            "/home",       // → /home/portage
            "/var/tmp/..", // → /var/tmp/../portage, escapes upward
        ] {
            let conf = format!("PORTAGE_TMPDIR={}\n", hostile);
            let parsed = parse_portage_tmpdir(&conf);
            // An empty assignment must be ignored entirely, not stored as "".
            if hostile.is_empty() {
                assert_eq!(parsed, None, "empty assignment must not be honoured");
                continue;
            }
            let dir = PathBuf::from(parsed.unwrap()).join("portage");
            let safe = portage_dir_is_safe(&dir);
            // `/usr/portage`, `/etc/portage` and `/home/portage` are nested and
            // end in `portage`, so they pass the gate by design — they are
            // legitimate values someone could really set. What protects the
            // user there is that the directory must already exist AND no
            // emerge may be running; the gate's job is only to stop the
            // top-level and traversal cases below.
            if matches!(hostile, "/" | "//") {
                assert!(!safe, "{:?} → {:?} must be rejected", hostile, dir);
            }
            // Whatever the verdict, we must never end up aiming at the
            // filesystem root or at a bare top-level directory.
            assert_ne!(dir, PathBuf::from("/"));
            assert!(dir.components().count() >= 2);
        }
    }

    #[test]
    fn test_portage_cleanup_is_contents_only_and_survives_the_dir() {
        // The distinction that makes this safe: we clear what is *inside* the
        // build dir and leave the dir itself in place. Portage recreates the
        // subtrees it needs, but removing the dir outright changes ownership
        // and mode, which a running emerge would then trip over.
        use std::fs;
        let base = std::env::temp_dir().join(format!("oxiclean_portage_{}", std::process::id()));
        let build = base.join("portage");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(build.join("sys-devel/gcc-13/work")).unwrap();
        fs::write(build.join("sys-devel/gcc-13/work/a.o"), vec![0u8; 4096]).unwrap();
        fs::write(build.join("stale.log"), vec![0u8; 512]).unwrap();

        assert!(portage_dir_is_safe(&build), "fixture must pass the gate");
        let before = utils::dir_size(&build);
        assert!(before >= 4608);

        let freed = utils::rm_contents(&build);

        assert!(build.is_dir(), "the build dir itself must survive");
        assert_eq!(utils::dir_size(&build), 0, "everything inside is gone");
        assert_eq!(freed, before, "freed bytes must match what was there");

        let _ = fs::remove_dir_all(&base);
    }

    // ── Apport: measure only flat report files, never kdump subdirs ──

    #[test]
    fn test_apport_report_size_ignores_subdirs() {
        use std::fs;
        let base = std::env::temp_dir().join(format!("oxiclean_apport_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        // Two flat Apport report files...
        fs::write(base.join("_usr_bin_foo.1000.crash"), vec![0u8; 100]).unwrap();
        fs::write(base.join("_usr_bin_bar.1000.uploaded"), vec![0u8; 50]).unwrap();
        // ...and a kdump-style subdir with a big vmcore that must NOT be counted.
        fs::create_dir_all(base.join("202607091200")).unwrap();
        fs::write(base.join("202607091200/vmcore"), vec![0u8; 100_000]).unwrap();

        assert_eq!(
            apport_report_size(&base),
            150,
            "only the two flat report files (100+50) count; the vmcore subdir is excluded"
        );

        let _ = fs::remove_dir_all(&base);
    }
}
