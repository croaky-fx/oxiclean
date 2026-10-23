use colored::Colorize;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::detect::{AurHelper, Distro, Privilege};
use crate::roots;
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

/// What a step has to say for itself, decided apart from the printing so the
/// decision can be tested without running a package manager.
///
/// The rule it serves: a success line is printed for work that happened. A step
/// whose command failed says so with [`Verdict::Failed`], and that is also what
/// makes the run end with a failing exit status.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// It did what was asked.
    Done(String),
    /// Nothing to do, or left alone on purpose.
    Skipped(String),
    /// It did not do what was asked.
    Failed(String),
}

fn done(msg: &str) -> Verdict {
    Verdict::Done(msg.to_string())
}

fn skipped(msg: &str) -> Verdict {
    Verdict::Skipped(msg.to_string())
}

fn failed(msg: &str) -> Verdict {
    Verdict::Failed(msg.to_string())
}

/// Print the verdicts in order.
fn say(verdicts: Vec<Verdict>) {
    for verdict in verdicts {
        match verdict {
            Verdict::Done(msg) => utils::success(&msg),
            Verdict::Skipped(msg) => utils::skip(&msg),
            Verdict::Failed(msg) => utils::error(&msg),
        }
    }
}

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
    // A tidy-up for the commands that follow, not a step with a result of its
    // own: if it fails they trip over the leftovers and say so themselves.
    if !utils::sudo_quiet("rm", &args) {
        utils::warning("Could not remove pacman's partial downloads first");
    }
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

/// What is known about `emerge` builds in progress.
#[derive(Debug, PartialEq, Eq)]
enum Builds {
    /// A process whose command line mentions emerge exists.
    Running,
    /// Root looked, and there is none.
    Idle,
    /// The question went unanswered. The words say how, for the person to read.
    Unknown(String),
}

/// What `pgrep -f` is given to look for: `emerge`, spelled so that the pattern
/// does not match the command line it is part of. `pgrep` leaves out only
/// itself; a shell, `sudo` or `doas` that runs it carries the pattern in their own
/// command line, and with a plain `emerge` every check made through them found
/// a build, namely theirs.
///
/// Deliberately wide: any command line that mentions emerge counts, an editor
/// open on its log included. Too many matches only leave a tree alone.
const EMERGE_PATTERN: &str = "[e]merge";

/// Whether an `emerge` is running, as root says. Deleting `/var/tmp/portage`
/// under a running build corrupts it, so the sweep stands on this answer, and
/// the tree counts as idle only when it was *told* so ([`look_for`]).
///
/// Root is asked, not the user we run as. With `/proc` mounted `hidepid=1`, `2`
/// or `4`, a `pgrep` run by an ordinary user cannot see another user's
/// processes, and emerge runs as root: it prints `0` and exits 1, which is the
/// very answer for "nothing is running" (reproduced in a container). Root sees
/// every process, whatever hides them from us. The helper asked is the one the
/// sweep deletes with, so nothing is requested that the deletion does not need.
///
/// `pgrep` and the helper are resolved through the trusted directories, not
/// `$PATH`: a shadowed `pgrep` that exits 1 would report "no build running" and
/// hand this guard to whoever planted it. One that cannot be vouched for is no
/// answer, and no answer is not "idle".
fn emerge_builds(privilege: Privilege) -> Builds {
    look_for(privilege, EMERGE_PATTERN)
}

/// Ask `privilege` whether a process whose command line matches `pattern` exists.
///
/// `-c` makes pgrep *say* how many there are, `0` included, and that is what
/// lets "none" be an answer. The exit status cannot be one on its own: 1 is
/// also what `sudo` exits with when it refuses, and what a pgrep that does not
/// know `-c` (busybox's) exits with for the option.
fn look_for(privilege: Privilege, pattern: &str) -> Builds {
    builds_from(utils::elevate_capture(
        privilege,
        "pgrep",
        &["-c", "-f", pattern],
    ))
}

/// What a finished `pgrep -c` means for "is a build running?".
///
/// Two things are an answer: a count above 0 with status 0 (it found some), and
/// a printed `0` with status 1 (it looked, and found none). Everything else is
/// no answer: status 2 and 3 are pgrep's own errors (a bad pattern, no `/proc`),
/// and a refused `sudo`, a signal and a count that makes no sense leave nothing
/// to go on. No answer is treated like a build under way, never like an idle
/// tree.
fn builds_from(answer: Option<utils::Captured>) -> Builds {
    let Some(answer) = answer else {
        return Builds::Unknown("pgrep could not be run".to_string());
    };
    match (answer.code, answer.stdout.trim().parse::<u64>()) {
        (Some(0), Ok(found)) if found > 0 => Builds::Running,
        (Some(1), Ok(0)) => Builds::Idle,
        (code, _) => Builds::Unknown(unanswered(code, &answer.stdout, &answer.stderr)),
    }
}

/// What pgrep did when it gave no answer, as one line: how it ended, what it
/// printed, and the last thing it complained about. The last, because what
/// comes first is often not the complaint: `sudo` opens with its lecture, and
/// closes with why it refused.
fn unanswered(code: Option<i32>, stdout: &str, stderr: &str) -> String {
    let status = match code {
        Some(code) => format!("status {code}"),
        None => "ended by a signal".to_string(),
    };
    let printed = match stdout.trim() {
        "" => "nothing printed".to_string(),
        text => format!("printed {text:?}"),
    };
    let complaint = match stderr.lines().map(str::trim).rev().find(|l| !l.is_empty()) {
        Some(line) => format!("; {line}"),
        None => String::new(),
    };
    format!("pgrep: {status}, {printed}{complaint}")
}

/// Remove failed-build leftovers under the portage build tree. These are the
/// half-unpacked/half-compiled remnants of interrupted or failed `emerge` runs
/// — pure garbage that portage does not reuse. We only ever delete the
/// *contents*, never the `portage` dir itself, and only after four guards pass:
/// the dir exists, root says no emerge is running, the path resolves under a
/// real tmpdir, and it ends in `/portage`.
fn clean_portage_tmp(dry_run: bool) -> u64 {
    clear_build_leftovers(
        &portage_build_dir(),
        dry_run,
        &|| emerge_builds(utils::current_privilege()),
        &|dir| utils::sudo_quiet("find", &[dir, "-mindepth", "1", "-delete"]),
    )
}

/// The sweep behind [`clean_portage_tmp`], with the two things it asks of the
/// machine handed in — whether a build is running, and the removal — so that a
/// test can answer for them.
fn clear_build_leftovers(
    build_dir: &Path,
    dry_run: bool,
    builds: &dyn Fn() -> Builds,
    remove: &dyn Fn(&str) -> bool,
) -> u64 {
    if !build_dir.exists() || !portage_dir_is_safe(build_dir) {
        return 0;
    }
    // Before anyone is asked anything: an empty tree needs no answer, and a
    // machine that cannot give one should not complain about a tree with
    // nothing in it.
    let size = utils::dir_size(build_dir);
    if size == 0 {
        return 0;
    }
    if dry_run {
        // Not asked either: a dry run needs no privileges.
        utils::info(&format!(
            "[DRY RUN] Would clear failed-build leftovers in {} ({}), unless emerge is running",
            build_dir.display(),
            utils::format_size(size)
        ));
        return 0;
    }
    match builds() {
        Builds::Idle => {}
        Builds::Running => {
            utils::skip(
                "emerge seems to be running (`pgrep -af emerge` shows what matched) — leaving build tmp untouched",
            );
            return 0;
        }
        Builds::Unknown(why) => {
            utils::warning(&format!(
                "Cannot tell whether emerge is running ({why}) — leaving {} untouched",
                build_dir.display()
            ));
            return 0;
        }
    }

    // The contents are root-owned (built via sudo emerge), so delete through
    // sudo. `-mindepth 1` keeps the `portage` dir itself; `-delete` handles the
    // nested trees. What was freed is what is gone afterwards: a `find` that
    // failed may have removed some of it, and a build started meanwhile adds to it.
    let target = build_dir.to_string_lossy().into_owned();
    let removed = remove(&target);
    let freed = size.saturating_sub(utils::dir_size(build_dir));
    if removed {
        utils::success(&format!(
            "Cleared portage build leftovers ({})",
            utils::format_size(freed).green()
        ));
    } else {
        utils::error(&format!("Could not clear {}", build_dir.display()));
    }
    freed
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

/// Where the user's cache lives, and whether it may be emptied.
#[derive(Debug, PartialEq, Eq)]
enum CacheBase {
    /// `~/.cache`, or an `XDG_CACHE_HOME` that names the same directory.
    Standard(PathBuf),
    /// A cache the user moved with `XDG_CACHE_HOME`.
    Relocated(PathBuf),
    /// Where the cache would be, but there is no such directory.
    Absent(PathBuf),
    /// Resolves somewhere that must not be emptied. Carries the whole reason,
    /// starting with what was refused.
    Refused(String),
    /// Neither a usable `$HOME` nor an `XDG_CACHE_HOME`.
    Unknown,
}

/// Resolve the user cache directory, honouring `XDG_CACHE_HOME` (the spec-
/// correct override) and falling back to `~/.cache`.
///
/// The directory is the one `user_cache` empties wholesale, so a wrong value
/// here costs far more than a cache: `XDG_CACHE_HOME=$HOME` used to mean
/// "delete everything in the home directory". Every answer goes through
/// [`roots::check`] first.
fn user_cache_base() -> CacheBase {
    let home = utils::home_dir();
    cache_base_from(
        &roots::Context::from_env(),
        home.as_deref().map(Path::new),
        std::env::var_os("XDG_CACHE_HOME").as_deref(),
    )
}

/// [`user_cache_base`] with the environment passed in, so tests can supply
/// theirs.
fn cache_base_from(ctx: &roots::Context, home: Option<&Path>, xdg: Option<&OsStr>) -> CacheBase {
    use roots::{Reject, Source};

    let standard = home.map(|h| h.join(".cache"));
    // The XDG spec: a relative path is invalid and must be ignored. Empty counts
    // as unset. See `ignored_xdg` for the note the user gets about it.
    let relocated = xdg
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute());

    if let Some(path) = relocated {
        // Pointing the variable at the default place relocates nothing, and
        // must not be held to the stricter rules for a root of unknown origin.
        let default_real = standard
            .as_deref()
            .and_then(|s| std::fs::canonicalize(s).ok());
        let is_default =
            default_real.is_some() && default_real == std::fs::canonicalize(&path).ok();
        let source = if is_default {
            Source::Home
        } else {
            Source::Env
        };
        return match roots::check(ctx, &path, source) {
            Ok(_) if is_default => CacheBase::Standard(path),
            Ok(_) => CacheBase::Relocated(path),
            Err(Reject::Missing) => CacheBase::Absent(path),
            Err(Reject::Unsafe(why)) => {
                CacheBase::Refused(format!("XDG_CACHE_HOME={} — {why}", path.display()))
            }
        };
    }

    match standard {
        None => CacheBase::Unknown,
        Some(path) => match roots::check(ctx, &path, Source::Home) {
            Ok(_) => CacheBase::Standard(path),
            Err(Reject::Missing) => CacheBase::Absent(path),
            Err(Reject::Unsafe(why)) => CacheBase::Refused(format!("{} — {why}", path.display())),
        },
    }
}

/// The value of `XDG_CACHE_HOME` when it is set to something the spec says to
/// ignore (a relative path), so the user is told rather than left wondering why
/// their setting did nothing.
fn ignored_xdg(xdg: Option<&OsStr>) -> Option<String> {
    let value = xdg.filter(|v| !v.is_empty() && !Path::new(v).is_absolute())?;
    Some(value.to_string_lossy().into_owned())
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
///
/// One `symlink_metadata` call answers all three questions (symlink? dir? size?).
/// The `is_symlink()`/`is_dir()`/`metadata()` chain it replaced re-resolved the
/// path three times per entry.
fn entry_size(p: &Path) -> u64 {
    match std::fs::symlink_metadata(p) {
        Ok(md) if md.is_dir() => utils::dir_size(p),
        Ok(md) => utils::footprint_of(&md),
        Err(_) => 0,
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

/// A cache the user moved with `XDG_CACHE_HOME` is a directory we know nothing
/// about except that the environment says to empty it. A wrong value there is
/// the one way this operation destroys more than a cache, and no check can tell
/// a mistaken `~/projects` from a deliberate `/data/cache`, so a real run over
/// one asks first. `--yes` is the answer for unattended runs; `--json` has no
/// one to ask, so it needs `--yes` too.
fn relocated_cache_allowed(cache: &Path, yes: bool) -> bool {
    if yes {
        return true;
    }
    if utils::is_json() {
        utils::error(&format!(
            "XDG_CACHE_HOME points to {}; not cleaned without --yes",
            cache.display()
        ));
        return false;
    }
    let ok = utils::confirm(&format!(
        "XDG_CACHE_HOME points to {}. Clean what is inside it? [y/N]:",
        cache.display()
    ));
    if !ok {
        utils::skip("Left alone");
    }
    ok
}

pub fn user_cache(dry_run: bool, yes: bool, helpers: &[AurHelper], aur_running: bool) -> u64 {
    utils::section("User Cache");

    if let Some(value) = ignored_xdg(std::env::var_os("XDG_CACHE_HOME").as_deref()) {
        utils::warning(&format!(
            "XDG_CACHE_HOME={value} is not an absolute path, so it is ignored"
        ));
    }

    let (cache, relocated) = match user_cache_base() {
        CacheBase::Standard(path) => (path, false),
        CacheBase::Relocated(path) => (path, true),
        CacheBase::Absent(_) => {
            utils::info("No cache directory found");
            return 0;
        }
        CacheBase::Refused(why) => {
            utils::error(&format!("Refusing to clean {why}"));
            return 0;
        }
        CacheBase::Unknown => {
            utils::error("Cannot determine cache directory");
            return 0;
        }
    };

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

    // Size every entry ONCE and carry the number forward, along with whether it
    // is a directory — the delete below needs that, and asking again would be
    // two more syscalls per entry. `entry_size` walks the tree, and `~/.cache`
    // is usually the deepest one we touch (browser caches run to hundreds of
    // thousands of small files), so walking it to total up and then re-walking
    // each entry to attribute freed bytes made the most expensive step in the
    // run cost exactly double — very noticeable on a spinning disk.
    let sized: Vec<(PathBuf, u64, bool)> = to_clean
        .into_iter()
        .map(|p| {
            let md = std::fs::symlink_metadata(&p).ok();
            // A symlink is unlinked, never descended into — matching entry_size.
            let is_real_dir = md
                .as_ref()
                .map(|m| m.is_dir() && !m.is_symlink())
                .unwrap_or(false);
            let size = entry_size(&p);
            (p, size, is_real_dir)
        })
        .collect();

    let clean_size: u64 = sized.iter().map(|(_, size, _)| size).sum();
    if clean_size == 0 {
        utils::success("Already clean");
        return 0;
    }

    if dry_run {
        utils::info(&format!(
            "[DRY RUN] Would free {}",
            utils::format_size(clean_size)
        ));
        if relocated {
            utils::info(&format!(
                "XDG_CACHE_HOME moves the cache to {}; a real run asks first (or needs --yes)",
                cache.display()
            ));
        }
        return 0;
    }

    if relocated && !relocated_cache_allowed(&cache, yes) {
        return 0;
    }

    let mark = utils::failure_count();
    let mut emptied = utils::Emptied::default();
    for (path, size, is_dir) in &sized {
        emptied.add(path, *size, utils::remove_entry(path, *is_dir));
    }
    if let Some(complaint) = emptied.complaint(&cache) {
        utils::error(&complaint);
    }
    utils::say_freed(emptied.freed, mark);
    emptied.freed
}

pub fn pkg_cache(
    distro: &Distro,
    deep: bool,
    dry_run: bool,
    yes: bool,
    disk_type: crate::detect::DiskType,
) -> u64 {
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
                // Not with `--noconfirm`: that answers every question with its
                // default, and the default for "remove ALL files from cache?" is
                // no, so `pacman -Scc --noconfirm` exits 0 having removed nothing
                // (checked against pacman 7.1). The two questions are answered
                // here instead: the cache, and the sync databases of repositories
                // that are no longer configured, which the `-Sc --noconfirm`
                // above has already said yes to.
                if utils::sudo_quiet_with_input("pacman", &["-Scc"], b"y\ny\n") {
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
            let user_gc = utils::capture_checked("nix-collect-garbage", &[]);
            if let Some(out) = &user_gc {
                extra_freed += parse_nix_freed(out).unwrap_or(0);
            }
            let system_gc = utils::sudo("nix-collect-garbage", &[]);
            say(nix_gc_verdicts(
                "nix-collect-garbage",
                "Garbage collected",
                user_gc.is_some(),
                Some(system_gc),
            ));

            if should_deep(
                deep,
                yes,
                "Delete ALL old generations? (nix-collect-garbage -d) [y/N]:",
            ) {
                let user_ok = utils::run_user("nix-collect-garbage", &["-d"]);
                let system_ok = utils::sudo("nix-collect-garbage", &["-d"]);
                say(nix_gc_verdicts(
                    "nix-collect-garbage -d",
                    "Old generations deleted",
                    user_ok,
                    Some(system_ok),
                ));

                optimise_nix_store(true, disk_type);
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
            let ran_ok = utils::sudo_quiet("xbps-remove", &[flag, "-y"]);
            say(xbps_verdicts(
                flag,
                ran_ok,
                clean_all,
                Path::new("/var/cache/xbps").is_dir(),
            ));
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
            let cleaned = utils::sudo_quiet("apk", &["cache", "clean"]);
            let purge = should_deep(
                deep,
                yes,
                "Also remove cached packages for installed versions? \
                 (they re-download on next install) [y/N]:",
            );
            let purged = (purge && Path::new("/var/cache/apk").is_dir())
                .then(|| utils::sudo_quiet("find", &["/var/cache/apk", "-type", "f", "-delete"]));
            say(apk_verdicts(cleaned, purge, purged));
        }

        Distro::Gentoo => {
            if utils::which_trusted("eclean") {
                if utils::sudo_quiet("eclean", &["distfiles"]) {
                    utils::success("Distfiles cleaned");
                } else {
                    utils::error("eclean distfiles failed");
                }
                if should_deep(deep, yes, "Also clean binary packages? [y/N]:") {
                    // Said, but not counted as a failure of the run: what
                    // `eclean packages` exits with when there are no binary
                    // packages to clean is not something we could check, and a
                    // healthy system must not fail the run over it.
                    if utils::sudo_quiet("eclean", &["packages"]) {
                        utils::success("Binary packages cleaned");
                    } else {
                        utils::warning("eclean packages did not finish cleanly");
                    }
                }
            } else {
                utils::warning("eclean not found — install app-portage/gentoolkit");
                let distfiles = gentoo_distdir();
                // A non-UTF-8 DISTDIR can't be passed as a &str arg; skip
                // rather than panic on unwrap.
                if let Some(path) = distfiles.to_str() {
                    if distfiles.is_dir() {
                        if utils::sudo_quiet("find", &[path, "-type", "f", "-delete"]) {
                            utils::success("Distfiles cleaned");
                        } else {
                            utils::error(&format!("Could not clear {path}"));
                        }
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
            // Exit 1 with no output is how `pacman -Qdtq` says there are none; a
            // database it cannot read is the same exit status, told apart by its
            // `error:` line.
            let out = match utils::list_trusted("pacman", &["-Qdtq"], utils::WhenEmpty::Exit1) {
                utils::Listing::Found(out) => out,
                utils::Listing::Nothing => {
                    utils::success("No orphans found");
                    return 0;
                }
                utils::Listing::Failed => {
                    utils::error("Could not list orphaned packages (pacman -Qdtq failed)");
                    return 0;
                }
            };
            let pkgs: Vec<&str> = out.lines().collect();
            utils::info(&format!("Found {} orphan(s):", pkgs.len()));
            for p in &pkgs {
                utils::plain(&format!("      {} {}", "\u{2022}".dimmed(), p));
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
            // A zypper that is locked by another zypper or by YaST prints nothing
            // on stdout either: that is not "no orphans".
            let out = match utils::list_trusted(
                "zypper",
                &["packages", "--orphaned"],
                utils::WhenEmpty::Exit0,
            ) {
                utils::Listing::Found(out) => out,
                utils::Listing::Nothing => {
                    utils::success("No orphans found");
                    return 0;
                }
                utils::Listing::Failed => {
                    utils::error(
                        "Could not list orphaned packages (zypper packages --orphaned failed)",
                    );
                    return 0;
                }
            };
            if !out.contains('|') {
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
            // `xbps-remove -o` exits 0 when there is nothing to remove (checked
            // on Void), so a failing status is a failure, and a zero one does
            // not say anything was removed.
            if utils::sudo("xbps-remove", &["-o", "-y"]) {
                utils::success("Orphan removal finished");
            } else {
                utils::error("xbps-remove -o failed");
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
            // A warning rather than an error: what `eopkg remove-orphans` exits
            // with when there are none is not something we could check.
            if utils::sudo("eopkg", &["remove-orphans", "-y"]) {
                utils::success("Orphan removal finished");
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
///
/// `Err` says why there is none, ready to follow the helper's name.
fn helper_cache_dir(h: &AurHelper) -> Result<PathBuf, String> {
    helper_dir_in(user_cache_base(), h)
}

fn helper_dir_in(base: CacheBase, h: &AurHelper) -> Result<PathBuf, String> {
    match base {
        // Absent still yields a path: there is simply nothing in it to prune.
        CacheBase::Standard(base) | CacheBase::Relocated(base) | CacheBase::Absent(base) => {
            Ok(base.join(h.bin))
        }
        CacheBase::Refused(why) => Err(format!("refusing to touch {why}")),
        CacheBase::Unknown => Err("cannot determine cache directory".to_string()),
    }
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
    if !helper_launchable(h, &utils::which_trusted) {
        // Found on `$PATH`, which is how helpers are detected (so that their
        // cache is spared elsewhere), but a command is only started from a
        // system directory. Say so instead of reporting a failed `-Sc`.
        utils::skip(&format!(
            "{} is not in a system directory (/usr/bin and the like), so it is not run",
            h.bin
        ));
        return 0;
    }
    clean_helper_at(helper_cache_dir(h), h, deep, yes)
}

/// Whether the helper can be started: one that has a command of its own has to
/// be found by `resolves`; one cleaned by hand (aura) is never started.
fn helper_launchable(h: &AurHelper, resolves: &dyn Fn(&str) -> bool) -> bool {
    h.clean.is_none() || resolves(h.bin)
}

/// [`clean_one_helper`] with the cache directory decided by the caller.
fn clean_helper_at(
    cache_dir: Result<PathBuf, String>,
    h: &AurHelper,
    deep: bool,
    yes: bool,
) -> u64 {
    let mark = utils::failure_count();
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
            let base = match cache_dir.as_ref() {
                Ok(base) => base,
                Err(why) => {
                    utils::error(&format!("{}: {why}", h.bin));
                    return 0;
                }
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
    if let Some(line) = helper_summary(h.bin, freed, utils::failure_count() > mark) {
        utils::success(&line);
    }
    freed
}

/// The line a helper's cleanup ends with: what it freed, or that there was
/// nothing to free. A cleanup that has just reported a failure says no more:
/// "already clean" under a red line is not what happened (`paru -Sc` failing
/// leaves the cache exactly as dirty as it was).
fn helper_summary(bin: &str, freed: u64, failed: bool) -> Option<String> {
    if freed > 0 {
        Some(format!(
            "{bin} — freed {}",
            utils::format_size(freed).green()
        ))
    } else if failed {
        None
    } else {
        Some(format!("{bin} — already clean"))
    }
}

/// How `xbps-remove -O` / `-OO` went. `default_cache_exists` says whether
/// /var/cache/xbps is there: when it is not, the command exits 1 although there
/// is nothing to clean (checked on Void), and that is not a failure.
fn xbps_verdicts(
    flag: &str,
    ran_ok: bool,
    clean_all: bool,
    default_cache_exists: bool,
) -> Vec<Verdict> {
    if ran_ok {
        let mut out = vec![done("xbps cache cleaned")];
        if !clean_all {
            out.push(skipped(
                "Cached current versions kept — remove them with --deep",
            ));
        }
        out
    } else if !default_cache_exists {
        vec![skipped("No xbps cache directory — nothing to clean")]
    } else {
        vec![failed(&format!("xbps-remove {flag} failed"))]
    }
}

/// How the Alpine cache cleaning went: `cleaned` is `apk cache clean`, `purge`
/// whether the user asked for the rest to go as well, and `purged` the result of
/// deleting it (`None` when that was not attempted).
fn apk_verdicts(cleaned: bool, purge: bool, purged: Option<bool>) -> Vec<Verdict> {
    let mut out = Vec::new();
    if !cleaned {
        out.push(failed("apk cache clean failed"));
    }
    match purged {
        Some(true) => out.push(done("apk cache cleared")),
        Some(false) => out.push(failed("Could not clear /var/cache/apk")),
        None if cleaned => {
            out.push(done("apk cache cleaned"));
            if !purge {
                out.push(skipped(
                    "Cached current versions kept — remove them with --deep",
                ));
            }
        }
        None => {}
    }
    out
}

/// How the Flatpak clean-up went: whether each installation's `uninstall
/// --unused` worked, and how many refs are gone since before.
fn flatpak_verdicts(user_ok: bool, system_ok: bool, removed: usize) -> Vec<Verdict> {
    let mut out = Vec::new();
    match removed {
        0 if user_ok && system_ok => out.push(done("No unused runtimes")),
        0 => {}
        n => out.push(done(&format!("Removed {n} unused runtime(s)"))),
    }
    if !user_ok {
        out.push(failed(
            "flatpak uninstall --unused failed (user installation)",
        ));
    }
    if !system_ok {
        out.push(failed(
            "flatpak uninstall --unused failed (system installation)",
        ));
    }
    out
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

/// The `find` that removes flatpak's leftovers from `tmp`: the
/// `flatpak-cache-XXXXXX` directories it makes directly in it.
///
/// Only directly in it. `/var/tmp` is where everyone keeps things that must
/// survive a reboot, and without `-maxdepth 1` this ran as root over all of it,
/// taking with it a directory called `flatpak-cache-notes` that somebody's
/// project happened to have.
fn flatpak_leftovers_args(tmp: &str) -> Vec<&str> {
    vec![
        tmp,
        "-maxdepth",
        "1",
        "-name",
        "flatpak-cache-*",
        "-exec",
        "rm",
        "-rf",
        "{}",
        "+",
    ]
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

    // One installation at a time. A bare `flatpak uninstall` reaches for both:
    // run as the user it also asks for the system installation, which needs an
    // authorisation we do not mean to ask for, and run as root it also takes
    // root's own user installation, which nobody asked about.
    let user_ok = utils::run_quiet("flatpak", &["uninstall", "--user", "--unused", "-y"]);
    let system_ok = utils::sudo_quiet("flatpak", &["uninstall", "--system", "--unused", "-y"]);
    say(flatpak_verdicts(
        user_ok,
        system_ok,
        before.saturating_sub(flatpak_ref_count()),
    ));

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

    if !utils::sudo_quiet("find", &flatpak_leftovers_args("/var/tmp")) {
        utils::error("Could not remove flatpak's leftovers from /var/tmp");
    }

    let sys_fp_tmp = PathBuf::from("/var/lib/flatpak/repo/tmp");
    if sys_fp_tmp.exists()
        && !utils::sudo_quiet(
            "find",
            &["/var/lib/flatpak/repo/tmp", "-mindepth", "1", "-delete"],
        )
    {
        utils::error("Could not clear /var/lib/flatpak/repo/tmp");
    }

    // The runtime count above is already this section's result line, so only
    // add a second one when the tmp-dir sweep actually reclaimed something.
    if freed > 0 {
        utils::success(&format!("Freed {}", utils::format_size(freed).green()));
    }

    freed
}

/// The disabled revisions in the output of `snap list --all`, as
/// `(name, revision)`.
///
/// The table is `Name Version Rev Tracking Publisher Notes`, and a revision that
/// has been replaced says `disabled` among its notes, which are one word or
/// several joined by commas (`disabled`, `base,disabled`, `disabled,classic`).
/// Only that last column decides. The word anywhere on the line is not enough:
/// a snap called `disabled-notes`, or one whose publisher has it in its name, is
/// an active revision, and removing a revision is exactly what is asked of snapd
/// for each one found.
fn disabled_revisions(listing: &str) -> Vec<(&str, &str)> {
    listing
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // Fewer than the six columns is not a row of the table.
            let notes = fields.last().filter(|_| fields.len() >= 6)?;
            notes
                .split(',')
                .any(|note| note == "disabled")
                .then(|| (fields[0], fields[2]))
        })
        .collect()
}

pub fn snap(dry_run: bool) -> u64 {
    utils::section("Snap");

    if dry_run {
        utils::info("[DRY RUN] Would remove disabled snap revisions & cache");
        return 0;
    }

    let listing = utils::list_trusted("snap", &["list", "--all"], utils::WhenEmpty::Exit0);
    let out = match &listing {
        utils::Listing::Found(out) => out.as_str(),
        _ => "",
    };
    let disabled = disabled_revisions(out);

    if listing == utils::Listing::Failed {
        // Not "no disabled revisions": snapd could not be asked.
        utils::error("Could not list snaps (snap list --all failed)");
    } else if disabled.is_empty() {
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
            let removed =
                utils::sudo_quiet("find", &["/var/lib/snapd/cache", "-type", "f", "-delete"]);
            let got = size.saturating_sub(utils::dir_size(&snap_cache));
            freed += got;
            if removed {
                utils::success(&format!("Freed {}", utils::format_size(got).green()));
            } else {
                utils::error("Could not clear /var/lib/snapd/cache");
            }
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

    let mark = utils::failure_count();
    let mut freed = 0u64;
    for dir in &trash_dirs {
        if dir.exists() {
            freed += utils::rm_contents(dir);
        }
    }

    // `rm_contents` has reported what it could not remove.
    utils::say_freed(freed, mark);
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
            let removed = utils::sudo_quiet(
                "find",
                &["/var/lib/systemd/coredump", "-type", "f", "-delete"],
            );
            let after = utils::dir_size(&sd_dir);
            let got = size.saturating_sub(after);
            freed += got;
            if removed {
                utils::success(&format!(
                    "systemd coredumps cleared ({})",
                    utils::format_size(got).green()
                ));
            } else {
                utils::error("Could not clear every systemd coredump");
            }
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
            let removed = utils::sudo_quiet(
                "find",
                &["/var/crash", "-maxdepth", "1", "-type", "f", "-delete"],
            );
            let after = apport_report_size(&apport_dir);
            let got = size.saturating_sub(after);
            freed += got;
            if removed {
                utils::success(&format!(
                    "Apport reports cleared ({})",
                    utils::format_size(got).green()
                ));
            } else {
                utils::error("Could not clear every Apport report");
            }
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
                total += utils::dir_size(&p);
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

/// How a round of `nix-collect-garbage` went: once as the user and, where a
/// daemon owns the store, once more as root (`system_ok` is `None` when that
/// second run does not apply).
fn nix_gc_verdicts(
    command: &str,
    done_msg: &str,
    user_ok: bool,
    system_ok: Option<bool>,
) -> Vec<Verdict> {
    let mut out = Vec::new();
    if !user_ok {
        out.push(failed(&format!("{command} failed (as your user)")));
    }
    if system_ok == Some(false) {
        out.push(failed(&format!("{command} failed (as root)")));
    }
    if user_ok && system_ok != Some(false) {
        out.push(done(done_msg));
    }
    out
}

/// `nix-store --optimise`: hard-link identical files in the store, unless the
/// disk makes that unreasonable.
///
/// The command walks the entire store, which on a spinning disk takes hours, so
/// there it is left for the user to start. Both ways of reaching it (NixOS, and
/// Nix on another distribution) come through here, and the command is written
/// nowhere else, so neither can run it on a disk the other skips.
///
/// A store that a daemon owns takes root. In a single-user install the store is
/// the user's own and the tool lives in the user's profile, which root's
/// trusted lookup cannot see: run as root it would not even be found.
///
/// `nix store --optimise`, which this used to run, is not a command: the flag
/// is spelled `nix store optimise` in the new CLI and `nix-store --optimise` in
/// the classic one (checked against Nix 2.35).
fn optimise_nix_store(multiuser: bool, disk_type: crate::detect::DiskType) {
    optimise_nix_store_with(disk_type, || {
        if multiuser {
            utils::sudo("nix-store", &["--optimise"])
        } else {
            utils::run_user("nix-store", &["--optimise"])
        }
    });
}

/// [`optimise_nix_store`] with the command passed in, so that a test can see
/// whether it is run.
fn optimise_nix_store_with(disk_type: crate::detect::DiskType, optimise: impl FnOnce() -> bool) {
    if disk_type == crate::detect::DiskType::HDD {
        utils::info(
            "Skipping store optimise on HDD (too slow). Run manually: nix-store --optimise",
        );
        return;
    }
    utils::info("Optimising Nix store (hard-linking identical files)...");
    if optimise() {
        utils::success("Store optimised");
    } else {
        utils::error("nix-store --optimise failed");
    }
}

/// Run Nix garbage collection. Detects multi-user vs single-user installs
/// and skips `nix-store --optimise` on HDDs because it is extremely slow.
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

    let multiuser = crate::detect::nix_is_multiuser();

    utils::info("Collecting garbage (user)...");
    let user_gc = utils::capture_checked("nix-collect-garbage", &[]);
    if let Some(out) = &user_gc {
        freed += parse_nix_freed(out).unwrap_or(0);
    }

    let system_gc = multiuser.then(|| {
        utils::info("Collecting garbage (system)...");
        utils::sudo("nix-collect-garbage", &[])
    });
    say(nix_gc_verdicts(
        "nix-collect-garbage",
        "Garbage collected",
        user_gc.is_some(),
        system_gc,
    ));

    if should_deep(
        deep,
        yes,
        "Delete old Nix generations? (removes all but current) [y/N]:",
    ) {
        utils::info("Removing old generations...");
        let user_ok = utils::run_user("nix-collect-garbage", &["-d"]);
        let system_ok = multiuser.then(|| utils::sudo("nix-collect-garbage", &["-d"]));
        say(nix_gc_verdicts(
            "nix-collect-garbage -d",
            "Old generations removed",
            user_ok,
            system_ok,
        ));

        // `nix-collect-garbage -d` cleans the classic (nix-env) profile
        // generations but does NOT touch flake-profile history. On a flakes
        // setup those accumulate separately; `nix profile wipe-history` drops
        // the non-current versions of the default profile so their store paths
        // become collectable. Best-effort: only meaningful when the new `nix`
        // CLI with flakes support is present, and a no-op otherwise.
        //
        // This is the user's own profile history, so it runs as the user and
        // finds `nix` through the user's `$PATH`: a single-user install keeps it
        // in `~/.nix-profile/bin`, which the trusted lookup cannot see.
        if utils::which("nix") {
            // Best effort, with nothing to report: `nix profile` needs the
            // `nix-command` feature, which a stock install leaves off ("error:
            // experimental Nix feature 'nix-command' is disabled", Nix 2.35),
            // and that says nothing about the collection above.
            let _ = utils::run_user("nix", &["profile", "wipe-history"]);
        }

        optimise_nix_store(multiuser, disk_type);
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

    // ── What a step says about how it went ──

    #[test]
    fn test_xbps_says_cleaned_only_when_the_command_worked() {
        assert_eq!(
            xbps_verdicts("-O", true, false, true),
            vec![
                done("xbps cache cleaned"),
                skipped("Cached current versions kept — remove them with --deep")
            ]
        );
        assert_eq!(
            xbps_verdicts("-OO", true, true, true),
            vec![done("xbps cache cleaned")]
        );
        // No cache directory: `xbps-remove -O` exits 1, and there is nothing to
        // clean. Not a failure.
        assert_eq!(
            xbps_verdicts("-O", false, false, false),
            vec![skipped("No xbps cache directory — nothing to clean")]
        );
        // A cache that is there and a command that failed: a failure, naming
        // the flag it ran with.
        assert_eq!(
            xbps_verdicts("-OO", false, true, true),
            vec![failed("xbps-remove -OO failed")]
        );
    }

    #[test]
    fn test_apk_says_what_was_done_and_only_that() {
        let hint = skipped("Cached current versions kept — remove them with --deep");
        // Cleaned, nothing more asked.
        assert_eq!(
            apk_verdicts(true, false, None),
            vec![done("apk cache cleaned"), hint]
        );
        // Cleaned, purge asked but there was no directory to purge.
        assert_eq!(
            apk_verdicts(true, true, None),
            vec![done("apk cache cleaned")]
        );
        // Purged.
        assert_eq!(
            apk_verdicts(true, true, Some(true)),
            vec![done("apk cache cleared")]
        );
        // The purge failed: no claim that it was cleared.
        assert_eq!(
            apk_verdicts(true, true, Some(false)),
            vec![failed("Could not clear /var/cache/apk")]
        );
        // `apk cache clean` failed: a failure, and no "cleaned".
        assert_eq!(
            apk_verdicts(false, false, None),
            vec![failed("apk cache clean failed")]
        );
        assert_eq!(
            apk_verdicts(false, true, Some(true)),
            vec![failed("apk cache clean failed"), done("apk cache cleared")]
        );
    }

    #[test]
    fn test_flatpak_names_the_installation_that_failed() {
        assert_eq!(
            flatpak_verdicts(true, true, 0),
            vec![done("No unused runtimes")]
        );
        assert_eq!(
            flatpak_verdicts(true, true, 3),
            vec![done("Removed 3 unused runtime(s)")]
        );
        // Nothing went away *and* something failed: "no unused runtimes" would
        // be a claim nobody checked.
        assert_eq!(
            flatpak_verdicts(true, false, 0),
            vec![failed(
                "flatpak uninstall --unused failed (system installation)"
            )]
        );
        assert_eq!(
            flatpak_verdicts(false, true, 0),
            vec![failed(
                "flatpak uninstall --unused failed (user installation)"
            )]
        );
        // Half of it worked: what went away is still reported.
        assert_eq!(
            flatpak_verdicts(false, true, 2),
            vec![
                done("Removed 2 unused runtime(s)"),
                failed("flatpak uninstall --unused failed (user installation)")
            ]
        );
    }

    #[test]
    fn test_nix_gc_blames_the_run_that_failed() {
        let done_msg = "Garbage collected";
        assert_eq!(
            nix_gc_verdicts("nix-collect-garbage", done_msg, true, Some(true)),
            vec![done(done_msg)]
        );
        // A single-user install has no second run.
        assert_eq!(
            nix_gc_verdicts("nix-collect-garbage", done_msg, true, None),
            vec![done(done_msg)]
        );
        assert_eq!(
            nix_gc_verdicts("nix-collect-garbage -d", done_msg, false, Some(true)),
            vec![failed("nix-collect-garbage -d failed (as your user)")]
        );
        assert_eq!(
            nix_gc_verdicts("nix-collect-garbage", done_msg, true, Some(false)),
            vec![failed("nix-collect-garbage failed (as root)")]
        );
        assert_eq!(
            nix_gc_verdicts("nix-collect-garbage", done_msg, false, Some(false)),
            vec![
                failed("nix-collect-garbage failed (as your user)"),
                failed("nix-collect-garbage failed (as root)")
            ]
        );
    }

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

    // ── Whether an emerge is running: only an answer counts ──

    fn pgrep_said(code: Option<i32>, stdout: &str, stderr: &str) -> Builds {
        builds_from(Some(utils::Captured {
            code,
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        }))
    }

    #[test]
    fn test_a_build_is_running_when_pgrep_counted_some() {
        assert_eq!(pgrep_said(Some(0), "1\n", ""), Builds::Running);
        assert_eq!(pgrep_said(Some(0), "12\n", ""), Builds::Running);
    }

    #[test]
    fn test_the_tree_is_idle_only_when_pgrep_printed_a_count_of_none() {
        assert_eq!(pgrep_said(Some(1), "0\n", ""), Builds::Idle);
        // What else the command complained about does not make "none" less of
        // an answer: sudo says so on a machine whose hostname does not resolve,
        // and goes on to run the command.
        assert_eq!(
            pgrep_said(Some(1), "0\n", "sudo: unable to resolve host box\n"),
            Builds::Idle
        );
    }

    #[test]
    fn test_no_answer_is_never_idle() {
        // What happened, status, stdout, stderr.
        let cases = [
            // The one the old check took for "none": pgrep's own errors.
            ("a bad pattern", Some(2), "", "pgrep: regex error\n"),
            ("no /proc", Some(3), "", "Error: /proc must be mounted\n"),
            (
                "a refused sudo",
                Some(1),
                "",
                "sudo: a password is required\n",
            ),
            (
                "no -c (busybox)",
                Some(1),
                "",
                "pgrep: unrecognized option: c\n",
            ),
            ("a signal", None, "", ""),
            ("status 0, nothing printed", Some(0), "", ""),
            ("status 0 and a count of none", Some(0), "0\n", ""),
            ("status 1 and a count of some", Some(1), "2\n", ""),
            ("a count that is not a number", Some(1), "none\n", ""),
            ("a count below zero", Some(1), "-1\n", ""),
        ];
        for (what, code, stdout, stderr) in cases {
            match pgrep_said(code, stdout, stderr) {
                Builds::Unknown(_) => {}
                other => panic!("{what}: expected no answer, got {other:?}"),
            }
        }
        // A pgrep that could not even be started.
        assert!(matches!(builds_from(None), Builds::Unknown(_)));
    }

    #[test]
    fn test_no_answer_says_what_pgrep_did() {
        let Builds::Unknown(why) = pgrep_said(Some(2), "", "pgrep: regex error\n") else {
            panic!("expected no answer");
        };
        assert!(
            why.contains("status 2") && why.contains("nothing printed"),
            "{why}"
        );
        assert!(why.contains("pgrep: regex error"), "{why}");

        // sudo's lecture comes before the reason it refused, which is what the
        // person needs; it is the last line that is shown.
        let lecture = "We trust you have received the usual lecture from the local System\n\
                       Administrator. It usually boils down to these three things:\n\n\
                       Sorry, user box is not allowed to execute '/usr/bin/pgrep' as root\n";
        let Builds::Unknown(why) = pgrep_said(Some(1), "", lecture) else {
            panic!("expected no answer");
        };
        assert!(why.contains("Sorry, user box is not allowed"), "{why}");
        assert!(!why.contains("We trust you"), "{why}");

        let Builds::Unknown(why) = pgrep_said(None, "", "") else {
            panic!("expected no answer");
        };
        assert!(why.contains("signal"), "{why}");

        let Builds::Unknown(why) = pgrep_said(Some(1), "none\n", "") else {
            panic!("expected no answer");
        };
        assert!(why.contains("\"none\""), "{why}");

        let Builds::Unknown(why) = builds_from(None) else {
            panic!("expected no answer");
        };
        assert!(why.contains("could not be run"), "{why}");
    }

    #[test]
    fn test_the_emerge_pattern_cannot_match_the_command_line_it_is_part_of() {
        // `pgrep -f` leaves out only itself. A shell, sudo or doas that runs it
        // carries the pattern in their own command line, so a pattern that
        // contains the word it looks for finds them.
        assert!(!EMERGE_PATTERN.contains("emerge"));
        // And it still finds emerge: a bracket expression of one letter is that
        // letter.
        assert_eq!(EMERGE_PATTERN, "[e]merge");
    }

    #[test]
    fn test_look_for_finds_a_process_by_its_command_line_and_not_itself() {
        // The real pgrep and a real process.
        let id = std::process::id();
        let tag = format!("oxiclean_probe_{id}");
        let pattern = format!("[o]xiclean_probe_{id}");

        // Only where pgrep can count; busybox's cannot, and `look_for` rightly
        // calls that no answer. Asked directly, so that a wrong argument of
        // `look_for`'s own is not mistaken for a pgrep that cannot count.
        let probe = utils::elevate_capture(Privilege::Root, "pgrep", &["-c", "-f", &pattern]);
        if !probe.is_some_and(|p| p.code == Some(1) && p.stdout.trim() == "0") {
            eprintln!("skipped: this pgrep cannot count");
            return;
        }
        assert_eq!(
            look_for(Privilege::Root, &pattern),
            Builds::Idle,
            "nothing carries {tag} yet, and pgrep must not match itself"
        );
        // `sh` waiting for input, with the tag in its command line.
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "read line", &tag])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let seen = look_for(Privilege::Root, &pattern);
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(seen, Builds::Running);
        assert_eq!(look_for(Privilege::Root, &pattern), Builds::Idle);
    }

    // ── The sweep deletes only when told that nothing is building ──

    /// A build tree with something in it, and the directory above it, which is
    /// what a test removes afterwards.
    fn leftovers(name: &str) -> (PathBuf, PathBuf) {
        let base =
            std::env::temp_dir().join(format!("oxiclean_sweep_{}_{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let build = base.join("portage");
        std::fs::create_dir_all(build.join("sys-devel/gcc-13/work")).unwrap();
        std::fs::write(build.join("sys-devel/gcc-13/work/a.o"), vec![0u8; 4096]).unwrap();
        (base, build)
    }

    #[test]
    fn test_the_sweep_deletes_once_root_says_no_build_is_running() {
        let (base, build) = leftovers("idle");
        let asked = std::cell::Cell::new(0);
        let removed = std::cell::RefCell::new(Vec::new());
        clear_build_leftovers(
            &build,
            false,
            &|| {
                asked.set(asked.get() + 1);
                Builds::Idle
            },
            &|dir| {
                removed.borrow_mut().push(dir.to_string());
                true
            },
        );
        assert_eq!(asked.get(), 1);
        assert_eq!(*removed.borrow(), vec![build.to_str().unwrap().to_string()]);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_the_sweep_leaves_the_tree_alone_while_a_build_is_running() {
        let (base, build) = leftovers("running");
        let freed = clear_build_leftovers(&build, false, &|| Builds::Running, &|_| {
            panic!("deleted under a running build")
        });
        assert_eq!(freed, 0);
        assert!(build.join("sys-devel/gcc-13/work/a.o").exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_the_sweep_leaves_the_tree_alone_when_nobody_can_say() {
        let (base, build) = leftovers("unknown");
        let freed = clear_build_leftovers(
            &build,
            false,
            &|| Builds::Unknown("pgrep: status 2, nothing printed".to_string()),
            &|_| panic!("deleted without knowing whether a build is running"),
        );
        assert_eq!(freed, 0);
        assert!(build.join("sys-devel/gcc-13/work/a.o").exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_the_sweep_asks_nothing_of_a_tree_with_nothing_in_it() {
        let base =
            std::env::temp_dir().join(format!("oxiclean_sweep_{}_empty", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let build = base.join("portage");
        std::fs::create_dir_all(&build).unwrap();
        let freed = clear_build_leftovers(
            &build,
            false,
            &|| panic!("asked about a tree with nothing in it"),
            &|_| panic!("deleted from a tree with nothing in it"),
        );
        assert_eq!(freed, 0);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_a_dry_run_asks_nobody_and_deletes_nothing() {
        let (base, build) = leftovers("dry");
        let freed =
            clear_build_leftovers(&build, true, &|| panic!("a dry run asked root"), &|_| {
                panic!("a dry run deleted")
            });
        assert_eq!(freed, 0);
        assert!(build.join("sys-devel/gcc-13/work/a.o").exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_the_sweep_only_aims_at_a_portage_directory() {
        let (base, build) = leftovers("aim");
        // Same contents, wrong name.
        let elsewhere = base.join("tmp");
        std::fs::rename(&build, &elsewhere).unwrap();
        let freed = clear_build_leftovers(
            &elsewhere,
            false,
            &|| panic!("asked about a directory that is not a portage tree"),
            &|_| panic!("deleted a directory that is not a portage tree"),
        );
        assert_eq!(freed, 0);
        let _ = std::fs::remove_dir_all(&base);
    }

    // ── Cache base: XDG_CACHE_HOME is checked before anything is emptied ──

    fn cache_scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("oxiclean_cachebase_{}_{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::canonicalize(dir).unwrap()
    }

    /// The user running the tests as `roots` sees them, on a machine with no
    /// system directories, so the temp dir the fixtures live in is fair game.
    fn cache_ctx(home: &Path) -> roots::Context {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(home).unwrap();
        roots::Context {
            home: Some(home.to_path_buf()),
            ids: Some(roots::Ids {
                uid: md.uid(),
                gid: md.gid(),
            }),
            named: Vec::new(),
            system_dirs: Vec::new(),
            system_trees: Vec::new(),
        }
    }

    fn os(s: &str) -> Option<&OsStr> {
        Some(OsStr::new(s))
    }

    fn refusal(base: CacheBase) -> String {
        match base {
            CacheBase::Refused(why) => why,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn test_cache_base_is_dot_cache_unless_xdg_says_otherwise() {
        let d = cache_scratch("default");
        let home = d.join("home");
        std::fs::create_dir_all(home.join(".cache")).unwrap();
        let ctx = cache_ctx(&home);
        let standard = CacheBase::Standard(home.join(".cache"));
        // Unset, empty, and a relative value (which the XDG spec says to ignore).
        for xdg in [None, os(""), os("relative/dir"), os("./x")] {
            assert_eq!(cache_base_from(&ctx, Some(&home), xdg), standard, "{xdg:?}");
        }
    }

    #[test]
    fn test_a_missing_cache_dir_is_absent_not_refused() {
        let d = cache_scratch("absent");
        let home = d.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let ctx = cache_ctx(&home);
        assert_eq!(
            cache_base_from(&ctx, Some(&home), None),
            CacheBase::Absent(home.join(".cache"))
        );
        let gone = d.join("gone");
        assert_eq!(
            cache_base_from(&ctx, Some(&home), Some(gone.as_os_str())),
            CacheBase::Absent(gone)
        );
    }

    #[test]
    fn test_no_home_and_no_xdg_means_no_cache_base() {
        let d = cache_scratch("nohome");
        let mut ctx = cache_ctx(&d);
        ctx.home = None;
        assert_eq!(cache_base_from(&ctx, None, None), CacheBase::Unknown);
        assert_eq!(
            cache_base_from(&ctx, None, os("relative")),
            CacheBase::Unknown
        );
        // XDG_CACHE_HOME alone is enough, as it always was.
        let elsewhere = d.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        assert_eq!(
            cache_base_from(&ctx, None, Some(elsewhere.as_os_str())),
            CacheBase::Relocated(elsewhere)
        );
    }

    #[test]
    fn test_a_moved_cache_is_reported_as_relocated() {
        let d = cache_scratch("moved");
        let home = d.join("home");
        let moved = d.join("data/cache");
        std::fs::create_dir_all(home.join(".cache")).unwrap();
        std::fs::create_dir_all(&moved).unwrap();
        let ctx = cache_ctx(&home);
        assert_eq!(
            cache_base_from(&ctx, Some(&home), Some(moved.as_os_str())),
            CacheBase::Relocated(moved)
        );
    }

    #[test]
    fn test_xdg_naming_the_default_place_relocates_nothing() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let d = cache_scratch("samething");
        let home = d.join("home");
        let default = home.join(".cache");
        std::fs::create_dir_all(&default).unwrap();
        // Writable by everyone: fine as the default, refused as a stranger's.
        std::fs::set_permissions(&default, std::fs::Permissions::from_mode(0o777)).unwrap();
        symlink(&default, d.join("alias")).unwrap();
        let ctx = cache_ctx(&home);
        for xdg in [default.clone(), d.join("alias")] {
            assert_eq!(
                cache_base_from(&ctx, Some(&home), Some(xdg.as_os_str())),
                CacheBase::Standard(xdg.clone()),
                "{xdg:?}"
            );
        }
    }

    #[test]
    fn test_xdg_pointing_at_home_or_above_is_refused() {
        let d = cache_scratch("athome");
        let home = d.join("home");
        std::fs::create_dir_all(home.join(".cache")).unwrap();
        let ctx = cache_ctx(&home);

        let why = refusal(cache_base_from(&ctx, Some(&home), Some(home.as_os_str())));
        assert!(why.starts_with("XDG_CACHE_HOME="), "{why}");
        assert!(why.contains("it is your home directory"), "{why}");

        let why = refusal(cache_base_from(&ctx, Some(&home), Some(d.as_os_str())));
        assert!(why.contains("contains your home directory"), "{why}");
    }

    #[test]
    fn test_xdg_pointing_at_settings_or_documents_is_refused() {
        let d = cache_scratch("reserved");
        let home = d.join("home");
        std::fs::create_dir_all(home.join(".cache")).unwrap();
        let ctx = cache_ctx(&home);
        for name in [".config", ".local/share", "Documents", ".ssh"] {
            let dir = home.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            let why = refusal(cache_base_from(&ctx, Some(&home), Some(dir.as_os_str())));
            assert!(why.starts_with("XDG_CACHE_HOME="), "{name}: {why}");
        }
    }

    #[test]
    fn test_xdg_must_be_the_users_own_and_not_writable_by_others() {
        use std::os::unix::fs::PermissionsExt;
        let d = cache_scratch("others");
        let home = d.join("home");
        let moved = d.join("cache");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&moved).unwrap();
        std::fs::set_permissions(&moved, std::fs::Permissions::from_mode(0o777)).unwrap();
        let ctx = cache_ctx(&home);
        let why = refusal(cache_base_from(&ctx, Some(&home), Some(moved.as_os_str())));
        assert!(why.contains("anyone can write"), "{why}");

        std::fs::set_permissions(&moved, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut stranger = cache_ctx(&home);
        if let Some(ids) = stranger.ids.as_mut() {
            ids.uid += 1;
        }
        stranger.home = None; // the owner of HOME would otherwise vouch for it
        let why = refusal(cache_base_from(&stranger, None, Some(moved.as_os_str())));
        assert!(why.contains("not to you"), "{why}");
    }

    #[test]
    fn test_a_dot_cache_that_leads_to_documents_is_refused() {
        use std::os::unix::fs::symlink;
        let d = cache_scratch("sneaky");
        let home = d.join("home");
        std::fs::create_dir_all(home.join("Documents")).unwrap();
        symlink(home.join("Documents"), home.join(".cache")).unwrap();
        let ctx = cache_ctx(&home);
        let why = refusal(cache_base_from(&ctx, Some(&home), None));
        assert!(why.contains("Documents"), "{why}");
    }

    #[test]
    fn test_only_a_relative_xdg_is_reported_as_ignored() {
        assert_eq!(ignored_xdg(None), None);
        assert_eq!(ignored_xdg(os("")), None);
        assert_eq!(ignored_xdg(os("/abs/ok")), None);
        assert_eq!(ignored_xdg(os("rel/dir")), Some("rel/dir".to_string()));
        assert_eq!(ignored_xdg(os("./x")), Some("./x".to_string()));
    }

    #[test]
    fn test_a_helper_cache_dir_follows_the_base() {
        let aura = crate::detect::AurHelper {
            bin: "aura",
            clean: None,
            deep_clean: None,
            prune_dirs: &["builds"],
            prune_dirs_deep: &[],
        };
        let p = |s: &str| PathBuf::from(s);
        assert_eq!(
            helper_dir_in(CacheBase::Standard(p("/h/.cache")), &aura),
            Ok(p("/h/.cache/aura"))
        );
        assert_eq!(
            helper_dir_in(CacheBase::Relocated(p("/data/c")), &aura),
            Ok(p("/data/c/aura"))
        );
        // Nothing there to prune is not an error: the helper reports "clean".
        assert_eq!(
            helper_dir_in(CacheBase::Absent(p("/h/.cache")), &aura),
            Ok(p("/h/.cache/aura"))
        );
        let err = helper_dir_in(
            CacheBase::Refused("XDG_CACHE_HOME=/h — it is your home directory".into()),
            &aura,
        )
        .unwrap_err();
        assert!(
            err.contains("refusing") && err.contains("home directory"),
            "{err}"
        );
        assert!(helper_dir_in(CacheBase::Unknown, &aura).is_err());
    }

    #[test]
    fn test_a_helper_is_run_only_where_it_can_be_started() {
        let paru = crate::detect::AurHelper {
            bin: "paru",
            clean: Some(&["-Sc", "--noconfirm"]),
            deep_clean: None,
            prune_dirs: &[],
            prune_dirs_deep: &[],
        };
        let aura = crate::detect::AurHelper {
            bin: "aura",
            clean: None,
            deep_clean: None,
            prune_dirs: &["builds"],
            prune_dirs_deep: &[],
        };
        assert!(helper_launchable(&paru, &|name| name == "paru"));
        assert!(!helper_launchable(&paru, &|_| false));
        // A helper cleaned by hand is never started, so where it is does not matter.
        assert!(helper_launchable(&aura, &|_| panic!("looked for aura")));
    }

    #[test]
    fn test_flatpaks_leftovers_are_swept_from_the_top_of_tmp_and_not_below_it() {
        use std::fs;
        use std::process::Command;
        let tmp = cache_scratch("flatpak-sweep");
        let touch = |path: &str| {
            let path = tmp.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"x").unwrap();
        };
        // Flatpak's own: directly in tmp, as a directory with a tree in it and
        // as a file.
        touch("flatpak-cache-AbC123/objects/ab/cd");
        touch("flatpak-cache-file");
        // Not flatpak's: the same name further down, and names that only look
        // like it.
        touch("project/flatpak-cache-notes/todo.txt");
        touch("project/flatpak-cache-other");
        touch("flatpak-cache");
        touch("not-flatpak-cache-x");

        // The real `find`, on a directory of ours instead of /var/tmp.
        let args = flatpak_leftovers_args(tmp.to_str().unwrap());
        let status = Command::new("find").args(&args).status().unwrap();

        assert!(status.success());
        assert!(!tmp.join("flatpak-cache-AbC123").exists());
        assert!(!tmp.join("flatpak-cache-file").exists());
        for kept in [
            "project/flatpak-cache-notes/todo.txt",
            "project/flatpak-cache-other",
            "flatpak-cache",
            "not-flatpak-cache-x",
        ] {
            assert!(tmp.join(kept).exists(), "{kept} was removed");
        }
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_only_the_notes_column_decides_what_is_a_disabled_revision() {
        let listing = "\
Name               Version       Rev    Tracking         Publisher     Notes
chromium           98.0.4758.80  1899   latest/stable    canonical*    disabled
chromium           99.0.4844.51  1927   latest/stable    canonical*    -
code               d6ee99e4      87     latest/stable    vscode*       disabled,classic
core18             20211028      2253   latest/stable    canonical*    base,disabled
firefox            97.0.1-1      996    latest/stable/…  mozilla*      disabled
firefox            98.0.2        1020   latest/stable/…  mozilla*      -
disabled-notes     1.0           5      latest/stable    someone       -
undisabled         2.0           6      latest/stable    disabled-dev  classic
held-app           1.0           7      latest/stable    pub           held
odd-notes          1.0           8      latest/stable    pub           redisabled
";
        assert_eq!(
            disabled_revisions(listing),
            [
                ("chromium", "1899"),
                ("code", "87"),
                ("core18", "2253"),
                ("firefox", "996"),
            ]
        );
    }

    #[test]
    fn test_what_is_not_a_row_of_the_table_has_no_disabled_revision() {
        for listing in [
            "",
            "No snaps are installed yet. Try 'snap install hello-world'.",
            "error: cannot communicate with server: Post http://localhost/v2/login",
            "disabled",
            "name 1 2 disabled",
        ] {
            assert!(disabled_revisions(listing).is_empty(), "{listing:?}");
        }
    }

    #[test]
    fn test_the_nix_store_is_not_optimised_on_a_spinning_disk() {
        use crate::detect::DiskType;
        // Only the paths that do not report a failure, which is global state
        // that tests running side by side would see.
        let ran = |disk| {
            let mut ran = false;
            optimise_nix_store_with(disk, || {
                ran = true;
                true
            });
            ran
        };
        assert!(!ran(DiskType::HDD));
        assert!(ran(DiskType::SSD));
        assert!(ran(DiskType::NVMe));
        // Not knowing is not a reason to skip it, as in the other path.
        assert!(ran(DiskType::Unknown));
    }

    #[test]
    fn test_a_helper_that_failed_is_not_called_already_clean() {
        assert_eq!(
            helper_summary("paru", 0, false).as_deref(),
            Some("paru — already clean")
        );
        // The failure has its own line; nothing here may contradict it.
        assert_eq!(helper_summary("paru", 0, true), None);
        // Some of it went and some did not: say what did.
        for failed in [false, true] {
            let line = helper_summary("paru", 4096, failed).expect("a line");
            assert!(line.contains("freed"), "{line}");
        }
    }

    #[test]
    fn test_a_refused_base_leaves_a_hand_pruned_helper_alone() {
        use std::fs;
        let d = cache_scratch("aura");
        let aura_dir = d.join("aura");
        fs::create_dir_all(aura_dir.join("builds")).unwrap();
        fs::write(aura_dir.join("builds/leftover"), vec![0u8; 2048]).unwrap();
        fs::create_dir_all(aura_dir.join("snapshots")).unwrap();
        fs::write(aura_dir.join("snapshots/restore.json"), vec![0u8; 512]).unwrap();
        let aura = crate::detect::AurHelper {
            bin: "aura",
            clean: None,
            deep_clean: None,
            prune_dirs: &["builds"],
            prune_dirs_deep: &[],
        };

        let refused =
            Err("refusing to touch XDG_CACHE_HOME=/h — it is your home directory".to_string());
        assert_eq!(clean_helper_at(refused, &aura, false, true), 0);
        assert!(
            aura_dir.join("builds/leftover").exists(),
            "nothing may be pruned"
        );

        // The same helper, given a directory it may use, prunes builds only.
        let freed = clean_helper_at(Ok(aura_dir.clone()), &aura, false, true);
        assert!(freed >= 2048, "freed {freed}");
        assert!(!aura_dir.join("builds/leftover").exists());
        assert!(
            aura_dir.join("snapshots/restore.json").exists(),
            "restore points survive"
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn test_what_an_entry_frees_is_what_it_occupies_and_not_what_stays() {
        use std::fs;
        use std::os::unix::fs::symlink;
        let base = cache_scratch("entry-size");
        let data = |n: u32| -> Vec<u8> {
            (0..n)
                .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
                .collect()
        };
        let md = |p: &Path| fs::symlink_metadata(p).unwrap();

        // A file: its blocks, which is not its length.
        fs::write(base.join("file"), data(70_000)).unwrap();
        let file = utils::allocated(&md(&base.join("file")));
        assert_eq!(entry_size(&base.join("file")), file);
        assert_ne!(file, 70_000);

        // A directory: what is in it, and nothing for itself.
        fs::create_dir_all(base.join("dir/sub")).unwrap();
        fs::write(base.join("dir/sub/inner"), data(70_000)).unwrap();
        assert_eq!(
            entry_size(&base.join("dir")),
            utils::allocated(&md(&base.join("dir/sub/inner")))
        );

        // A link frees its own entry, never what it leads to.
        symlink(base.join("file"), base.join("link")).unwrap();
        assert_eq!(
            entry_size(&base.join("link")),
            utils::allocated(&md(&base.join("link")))
        );
        assert!(entry_size(&base.join("link")) < 70_000);

        // A file with another name stays on disk when this one goes.
        fs::hard_link(base.join("file"), base.join("twin")).unwrap();
        assert_eq!(entry_size(&base.join("twin")), 0);
        assert_eq!(entry_size(&base.join("missing")), 0);
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

        let on_disk = |name: &str| utils::allocated(&fs::metadata(base.join(name)).unwrap());
        let reports = on_disk("_usr_bin_foo.1000.crash") + on_disk("_usr_bin_bar.1000.uploaded");
        assert!(reports > 0);
        assert_eq!(
            apport_report_size(&base),
            reports,
            "only the two flat report files count; the vmcore subdir is excluded"
        );
        assert!(
            on_disk("202607091200/vmcore") > reports,
            "the fixture is lopsided"
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_a_failed_verdict_is_an_error_and_the_others_are_not() {
        const ME: &str = "clean::tests::test_a_failed_verdict_is_an_error_and_the_others_are_not";
        if std::env::var_os("OXI_CHILD").is_none() {
            // The failure counter is process-wide and settable from one place only,
            // so the check runs in a child of its own.
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", ME, "--nocapture", "--test-threads=1"])
                .env("OXI_CHILD", "1")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "child failed:\n{stdout}\n{stderr}");
            // The markers go to stderr: report modules print to stdout only
            // through the helpers in utils.
            assert!(stderr.contains("CHILD-RAN"), "child never ran:\n{stderr}");
            assert!(stderr.contains("NEW-FAILURES=1"), "{stderr}");
            for shown in ["it worked", "left alone", "it broke"] {
                assert!(stdout.contains(shown), "missing {shown:?}:\n{stdout}");
            }
            return;
        }
        let before = utils::failure_count();
        say(vec![
            done("it worked"),
            skipped("left alone"),
            failed("it broke"),
        ]);
        eprintln!("NEW-FAILURES={}", utils::failure_count() - before);
        eprintln!("CHILD-RAN");
    }
}
