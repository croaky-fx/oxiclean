//! Which directories oxiclean is willing to empty.
//!
//! Most of what it deletes sits at a path it builds itself (`~/.npm/_cacache`).
//! A few roots are handed to it by the environment instead: `XDG_CACHE_HOME`,
//! `UV_CACHE_DIR`, `DENO_DIR`, `CCACHE_DIR`, `GOMODCACHE`, `GOPATH`,
//! `PIP_CACHE_DIR`, `COMPOSER_CACHE_DIR` and `NUGET_PACKAGES`, and, for what root
//! empties, Gentoo's `DISTDIR`. Those used to be emptied without asking what
//! they point at, so
//! `XDG_CACHE_HOME=$HOME` (a typo, a mixed-up line in a profile, a variable
//! inherited from another account) turned "clean my cache" into "empty my home
//! directory".
//!
//! [`check`] is the gate every such root goes through. It is a floor, not a
//! judgement of what makes a cache: it refuses the directories that can never
//! be one (the filesystem root, the home directory and its parents, the places
//! settings, data and documents live, system trees) and, for roots that came
//! from the environment, anything that is not plainly the user's own. Whether a
//! directory it lets through deserves to be emptied is for the caller to settle,
//! by asking.
//!
//! It does not defend against another local user swapping directories underneath
//! a run: the checks are only as strong as the directory's own permissions.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Directories no root may be, and none may contain.
const SYSTEM_DIRS: &[&str] = &[
    "/",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/home",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/media",
    "/mnt",
    "/nix",
    "/opt",
    "/proc",
    "/root",
    "/run",
    "/run/user",
    "/sbin",
    "/srv",
    "/sys",
    "/tmp",
    "/usr",
    "/var",
    "/var/cache",
    "/var/lib",
    "/var/log",
    "/var/tmp",
];

/// Trees nothing below may be emptied, whoever owns it. A home directory inside
/// one (a service account at `/usr/share/nginx`) exempts what lies under it.
const SYSTEM_TREES: &[&str] = &[
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/nix/store",
    "/proc",
    "/sbin",
    "/sys",
    "/usr",
];

/// Places inside a system tree where a system's own caches are known to live,
/// which a root of [`Source::System`] may lie under. Portage kept its distfiles
/// in `/usr/portage/distfiles` until 2.3.8 moved the default to
/// `/var/cache/distfiles`, and plenty of installs still have them there.
const SYSTEM_CACHE_PLACES: &[&str] = &["/usr/portage"];

/// Places under `$HOME` that hold something other than a cache, with what to
/// call them in a refusal. `XDG_CACHE_HOME=$HOME/.config`, a line copied from the
/// wrong variable in a profile, is the mistake this list is for.
const RESERVED_UNDER_HOME: &[(&str, &str)] = &[
    (".config", "where your settings live"),
    (".local", "where your local data lives"),
    (".local/share", "where your application data lives"),
    (".local/state", "where your application state lives"),
    (".gnupg", "where your keys live"),
    (".ssh", "where your keys live"),
    ("Desktop", "your Desktop folder"),
    ("Documents", "your Documents folder"),
    ("Downloads", "your Downloads folder"),
    ("Music", "your Music folder"),
    ("Pictures", "your Pictures folder"),
    ("Public", "your Public folder"),
    ("Templates", "your Templates folder"),
    ("Videos", "your Videos folder"),
];

/// Effective user and group of the process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ids {
    pub uid: u32,
    pub gid: u32,
}

/// Who is running us, from `/proc/self/status`. `None` when that cannot be read
/// or parsed, which makes every root from the environment fail closed: without
/// knowing who we are there is no telling whose directory it is.
pub fn effective_ids() -> Option<Ids> {
    parse_ids(&fs::read_to_string("/proc/self/status").ok()?)
}

/// Format: `Uid:\t<real>\t<effective>\t<saved>\t<fs>`, and the same for `Gid:`.
fn parse_ids(status: &str) -> Option<Ids> {
    let effective = |key: &str| -> Option<u32> {
        let line = status.lines().find_map(|line| line.strip_prefix(key))?;
        line.split_whitespace().nth(1)?.parse().ok()
    };
    Some(Ids {
        uid: effective("Uid:")?,
        gid: effective("Gid:")?,
    })
}

/// Where a root came from, which decides how much of the user's own say-so it
/// carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Built by us below `$HOME`. It is the user's by construction, and may be a
    /// symlink onto another disk they own or share. (Root in somebody else's home
    /// does not get here: see `utils::foreign_home`.)
    Home,
    /// Supplied by an environment variable. Nothing about it is known.
    Env,
    /// A cache the system keeps, which root empties: Gentoo's `DISTDIR`, which
    /// portage takes from the environment before it takes it from make.conf. It
    /// is held to the same floor, except that it may lie where a system's caches
    /// are known to (`/usr/portage`), and whose it is is not asked: it is root's
    /// and the portage group's, not the user's.
    System,
}

/// Why a root was turned down.
#[derive(Debug, PartialEq, Eq)]
pub enum Reject {
    /// There is nothing there. Not a problem: there is simply nothing to clean.
    Missing,
    /// Something is there and must not be emptied. Carries the reason, phrased
    /// to follow "it is not safe to clean because ...".
    Unsafe(String),
}

fn refuse(why: impl Into<String>) -> Reject {
    Reject::Unsafe(why.into())
}

/// Everything [`check`] needs to know about the machine. Built once from the
/// real environment; the tests build their own.
pub struct Context {
    /// The user's home directory, when `$HOME` is usable.
    pub home: Option<PathBuf>,
    /// Who is running us.
    pub ids: Option<Ids>,
    /// Absolute locations the environment names for settings, data, state and
    /// runtime files, as `(variable, path)`. A cache is never one of them.
    pub named: Vec<(&'static str, PathBuf)>,
    /// Directories no root may be or contain.
    pub system_dirs: Vec<PathBuf>,
    /// Trees nothing below may be emptied.
    pub system_trees: Vec<PathBuf>,
    /// Places inside a system tree that a system's caches may lie under, for a
    /// root of [`Source::System`] only.
    pub cache_places: Vec<PathBuf>,
}

impl Context {
    pub fn from_env() -> Context {
        let named = [
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_RUNTIME_DIR",
        ]
        .into_iter()
        .filter_map(|var| {
            let path = PathBuf::from(std::env::var_os(var)?);
            path.is_absolute().then_some((var, path))
        })
        .collect();
        Context {
            home: crate::utils::home_dir().map(PathBuf::from),
            ids: effective_ids(),
            named,
            system_dirs: with_real_paths(SYSTEM_DIRS),
            system_trees: with_real_paths(SYSTEM_TREES),
            cache_places: with_real_paths(SYSTEM_CACHE_PLACES),
        }
    }
}

/// The listed paths plus wherever their symlinks lead. On a merged-`/usr` system
/// `/bin` is `/usr/bin`, and on Fedora Silverblue `/home` is `/var/home`; a root
/// that arrives by its real name must be recognised too.
fn with_real_paths(list: &[&str]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for item in list {
        let path = PathBuf::from(item);
        if let Ok(real) = fs::canonicalize(&path) {
            if real != path && !out.contains(&real) {
                out.push(real);
            }
        }
        if !out.contains(&path) {
            out.push(path);
        }
    }
    out
}

fn real_or_lexical(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Decide whether `candidate` may be emptied. On success returns its canonical
/// path (symlinks resolved), which is the directory that really gets emptied;
/// callers keep the path they were given for display and for matching against
/// other lexical paths.
///
/// Every rule applies to the resolved path, so a symlink cannot launder a
/// forbidden target. The rules are, in order:
///
/// 1. absolute, present, and a directory;
/// 2. not the home directory, a system directory, or a parent of either;
/// 3. not where settings, data, state, keys or personal folders live;
/// 4. not inside a system tree, unless the home directory is there or, for a
///    [`Source::System`] root, a place where a system's caches live (below it,
///    not the place itself);
/// 5. for [`Source::Env`] only: owned by the user running oxiclean, and writable
///    by nobody else.
pub fn check(ctx: &Context, candidate: &Path, source: Source) -> Result<PathBuf, Reject> {
    if !candidate.is_absolute() {
        return Err(refuse("it is not an absolute path"));
    }
    let root = match fs::canonicalize(candidate) {
        Ok(real) => real,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(Reject::Missing),
        Err(e) => return Err(refuse(format!("it cannot be resolved ({e})"))),
    };
    let md = fs::metadata(&root).map_err(|e| refuse(format!("it cannot be read ({e})")))?;
    if !md.is_dir() {
        return Err(refuse("it is not a directory"));
    }

    let home = ctx.home.as_deref().map(real_or_lexical);
    if let Some(why) = off_limits(ctx, home.as_deref(), &root, source) {
        return Err(refuse(why));
    }
    if source == Source::Env {
        if let Some(why) = not_plainly_the_users(ctx, &md) {
            return Err(refuse(why));
        }
    }
    Ok(root)
}

/// Rules 2 to 4: places that can never be a cache root, whoever asks.
fn off_limits(ctx: &Context, home: Option<&Path>, root: &Path, source: Source) -> Option<String> {
    let guarded = home.map(|h| (h, "your home directory")).into_iter().chain(
        ctx.system_dirs
            .iter()
            .map(|d| (d.as_path(), "a system directory")),
    );
    for (dir, what) in guarded {
        if root == dir {
            return Some(format!("it is {what}"));
        }
        if dir.starts_with(root) {
            return Some(format!("it contains {what}"));
        }
    }

    for (var, path) in &ctx.named {
        if real_or_lexical(path) == root {
            return Some(format!("it is the directory {var} points to"));
        }
    }
    if let Some(home) = home {
        for (relative, what) in RESERVED_UNDER_HOME {
            if real_or_lexical(&home.join(relative)) == root {
                return Some(format!("it is {what}"));
            }
        }
    }

    // A home directory inside a system tree (a service account) is its owner's.
    // `/` as a home directory is not: everything would count as under it.
    let in_home = home.is_some_and(|h| h != Path::new("/") && root.starts_with(h));
    // Below such a place, not at it: `/usr/portage` is the tree, and the
    // distfiles are what is in it.
    let in_cache_place = source == Source::System
        && ctx
            .cache_places
            .iter()
            .any(|place| root != place && root.starts_with(place));
    if !in_home && !in_cache_place && ctx.system_trees.iter().any(|tree| root.starts_with(tree)) {
        return Some("it is inside a system directory".to_string());
    }
    None
}

/// Rule 5: a root named by the environment has to be plainly the user's own.
/// Anything another account owns or can write to is somewhere we could be made
/// to delete things that were never ours.
fn not_plainly_the_users(ctx: &Context, md: &fs::Metadata) -> Option<String> {
    let Some(me) = ctx.ids else {
        return Some("it could not be determined who is running oxiclean".to_string());
    };
    // Nobody stands in for whoever is running: root with somebody else's HOME
    // (`sudo -E`) does not clean what that account names, which is theirs to
    // clean as themselves. Root in that home does no user-level cleaning at all
    // (`utils::foreign_home`), so this is not where that is stopped; it is what
    // keeps the variables of such a run from being believed.
    if md.uid() != me.uid {
        return Some(format!("it belongs to uid {}, not to you", md.uid()));
    }
    let mode = md.mode();
    if mode & 0o002 != 0 {
        return Some("anyone can write to it".to_string());
    }
    if mode & 0o020 != 0 && md.gid() != me.gid {
        return Some(format!("members of group {} can write to it", md.gid()));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    /// A fresh directory, resolved so comparisons survive a symlinked temp dir.
    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("oxiclean_roots_{}_{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::canonicalize(dir).unwrap()
    }

    fn mkdir(path: impl AsRef<Path>) -> PathBuf {
        fs::create_dir_all(path.as_ref()).unwrap();
        path.as_ref().to_path_buf()
    }

    fn chmod(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// The ids that own whatever a test creates in `dir`.
    fn owner_of(dir: &Path) -> Ids {
        let md = fs::metadata(dir).unwrap();
        Ids {
            uid: md.uid(),
            gid: md.gid(),
        }
    }

    /// A machine whose only system locations are the ones a test names.
    fn context(home: Option<&Path>, ids: Option<Ids>) -> Context {
        Context {
            home: home.map(Path::to_path_buf),
            ids,
            named: Vec::new(),
            system_dirs: Vec::new(),
            system_trees: Vec::new(),
            cache_places: Vec::new(),
        }
    }

    fn why(result: Result<PathBuf, Reject>) -> String {
        match result {
            Err(Reject::Unsafe(why)) => why,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    const ALL: [Source; 3] = [Source::Home, Source::Env, Source::System];

    // ── who is running us ───────────────────────────────

    #[test]
    fn parse_ids_takes_the_effective_pair() {
        let status = "Name:\tx\nUid:\t1000\t1001\t1002\t1003\nGid:\t2000\t2001\t2002\t2003\n";
        assert_eq!(
            parse_ids(status),
            Some(Ids {
                uid: 1001,
                gid: 2001
            })
        );
    }

    #[test]
    fn parse_ids_gives_up_on_anything_odd() {
        assert_eq!(parse_ids(""), None);
        assert_eq!(parse_ids("Uid:\t1\t2\t3\t4\n"), None, "no Gid line");
        assert_eq!(parse_ids("Gid:\t1\t2\t3\t4\n"), None, "no Uid line");
        assert_eq!(parse_ids("Uid:\t1\nGid:\t1\t2\n"), None, "Uid too short");
        assert_eq!(
            parse_ids("Uid:\t1\tx\t3\t4\nGid:\t1\t2\t3\t4\n"),
            None,
            "not a number"
        );
    }

    #[test]
    fn this_process_can_say_who_it_is() {
        if Path::new("/proc/self/status").exists() {
            assert!(effective_ids().is_some());
        }
    }

    // ── rule 1: absolute, present, a directory ──────────

    #[test]
    fn a_relative_path_is_never_a_root() {
        let d = scratch("relative");
        let c = context(Some(&d), Some(owner_of(&d)));
        for source in ALL {
            for path in ["cache", "./cache", "..", ""] {
                assert!(
                    why(check(&c, Path::new(path), source)).contains("not an absolute path"),
                    "{path:?} via {source:?}"
                );
            }
        }
    }

    #[test]
    fn nothing_there_is_missing_not_unsafe() {
        let d = scratch("missing");
        let c = context(Some(&d), Some(owner_of(&d)));
        for source in ALL {
            assert_eq!(check(&c, &d.join("nope"), source), Err(Reject::Missing));
        }
    }

    #[test]
    fn a_file_is_not_a_root() {
        let d = scratch("file");
        let c = context(None, Some(owner_of(&d)));
        let file = d.join("plain");
        fs::write(&file, "x").unwrap();
        for source in ALL {
            assert!(why(check(&c, &file, source)).contains("not a directory"));
        }
    }

    // ── rule 2: home and system directories, and their parents ──

    #[test]
    fn the_home_directory_and_its_parents_are_off_limits() {
        let d = scratch("home");
        let home = mkdir(d.join("a/b/home"));
        let c = context(Some(&home), Some(owner_of(&d)));
        for source in ALL {
            assert!(why(check(&c, &home, source)).contains("it is your home directory"));
            for parent in [home.parent().unwrap(), d.as_path()] {
                assert!(
                    why(check(&c, parent, source)).contains("contains your home directory"),
                    "{parent:?} via {source:?}"
                );
            }
        }
    }

    #[test]
    fn a_directory_below_home_is_fine() {
        let d = scratch("below");
        let home = mkdir(d.join("home"));
        let cache = mkdir(home.join(".cache"));
        let c = context(Some(&home), Some(owner_of(&d)));
        for source in ALL {
            assert_eq!(check(&c, &cache, source), Ok(cache.clone()));
        }
    }

    #[test]
    fn named_system_directories_and_their_parents_are_off_limits() {
        let d = scratch("sysdirs");
        let srv = mkdir(d.join("srv"));
        let mut c = context(None, Some(owner_of(&d)));
        c.system_dirs = vec![srv.clone()];
        for source in ALL {
            assert!(why(check(&c, &srv, source)).contains("it is a system directory"));
            assert!(why(check(&c, &d, source)).contains("contains a system directory"));
            // Only the directory itself is protected, not what is below it.
            let below = mkdir(srv.join("cache"));
            assert_eq!(check(&c, &below, source), Ok(below.clone()));
        }
    }

    // ── rule 3: settings, data, keys and personal folders ──

    #[test]
    fn settings_data_keys_and_personal_folders_are_off_limits() {
        let d = scratch("reserved");
        let home = mkdir(d.join("home"));
        let c = context(Some(&home), Some(owner_of(&d)));
        for (relative, what) in RESERVED_UNDER_HOME {
            let dir = mkdir(home.join(relative));
            for source in ALL {
                let reason = why(check(&c, &dir, source));
                assert!(reason.contains(what), "{relative}: {reason}");
            }
            // A directory inside one is the user's own business.
            let below = mkdir(dir.join("cache"));
            assert_eq!(check(&c, &below, Source::Env), Ok(below.clone()));
        }
    }

    #[test]
    fn the_locations_the_environment_names_are_off_limits() {
        let d = scratch("named");
        let state = mkdir(d.join("xdg-state"));
        let runtime = mkdir(d.join("run-user"));
        let other = mkdir(d.join("other"));
        let mut c = context(None, Some(owner_of(&d)));
        c.named = vec![
            ("XDG_STATE_HOME", state.clone()),
            ("XDG_RUNTIME_DIR", runtime.clone()),
            ("XDG_DATA_HOME", d.join("not-created")),
        ];
        for source in ALL {
            assert!(why(check(&c, &state, source)).contains("XDG_STATE_HOME"));
            assert!(why(check(&c, &runtime, source)).contains("XDG_RUNTIME_DIR"));
            assert_eq!(check(&c, &other, source), Ok(other.clone()));
        }
    }

    // ── symlinks ────────────────────────────────────────

    #[test]
    fn a_symlink_cannot_launder_a_forbidden_target() {
        let d = scratch("links");
        let home = mkdir(d.join("home"));
        mkdir(home.join("Documents"));
        symlink(&home, home.join("alias")).unwrap();
        symlink(home.join("Documents"), home.join("docs")).unwrap();
        symlink(&d, home.join("up")).unwrap();
        let c = context(Some(&home), Some(owner_of(&d)));
        for source in ALL {
            assert!(why(check(&c, &home.join("alias"), source)).contains("your home directory"));
            assert!(why(check(&c, &home.join("docs"), source)).contains("Documents"));
            assert!(why(check(&c, &home.join("up"), source)).contains("contains your home"));
        }
    }

    #[test]
    fn a_dotfile_symlinked_settings_directory_is_still_settings() {
        // `~/.config -> ~/dotfiles/config` is how dotfile managers lay it out.
        let d = scratch("dotfiles");
        let home = mkdir(d.join("home"));
        let real = mkdir(home.join("dotfiles/config"));
        symlink(&real, home.join(".config")).unwrap();
        let c = context(Some(&home), Some(owner_of(&d)));
        for source in ALL {
            assert!(why(check(&c, &real, source)).contains("where your settings live"));
        }
    }

    #[test]
    fn the_answer_is_the_resolved_path() {
        let d = scratch("resolved");
        let home = mkdir(d.join("home"));
        let target = mkdir(d.join("elsewhere/cache"));
        symlink(&target, home.join(".cache")).unwrap();
        let c = context(Some(&home), Some(owner_of(&d)));
        for source in ALL {
            assert_eq!(check(&c, &home.join(".cache"), source), Ok(target.clone()));
        }
    }

    // ── rule 4: system trees ────────────────────────────

    #[test]
    fn nothing_inside_a_system_tree_is_a_root() {
        let d = scratch("trees");
        let usr = mkdir(d.join("usr"));
        let share = mkdir(usr.join("share"));
        let mut c = context(None, Some(owner_of(&d)));
        c.system_trees = vec![usr.clone()];
        for source in ALL {
            for path in [&usr, &share] {
                assert!(
                    why(check(&c, path, source)).contains("inside a system directory"),
                    "{path:?}"
                );
            }
        }
    }

    #[test]
    fn a_home_directory_in_a_system_tree_exempts_what_is_under_it() {
        // Service accounts live in places like /var/lib/jenkins.
        let d = scratch("service");
        let usr = mkdir(d.join("usr"));
        let home = mkdir(usr.join("svc"));
        let cache = mkdir(home.join(".cache"));
        let share = mkdir(usr.join("share"));
        let mut c = context(Some(&home), Some(owner_of(&d)));
        c.system_trees = vec![usr.clone()];
        for source in ALL {
            assert_eq!(check(&c, &cache, source), Ok(cache.clone()));
            assert!(why(check(&c, &share, source)).contains("inside a system directory"));
        }
    }

    #[test]
    fn a_home_directory_of_slash_exempts_nothing() {
        // Everything is "under" /, so the exemption would swallow the rule.
        let d = scratch("slashhome");
        let usr = mkdir(d.join("usr"));
        let share = mkdir(usr.join("share"));
        let mut c = context(Some(Path::new("/")), Some(owner_of(&d)));
        c.system_trees = vec![usr];
        for source in ALL {
            assert!(why(check(&c, &share, source)).contains("inside a system directory"));
        }
    }

    // ── rule 5: roots from the environment ──────────────

    #[test]
    fn another_accounts_directory_is_refused_for_env_roots_only() {
        let d = scratch("owner");
        let dir = mkdir(d.join("cache"));
        let me = owner_of(&d);
        let stranger = Ids {
            uid: me.uid + 1,
            ..me
        };
        let c = context(None, Some(stranger));
        assert!(why(check(&c, &dir, Source::Env)).contains("not to you"));
        assert_eq!(check(&c, &dir, Source::Home), Ok(dir.clone()));
    }

    #[test]
    fn root_does_not_stand_in_for_the_owner_of_home() {
        // `sudo -E`: root, with the HOME of whoever ran sudo. What the
        // environment names in their home is theirs, not root's to empty.
        let d = scratch("sudo");
        let home = mkdir(d.join("home"));
        let dir = mkdir(d.join("cache"));
        let me = owner_of(&d);
        let root_like = Ids {
            uid: me.uid + 1,
            ..me
        };
        let c = context(Some(&home), Some(root_like));
        assert!(why(check(&c, &dir, Source::Env)).contains("not to you"));
    }

    #[test]
    fn a_world_writable_env_root_is_refused() {
        let d = scratch("world");
        let dir = mkdir(d.join("cache"));
        let c = context(None, Some(owner_of(&d)));
        for mode in [0o777, 0o757, 0o703] {
            chmod(&dir, mode);
            assert!(
                why(check(&c, &dir, Source::Env)).contains("anyone can write"),
                "{mode:o}"
            );
            assert_eq!(check(&c, &dir, Source::Home), Ok(dir.clone()), "{mode:o}");
        }
        for mode in [0o700, 0o755, 0o775] {
            chmod(&dir, mode);
            assert_eq!(check(&c, &dir, Source::Env), Ok(dir.clone()), "{mode:o}");
        }
    }

    #[test]
    fn a_group_writable_env_root_needs_the_users_own_group() {
        let d = scratch("group");
        let dir = mkdir(d.join("cache"));
        let me = owner_of(&d);
        chmod(&dir, 0o775);
        let own = context(None, Some(me));
        assert_eq!(check(&own, &dir, Source::Env), Ok(dir.clone()));

        let other_group = context(
            None,
            Some(Ids {
                gid: me.gid + 1,
                ..me
            }),
        );
        assert!(why(check(&other_group, &dir, Source::Env)).contains("members of group"));
        assert_eq!(check(&other_group, &dir, Source::Home), Ok(dir.clone()));

        // Not group-writable: whose group it is does not matter.
        chmod(&dir, 0o755);
        assert_eq!(check(&other_group, &dir, Source::Env), Ok(dir.clone()));
    }

    #[test]
    fn without_knowing_who_we_are_env_roots_fail_closed() {
        let d = scratch("noids");
        let dir = mkdir(d.join("cache"));
        let c = context(None, None);
        assert!(why(check(&c, &dir, Source::Env)).contains("could not be determined"));
        assert_eq!(check(&c, &dir, Source::Home), Ok(dir.clone()));
    }

    // ── roots the system keeps ──────────────────────────

    #[test]
    fn a_system_cache_is_not_asked_whose_it_is() {
        // Gentoo's distfiles belong to root and the portage group.
        let d = scratch("system-owner");
        let dir = mkdir(d.join("distfiles"));
        let me = owner_of(&d);
        let stranger = Ids {
            uid: me.uid + 1,
            gid: me.gid + 1,
        };
        let c = context(None, Some(stranger));
        for mode in [0o700, 0o775, 0o777] {
            chmod(&dir, mode);
            assert_eq!(check(&c, &dir, Source::System), Ok(dir.clone()), "{mode:o}");
        }
        // And it does not need to be known who is running us.
        let nobody = context(None, None);
        assert_eq!(check(&nobody, &dir, Source::System), Ok(dir.clone()));
    }

    #[test]
    fn where_a_systems_caches_live_inside_a_system_tree_is_fine_for_a_system_root() {
        // /usr/portage/distfiles, inside /usr.
        let d = scratch("cache-places");
        let usr = mkdir(d.join("usr"));
        let portage = mkdir(usr.join("portage"));
        let distfiles = mkdir(portage.join("distfiles"));
        let share = mkdir(usr.join("share"));
        let mut c = context(None, Some(owner_of(&d)));
        c.system_trees = vec![usr.clone()];
        c.cache_places = vec![portage.clone()];

        assert_eq!(check(&c, &distfiles, Source::System), Ok(distfiles.clone()));
        // Only for the system's own roots.
        for source in [Source::Home, Source::Env] {
            assert!(why(check(&c, &distfiles, source)).contains("inside a system directory"));
        }
        // What is below the place, not the place itself, and nothing else in the tree.
        assert!(why(check(&c, &portage, Source::System)).contains("inside a system directory"));
        assert!(why(check(&c, &share, Source::System)).contains("inside a system directory"));
        assert!(why(check(&c, &usr, Source::System)).contains("inside a system directory"));
    }

    #[test]
    fn a_link_into_a_systems_caches_is_judged_by_where_it_leads() {
        let d = scratch("cache-places-link");
        let usr = mkdir(d.join("usr"));
        let portage = mkdir(usr.join("portage"));
        let distfiles = mkdir(portage.join("distfiles"));
        let share = mkdir(usr.join("share"));
        let outside = d.join("distfiles-link");
        symlink(&distfiles, &outside).unwrap();
        let into_share = d.join("share-link");
        symlink(&share, &into_share).unwrap();
        let mut c = context(None, Some(owner_of(&d)));
        c.system_trees = vec![usr];
        c.cache_places = vec![portage];

        assert_eq!(check(&c, &outside, Source::System), Ok(distfiles));
        assert!(why(check(&c, &into_share, Source::System)).contains("inside a system directory"));
    }

    // ── the real machine ────────────────────────────────

    #[test]
    fn the_real_lists_refuse_the_obvious_disasters() {
        let mut c = Context::from_env();
        // The home directory is checked first, and on most machines it sits
        // under /home, so with a real $HOME the reason for `/home` would be
        // "contains your home directory". The verdict on system paths must not
        // depend on whose machine this is, so take it out of the picture.
        c.home = None;

        // Spelled out rather than read from the lists: this is the specification
        // they have to meet, whether or not the directory exists on this machine.
        let dirs = [
            "/",
            "/bin",
            "/boot",
            "/dev",
            "/etc",
            "/home",
            "/lib",
            "/lib32",
            "/lib64",
            "/libx32",
            "/media",
            "/mnt",
            "/nix",
            "/opt",
            "/proc",
            "/root",
            "/run",
            "/run/user",
            "/sbin",
            "/srv",
            "/sys",
            "/tmp",
            "/usr",
            "/var",
            "/var/cache",
            "/var/lib",
            "/var/log",
            "/var/tmp",
        ];
        let trees = [
            "/bin",
            "/boot",
            "/dev",
            "/etc",
            "/lib",
            "/lib32",
            "/lib64",
            "/libx32",
            "/nix/store",
            "/proc",
            "/sbin",
            "/sys",
            "/usr",
        ];
        for dir in dirs {
            assert!(
                c.system_dirs.iter().any(|d| d == Path::new(dir)),
                "{dir} is not listed as a system directory"
            );
        }
        for tree in trees {
            assert!(
                c.system_trees.iter().any(|d| d == Path::new(tree)),
                "{tree} is not listed as a system tree"
            );
        }

        // And the lists do what they say, where the directory is there to ask.
        for source in ALL {
            for path in dirs.into_iter().chain(["/usr/lib", "/usr/share"]) {
                if Path::new(path).is_dir() {
                    assert!(
                        why(check(&c, Path::new(path), source)).contains("system directory"),
                        "{path} via {source:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_real_lists_name_where_a_systems_caches_may_lie_inside_a_system_tree() {
        let c = Context::from_env();
        let portage = Path::new("/usr/portage");
        assert!(c.cache_places.iter().any(|place| place == portage));
        // That is the point of the list: it is inside /usr, which is a tree.
        assert!(c.system_trees.iter().any(|tree| portage.starts_with(tree)));
    }

    #[test]
    fn every_place_that_must_never_be_a_cache_is_listed() {
        // Spelled out for the same reason: the table above is checked against
        // itself by the test that walks it.
        for relative in [
            ".config",
            ".local",
            ".local/share",
            ".local/state",
            ".gnupg",
            ".ssh",
            "Desktop",
            "Documents",
            "Downloads",
            "Music",
            "Pictures",
            "Public",
            "Templates",
            "Videos",
        ] {
            assert!(
                RESERVED_UNDER_HOME.iter().any(|(r, _)| *r == relative),
                "~/{relative} is not protected"
            );
        }
    }

    #[test]
    fn symlinked_system_paths_are_listed_under_both_names() {
        let d = scratch("realpaths");
        let real = mkdir(d.join("var-home"));
        let link = d.join("home");
        symlink(&real, &link).unwrap();
        // Given only the symlink, the list must also hold where it leads.
        let list = with_real_paths(&[link.to_str().unwrap()]);
        assert!(list.contains(&link) && list.contains(&real), "{list:?}");
        assert_eq!(list.len(), 2, "{list:?}");
        // Given a path that is already real, there is nothing to add.
        let list = with_real_paths(&[real.to_str().unwrap()]);
        assert_eq!(list, vec![real.clone()]);
        // Both names given: each appears once.
        let list = with_real_paths(&[link.to_str().unwrap(), real.to_str().unwrap()]);
        assert_eq!(list.len(), 2, "no duplicates: {list:?}");
    }
}
