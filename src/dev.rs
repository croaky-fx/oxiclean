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
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use crate::mounts::Mounts;
use crate::roots;
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

/// A cache location that came from the environment (or from a tool reading it),
/// after [`roots::check`].
///
/// `UV_CACHE_DIR=$HOME` is one typo away, and a directory named this way is
/// emptied by `uv cache clean`, `go clean -modcache` or our own fallback without
/// anyone asking what it is. Locations built from `$HOME` by us skip the check:
/// they are fixed suffixes below a directory that is the user's by definition.
#[derive(Debug, PartialEq, Eq)]
enum Root {
    /// Not set, or nothing there: nothing to scan and nothing to say.
    Absent,
    /// Present, and not safe to clean. Carries what was refused and why.
    Refused(String),
    /// Safe to use.
    Dir(PathBuf),
}

impl Root {
    /// The directory, or `None` for either way of having none. Silent: refusals
    /// are reported once, by the scan (see [`reported`]).
    fn dir(self) -> Option<PathBuf> {
        match self {
            Root::Dir(path) => Some(path),
            Root::Absent | Root::Refused(_) => None,
        }
    }
}

/// Run a location the environment named through [`roots::check`]. `label` says
/// where it came from, for the message (`UV_CACHE_DIR=/x`).
fn env_root(label: &str, path: PathBuf) -> Root {
    match roots::check(&roots::Context::from_env(), &path, roots::Source::Env) {
        Ok(_) => Root::Dir(path),
        Err(roots::Reject::Missing) => Root::Absent,
        Err(roots::Reject::Unsafe(why)) => Root::Refused(format!("{label} — {why}")),
    }
}

/// Unwrap a [`Root`] for the scan, saying so when it was refused. Only
/// `scan_all` calls this, and it runs once per run, so a refusal is reported
/// once; the cleaners resolve the same locations again and stay quiet.
fn reported(root: Root) -> Option<PathBuf> {
    match root {
        Root::Dir(path) => Some(path),
        Root::Absent => None,
        Root::Refused(why) => {
            utils::error(&format!("Not cleaning {why}"));
            None
        }
    }
}

/// Resolve `pnpm store path` at runtime. Falls back to `~/.local/share/pnpm/store`
/// only if pnpm isn't on PATH.
///
/// The default location is checked first because asking pnpm costs ~280 ms — it
/// is a Node program, so the answer arrives after a full interpreter startup.
/// When the store is where pnpm puts it by default, that subprocess tells us
/// nothing we did not already know. A relocated store (`store-dir` in
/// `.npmrc`, or a pnpm-managed Node install) still falls through to asking.
fn pnpm_store_path() -> Option<PathBuf> {
    if let Some(default) = home_join(".local/share/pnpm/store") {
        if default.is_dir() {
            return Some(default);
        }
    }
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
///
/// `GOMODCACHE` and `GOPATH` are read from the environment first: when either is
/// set we already have the answer, and `go env` would only echo it back. Same
/// default-first shortcut as pnpm, though `go env` is cheap by comparison.
fn go_modcache_path() -> Root {
    for var in ["GOMODCACHE", "GOPATH"] {
        if let Ok(val) = std::env::var(var) {
            if !val.is_empty() {
                // GOPATH is a list, and the module cache lives under its first
                // entry. Joining the whole string made `/a:/b` into `/a:/b/pkg/mod`.
                let path = if var == "GOMODCACHE" {
                    PathBuf::from(&val)
                } else {
                    std::env::split_paths(&val)
                        .next()
                        .unwrap_or_default()
                        .join("pkg/mod")
                };
                return env_root(&format!("{var}={val}"), path);
            }
        }
    }
    if let Some(default) = home_join("go/pkg/mod") {
        if default.is_dir() {
            return Root::Dir(default);
        }
    }
    if utils::which("go") {
        if let Some(out) = utils::capture("go", &["env", "GOMODCACHE"]) {
            if !out.is_empty() {
                return env_root(
                    &format!("`go env GOMODCACHE` says {out}"),
                    PathBuf::from(out),
                );
            }
        }
    }
    home_join("go/pkg/mod").map_or(Root::Absent, Root::Dir)
}

/// Resolve `uv cache dir`. Falls back to `~/.cache/uv`, honouring
/// `UV_CACHE_DIR` and `XDG_CACHE_HOME` before spawning uv.
fn uv_cache_path() -> Root {
    if let Ok(val) = std::env::var("UV_CACHE_DIR") {
        if !val.is_empty() {
            return env_root(&format!("UV_CACHE_DIR={val}"), PathBuf::from(val));
        }
    }
    // uv's own default is `$XDG_CACHE_HOME/uv`. A relative XDG_CACHE_HOME is
    // invalid per the spec and ignored, as everywhere else.
    let default = match std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
    {
        Some(x) => env_root(&format!("XDG_CACHE_HOME={}", x.display()), x.join("uv")),
        None => home_join(".cache/uv").map_or(Root::Absent, Root::Dir),
    };
    if matches!(&default, Root::Dir(d) if d.is_dir()) {
        return default;
    }
    if utils::which("uv") {
        if let Some(out) = utils::capture("uv", &["cache", "dir"]) {
            if !out.is_empty() {
                return env_root(&format!("`uv cache dir` says {out}"), PathBuf::from(out));
            }
        }
    }
    default
}

/// Resolve `deno info` cache root. Falls back to `~/.cache/deno`.
fn deno_dir_path() -> Root {
    if let Ok(env) = std::env::var("DENO_DIR") {
        if !env.is_empty() {
            return env_root(&format!("DENO_DIR={env}"), PathBuf::from(env));
        }
    }
    home_join(".cache/deno").map_or(Root::Absent, Root::Dir)
}

/// Resolve conda's package cache. Tries `conda info --json` and reads the
/// first entry of `pkgs_dirs`; falls back to `~/.conda/pkgs`.
fn conda_cache_path() -> Option<PathBuf> {
    if utils::which("conda") {
        if let Some(out) = utils::capture("conda", &["info", "--json"]) {
            if let Some(p) = parse_conda_pkgs_dir(&out) {
                return Some(PathBuf::from(p));
            }
        }
    }
    home_join(".conda/pkgs")
}

/// The first entry of `pkgs_dirs` in the JSON that `conda info --json` prints,
/// or `None` when it is missing, empty or not a string, and the caller falls
/// back.
///
/// Read as JSON, not searched for between quotes: conda is Python, and Python's
/// `json.dumps` writes every non-ASCII character as an escape unless told not
/// to (`/home/محمد/.conda/pkgs` for a home directory in
/// Arabic), so what lay between the quotes was text that is not the path. Only
/// the first value is read, so whatever a wrapper prints after it is not held
/// against it.
fn parse_conda_pkgs_dir(json: &str) -> Option<String> {
    let info: serde_json::Value = serde_json::Deserializer::from_str(json)
        .into_iter::<serde_json::Value>()
        .next()?
        .ok()?;
    let first = info.get("pkgs_dirs")?.as_array()?.first()?.as_str()?;
    (!first.is_empty()).then(|| first.to_owned())
}

/// ccache cache directory. Reads `CCACHE_DIR` env var, falls back to `~/.cache/ccache`.
fn ccache_dir_path() -> Root {
    if let Ok(env) = std::env::var("CCACHE_DIR") {
        if !env.is_empty() {
            return env_root(&format!("CCACHE_DIR={env}"), PathBuf::from(env));
        }
    }
    home_join(".cache/ccache").map_or(Root::Absent, Root::Dir)
}

/// A cache that the environment can move, found the way the tool finds it: its
/// own variable first, then `$XDG_CACHE_HOME/<xdg_subdir>` for a tool that
/// honours that (a relative one is invalid and ignored), and otherwise the
/// default below `$HOME`.
///
/// `pip cache purge`, `composer clear-cache` and `dotnet nuget locals --clear`
/// empty whatever the tool takes from its variable, so the value goes through
/// [`roots::check`] like the others, and a refusal keeps the tool from being
/// run at all (see [`scan_all`]). It also makes the scan look where the tool
/// does: a relocated cache used to be reported as the empty default.
fn relocatable_root(var: &str, xdg_subdir: Option<&str>, home_default: &str) -> Root {
    if let Ok(val) = std::env::var(var) {
        if !val.is_empty() {
            return env_root(&format!("{var}={val}"), PathBuf::from(val));
        }
    }
    if let Some(sub) = xdg_subdir {
        if let Some(x) = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
        {
            return env_root(&format!("XDG_CACHE_HOME={}", x.display()), x.join(sub));
        }
    }
    home_join(home_default).map_or(Root::Absent, Root::Dir)
}

/// pip's cache: `PIP_CACHE_DIR`, else `$XDG_CACHE_HOME/pip`, else `~/.cache/pip`.
fn pip_cache_path() -> Root {
    relocatable_root("PIP_CACHE_DIR", Some("pip"), ".cache/pip")
}

/// Composer's cache: `COMPOSER_CACHE_DIR`, else `$XDG_CACHE_HOME/composer`, else
/// `~/.cache/composer`.
fn composer_cache_path() -> Root {
    relocatable_root("COMPOSER_CACHE_DIR", Some("composer"), ".cache/composer")
}

/// NuGet's global package cache: `NUGET_PACKAGES`, else `~/.nuget/packages`.
fn nuget_cache_path() -> Root {
    relocatable_root("NUGET_PACKAGES", None, ".nuget/packages")
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

/// Whether `dir` has anything in it: the cheap question, for deciding that a
/// cache is there to be mentioned without walking all of it.
fn has_entries(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_some())
}

/// Where a cache is when only its own tool can clean it, or `None` when that
/// tool is not here.
///
/// `pnpm store prune` keeps every project's hard links valid, which deleting
/// the store by hand does not, and `go clean -modcache` copes with the
/// read-only files that defeat `rm`; the other tools listed with it are the
/// same kind of case. Without the tool nothing can be done about the cache, and
/// listing it anyway promised space that could not be freed ("Will clean now"
/// counted it) and, for pnpm, then ended the run as a failure on a machine
/// where nothing was wrong.
///
/// The tool is looked for first, so a machine that never had it pays nothing,
/// and a cache left behind by a tool that is gone, or that this `$PATH` does
/// not reach, is mentioned once, as left alone. A location the environment
/// named and [`roots::check`] refused is reported only when the tool is there
/// to act on it: without the tool nothing is run, so there is nothing to
/// refuse.
fn needs_tool(name: &str, tool: &str, root: Root) -> Option<PathBuf> {
    if utils::which(tool) {
        return reported(root);
    }
    let dir = root.dir()?;
    if has_entries(&dir) {
        utils::skip(&format!(
            "{name}: found a cache, but `{tool}` is not in your PATH — left alone"
        ));
    }
    None
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
    if let Some(c) = scan_simple(
        "pnpm",
        needs_tool(
            "pnpm",
            "pnpm",
            pnpm_store_path().map_or(Root::Absent, Root::Dir),
        ),
        "store prune",
    ) {
        out.push(c);
    }
    if let Some(c) = scan_simple("deno", reported(deno_dir_path()), "safe") {
        out.push(c);
    }

    // ── Python ecosystem ──
    if let Some(c) = scan_simple("pip", reported(pip_cache_path()), "safe") {
        out.push(c);
    }
    if let Some(c) = scan_simple("uv", reported(uv_cache_path()), "safe") {
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
    if let Some(c) = scan_simple(
        "conda",
        needs_tool(
            "conda",
            "conda",
            conda_cache_path().map_or(Root::Absent, Root::Dir),
        ),
        "safe",
    ) {
        out.push(c);
    }

    // ── C/C++ ──
    if let Some(c) = scan_simple(
        "ccache",
        needs_tool("ccache", "ccache", ccache_dir_path()),
        "safe",
    ) {
        out.push(c);
    }

    // ── .NET ──
    if let Some(c) = scan_simple(
        "nuget",
        needs_tool("nuget", "dotnet", nuget_cache_path()),
        "safe",
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
        needs_tool("go modules", "go", go_modcache_path()),
        "re-download on next build",
    ) {
        out.push(c);
    }

    // ── Ruby ──
    if utils::which("gem") {
        // gem cleanup doesn't operate on a fixed directory — it walks
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
    if let Some(c) = scan_simple(
        "composer",
        needs_tool("composer", "composer", composer_cache_path()),
        "safe",
    ) {
        out.push(c);
    }

    // ── JVM ──
    // Gradle: ONLY `caches/`, never `wrapper/` (distributions).
    if let Some(c) = scan_simple("gradle", home_join(".gradle/caches"), "safe") {
        out.push(c);
    }
    // Maven local repo. Often huge, and mostly what it can fetch again; what was
    // installed on this machine is not that, and stays (see `read_maven_repo`).
    if let Some(c) = scan_maven(home_join(".m2/repository")) {
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
        utils::plain(&format!(
            "      \u{2022} {:width$}  {:>10}   {} {}",
            c.name,
            size_str,
            marker,
            c.note.dimmed(),
            width = name_width
        ));
    }

    let total = total_size(caches);
    let to_clean = cleanable_size(caches, deep);
    utils::plain(&format!(
        "      {} Total: {}   |   Will clean now: {}",
        "\u{2500}".dimmed(),
        utils::format_size(total).cyan().bold(),
        utils::format_size(to_clean).green().bold()
    ));
    // Advice rather than content: `--quiet` drops it like every `info` line.
    if !deep && total > to_clean && !utils::is_quiet() {
        utils::plain(&format!(
            "      {} {}",
            "\u{2139}".blue(),
            "Pass --deep to also clean caches that trigger re-downloads".dimmed()
        ));
    }
}

// ─── Maven's local repository ────────────────────────
//
// `~/.m2/repository` holds two kinds of things that look alike: what Maven
// fetched from a remote repository, which the next build fetches again, and what
// was installed on this machine (`mvn install` of one's own modules,
// `install:install-file`), which no repository has. Wiping all of it, as this
// once did, loses the second kind for good.
//
// Maven keeps the difference itself. Each version directory has a
// `_remote.repositories` file that says, for every file in it, which repository
// it was fetched from, and leaves the repository empty for what was installed
// here. Only a directory whose record shows that everything in it was fetched is
// removed. One without a record (a build published to the local repository by
// Gradle leaves none), with a file the record does not list, or with anything
// installed here, stays as it is.

/// The file that holds the record.
const MAVEN_RECORD: &str = "_remote.repositories";

/// No real record is anywhere near this size; a larger one is not read.
const MAVEN_RECORD_MAX: u64 = 64 * 1024;

/// What Maven keeps beside an artifact that is not an artifact, and does not list
/// in the record: its checksums and signature, and the note of a download that
/// failed.
const MAVEN_SIDECARS: [&str; 6] = ["sha1", "md5", "sha256", "sha512", "asc", "lastUpdated"];

/// The files a record lists, when it says that every one of them was fetched from
/// a remote repository (`name>repository=`, the repository not empty), which is
/// what makes them something to download again. `None` for anything else: a file
/// installed here (empty repository), a record that lists nothing, a line that is
/// not one. What is not shown to have been fetched is not taken for it.
fn fetched_files(record: &str) -> Option<HashSet<&str>> {
    let mut files = HashSet::new();
    for line in record.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, rest) = line.rsplit_once('>')?;
        let (repository, _) = rest.split_once('=')?;
        if name.is_empty() || repository.is_empty() {
            return None;
        }
        files.insert(name);
    }
    (!files.is_empty()).then_some(files)
}

fn is_sidecar(name: &str) -> bool {
    name.rsplit_once('.')
        .is_some_and(|(_, extension)| MAVEN_SIDECARS.contains(&extension))
}

/// Whether the record in version directory `dir` shows everything in it, `files`,
/// to have been fetched.
fn all_fetched(dir: &Path, files: &[String]) -> bool {
    let record = dir.join(MAVEN_RECORD);
    let readable = std::fs::symlink_metadata(&record)
        .is_ok_and(|md| md.is_file() && md.len() <= MAVEN_RECORD_MAX);
    if !readable {
        return false;
    }
    let Ok(text) = std::fs::read_to_string(&record) else {
        return false;
    };
    let Some(fetched) = fetched_files(&text) else {
        return false;
    };
    files
        .iter()
        .all(|f| f == MAVEN_RECORD || fetched.contains(f.as_str()) || is_sidecar(f))
}

/// What a walk of the repository found.
#[derive(Debug, Default, PartialEq, Eq)]
struct MavenRepo {
    /// The version directories whose files were all fetched, by path.
    fetched: Vec<PathBuf>,
    /// How many version directories are not: installed here, or with nothing to
    /// say where they came from.
    kept: usize,
}

/// Walk the repository, `root` being its real path. Links are neither entered nor
/// counted: what a link leads to is not in the repository.
fn read_maven_repo(root: &Path) -> MavenRepo {
    let mut repo = MavenRepo::default();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let (mut files, mut subdirs) = (Vec::new(), Vec::new());
        for entry in entries.flatten() {
            // `file_type` does not follow a link.
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => subdirs.push(entry.path()),
                Ok(kind) if kind.is_file() => {
                    files.push(entry.file_name().to_string_lossy().into_owned());
                }
                _ => {}
            }
        }
        if files.iter().any(|f| f == MAVEN_RECORD) {
            if subdirs.is_empty() && all_fetched(&dir, &files) {
                repo.fetched.push(dir);
            } else {
                repo.kept += 1;
            }
        } else if subdirs.is_empty()
            && files
                .iter()
                .any(|f| f.ends_with(".pom") || f.ends_with(".jar"))
        {
            // An artifact without a record of where it came from.
            repo.kept += 1;
        } else {
            stack.extend(subdirs);
        }
    }
    repo.fetched.sort();
    repo
}

/// The repository as a cache: its size is what a clean would free, not what is
/// in it.
fn scan_maven(path: Option<PathBuf>) -> Option<DevCache> {
    let path = path?;
    // A link is not followed, as for every cache that is measured.
    if std::fs::symlink_metadata(&path).ok()?.is_symlink() {
        return None;
    }
    let real = std::fs::canonicalize(&path).ok()?;
    let mounts = Mounts::read().unwrap_or_default();
    let size: u64 = read_maven_repo(&real)
        .fetched
        .iter()
        .map(|dir| utils::dir_size_in(dir, &mounts))
        .sum();
    (size > 0).then_some(DevCache {
        name: "maven (.m2)",
        size,
        needs_redownload: true,
        note: "re-download on next build; what was installed here is kept",
    })
}

// ─── Cleaners ────────────────────────────────────────

fn clean_dir_contents(path: &Path) -> u64 {
    if !path.exists() {
        return 0;
    }
    utils::rm_contents(path)
}

/// Remove what Maven fetched from the repository at `path`, and the directories
/// that held only that. What is left is said, and is not a failure: it is what
/// cannot be fetched again.
fn clean_maven(path: &Path) -> u64 {
    clean_maven_with(path, Mounts::read())
}

/// [`clean_maven`] with the list of mounts handed in, so that a test can say what
/// is mounted where.
fn clean_maven_with(path: &Path, mounts: std::io::Result<Mounts>) -> u64 {
    // As the scan: a link is not followed.
    if std::fs::symlink_metadata(path).is_ok_and(|md| md.is_symlink()) {
        return 0;
    }
    // The mounts are listed by their real paths, so the paths below must be real.
    let root = match std::fs::canonicalize(path) {
        Ok(root) => root,
        Err(why) if why.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(why) => {
            utils::error(&format!("Could not read {}: {why}", path.display()));
            return 0;
        }
    };
    let mounts = match mounts {
        Ok(mounts) => mounts,
        Err(why) => {
            utils::error(&format!(
                "Could not read the list of mounts ({why}), so {} was left alone",
                path.display()
            ));
            return 0;
        }
    };

    // Read again: the scan was a while ago, and what it listed may have changed.
    let repo = read_maven_repo(&root);
    let mut emptied = utils::Emptied::default();
    for dir in &repo.fetched {
        let size = utils::dir_size_in(dir, &mounts);
        emptied.add(dir, size, utils::remove_entry(dir, true, &mounts));
    }
    prune_empty_parents(&repo.fetched, &root);

    emptied.mention_left();
    if let Some(complaint) = emptied.complaint(path) {
        utils::error(&complaint);
    }
    if repo.kept > 0 {
        utils::info(&format!(
            "maven (.m2): kept {} artifact(s) installed on this machine or of unknown origin — they cannot be downloaded again",
            repo.kept
        ));
    }
    emptied.freed
}

/// Remove the directories above `removed`, up to but not including `root`, that
/// nothing is left in. `remove_dir` takes only an empty directory, so what still
/// holds something (the metadata beside the versions, a version that stayed) stays.
fn prune_empty_parents(removed: &[PathBuf], root: &Path) {
    let mut parents = BTreeSet::new();
    for dir in removed {
        let mut above = dir.parent();
        while let Some(parent) = above.filter(|p| *p != root && p.starts_with(root)) {
            parents.insert(parent.to_path_buf());
            above = parent.parent();
        }
    }
    // A directory sorts after the one it is in, so the innermost come first.
    for parent in parents.iter().rev() {
        let _ = std::fs::remove_dir(parent);
    }
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

/// Run the tool's own cleanup command for `c`, with its chatter captured.
///
/// One line says what is running, because these can take a while and the
/// tool's own output no longer shows progress. A failure is reported under the
/// cache's name: `run_user_quiet` has replayed the tool's complaint by then,
/// and before output was captured that complaint was the only trace of a failed
/// cleanup, so swallowing it now would be a regression.
fn run_tool(c: &DevCache, cmd: &str, args: &[&str]) -> bool {
    let command = std::iter::once(cmd)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    utils::info(&format!("Cleaning {}: {command}", c.name));
    let ok = utils::run_user_quiet(cmd, args);
    if !ok {
        utils::error(&format!("{}: `{command}` failed", c.name));
    }
    ok
}

/// One result line per cleaned cache. The tools' own output is captured now, so
/// without this the only trace of a cleanup would be the grand total.
fn report_cleaned(c: &DevCache, deep: bool, freed: u64) {
    if c.needs_redownload && !deep {
        return; // skipped on purpose, and already flagged in the summary
    }
    if freed > 0 {
        utils::success(&format!("{}: {}", c.name, utils::format_size(freed)));
    } else if c.size > 0 {
        utils::info(&format!("{}: nothing freed", c.name));
    }
}

/// Clean one cache. The caches only their own tool can clean were listed
/// because that tool was found (see [`needs_tool`]), so their arms run it
/// without asking again; one that has gone since is reported as the failure it
/// is, not skipped in silence.
fn clean_one(c: &DevCache, deep: bool, dry_run: bool) -> u64 {
    if c.needs_redownload && !deep {
        return 0; // skipped — already reported in summary
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

        // pnpm: hard-linked store — NEVER touch directly.
        //
        // Every command-driven cleaner below takes its "before" size from
        // `c.size`, which scan_all already measured. Re-walking here doubled the
        // cost of the largest trees for a number we were holding.
        "pnpm" => {
            let before = c.size;
            run_tool(c, "pnpm", &["store", "prune"]);
            let after = pnpm_store_path().map(|p| utils::dir_size(&p)).unwrap_or(0);
            before.saturating_sub(after)
        }

        "deno" => {
            // Prefer the official command when available; otherwise fall
            // back to wiping DENO_DIR.
            if utils::which("deno") {
                let before = c.size;
                run_tool(c, "deno", &["clean"]);
                let after = deno_dir_path()
                    .dir()
                    .map(|p| utils::dir_size(&p))
                    .unwrap_or(0);
                before.saturating_sub(after)
            } else {
                deno_dir_path()
                    .dir()
                    .as_deref()
                    .map(clean_dir_contents)
                    .unwrap_or(0)
            }
        }

        // ── Python ──
        "pip" => {
            if utils::which("pip") {
                let before = c.size;
                run_tool(c, "pip", &["cache", "purge"]);
                let after = pip_cache_path()
                    .dir()
                    .map(|p| utils::dir_size(&p))
                    .unwrap_or(0);
                before.saturating_sub(after)
            } else {
                pip_cache_path()
                    .dir()
                    .as_deref()
                    .map(clean_dir_contents)
                    .unwrap_or(0)
            }
        }
        "uv" => {
            if utils::which("uv") {
                let before = c.size;
                run_tool(c, "uv", &["cache", "clean"]);
                let after = uv_cache_path()
                    .dir()
                    .map(|p| utils::dir_size(&p))
                    .unwrap_or(0);
                before.saturating_sub(after)
            } else {
                uv_cache_path()
                    .dir()
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
        "go modules" => {
            let before = c.size;
            run_tool(c, "go", &["clean", "-modcache"]);
            let after = go_modcache_path()
                .dir()
                .map(|p| utils::dir_size(&p))
                .unwrap_or(0);
            before.saturating_sub(after)
        }

        // ── Ruby ──
        "ruby gems (old versions)" => {
            // `gem cleanup` removes old versions only — it never touches
            // currently required gems. Safe by design.
            if run_tool(c, "gem", &["cleanup"]) {
                // The one line this cache gets: it has no size to report, and a
                // cleanup that worked should not look like one that did not run.
                utils::success(&format!("{}: cleaned (size not measured)", c.name));
            }
            0 // gem cleanup doesn't report freed bytes in a parseable way
        }

        // ── PHP ──
        // Prefer Composer's own cache command when it exists instead of
        // blindly deleting the directory.
        "composer" => {
            let before = c.size;
            run_tool(c, "composer", &["clear-cache", "--no-interaction"]);
            let after = composer_cache_path()
                .dir()
                .map(|p| utils::dir_size(&p))
                .unwrap_or(0);
            before.saturating_sub(after)
        }

        "conda" => {
            let before = c.size;
            run_tool(c, "conda", &["clean", "--all", "--yes"]);
            let after = conda_cache_path().map(|p| utils::dir_size(&p)).unwrap_or(0);
            before.saturating_sub(after)
        }

        // ── C/C++ ──
        "ccache" => {
            let before = c.size;
            run_tool(c, "ccache", &["-C"]);
            let after = ccache_dir_path()
                .dir()
                .map(|p| utils::dir_size(&p))
                .unwrap_or(0);
            before.saturating_sub(after)
        }

        // ── .NET ──
        "nuget" => {
            let before = c.size;
            run_tool(c, "dotnet", &["nuget", "locals", "all", "--clear"]);
            let after = nuget_cache_path()
                .dir()
                .map(|p| utils::dir_size(&p))
                .unwrap_or(0);
            before.saturating_sub(after)
        }

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
            .map(clean_maven)
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

    let mark = utils::failure_count();
    let mut freed = 0u64;
    for c in &caches {
        let f = clean_one(c, deep, dry_run);
        freed += f;
        report_cleaned(c, deep, f);
    }
    utils::say_freed(freed, mark);
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
        // What the file occupies on disk (a block, not its eleven bytes).
        let on_disk = utils::allocated(&fs::metadata(dir.join("a")).unwrap());
        assert!(on_disk > 0);
        assert_eq!(c.size, on_disk);
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

    #[test]
    fn test_has_entries_sees_a_cache_without_measuring_it() {
        let dir = std::env::temp_dir().join(format!("oxiclean_dev_entries_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        assert!(!has_entries(&dir), "a directory that is not there is empty");
        fs::create_dir_all(&dir).unwrap();
        assert!(!has_entries(&dir), "so is one with nothing in it");
        fs::write(dir.join("a"), b"x").unwrap();
        assert!(has_entries(&dir));
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
    /// We don't actually need it for the current tool set — every cleaner
    /// targets a leaf cache directory — but the property test makes the
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
    /// scanner list targets `~/.cargo` itself — they all target
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

    /// Poetry virtualenvs live in `~/.cache/pypoetry/virtualenvs/` — they
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

    /// conda must use the official `conda clean` command (which only removes
    /// tarballs/index/unused pkgs), and its path must point at the package
    /// cache, never at `envs/` where real environments live.
    #[test]
    fn test_conda_path_is_pkgs_not_envs() {
        if let Some(p) = conda_cache_path() {
            let s = p.to_string_lossy().to_string();
            assert!(!s.contains("/envs/"), "conda must never target envs/: {s}");
        }
    }

    /// The `pkgs_dirs` parser must read the first array entry, and must return
    /// `None` (so the caller falls back) for an empty array or a missing key.
    #[test]
    fn test_parse_conda_pkgs_dir() {
        let json = r#"{"pkgs_dirs": ["/home/u/.conda/pkgs", "/opt/conda/pkgs"], "envs_dirs": ["/home/u/.conda/envs"]}"#;
        assert_eq!(
            parse_conda_pkgs_dir(json).as_deref(),
            Some("/home/u/.conda/pkgs")
        );

        // Empty array must NOT leak into envs_dirs' value.
        let empty = r#"{"pkgs_dirs": [], "envs_dirs": ["/home/u/.conda/envs"]}"#;
        assert_eq!(parse_conda_pkgs_dir(empty), None);

        // Missing key.
        assert_eq!(parse_conda_pkgs_dir(r#"{"envs_dirs": []}"#), None);
    }

    #[test]
    fn test_conda_paths_are_read_the_way_json_writes_them() {
        // Python escapes what is not ASCII: the path is what the escapes say.
        let arabic = r#"{"pkgs_dirs": ["/home/محمد/.conda/pkgs"]}"#;
        assert_eq!(
            parse_conda_pkgs_dir(arabic).as_deref(),
            Some("/home/محمد/.conda/pkgs")
        );
        // Quotes and backslashes in a name.
        let odd = r#"{"pkgs_dirs": ["/home/we\"ird\\dir/pkgs"]}"#;
        assert_eq!(
            parse_conda_pkgs_dir(odd).as_deref(),
            Some(r#"/home/we"ird\dir/pkgs"#)
        );
        // The key's name inside another value is not the key.
        let decoy = r#"{"note": "\"pkgs_dirs\": [\"/decoy\"]", "pkgs_dirs": ["/real"]}"#;
        assert_eq!(parse_conda_pkgs_dir(decoy).as_deref(), Some("/real"));
        // What comes after the document is not read.
        let trailing = "{\"pkgs_dirs\": [\"/a\"]}\nsome wrapper's goodbye";
        assert_eq!(parse_conda_pkgs_dir(trailing).as_deref(), Some("/a"));
    }

    #[test]
    fn test_what_is_not_a_package_directory_falls_back() {
        for json in [
            "",
            "not json",
            "WARNING first {\"pkgs_dirs\": [\"/a\"]}",
            r#"{"pkgs_dirs": [""]}"#,
            r#"{"pkgs_dirs": [1, "/a"]}"#,
            r#"{"pkgs_dirs": "/a"}"#,
            r#"{"pkgs_dirs": null}"#,
            r#"["pkgs_dirs", ["/a"]]"#,
        ] {
            assert_eq!(parse_conda_pkgs_dir(json), None, "{json:?}");
        }
    }

    /// ccache is a pure compiler cache — fully safe to wipe. Just guard that
    /// the resolved path is the ccache dir and not something unrelated.
    #[test]
    fn test_ccache_path_shape() {
        if let Some(p) = ccache_dir_path().dir() {
            let s = p.to_string_lossy().to_string();
            assert!(s.contains("ccache"), "ccache path must mention ccache: {s}");
        }
    }

    /// NuGet's global packages cache is safe to clear (restored on next build).
    /// Guard the path shape.
    #[test]
    fn test_nuget_path_shape() {
        // Only the default is a fixed shape; a relocated one is the user's.
        if std::env::var_os("NUGET_PACKAGES").is_none() {
            if let Some(p) = nuget_cache_path().dir() {
                let s = p.to_string_lossy().to_string();
                assert!(s.ends_with(".nuget/packages"), "unexpected nuget path: {s}");
            }
        }
    }

    // ── Maven's local repository ────────────────────────

    const FETCHED: &str = "#NOTE: This is a Maven Resolver internal implementation file, its format can be changed without prior notice.\n#Wed Oct 28 10:00:00 UTC 2026\nlib-1.0.jar>central=\nlib-1.0.pom>central=\n";
    const INSTALLED: &str = "#NOTE: This is a Maven Resolver internal implementation file, its format can be changed without prior notice.\n#Wed Oct 28 10:00:00 UTC 2026\nlib-1.0.jar>=\nlib-1.0.pom>=\n";

    /// A repository in a fresh directory with a real path; `files` are
    /// (path, contents) below it.
    fn maven_repo(name: &str, files: &[(&str, &str)]) -> PathBuf {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        let root = base.join(format!("oxiclean_m2_{name}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        for (path, body) in files {
            let file = root.join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, body).unwrap();
        }
        root
    }

    const LANG3: &str = "org/apache/commons/commons-lang3/3.12.0";

    /// One of each kind: fetched (with the checksums and the failed download's
    /// note Maven leaves beside it), installed here, without any record, and
    /// fetched but with a file of someone's own beside it.
    fn mixed_repo(name: &str) -> PathBuf {
        maven_repo(
            name,
            &[
                (
                    "org/apache/commons/commons-lang3/3.12.0/_remote.repositories",
                    "commons-lang3-3.12.0.jar>central=\ncommons-lang3-3.12.0.pom>central=\n",
                ),
                (
                    "org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar",
                    "jar",
                ),
                (
                    "org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom",
                    "pom",
                ),
                (
                    "org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar.sha1",
                    "sum",
                ),
                (
                    "org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom.lastUpdated",
                    "note",
                ),
                (
                    "org/apache/commons/commons-lang3/maven-metadata-central.xml",
                    "meta",
                ),
                (
                    "com/me/app/1.0/_remote.repositories",
                    "app-1.0.jar>=\napp-1.0.pom>=\n",
                ),
                ("com/me/app/1.0/app-1.0.jar", "jar"),
                ("com/me/app/1.0/app-1.0.pom", "pom"),
                ("com/me/lib/2.0/lib-2.0.jar", "jar"),
                ("com/me/lib/2.0/lib-2.0.pom", "pom"),
                ("io/x/y/1.0/_remote.repositories", "y-1.0.jar>central=\n"),
                ("io/x/y/1.0/y-1.0.jar", "jar"),
                ("io/x/y/1.0/y-1.0-extra.jar", "mine"),
            ],
        )
    }

    const KEPT_FILES: [&str; 7] = [
        "com/me/app/1.0/app-1.0.jar",
        "com/me/app/1.0/app-1.0.pom",
        "com/me/app/1.0/_remote.repositories",
        "com/me/lib/2.0/lib-2.0.jar",
        "com/me/lib/2.0/lib-2.0.pom",
        "io/x/y/1.0/y-1.0.jar",
        "io/x/y/1.0/y-1.0-extra.jar",
    ];

    #[test]
    fn test_a_record_of_fetched_files_only_means_they_can_be_downloaded_again() {
        assert_eq!(
            fetched_files(FETCHED),
            Some(HashSet::from(["lib-1.0.jar", "lib-1.0.pom"]))
        );
        // Which repository it was does not matter, nor how the lines end.
        assert!(fetched_files("a.jar>my-repo=\r\n").is_some());
        assert!(fetched_files("a.pom>central=\n\nb.pom>other=\n").is_some());
        assert!(fetched_files("  a.pom>central=  \n").is_some());
    }

    #[test]
    fn test_anything_else_in_the_record_is_not_taken_for_a_download() {
        for record in [
            // installed here
            INSTALLED,
            // one of the files is
            "a.jar>central=\na.pom>=\n",
            // says nothing
            "",
            "# only a comment\n",
            "\n\n",
            // not lines of the record
            "a.jar\n",
            "a.jar>central\n",
            ">central=\n",
            "garbage\na.jar>central=\n",
        ] {
            assert_eq!(fetched_files(record), None, "{record:?}");
        }
    }

    #[test]
    fn test_what_maven_keeps_beside_an_artifact_is_not_an_artifact() {
        for name in [
            "a-1.0.jar.sha1",
            "a-1.0.pom.md5",
            "a-1.0.jar.sha256",
            "a-1.0.jar.sha512",
            "a-1.0.jar.asc",
            "a-1.0.pom.lastUpdated",
        ] {
            assert!(is_sidecar(name), "{name}");
        }
        for name in [
            "a-1.0.jar",
            "a-1.0.pom",
            "a-1.0.jar.part",
            "a-1.0-extra.zip",
            "sha1",
            "",
        ] {
            assert!(!is_sidecar(name), "{name}");
        }
    }

    #[test]
    fn test_the_repository_is_read_for_what_can_be_downloaded_again() {
        let root = mixed_repo("read");
        let repo = read_maven_repo(&root);
        assert_eq!(repo.fetched, vec![root.join(LANG3)]);
        // Installed here, no record, and a file the record does not list.
        assert_eq!(repo.kept, 3);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_a_record_that_cannot_be_trusted_keeps_the_directory() {
        let big = format!("a.jar>central=\n#{}\n", "x".repeat(70_000));
        let root = maven_repo(
            "untrusted",
            &[
                ("g/a/1.0/_remote.repositories", &big),
                ("g/a/1.0/a.jar", "jar"),
                ("g/b/1.0/_remote.repositories", "b.jar>central=\n"),
                ("g/b/1.0/b.jar", "jar"),
                ("g/b/1.0/deeper/c.jar", "inside a directory"),
            ],
        );
        let repo = read_maven_repo(&root);
        assert!(repo.fetched.is_empty(), "{repo:?}");
        assert_eq!(repo.kept, 2);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_cleaning_removes_what_was_fetched_and_keeps_the_rest() {
        let root = mixed_repo("clean");
        let freed = clean_maven_with(&root, Ok(Mounts::default()));
        assert!(freed > 0);
        assert!(!root.join(LANG3).exists(), "the fetched version is gone");
        // What is not a version stays, and so does the directory that holds it.
        assert!(root
            .join("org/apache/commons/commons-lang3/maven-metadata-central.xml")
            .is_file());
        for kept in KEPT_FILES {
            assert!(root.join(kept).is_file(), "{kept} was removed");
        }
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_a_repository_of_downloads_only_is_left_empty() {
        let root = maven_repo(
            "all_fetched",
            &[
                ("org/a/1.0/_remote.repositories", "a-1.0.jar>central=\n"),
                ("org/a/1.0/a-1.0.jar", "jar"),
                ("org/a/2.0/_remote.repositories", "a-2.0.jar>central=\n"),
                ("org/a/2.0/a-2.0.jar", "jar"),
                ("org/b/1.0/_remote.repositories", "b-1.0.jar>other=\n"),
                ("org/b/1.0/b-1.0.jar", "jar"),
            ],
        );
        assert!(clean_maven_with(&root, Ok(Mounts::default())) > 0);
        // The directories that held only what went are gone; the repository stays.
        assert!(root.is_dir());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_a_link_in_the_repository_is_neither_entered_nor_removed() {
        use std::os::unix::fs::symlink;
        let root = mixed_repo("links");
        let outside = maven_repo(
            "links_outside",
            &[
                ("1.0/_remote.repositories", "a-1.0.jar>central=\n"),
                ("1.0/a-1.0.jar", "jar"),
            ],
        );
        symlink(outside.join("1.0"), root.join("com/me/linked")).unwrap();
        symlink(&outside, root.join("outside")).unwrap();
        let repo = read_maven_repo(&root);
        assert_eq!(repo.fetched, vec![root.join(LANG3)]);
        assert_eq!(repo.kept, 3);
        clean_maven_with(&root, Ok(Mounts::default()));
        assert!(outside.join("1.0/a-1.0.jar").is_file());
        assert!(fs::symlink_metadata(root.join("com/me/linked")).is_ok());
        assert!(fs::symlink_metadata(root.join("outside")).is_ok());
        fs::remove_dir_all(&root).unwrap();
        fs::remove_dir_all(&outside).unwrap();
    }

    #[test]
    fn test_a_repository_that_is_a_link_is_not_followed() {
        use std::os::unix::fs::symlink;
        let real = mixed_repo("linked_repo");
        let link = real.with_file_name(format!("oxiclean_m2_link_{}", std::process::id()));
        let _ = fs::remove_file(&link);
        symlink(&real, &link).unwrap();
        assert!(scan_maven(Some(link.clone())).is_none());
        assert_eq!(clean_maven_with(&link, Ok(Mounts::default())), 0);
        assert!(real.join(LANG3).is_dir(), "it was cleaned through the link");
        fs::remove_file(&link).unwrap();
        fs::remove_dir_all(&real).unwrap();
    }

    #[test]
    fn test_a_version_that_is_a_mount_point_is_left_as_it_is() {
        let root = mixed_repo("mounted");
        let version = root.join(LANG3);
        let mounts = Mounts::of(&[&version]);
        assert_eq!(clean_maven_with(&root, Ok(mounts)), 0);
        assert!(version.join("commons-lang3-3.12.0.jar").is_file());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_without_the_list_of_mounts_nothing_is_removed_from_the_repository() {
        let root = mixed_repo("no_mounts");
        let freed = clean_maven_with(&root, Err(std::io::Error::other("no /proc here")));
        assert_eq!(freed, 0);
        assert!(root.join(LANG3).is_dir());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_the_scan_counts_what_a_clean_would_free() {
        let root = mixed_repo("scan");
        let cache = scan_maven(Some(root.clone())).expect("something to clean");
        assert_eq!(cache.name, "maven (.m2)");
        assert!(cache.needs_redownload);
        assert!(
            cache.note.contains("installed here is kept"),
            "{}",
            cache.note
        );
        assert_eq!(
            cache.size,
            utils::dir_size_in(&root.join(LANG3), &Mounts::default())
        );
        fs::remove_dir_all(&root).unwrap();

        // Nothing that can be fetched again: nothing to list, however much is there.
        let mine = maven_repo(
            "scan_mine",
            &[
                ("com/me/app/1.0/_remote.repositories", "app-1.0.jar>=\n"),
                ("com/me/app/1.0/app-1.0.jar", "x"),
            ],
        );
        assert!(scan_maven(Some(mine.clone())).is_none());
        assert!(scan_maven(Some(mine.join("missing"))).is_none());
        assert!(scan_maven(None).is_none());
        fs::remove_dir_all(&mine).unwrap();
    }
}
