//! End-to-end checks for the hardening work: the real binary, a throwaway
//! `HOME`, a controlled `$PATH`, and fake tools standing in for the real ones.
//!
//! Nothing here touches the developer's own caches or tools: every child runs
//! under `env_clear()` plus the few variables a test chooses to set.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

/// A fresh scratch directory, unique to this test and this process.
fn scratch(name: &str) -> PathBuf {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let dir = base.join(format!("{name}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Write `body` to `path` as an executable script, creating parent directories.
fn write_exec(path: &Path, body: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(path)
        .unwrap();
    file.write_all(body.as_bytes()).unwrap();
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Everything worth seeing when an assertion about a run fails.
fn report(out: &Output) -> String {
    format!(
        "status: {}\n--- stdout:\n{}\n--- stderr:\n{}",
        out.status,
        text(&out.stdout),
        text(&out.stderr)
    )
}

/// Put 64 KiB into `dir`, standing in for a tool's cache.
fn fill_cache(dir: &Path) {
    fs::create_dir_all(dir.join("data")).unwrap();
    fs::write(dir.join("data/blob"), vec![7u8; 64 * 1024]).unwrap();
}

fn entries(dir: &Path) -> usize {
    fs::read_dir(dir).map(|d| d.count()).unwrap_or(0)
}

/// A throwaway `HOME` with a tools directory that is the *whole* `PATH`, so no
/// real pnpm, go or gem on the developer's machine can wander into a run.
struct Sandbox {
    root: PathBuf,
    home: PathBuf,
    bin: PathBuf,
    log: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Self {
        let root = scratch(name);
        let home = root.join("home");
        let bin = home.join(".local/bin");
        fs::create_dir_all(&bin).unwrap();
        let log = root.join("calls.log");
        Sandbox {
            root,
            home,
            bin,
            log,
        }
    }

    /// The binary under test, with a minimal environment: nothing leaks in from
    /// the developer's shell, and nothing leaks out to their real `HOME`.
    fn oxiclean(&self, args: &[&str]) -> Command {
        self.command_for(Path::new(env!("CARGO_BIN_EXE_oxiclean")), args)
    }

    /// The same, for a copy of the binary somewhere else.
    fn command_for(&self, exe: &Path, args: &[&str]) -> Command {
        let mut command = Command::new(exe);
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", &self.bin)
            .env("TERM", "dumb")
            .env("NO_COLOR", "1")
            .args(args);
        command
    }

    /// What the fake tools logged, one line per call.
    fn calls(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn cleanup(&self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// What a fake tool says and does besides logging its calls.
struct Behaviour<'a> {
    stdout: &'a str,
    stderr: &'a str,
    exit: i32,
}

const WELL_BEHAVED: Behaviour = Behaviour {
    stdout: "",
    stderr: "",
    exit: 0,
};

/// A fake cleaner called `tool`: logs every call, makes the noise `behaviour`
/// asks for, and on `clean_args` empties `cache` the way the real one does,
/// provided it succeeds. It pins its own PATH first because it needs `rm`
/// whatever it was handed.
fn fake_cleaner(sb: &Sandbox, tool: &str, clean_args: &str, cache: &Path, behaviour: &Behaviour) {
    let script = "#!/bin/sh\nPATH=/usr/bin:/bin\n\
                  echo \"$*\" >> '@LOG@'\n\
                  [ -n '@OUT@' ] && echo '@OUT@'\n\
                  [ -n '@ERR@' ] && echo '@ERR@' >&2\n\
                  if [ \"$*\" = '@ARGS@' ] && [ @EXIT@ -eq 0 ]; then rm -rf '@CACHE@'/*; fi\n\
                  exit @EXIT@\n"
        .replace("@LOG@", sb.log.to_str().unwrap())
        .replace("@OUT@", behaviour.stdout)
        .replace("@ERR@", behaviour.stderr)
        .replace("@EXIT@", &behaviour.exit.to_string())
        .replace("@ARGS@", clean_args)
        .replace("@CACHE@", cache.to_str().unwrap());
    write_exec(&sb.bin.join(tool), &script);
}

/// A fake `uv`, which cleans on `cache clean` (see [`fake_cleaner`]).
fn fake_uv(sb: &Sandbox, cache: &Path, behaviour: &Behaviour) {
    fake_cleaner(sb, "uv", "cache clean", cache, behaviour);
}

/// A fake `dotnet` standing in for a freshly installed SDK on its first run.
///
/// Unless the environment says otherwise it prints the welcome banner on stdout
/// and creates `cert`, the kind of side effect no cache cleaner should cause
/// (the real SDK generates an HTTPS development certificate). Every call is
/// logged together with the switches it saw, and `nuget locals all --clear`
/// empties `nuget`. With `banner_always` the banner ignores `DOTNET_NOLOGO`, to
/// prove that capturing the output hides it regardless.
fn fake_first_run_dotnet(sb: &Sandbox, nuget: &Path, cert: &Path, banner_always: bool) {
    let banner_if = if banner_always {
        "true"
    } else {
        "[ -z \"$DOTNET_NOLOGO\" ]"
    };
    let script = "#!/bin/sh\nPATH=/usr/bin:/bin\n\
        echo \"NOLOGO=$DOTNET_NOLOGO TELEMETRY=$DOTNET_CLI_TELEMETRY_OPTOUT CERT=$DOTNET_GENERATE_ASPNET_CERTIFICATE TOOLS=$DOTNET_ADD_GLOBAL_TOOLS_TO_PATH WORKLOAD=$DOTNET_SKIP_WORKLOAD_INTEGRITY_CHECK ARGS=$*\" >> '@LOG@'\n\
        if @BANNER@; then echo 'Welcome to .NET 99.0!'; echo 'Learn about HTTPS: https://aka.ms/dotnet-https'; fi\n\
        if [ \"$DOTNET_GENERATE_ASPNET_CERTIFICATE\" != false ]; then : > '@CERT@'; fi\n\
        if [ \"$*\" = 'nuget locals all --clear' ]; then rm -rf '@NUGET@'/*; fi\n"
        .replace("@LOG@", sb.log.to_str().unwrap())
        .replace("@BANNER@", banner_if)
        .replace("@CERT@", cert.to_str().unwrap())
        .replace("@NUGET@", nuget.to_str().unwrap());
    write_exec(&sb.bin.join("dotnet"), &script);
}

// ── 1.8.0 regression: tools outside the trusted directories ──

#[test]
fn test_dev_runs_a_tool_installed_outside_the_trusted_dirs() {
    // `uv` lives in ~/.local/bin, which no trusted lookup can see, and `--dev`
    // skipped it without a word: the cache was measured, the cleaner "ran", and
    // nothing was freed.
    let sb = Sandbox::new("user_tool");
    let cache = sb.home.join(".cache/uv");
    fill_cache(&cache);
    fake_uv(&sb, &cache, &WELL_BEHAVED);

    let out = sb.oxiclean(&["--dev", "--yes"]).output().unwrap();

    assert!(out.status.success(), "{}", report(&out));
    assert!(
        sb.calls().lines().any(|l| l == "cache clean"),
        "uv was never asked to clean its cache\ncalls: {:?}\n{}",
        sb.calls(),
        report(&out)
    );
    assert_eq!(
        entries(&cache),
        0,
        "the cache should have been emptied\n{}",
        report(&out)
    );
    sb.cleanup();
}

// ── .NET first-run side effects ──

#[test]
fn test_dotnet_runs_without_banner_or_first_run_side_effects() {
    let sb = Sandbox::new("dotnet_first_run");
    let nuget = sb.home.join(".nuget/packages");
    fill_cache(&nuget);
    let cert = sb.root.join("https-dev-cert");
    fake_first_run_dotnet(&sb, &nuget, &cert, false);

    let out = sb.oxiclean(&["--dev", "--yes"]).output().unwrap();

    assert!(out.status.success(), "{}", report(&out));
    let stdout = text(&out.stdout);
    assert!(
        !stdout.contains("Welcome to .NET") && !stdout.contains("aka.ms"),
        "the SDK's welcome banner leaked into the report:\n{}",
        report(&out)
    );
    assert!(
        !cert.exists(),
        "a development certificate was generated as a side effect of clearing a cache"
    );
    let calls = sb.calls();
    for switch in [
        "NOLOGO=1",
        "TELEMETRY=1",
        "CERT=false",
        "TOOLS=false",
        "WORKLOAD=1",
    ] {
        assert!(calls.contains(switch), "{switch} was not set:\n{calls}");
    }
    assert!(calls.contains("ARGS=nuget locals all --clear"), "{calls}");
    assert_eq!(entries(&nuget), 0, "{}", report(&out));
    sb.cleanup();
}

#[test]
fn test_banner_is_hidden_even_if_the_sdk_ignores_the_switch() {
    // The switches stop the side effects; capturing the output is what keeps the
    // report clean regardless, for an SDK whose banner has no off switch.
    let sb = Sandbox::new("dotnet_banner_always");
    let nuget = sb.home.join(".nuget/packages");
    fill_cache(&nuget);
    fake_first_run_dotnet(&sb, &nuget, &sb.root.join("https-dev-cert"), true);

    let out = sb.oxiclean(&["--dev", "--yes"]).output().unwrap();

    assert!(out.status.success(), "{}", report(&out));
    assert!(
        !text(&out.stdout).contains("Welcome to .NET"),
        "{}",
        report(&out)
    );
    assert_eq!(entries(&nuget), 0, "{}", report(&out));
    sb.cleanup();
}

#[test]
fn test_dotnet_defaults_never_override_the_users_own_settings() {
    let sb = Sandbox::new("dotnet_user_choice");
    let nuget = sb.home.join(".nuget/packages");
    fill_cache(&nuget);
    fake_first_run_dotnet(&sb, &nuget, &sb.root.join("https-dev-cert"), false);

    // The user wants telemetry on; the other switches are still ours to set.
    let out = sb
        .oxiclean(&["--dev", "--yes"])
        .env("DOTNET_CLI_TELEMETRY_OPTOUT", "0")
        .output()
        .unwrap();

    assert!(out.status.success(), "{}", report(&out));
    let calls = sb.calls();
    assert!(
        calls.contains("TELEMETRY=0"),
        "user's choice lost:\n{calls}"
    );
    assert!(calls.contains("NOLOGO=1"), "{calls}");
    sb.cleanup();
}

// ── Captured tool output ──

#[test]
fn test_tool_output_is_captured_unless_verbose() {
    let sb = Sandbox::new("captured_output");
    let cache = sb.home.join(".cache/uv");
    fill_cache(&cache);
    let chatty = Behaviour {
        stdout: "UV-CHATTER-LINE",
        stderr: "",
        exit: 0,
    };
    fake_uv(&sb, &cache, &chatty);

    let quiet = sb.oxiclean(&["--dev", "--yes"]).output().unwrap();
    assert!(quiet.status.success(), "{}", report(&quiet));
    let stdout = text(&quiet.stdout);
    assert!(!stdout.contains("UV-CHATTER-LINE"), "{}", report(&quiet));
    // Our own report says what happened instead.
    assert!(stdout.contains("uv: "), "no result line for uv:\n{stdout}");
    assert_eq!(entries(&cache), 0, "{}", report(&quiet));

    // `--verbose` is the way back to the raw output.
    fill_cache(&cache);
    let verbose = sb
        .oxiclean(&["--dev", "--yes", "--verbose"])
        .output()
        .unwrap();
    assert!(
        text(&verbose.stdout).contains("UV-CHATTER-LINE"),
        "{}",
        report(&verbose)
    );
    sb.cleanup();
}

#[test]
fn test_failing_tool_replays_its_complaint_and_is_reported() {
    let sb = Sandbox::new("failing_tool");
    let cache = sb.home.join(".cache/uv");
    fill_cache(&cache);
    let failing = Behaviour {
        stdout: "",
        stderr: "uv: error: disk on fire",
        exit: 2,
    };
    fake_uv(&sb, &cache, &failing);

    let out = sb.oxiclean(&["--dev", "--yes"]).output().unwrap();

    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("uv: error: disk on fire"),
        "the tool's complaint was swallowed:\n{}",
        report(&out)
    );
    assert!(
        stdout.contains("`uv cache clean` failed"),
        "no failure line:\n{}",
        report(&out)
    );
    assert_eq!(
        entries(&cache),
        1,
        "a failed cleanup must leave the cache alone"
    );
    // The failure is the result; "Freed 0 B" beneath it would contradict it.
    assert!(
        !stdout.contains("Freed"),
        "a failed cleanup closed with a success line:\n{}",
        report(&out)
    );
    sb.cleanup();
}

#[test]
fn test_a_tools_complaint_cannot_drive_the_terminal() {
    // A tool quotes what it was given, and what it was given can be a file name,
    // which may hold anything but a slash: "clear the screen", "retitle the
    // window". The complaint is replayed under our failure line, so it is shown
    // and not obeyed.
    let sb = Sandbox::new("hostile_complaint");
    let cache = sb.home.join(".cache/uv");
    fill_cache(&cache);
    let hostile = Behaviour {
        stdout: "",
        stderr: "uv: error: bad name \u{1b}[2J\u{1b}]0;pwned\u{7}",
        exit: 2,
    };
    fake_uv(&sb, &cache, &hostile);

    let out = sb.oxiclean(&["--dev", "--yes"]).output().unwrap();

    // NO_COLOR is set, so oxiclean writes no escape sequence of its own: any ESC
    // or BEL in its output came from the tool.
    assert!(
        !out.stdout.contains(&0x1b) && !out.stdout.contains(&0x07),
        "an escape sequence reached the terminal:\n{}",
        report(&out)
    );
    assert!(
        text(&out.stdout).contains(r"uv: error: bad name \u{1b}[2J\u{1b}]0;pwned\u{7}"),
        "the complaint should still be readable:\n{}",
        report(&out)
    );
    sb.cleanup();
}

// ── What the summary promises ──

#[test]
fn test_redownload_caches_are_left_alone_without_deep_and_say_nothing() {
    // Without `--deep` a cache that would be downloaded again is flagged in the
    // summary and skipped. It must not also get a result line claiming that
    // nothing was freed from it.
    let sb = Sandbox::new("redownload_skipped");
    let registry = sb.home.join(".cargo/registry/cache");
    fill_cache(&registry);
    // Something that does get cleaned, so the run goes past "Nothing to clean"
    // and through the loop that reports on each cache.
    let uv = sb.home.join(".cache/uv");
    fill_cache(&uv);
    fake_uv(&sb, &uv, &WELL_BEHAVED);

    let out = sb.oxiclean(&["--dev", "--yes"]).output().unwrap();

    assert!(out.status.success(), "{}", report(&out));
    assert_eq!(entries(&uv), 0, "the run should have cleaned uv");
    let stdout = text(&out.stdout);
    assert!(stdout.contains("cargo registry/cache"), "{}", report(&out));
    assert!(
        !stdout.contains("cargo registry/cache:"),
        "a skipped cache got a result line:\n{}",
        report(&out)
    );
    assert_eq!(entries(&registry), 1, "the cache must be left alone");
    sb.cleanup();
}

#[test]
fn test_the_deep_hint_is_advice_so_quiet_drops_it() {
    let sb = Sandbox::new("deep_hint");
    fill_cache(&sb.home.join(".cargo/registry/cache"));
    fill_cache(&sb.home.join(".cache/uv"));
    fake_uv(&sb, &sb.home.join(".cache/uv"), &WELL_BEHAVED);

    let loud = sb.oxiclean(&["--dev", "--yes"]).output().unwrap();
    assert!(
        text(&loud.stdout).contains("Pass --deep"),
        "{}",
        report(&loud)
    );

    fill_cache(&sb.home.join(".cache/uv"));
    let quiet = sb
        .oxiclean(&["--dev", "--yes", "--quiet"])
        .output()
        .unwrap();
    assert!(quiet.status.success(), "{}", report(&quiet));
    assert!(
        !text(&quiet.stdout).contains("Pass --deep"),
        "{}",
        report(&quiet)
    );
    sb.cleanup();
}

// ── Tools that are not there ──

/// The caches only their own tool may clean: what `--dev` calls each one, the
/// tool it needs, and where the tool keeps it by default. `go` and `dotnet`
/// differ from the name of their cache, the case a message can get wrong.
const TOOL_OWNED: [(&str, &str, &str); 6] = [
    ("pnpm", "pnpm", ".local/share/pnpm/store"),
    ("go modules", "go", "go/pkg/mod"),
    ("conda", "conda", ".conda/pkgs"),
    ("ccache", "ccache", ".cache/ccache"),
    ("nuget", "dotnet", ".nuget/packages"),
    ("composer", "composer", ".cache/composer"),
];

#[test]
fn test_a_cache_whose_tool_is_missing_is_left_alone_and_is_not_a_failure() {
    // A pnpm store left behind, or one this PATH does not reach, used to be
    // listed as cleanable, counted in "Will clean now", and then to fail the
    // whole run when pnpm could not be started.
    for (name, tool, location) in TOOL_OWNED {
        let sb = Sandbox::new("tool_missing");
        let cache = sb.home.join(location);
        fill_cache(&cache);
        // Something that does get cleaned, so the run prints its summary.
        let uv = sb.home.join(".cache/uv");
        fill_cache(&uv);
        fake_uv(&sb, &uv, &WELL_BEHAVED);

        let out = sb.oxiclean(&["--dev", "--yes", "--deep"]).output().unwrap();
        let stdout = text(&out.stdout);

        assert!(out.status.success(), "{name}\n{}", report(&out));
        assert_eq!(
            entries(&cache),
            1,
            "{name}: the cache must be left alone\n{}",
            report(&out)
        );
        assert!(
            stdout.contains(&format!(
                "{name}: found a cache, but `{tool}` is not in your PATH"
            )),
            "{name}: no word about the tool\n{}",
            report(&out)
        );
        assert!(
            !stdout.contains(&format!("\u{2022} {name}")),
            "{name} was listed as cleanable\n{}",
            report(&out)
        );
        assert_eq!(entries(&uv), 0, "the rest of the run still happens");
        sb.cleanup();
    }
}

#[test]
fn test_a_machine_that_never_had_the_tool_hears_nothing_about_it() {
    // No cache and no tool: nothing to leave alone, so nothing to say.
    let sb = Sandbox::new("tool_never_had");
    let uv = sb.home.join(".cache/uv");
    fill_cache(&uv);
    fake_uv(&sb, &uv, &WELL_BEHAVED);

    let out = sb.oxiclean(&["--dev", "--yes", "--deep"]).output().unwrap();

    assert!(out.status.success(), "{}", report(&out));
    assert!(
        !text(&out.stdout).contains("left alone"),
        "{}",
        report(&out)
    );
    sb.cleanup();
}

#[test]
fn test_pnpm_prunes_its_store_when_it_is_there() {
    let sb = Sandbox::new("pnpm_present");
    let store = sb.home.join(".local/share/pnpm/store");
    fill_cache(&store);
    fake_cleaner(&sb, "pnpm", "store prune", &store, &WELL_BEHAVED);

    let out = sb.oxiclean(&["--dev", "--yes"]).output().unwrap();

    assert!(out.status.success(), "{}", report(&out));
    assert!(
        sb.calls().lines().any(|l| l == "store prune"),
        "pnpm was never asked to prune\n{:?}\n{}",
        sb.calls(),
        report(&out)
    );
    assert_eq!(entries(&store), 0, "{}", report(&out));
    assert!(text(&out.stdout).contains("Freed"), "{}", report(&out));
    sb.cleanup();
}

#[test]
fn test_a_successful_cleanup_that_frees_nothing_still_says_so() {
    // The other half of "no Freed line after a failure": a run where nothing
    // went wrong states its result, even when the result is zero.
    let sb = Sandbox::new("pnpm_nothing_to_prune");
    let store = sb.home.join(".local/share/pnpm/store");
    fill_cache(&store);
    // Prunes, succeeds, and finds nothing to remove.
    let elsewhere = sb.root.join("elsewhere");
    fake_cleaner(&sb, "pnpm", "store prune", &elsewhere, &WELL_BEHAVED);

    let out = sb.oxiclean(&["--dev", "--yes"]).output().unwrap();

    assert!(out.status.success(), "{}", report(&out));
    assert!(text(&out.stdout).contains("Freed 0 B"), "{}", report(&out));
    sb.cleanup();
}

#[test]
fn test_a_failed_pnpm_prune_is_a_failure_without_a_freed_line() {
    let sb = Sandbox::new("pnpm_fails");
    let store = sb.home.join(".local/share/pnpm/store");
    fill_cache(&store);
    let failing = Behaviour {
        stdout: "",
        stderr: "pnpm: ERR_DISK_ON_FIRE",
        exit: 1,
    };
    fake_cleaner(&sb, "pnpm", "store prune", &store, &failing);

    let out = sb.oxiclean(&["--dev", "--yes"]).output().unwrap();
    let stdout = text(&out.stdout);

    assert_eq!(out.status.code(), Some(1), "{}", report(&out));
    assert!(
        stdout.contains("`pnpm store prune` failed"),
        "{}",
        report(&out)
    );
    assert!(
        !stdout.contains("Freed"),
        "a failed prune closed with a success line:\n{}",
        report(&out)
    );
    assert_eq!(entries(&store), 1, "a failed prune must leave the store");
    sb.cleanup();
}

#[test]
fn test_quiet_drops_the_description_of_the_machine_and_keeps_the_warnings() {
    // `--help` promises "no banner sub-lines" under --quiet. What the run is going
    // to do is not one: a dry run, or a deep one, has to say so however quiet it is.
    let sb = Sandbox::new("quiet_banner");

    let loud = sb
        .oxiclean(&["--cache", "--dry-run", "--deep"])
        .output()
        .unwrap();
    let said = text(&loud.stdout);
    assert!(
        said.contains("System:") && said.contains("Distro:"),
        "{}",
        report(&loud)
    );

    let quiet = sb
        .oxiclean(&["--cache", "--dry-run", "--deep", "--quiet"])
        .output()
        .unwrap();
    let said = text(&quiet.stdout);
    assert!(
        !said.contains("System:") && !said.contains("Distro:"),
        "{}",
        report(&quiet)
    );
    assert!(
        said.contains("DRY RUN MODE") && said.contains("DEEP CLEAN MODE"),
        "{}",
        report(&quiet)
    );
    sb.cleanup();
}

// ── --json: exactly one document on stdout ──

#[test]
fn test_json_mode_stdout_is_a_single_document_even_with_chatty_tools() {
    let sb = Sandbox::new("json_single_document");
    let cache = sb.home.join(".cache/uv");
    fill_cache(&cache);
    let chatty = Behaviour {
        stdout: "UV-CHATTER-LINE",
        stderr: "uv: a note on stderr",
        exit: 0,
    };
    fake_uv(&sb, &cache, &chatty);

    let out = sb.oxiclean(&["--dev", "--yes", "--json"]).output().unwrap();

    assert!(out.status.success(), "{}", report(&out));
    let stdout = text(&out.stdout);
    assert_eq!(
        stdout.trim_end().lines().count(),
        1,
        "stdout must be exactly one line:\n{}",
        report(&out)
    );
    let doc: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}):\n{}", report(&out)));
    assert!(
        doc["operations"]["dev"].as_u64().unwrap_or(0) > 0,
        "dev should have freed something: {doc}"
    );
    assert!(!stdout.contains("UV-CHATTER-LINE"), "{}", report(&out));
    sb.cleanup();
}

// ── Roots handed over by the environment ──
//
// `XDG_CACHE_HOME`, `UV_CACHE_DIR`, `DENO_DIR`, `CCACHE_DIR`, `GOMODCACHE` and
// `GOPATH` name directories that get emptied. A value pointing at the home
// directory used to empty it.

/// Feed `input` to the process, as someone answering a prompt would.
fn run_with_input(command: &mut Command, input: &str) -> Output {
    use std::process::Stdio;
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The child may exit without reading (no prompt was due), so a closed pipe
    // is not a failure here.
    let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
    child.wait_with_output().unwrap()
}

/// Files in the sandbox's home that no cleanup has any business touching.
fn precious_files(sb: &Sandbox) -> Vec<PathBuf> {
    let files = vec![
        sb.home.join("thesis.txt"),
        sb.home.join("Documents/notes.txt"),
        sb.home.join("projects/app/src/main.rs"),
    ];
    for file in &files {
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, "irreplaceable").unwrap();
    }
    files
}

fn survive(files: &[PathBuf]) -> bool {
    files.iter().all(|f| f.exists())
}

/// A fake tool that only records that it was called.
fn fake_logger(sb: &Sandbox, name: &str) {
    let script = format!("#!/bin/sh\necho \"{name} $*\" >> '{}'\n", sb.log.display());
    write_exec(&sb.bin.join(name), &script);
}

#[test]
fn test_xdg_cache_home_pointing_at_home_deletes_nothing() {
    let sb = Sandbox::new("xdg_home");
    let precious = precious_files(&sb);
    let junk = sb.home.join(".cache/junk");
    fill_cache(&junk);
    // A symlink must not be a way round the check.
    let alias = sb.root.join("alias");
    std::os::unix::fs::symlink(&sb.home, &alias).unwrap();

    for target in [&sb.home, &alias] {
        let out = sb
            .oxiclean(&["--cache", "--yes"])
            .env("XDG_CACHE_HOME", target)
            .output()
            .unwrap();
        let stdout = text(&out.stdout);
        assert!(
            survive(&precious),
            "the home directory was emptied:\n{}",
            report(&out)
        );
        assert!(sb.bin.is_dir(), "{}", report(&out));
        assert!(
            stdout.contains("Refusing to clean XDG_CACHE_HOME=")
                && stdout.contains("home directory"),
            "no explanation:\n{}",
            report(&out)
        );
        // Nothing is cleaned in its place either: the user's tools use the
        // variable, so ~/.cache is not where their caches are.
        assert!(junk.join("data/blob").exists(), "{}", report(&out));
    }
    sb.cleanup();
}

#[test]
fn test_xdg_cache_home_naming_a_parent_or_a_settings_dir_is_refused() {
    let sb = Sandbox::new("xdg_parent");
    let precious = precious_files(&sb);
    fs::create_dir_all(sb.home.join(".config/app")).unwrap();
    fs::write(sb.home.join(".config/app/settings"), "x").unwrap();

    for target in [
        sb.root.clone(),
        sb.home.join(".config"),
        sb.home.join("Documents"),
    ] {
        let out = sb
            .oxiclean(&["--cache", "--yes"])
            .env("XDG_CACHE_HOME", &target)
            .output()
            .unwrap();
        assert!(survive(&precious), "{target:?}\n{}", report(&out));
        assert!(
            sb.home.join(".config/app/settings").exists(),
            "{target:?}\n{}",
            report(&out)
        );
        assert!(
            text(&out.stdout).contains("Refusing to clean"),
            "{target:?}\n{}",
            report(&out)
        );
    }
    sb.cleanup();
}

#[test]
fn test_relative_xdg_cache_home_is_ignored_not_read_against_the_cwd() {
    let sb = Sandbox::new("xdg_relative");
    let cwd = sb.root.join("cwd");
    fill_cache(&cwd.join("rel"));
    let junk = sb.home.join(".cache/junk");
    fill_cache(&junk);

    let out = sb
        .oxiclean(&["--cache", "--yes"])
        .env("XDG_CACHE_HOME", "rel")
        .current_dir(&cwd)
        .output()
        .unwrap();

    assert!(
        cwd.join("rel/data/blob").exists(),
        "a relative XDG_CACHE_HOME was resolved against the cwd:\n{}",
        report(&out)
    );
    assert!(
        text(&out.stdout).contains("not an absolute path"),
        "{}",
        report(&out)
    );
    // The spec says to ignore it, so the default cache is what gets cleaned.
    assert!(!junk.exists(), "{}", report(&out));
    sb.cleanup();
}

#[test]
fn test_a_moved_cache_is_cleaned_only_with_consent() {
    let sb = Sandbox::new("xdg_consent");
    let moved = sb.root.join("moved");
    let junk = moved.join("junk");
    let args = ["--cache"];

    // No one to say yes (cron without --yes): left alone.
    fill_cache(&junk);
    let out = run_with_input(sb.oxiclean(&args).env("XDG_CACHE_HOME", &moved), "");
    assert!(junk.join("data/blob").exists(), "{}", report(&out));
    assert!(
        text(&out.stdout).contains("XDG_CACHE_HOME points to"),
        "{}",
        report(&out)
    );

    // An explicit no.
    let out = run_with_input(sb.oxiclean(&args).env("XDG_CACHE_HOME", &moved), "n\n");
    assert!(junk.join("data/blob").exists(), "{}", report(&out));
    assert!(text(&out.stdout).contains("Left alone"), "{}", report(&out));

    // An explicit yes.
    let out = run_with_input(sb.oxiclean(&args).env("XDG_CACHE_HOME", &moved), "y\n");
    assert!(!junk.exists(), "{}", report(&out));
    assert!(moved.is_dir(), "the cache directory itself stays");

    // --yes answers for an unattended run, without a prompt.
    fill_cache(&junk);
    let out = run_with_input(
        sb.oxiclean(&["--cache", "--yes"])
            .env("XDG_CACHE_HOME", &moved),
        "",
    );
    assert!(!junk.exists(), "{}", report(&out));
    assert!(!text(&out.stdout).contains("[y/N]"), "{}", report(&out));
    sb.cleanup();
}

#[test]
fn test_a_dry_run_over_a_moved_cache_changes_nothing_and_asks_nothing() {
    let sb = Sandbox::new("xdg_dry_run");
    let moved = sb.root.join("moved");
    fill_cache(&moved.join("junk"));

    let out = run_with_input(
        sb.oxiclean(&["--cache", "--dry-run"])
            .env("XDG_CACHE_HOME", &moved),
        "",
    );

    let stdout = text(&out.stdout);
    assert!(moved.join("junk/data/blob").exists(), "{}", report(&out));
    assert!(!stdout.contains("[y/N]"), "{}", report(&out));
    assert!(
        stdout.contains("asks first"),
        "the dry run should say so:\n{}",
        report(&out)
    );
    sb.cleanup();
}

#[test]
fn test_json_mode_cleans_a_moved_cache_only_with_yes() {
    let sb = Sandbox::new("xdg_json");
    let moved = sb.root.join("moved");
    let junk = moved.join("junk");

    fill_cache(&junk);
    let out = sb
        .oxiclean(&["--cache", "--json"])
        .env("XDG_CACHE_HOME", &moved)
        .output()
        .unwrap();
    assert!(junk.join("data/blob").exists(), "{}", report(&out));
    let stdout = text(&out.stdout);
    assert_eq!(stdout.trim_end().lines().count(), 1, "{}", report(&out));
    let doc: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(doc["operations"]["cache"], 0, "{doc}");

    let out = sb
        .oxiclean(&["--cache", "--json", "--yes"])
        .env("XDG_CACHE_HOME", &moved)
        .output()
        .unwrap();
    assert!(!junk.exists(), "{}", report(&out));
    let doc: serde_json::Value = serde_json::from_str(text(&out.stdout).trim()).unwrap();
    assert!(
        doc["operations"]["cache"].as_u64().unwrap_or(0) > 0,
        "{doc}"
    );
    sb.cleanup();
}

#[test]
fn test_xdg_cache_home_naming_the_default_place_needs_no_consent() {
    // Plenty of profiles export it explicitly. Nothing has moved, so nobody
    // should be asked (and with no one to ask, the cache would stay dirty).
    let sb = Sandbox::new("xdg_default");
    let junk = sb.home.join(".cache/junk");
    fill_cache(&junk);

    let out = run_with_input(
        sb.oxiclean(&["--cache"])
            .env("XDG_CACHE_HOME", sb.home.join(".cache")),
        "",
    );

    assert!(!junk.exists(), "{}", report(&out));
    assert!(!text(&out.stdout).contains("[y/N]"), "{}", report(&out));
    sb.cleanup();
}

#[test]
fn test_a_world_writable_xdg_cache_home_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let sb = Sandbox::new("xdg_world_writable");
    let shared = sb.root.join("shared");
    fill_cache(&shared.join("junk"));
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();

    let out = sb
        .oxiclean(&["--cache", "--yes"])
        .env("XDG_CACHE_HOME", &shared)
        .output()
        .unwrap();

    assert!(shared.join("junk/data/blob").exists(), "{}", report(&out));
    assert!(
        text(&out.stdout).contains("anyone can write"),
        "{}",
        report(&out)
    );
    sb.cleanup();
}

#[test]
fn test_a_refusal_in_json_mode_is_still_one_document() {
    let sb = Sandbox::new("xdg_json_refused");
    let precious = precious_files(&sb);

    let out = sb
        .oxiclean(&["--cache", "--json", "--yes"])
        .env("XDG_CACHE_HOME", &sb.home)
        .output()
        .unwrap();

    assert!(survive(&precious), "{}", report(&out));
    let stdout = text(&out.stdout);
    assert_eq!(stdout.trim_end().lines().count(), 1, "{}", report(&out));
    serde_json::from_str::<serde_json::Value>(stdout.trim())
        .unwrap_or_else(|e| panic!("not JSON ({e}):\n{}", report(&out)));
    sb.cleanup();
}

#[test]
fn test_an_empty_or_relative_home_is_not_the_working_directory() {
    // `HOME=` made "~/.cache" into ".cache" under whatever directory the tool
    // was started from.
    for home in ["", "relative/home", "."] {
        let sb = Sandbox::new("home_unusable");
        let cwd = sb.root.join("cwd");
        fill_cache(&cwd.join(".cache/junk"));
        fill_cache(&cwd.join(".npm/_cacache"));
        fill_cache(&cwd.join("relative/home/.cache/junk"));

        let out = sb
            .oxiclean(&["--cache", "--dev", "--yes"])
            .env("HOME", home)
            .current_dir(&cwd)
            .output()
            .unwrap();

        assert!(
            cwd.join(".cache/junk/data/blob").exists(),
            "HOME={home:?}\n{}",
            report(&out)
        );
        assert!(
            cwd.join(".npm/_cacache/data/blob").exists(),
            "HOME={home:?}\n{}",
            report(&out)
        );
        assert!(
            cwd.join("relative/home/.cache/junk/data/blob").exists(),
            "HOME={home:?}\n{}",
            report(&out)
        );
        assert!(
            text(&out.stdout).contains("Cannot determine cache directory"),
            "HOME={home:?}\n{}",
            report(&out)
        );
        sb.cleanup();
    }
}

#[test]
fn test_uv_and_deno_dirs_naming_home_are_not_wiped_when_the_tool_is_missing() {
    // With no `uv` or `deno` on PATH the cleaner falls back to emptying the
    // directory itself, which is exactly where a wrong value did the damage.
    for var in ["UV_CACHE_DIR", "DENO_DIR"] {
        let sb = Sandbox::new("dev_dir_home");
        let precious = precious_files(&sb);

        let out = sb
            .oxiclean(&["--dev", "--yes", "--deep"])
            .env(var, &sb.home)
            .output()
            .unwrap();

        assert!(survive(&precious), "{var}\n{}", report(&out));
        assert!(sb.bin.is_dir(), "{var}\n{}", report(&out));
        assert!(
            text(&out.stdout).contains(&format!("Not cleaning {var}=")),
            "{var}\n{}",
            report(&out)
        );
        sb.cleanup();
    }
}

#[test]
fn test_tools_are_never_asked_to_clean_a_directory_that_is_not_a_cache() {
    // `go clean -modcache` and `ccache -C` do the deleting themselves, so the
    // only protection is not calling them.
    let cases = [
        ("go", "GOMODCACHE", "clean -modcache"),
        ("ccache", "CCACHE_DIR", "-C"),
        ("pip", "PIP_CACHE_DIR", "cache purge"),
        ("composer", "COMPOSER_CACHE_DIR", "clear-cache"),
        ("dotnet", "NUGET_PACKAGES", "nuget locals"),
    ];
    for (tool, var, call) in cases {
        let sb = Sandbox::new("tool_home");
        let precious = precious_files(&sb);
        fake_logger(&sb, tool);

        let out = sb
            .oxiclean(&["--dev", "--yes", "--deep"])
            .env(var, &sb.home)
            .output()
            .unwrap();

        assert!(survive(&precious), "{var}\n{}", report(&out));
        let calls = sb.calls();
        assert!(
            !calls.contains(call),
            "{tool} was told to clean a directory that is not a cache ({var}):\n{calls}\n{}",
            report(&out)
        );
        sb.cleanup();
    }
}

#[test]
fn test_ordinary_environment_settings_still_work() {
    // The check must not cost anyone their relocated caches.
    let sb = Sandbox::new("env_ordinary");
    let gomod = sb.root.join("gopath1/pkg/mod");
    fill_cache(&gomod);
    let uv = sb.root.join("uvcache");
    fill_cache(&uv);
    fake_logger(&sb, "go");
    fake_uv(&sb, &uv, &WELL_BEHAVED);

    // The Python, PHP and .NET caches move the same way.
    let pip = sb.root.join("pipcache");
    let composer = sb.root.join("composercache");
    let nuget = sb.root.join("nugetpkgs");
    for dir in [&pip, &composer, &nuget] {
        fill_cache(dir);
    }
    for tool in ["pip", "composer", "dotnet"] {
        fake_logger(&sb, tool);
    }

    // GOPATH is a list; the first entry owns the module cache.
    let gopath = format!(
        "{}:{}",
        sb.root.join("gopath1").display(),
        sb.root.join("gopath2").display()
    );
    let out = sb
        .oxiclean(&["--dev", "--yes", "--deep"])
        .env("GOPATH", gopath)
        .env("UV_CACHE_DIR", &uv)
        .env("PIP_CACHE_DIR", &pip)
        .env("COMPOSER_CACHE_DIR", &composer)
        .env("NUGET_PACKAGES", &nuget)
        .output()
        .unwrap();

    let calls = sb.calls();
    assert!(
        calls.contains("go clean -modcache"),
        "{calls}\n{}",
        report(&out)
    );
    for call in [
        "pip cache purge",
        "composer clear-cache",
        "dotnet nuget locals all --clear",
    ] {
        assert!(
            calls.contains(call),
            "{call} not run:\n{calls}\n{}",
            report(&out)
        );
    }
    assert!(calls.contains("cache clean"), "{calls}\n{}", report(&out));
    assert!(
        !text(&out.stdout).contains("Not cleaning"),
        "{}",
        report(&out)
    );
    sb.cleanup();
}

#[test]
fn test_xdg_cache_home_cannot_be_where_the_environment_keeps_data() {
    // A line copied from the wrong variable in a profile.
    let sb = Sandbox::new("xdg_named");
    let shared = sb.root.join("shared");
    fill_cache(&shared.join("junk"));

    for var in [
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_RUNTIME_DIR",
    ] {
        let out = sb
            .oxiclean(&["--cache", "--yes"])
            .env("XDG_CACHE_HOME", &shared)
            .env(var, &shared)
            .output()
            .unwrap();
        assert!(
            shared.join("junk/data/blob").exists(),
            "{var}\n{}",
            report(&out)
        );
        assert!(text(&out.stdout).contains(var), "{var}\n{}", report(&out));
    }
    sb.cleanup();
}

#[test]
fn test_a_tools_directory_others_can_write_to_is_not_cleaned() {
    use std::os::unix::fs::PermissionsExt;
    let sb = Sandbox::new("dev_world_writable");
    let shared = sb.root.join("shared-uv");
    fill_cache(&shared);
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    fake_uv(&sb, &shared, &WELL_BEHAVED);

    let out = sb
        .oxiclean(&["--dev", "--yes"])
        .env("UV_CACHE_DIR", &shared)
        .output()
        .unwrap();

    assert!(shared.join("data/blob").exists(), "{}", report(&out));
    assert!(!sb.calls().contains("cache clean"), "{}", report(&out));
    assert!(
        text(&out.stdout).contains("anyone can write"),
        "{}",
        report(&out)
    );
    sb.cleanup();
}

#[test]
fn test_a_relative_xdg_cache_home_does_not_stop_uv_from_being_cleaned() {
    // The spec says to ignore it; uv's own default then applies.
    let sb = Sandbox::new("uv_relative_xdg");
    let cache = sb.home.join(".cache/uv");
    fill_cache(&cache);
    fake_uv(&sb, &cache, &WELL_BEHAVED);

    let out = sb
        .oxiclean(&["--dev", "--yes"])
        .env("XDG_CACHE_HOME", "rel")
        .current_dir(&sb.root)
        .output()
        .unwrap();

    assert!(
        sb.calls().lines().any(|l| l == "cache clean"),
        "{:?}\n{}",
        sb.calls(),
        report(&out)
    );
    assert_eq!(entries(&cache), 0, "{}", report(&out));
    assert!(
        !text(&out.stdout).contains("Not cleaning"),
        "{}",
        report(&out)
    );
    sb.cleanup();
}

// ── --update ──

/// Whether `minisign.pub` holds a signing key yet. Until the maintainer adds
/// one, a build of this tree refuses to update, and says so.
fn update_key_is_embedded() -> bool {
    include_str!("../minisign.pub")
        .lines()
        .map(str::trim)
        .any(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
}

/// A stand-in HTTPS proxy on localhost. `ureq` asks it to `CONNECT` to the real
/// host; it records the request line and refuses, so nothing a test starts can
/// reach the real network, and the test learns whom the program tried to reach.
struct FakeProxy {
    url: String,
    seen: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl FakeProxy {
    fn start() -> FakeProxy {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (seen, stop) = (Arc::clone(&seen), Arc::clone(&stop));
            thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut conn, _)) => {
                            let _ = conn.set_nonblocking(false);
                            let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
                            let mut head = Vec::new();
                            let mut buf = [0u8; 1024];
                            while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 16384 {
                                match conn.read(&mut buf) {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => head.extend_from_slice(&buf[..n]),
                                }
                            }
                            let first = text(&head).lines().next().unwrap_or("").to_string();
                            seen.lock().unwrap().push(first);
                            let _ = conn.write_all(
                                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            );
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        FakeProxy {
            url,
            seen,
            stop,
            thread: Some(thread),
        }
    }

    /// The first line of every request made so far.
    fn requests(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for FakeProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[test]
fn test_update_with_json_is_refused_with_one_document() {
    // The update flow is a conversation in text. Run under --json it could
    // only be silent, so it is refused the way every other bad combination is.
    let sb = Sandbox::new("update_json");
    let proxy = FakeProxy::start();

    for args in [
        &["--update", "--json"][..],
        &["--update", "--json", "--yes"][..],
    ] {
        let out = sb
            .oxiclean(args)
            .env("HTTPS_PROXY", &proxy.url)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{}", report(&out));
        let doc: serde_json::Value = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("not exactly one JSON document ({e}):\n{}", report(&out)));
        let error = doc["error"].as_str().unwrap_or_default();
        assert!(
            error.contains("--update") && error.contains("--json"),
            "{doc}"
        );
        // An error document and nothing else: the common `status` and `schema`
        // fields, but no half-finished report mixed in.
        assert_eq!(doc["status"], "error", "{doc}");
        assert_eq!(doc["schema"], 1, "{doc}");
        assert_eq!(doc.as_object().unwrap().len(), 3, "{doc}");
    }
    assert!(proxy.requests().is_empty(), "{:?}", proxy.requests());
    sb.cleanup();
}

#[test]
fn test_update_fails_closed_and_leaves_the_binary_alone() {
    let sb = Sandbox::new("update_closed");
    let proxy = FakeProxy::start();

    // The binary under test, linked into the sandbox: it is what --update
    // would replace, and a replacement (a rename over this name) cannot reach
    // the real build output.
    let exe = sb.bin.join("oxiclean");
    let built = env!("CARGO_BIN_EXE_oxiclean");
    fs::hard_link(built, &exe)
        .or_else(|_| fs::copy(built, &exe).map(|_| ()))
        .unwrap();
    let before = fs::metadata(&exe).unwrap();

    let out = sb
        .command_for(&exe, &["--update", "--yes"])
        .env("HTTPS_PROXY", &proxy.url)
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1), "{}", report(&out));
    let said = format!("{}{}", text(&out.stdout), text(&out.stderr));
    if update_key_is_embedded() {
        // Asked GitHub, was refused, gave up. GitHub is the only one it asked.
        assert!(said.contains("couldn't check for updates"), "{said}");
        let asked = proxy.requests();
        assert!(!asked.is_empty(), "it never tried the network");
        assert!(
            asked
                .iter()
                .all(|r| r == "CONNECT api.github.com:443 HTTP/1.1"),
            "{asked:?}"
        );
    } else {
        // Nothing to verify a download against: it must not even ask.
        assert!(said.contains("no release-signing key"), "{said}");
        assert!(proxy.requests().is_empty(), "{:?}", proxy.requests());
    }

    let after = fs::metadata(&exe).unwrap();
    assert_eq!(
        (
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec()
        ),
        (after.ino(), after.len(), after.mtime(), after.mtime_nsec()),
        "the binary was touched"
    );
    let left: Vec<_> = fs::read_dir(&sb.bin)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(left, ["oxiclean"], "something was left beside the binary");
    sb.cleanup();
}

// ── What a run says about itself: exit status and the report ──
//
// Every step that did not do what it was asked prints a ✘ line, and the run now
// ends with a failing exit status to match. The JSON report carries the same
// news, so a script that never looks at the terminal still hears it.

/// Exactly one JSON document on stdout, parsed.
fn one_document(out: &Output) -> serde_json::Value {
    let stdout = text(&out.stdout);
    assert_eq!(
        stdout.trim_end().lines().count(),
        1,
        "stdout must be exactly one line:\n{}",
        report(out)
    );
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}):\n{}", report(out)))
}

const BROKEN_UV: Behaviour = Behaviour {
    stdout: "",
    stderr: "uv: error: disk on fire",
    exit: 2,
};

#[test]
fn test_a_failed_step_ends_the_run_with_status_1_and_says_how_many() {
    let sb = Sandbox::new("exit_failed_step");
    let cache = sb.home.join(".cache/uv");
    fill_cache(&cache);
    fake_uv(&sb, &cache, &BROKEN_UV);

    let out = sb.oxiclean(&["--dev", "--yes"]).output().unwrap();

    assert_eq!(out.status.code(), Some(1), "{}", report(&out));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("`uv cache clean` failed"),
        "the failure itself is still shown:\n{}",
        report(&out)
    );
    assert!(
        stdout.contains("1 error \u{2014} see the lines marked"),
        "the summary must say the run had a failure:\n{}",
        report(&out)
    );
    sb.cleanup();
}

#[test]
fn test_a_run_where_nothing_went_wrong_ends_with_status_0() {
    let sb = Sandbox::new("exit_all_well");
    let cache = sb.home.join(".cache/uv");
    fill_cache(&cache);
    fake_uv(&sb, &cache, &WELL_BEHAVED);

    let out = sb.oxiclean(&["--dev", "--yes"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", report(&out));
    assert!(!text(&out.stdout).contains("error"), "{}", report(&out));

    // Having nothing to do is not a failure either.
    let empty = sb.oxiclean(&["--trash"]).output().unwrap();
    assert_eq!(empty.status.code(), Some(0), "{}", report(&empty));
    sb.cleanup();
}

#[test]
fn test_json_mode_reports_a_failure_in_the_document_and_the_status() {
    let sb = Sandbox::new("json_failed_step");
    let cache = sb.home.join(".cache/uv");
    fill_cache(&cache);
    fake_uv(&sb, &cache, &BROKEN_UV);

    let out = sb.oxiclean(&["--dev", "--json"]).output().unwrap();

    assert_eq!(out.status.code(), Some(1), "{}", report(&out));
    let doc = one_document(&out);
    assert_eq!(doc["status"], "error", "{doc}");
    assert_eq!(doc["schema"], 1, "{doc}");
    let errors = doc["errors"].as_array().expect("errors is a list");
    assert_eq!(errors.len(), 1, "{doc}");
    assert_eq!(errors[0]["operation"], "dev", "{doc}");
    let message = errors[0]["message"].as_str().unwrap_or_default();
    assert!(message.contains("`uv cache clean` failed"), "{doc}");
    // What already read the document still finds its fields.
    assert_eq!(doc["operations"]["dev"], 0, "{doc}");
    assert!(doc["total_freed_bytes"].is_u64(), "{doc}");
    sb.cleanup();
}

#[test]
fn test_json_mode_says_ok_when_nothing_went_wrong() {
    let sb = Sandbox::new("json_all_well");
    let cache = sb.home.join(".cache/uv");
    fill_cache(&cache);
    fake_uv(&sb, &cache, &WELL_BEHAVED);

    let out = sb.oxiclean(&["--dev", "--json"]).output().unwrap();

    assert_eq!(out.status.code(), Some(0), "{}", report(&out));
    let doc = one_document(&out);
    assert_eq!(doc["status"], "ok", "{doc}");
    assert_eq!(doc["schema"], 1, "{doc}");
    assert_eq!(doc["errors"], serde_json::json!([]), "{doc}");
    sb.cleanup();
}

#[test]
fn test_only_the_operation_that_failed_is_blamed() {
    let sb = Sandbox::new("json_blame");
    // `--cache` has something to clean and succeeds; `--dev` fails.
    fill_cache(&sb.home.join(".cache/some-app"));
    let cache = sb.home.join(".cache/uv");
    fill_cache(&cache);
    fake_uv(&sb, &cache, &BROKEN_UV);

    let out = sb
        .oxiclean(&["--cache", "--dev", "--json"])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1), "{}", report(&out));
    let doc = one_document(&out);
    assert!(
        doc["operations"]["cache"].as_u64().unwrap_or(0) > 0,
        "the cache step did its work: {doc}"
    );
    let errors = doc["errors"].as_array().expect("errors is a list");
    assert_eq!(errors.len(), 1, "only dev failed: {doc}");
    assert_eq!(errors[0]["operation"], "dev", "{doc}");
    assert!(
        !sb.home.join(".cache/some-app").exists(),
        "a failure elsewhere must not stop the rest of the run"
    );
    sb.cleanup();
}

#[test]
fn test_a_failure_is_not_blamed_on_the_steps_after_it() {
    let sb = Sandbox::new("json_blame_order");
    let uv = sb.root.join("uv-cache");
    fill_cache(&uv);
    fake_uv(&sb, &uv, &WELL_BEHAVED);

    // `--cache` runs first and is refused (its root is the home directory);
    // `--dev` runs after it and has nothing to complain about.
    let out = sb
        .oxiclean(&["--cache", "--dev", "--json"])
        .env("XDG_CACHE_HOME", &sb.home)
        .env("UV_CACHE_DIR", &uv)
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1), "{}", report(&out));
    let doc = one_document(&out);
    let errors = doc["errors"].as_array().expect("errors is a list");
    assert_eq!(errors.len(), 1, "only the cache step failed: {doc}");
    assert_eq!(errors[0]["operation"], "cache", "{doc}");
    assert_eq!(
        entries(&uv),
        0,
        "an earlier failure must not stop the steps after it:\n{}",
        report(&out)
    );
    sb.cleanup();
}

#[test]
fn test_a_refused_root_is_a_failure_even_in_a_dry_run() {
    let sb = Sandbox::new("exit_refused_root");
    let precious = precious_files(&sb);

    for args in [
        &["--cache", "--yes"][..],
        &["--cache", "--dry-run"][..],
        &["--cache", "--yes", "--json"][..],
    ] {
        let out = sb
            .oxiclean(args)
            .env("XDG_CACHE_HOME", &sb.home)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(1),
            "{args:?} should fail:\n{}",
            report(&out)
        );
        assert!(survive(&precious), "{}", report(&out));
        if args.contains(&"--json") {
            let doc = one_document(&out);
            assert_eq!(doc["status"], "error", "{doc}");
            assert_eq!(doc["errors"][0]["operation"], "cache", "{doc}");
            let message = doc["errors"][0]["message"].as_str().unwrap_or_default();
            assert!(message.contains("Refusing to clean"), "{doc}");
        }
    }
    sb.cleanup();
}

#[test]
fn test_a_run_that_cannot_start_is_one_document_with_the_common_fields() {
    let sb = Sandbox::new("json_cannot_start");

    // No operation selected: exit 1, like always.
    let out = sb.oxiclean(&["--json"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", report(&out));
    let doc = one_document(&out);
    assert_eq!(doc["error"], "no operation selected", "{doc}");
    assert_eq!(doc["status"], "error", "{doc}");
    assert_eq!(doc["schema"], 1, "{doc}");

    // A command line that makes no sense: exit 2.
    let out = sb
        .oxiclean(&["--all", "--skip", "no-such-operation", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", report(&out));
    let doc = one_document(&out);
    assert!(doc["error"].is_string(), "{doc}");
    assert_eq!(doc["status"], "error", "{doc}");
    assert_eq!(doc["schema"], 1, "{doc}");
    sb.cleanup();
}

// ── Removing what cannot be removed as it stands ──

fn running_as_root() -> bool {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .map(|ids| ids.split_whitespace().nth(1) == Some("0"))
        })
        .unwrap_or(false)
}

fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// A tree like Go's module cache: nobody may write to its directories or files.
fn read_only_tree(root: &Path) {
    let deep = root.join("a/b/c");
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("file"), vec![1u8; 32 * 1024]).unwrap();
    chmod(&deep.join("file"), 0o444);
    for dir in [deep, root.join("a/b"), root.join("a"), root.to_path_buf()] {
        chmod(&dir, 0o555);
    }
}

#[test]
fn test_trash_holding_read_only_directories_is_emptied() {
    let sb = Sandbox::new("trash_read_only");
    let files = sb.home.join(".local/share/Trash/files");
    read_only_tree(&files.join("old-checkout"));

    let out = sb.oxiclean(&["--trash"]).output().unwrap();

    assert_eq!(out.status.code(), Some(0), "{}", report(&out));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("Freed"), "{}", report(&out));
    assert!(!stdout.contains("Could not"), "{}", report(&out));
    assert_eq!(entries(&files), 0, "the trash is not empty");
    sb.cleanup();
}

#[test]
fn test_a_trash_that_cannot_be_emptied_is_a_failure_that_says_so() {
    if running_as_root() {
        return; // root can remove anything
    }
    let sb = Sandbox::new("trash_stuck");
    let files = sb.home.join(".local/share/Trash/files");
    fs::create_dir_all(&files).unwrap();
    fs::write(files.join("a"), vec![1u8; 4096]).unwrap();
    fs::write(files.join("b"), vec![1u8; 4096]).unwrap();
    // The entries of this directory cannot be unlinked.
    chmod(&files, 0o555);

    let out = sb.oxiclean(&["--trash"]).output().unwrap();
    let json = sb.oxiclean(&["--trash", "--json"]).output().unwrap();
    chmod(&files, 0o755);

    assert_eq!(out.status.code(), Some(1), "{}", report(&out));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("Could not remove 2 of 2 item(s) in "),
        "{}",
        report(&out)
    );
    assert!(stdout.contains("ermission denied"), "{}", report(&out));
    assert!(stdout.contains("1 error"), "{}", report(&out));
    assert!(
        !stdout.contains("Freed 0 B"),
        "a success line for work that did not happen:\n{}",
        report(&out)
    );
    assert_eq!(entries(&files), 2, "nothing was removed");

    assert_eq!(json.status.code(), Some(1), "{}", report(&json));
    let doc = one_document(&json);
    assert_eq!(doc["status"], "error", "{doc}");
    assert_eq!(doc["errors"][0]["operation"], "trash", "{doc}");
    let message = doc["errors"][0]["message"].as_str().unwrap_or_default();
    assert!(message.starts_with("Could not remove 2 of 2"), "{doc}");
    sb.cleanup();
}

#[test]
fn test_a_cache_holding_read_only_directories_is_cleaned() {
    let sb = Sandbox::new("cache_read_only");
    let cache = sb.home.join(".cache");
    read_only_tree(&cache.join("some-app/go-mod"));
    fs::write(cache.join("plain"), vec![1u8; 4096]).unwrap();

    let out = sb.oxiclean(&["--cache", "--yes"]).output().unwrap();

    assert_eq!(out.status.code(), Some(0), "{}", report(&out));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("Freed"), "{}", report(&out));
    assert!(!stdout.contains("Could not"), "{}", report(&out));
    assert_eq!(entries(&cache), 0, "the cache is not empty");
    sb.cleanup();
}

#[test]
fn test_a_cache_that_cannot_be_cleaned_is_a_failure_that_says_so() {
    if running_as_root() {
        return; // root can remove anything
    }
    let sb = Sandbox::new("cache_stuck");
    let cache = sb.home.join(".cache");
    fs::create_dir_all(cache.join("app")).unwrap();
    fs::write(cache.join("app/blob"), vec![1u8; 4096]).unwrap();
    fs::write(cache.join("loose"), vec![1u8; 4096]).unwrap();
    // The entries of ~/.cache cannot be unlinked.
    chmod(&cache, 0o555);

    let out = sb.oxiclean(&["--cache", "--yes"]).output().unwrap();
    chmod(&cache, 0o755);

    assert_eq!(out.status.code(), Some(1), "{}", report(&out));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("Could not remove 2 of 2 item(s) in "),
        "{}",
        report(&out)
    );
    assert!(!stdout.contains("Freed 0 B"), "{}", report(&out));
    // Both entries are still there. What was inside `app` went, as it would
    // for `rm -rf`, and the directory itself could not be unlinked.
    assert!(cache.join("app").exists() && cache.join("loose").exists());
    sb.cleanup();
}

#[test]
fn test_a_relocated_pip_cache_is_found_where_pip_keeps_it() {
    // With XDG_CACHE_HOME set, pip's cache is $XDG_CACHE_HOME/pip, not
    // ~/.cache/pip, which used to be the only place looked at: the cache was
    // never reported and pip's own purge was never asked for.
    let sb = Sandbox::new("pip_xdg");
    let xdg = sb.root.join("xdg-cache");
    fill_cache(&xdg.join("pip"));
    fake_logger(&sb, "pip");

    let out = sb
        .oxiclean(&["--dev", "--yes"])
        .env("XDG_CACHE_HOME", &xdg)
        .output()
        .unwrap();

    assert!(
        sb.calls().contains("pip cache purge"),
        "{}\n{}",
        sb.calls(),
        report(&out)
    );
    assert!(
        !text(&out.stdout).contains("Not cleaning"),
        "{}",
        report(&out)
    );
    sb.cleanup();
}

#[test]
fn test_a_pip_variable_that_names_home_is_refused_in_the_report() {
    let sb = Sandbox::new("pip_home");
    let precious = precious_files(&sb);
    fake_logger(&sb, "pip");

    let out = sb
        .oxiclean(&["--dev", "--yes"])
        .env("PIP_CACHE_DIR", &sb.home)
        .output()
        .unwrap();

    assert!(survive(&precious), "{}", report(&out));
    assert!(
        text(&out.stdout).contains("Not cleaning PIP_CACHE_DIR="),
        "{}",
        report(&out)
    );
    assert_eq!(out.status.code(), Some(1), "{}", report(&out));
    sb.cleanup();
}

// ── A cache with another file system mounted inside it ──
//
// Real mounts, in a mount namespace of the test's own (`unshare -Urm`): nothing
// is mounted on the developer's machine, and the mounts are gone with the
// child. A machine that does not let a user have one (a hardened kernel, some
// containers) skips these, and the unit tests, which hand over a made-up list
// of mounts, are what is left of them there.

/// Run `script` with `sh -c`, `args` being `$1`, `$2`, … in it, as the root of a
/// user and mount namespace made for it. `None` when this machine does not
/// allow that.
fn in_private_mounts(script: &str, args: &[&Path]) -> Option<Output> {
    let probe_dir = scratch("mount_probe");
    let probe = Command::new("unshare")
        .args(["-Urm", "sh", "-c", "mount -t tmpfs tmpfs \"$0\""])
        .arg(&probe_dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .output();
    remove_unmounted(&probe_dir);
    if !probe.is_ok_and(|out| out.status.success()) {
        eprintln!("skipped: this machine gives no private mount namespace");
        return None;
    }
    Some(
        Command::new("unshare")
            .args(["-Urm", "sh", "-c", script, "sh"])
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("LC_ALL", "C")
            .output()
            .unwrap(),
    )
}

/// Remove a scratch directory, unless this process can see something mounted in
/// it: a test must not be able to empty what it has mounted, whatever went wrong.
fn remove_unmounted(dir: &Path) {
    let table = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    if !table.is_empty() && !table.contains(dir.to_str().unwrap()) {
        let _ = fs::remove_dir_all(dir);
    }
}

/// The part of a script's output that follows the line `@@ <name>`.
fn section<'a>(output: &'a str, name: &str) -> &'a str {
    let marker = format!("@@ {name}\n");
    let start = output.find(&marker).map(|at| at + marker.len());
    let rest = start.map(|at| &output[at..]).unwrap_or("");
    rest.split("\n@@ ").next().unwrap_or("")
}

/// What `label` is followed by on the first line that has it, to the end of it.
fn after(section: &str, label: &str) -> String {
    section
        .lines()
        .find_map(|line| {
            line.split_once(label)
                .map(|(_, rest)| rest.trim().to_string())
        })
        .unwrap_or_default()
}

const CACHE_WITH_MOUNTS: &str = r#"
set -u
BIN=$1; W=$2
C=$W/real/home/u/.cache
mkdir -p "$C/plain/sub" "$C/deep/inner/bound" "$C/mnt" "$W/source" "$W/empty"
ln -s real "$W/link"
head -c 300000 /dev/zero > "$C/plain/a"
head -c 100000 /dev/zero > "$C/plain/sub/b"
head -c 200000 /dev/zero > "$C/deep/f"
mount -t tmpfs tmpfs "$C/mnt" || exit 90
echo precious > "$C/mnt/precious"
echo precious > "$W/source/precious"
mount -o bind "$W/source" "$C/deep/inner/bound" || exit 91
echo precious > "$W/source-file"
: > "$C/deep/inner/file"
mount -o bind "$W/source-file" "$C/deep/inner/file" || exit 92
run() {
  env -i HOME="$W/link/home/u" PATH="$W/empty" TERM=dumb NO_COLOR=1 "$BIN" "$@" 2>&1
  echo "status=$?"
}
echo "@@ dry run"
run --cache --dry-run
echo "@@ run"
run --cache --yes
echo "@@ left"
(cd "$C" && find . -mindepth 1 | sort)
"#;

#[test]
fn test_a_cache_with_other_file_systems_mounted_in_it_keeps_them() {
    let work = fs::canonicalize(scratch("mounted_cache")).unwrap();
    let exe = Path::new(env!("CARGO_BIN_EXE_oxiclean"));
    let Some(out) = in_private_mounts(CACHE_WITH_MOUNTS, &[exe, &work]) else {
        remove_unmounted(&work);
        return;
    };
    let shown = report(&out);
    let stdout = text(&out.stdout);
    assert!(out.status.success(), "the script itself failed:\n{shown}");
    let (dry, real, left) = (
        section(&stdout, "dry run"),
        section(&stdout, "run"),
        section(&stdout, "left"),
    );

    // The home directory is reached through a link, as /home is /var/home on
    // Fedora Silverblue, and what the kernel lists is the real path.
    let cache = work.join("real/home/u/.cache");
    for kept in ["mnt", "deep/inner/bound", "deep/inner/file"] {
        let line = format!(
            "Kept {}: another file system is mounted there",
            cache.join(kept).display()
        );
        assert!(real.contains(&line), "{line}\n{shown}");
    }
    // In the order of the paths, not of the directory listings.
    let said: Vec<&str> = real.lines().filter(|l| l.contains("Kept ")).collect();
    let mut sorted = said.clone();
    sorted.sort();
    assert_eq!((said.len(), said), (3, sorted), "{shown}");
    // Leaving them is the job: nothing failed, and the preview was right.
    assert!(real.contains("status=0"), "{shown}");
    assert!(!real.contains("Could not"), "{shown}");
    let (would, freed) = (after(dry, "Would free "), after(real, "Freed "));
    assert!(
        !freed.is_empty() && would == freed,
        "{would:?} / {freed:?}\n{shown}"
    );
    assert!(dry.contains("status=0"), "{shown}");

    // What is mounted there is as it was, and so is what it is mounted from.
    assert_eq!(
        left.lines().collect::<Vec<_>>(),
        [
            "./deep",
            "./deep/inner",
            "./deep/inner/bound",
            "./deep/inner/bound/precious",
            "./deep/inner/file",
            "./mnt",
            "./mnt/precious",
        ],
        "{shown}"
    );
    assert_eq!(
        fs::read_to_string(work.join("source/precious")).unwrap(),
        "precious\n"
    );
    assert_eq!(
        fs::read_to_string(work.join("source-file")).unwrap(),
        "precious\n"
    );
    remove_unmounted(&work);
}

const CACHE_THAT_IS_A_MOUNT: &str = r#"
set -u
BIN=$1; W=$2
C=$W/home/.cache
mkdir -p "$C" "$W/empty"
mount -t tmpfs tmpfs "$C" || exit 90
mkdir -p "$C/plain/sub"
head -c 300000 /dev/zero > "$C/plain/sub/a"
head -c 100000 /dev/zero > "$C/b"
echo "@@ run"
env -i HOME="$W/home" PATH="$W/empty" TERM=dumb NO_COLOR=1 "$BIN" --cache --yes 2>&1
echo "status=$?"
echo "@@ left"
(cd "$C" && find . -mindepth 1 | sort)
"#;

#[test]
fn test_a_cache_that_is_itself_a_mount_is_still_emptied() {
    // ~/.cache on a file system of its own is ordinary; it is what is mounted
    // *inside* it that is not part of it.
    let work = fs::canonicalize(scratch("cache_is_mount")).unwrap();
    let exe = Path::new(env!("CARGO_BIN_EXE_oxiclean"));
    let Some(out) = in_private_mounts(CACHE_THAT_IS_A_MOUNT, &[exe, &work]) else {
        remove_unmounted(&work);
        return;
    };
    let shown = report(&out);
    let stdout = text(&out.stdout);
    assert!(out.status.success(), "the script itself failed:\n{shown}");
    let (real, left) = (section(&stdout, "run"), section(&stdout, "left"));
    assert!(real.contains("status=0"), "{shown}");
    assert!(real.contains("Freed "), "{shown}");
    assert!(
        !real.contains("Kept") && !real.contains("Could not"),
        "{shown}"
    );
    assert_eq!(left, "", "the cache is not empty:\n{shown}");
    remove_unmounted(&work);
}

const CACHE_WITHOUT_THE_MOUNT_LIST: &str = r#"
set -u
BIN=$1; W=$2
C=$W/home/.cache
mkdir -p "$C/plain" "$W/empty"
head -c 300000 /dev/zero > "$C/plain/a"
mount -t tmpfs tmpfs /proc || exit 90
echo "@@ run"
env -i HOME="$W/home" PATH="$W/empty" TERM=dumb NO_COLOR=1 "$BIN" --cache --yes 2>&1
echo "status=$?"
echo "@@ left"
(cd "$C" && find . -mindepth 1 | sort)
"#;

#[test]
fn test_a_cache_is_left_alone_when_the_mounts_cannot_be_listed() {
    // With /proc hidden there is no list of what is mounted where, and emptying
    // a tree without it is how a cache run empties something that is not one.
    let work = fs::canonicalize(scratch("cache_no_mount_list")).unwrap();
    let exe = Path::new(env!("CARGO_BIN_EXE_oxiclean"));
    let Some(out) = in_private_mounts(CACHE_WITHOUT_THE_MOUNT_LIST, &[exe, &work]) else {
        remove_unmounted(&work);
        return;
    };
    let shown = report(&out);
    let stdout = text(&out.stdout);
    assert!(out.status.success(), "the script itself failed:\n{shown}");
    let (real, left) = (section(&stdout, "run"), section(&stdout, "left"));
    assert!(real.contains("status=1"), "{shown}");
    assert!(
        real.contains("Could not read the list of mounts"),
        "{shown}"
    );
    assert!(!real.contains("Freed "), "{shown}");
    assert_eq!(
        left.lines().collect::<Vec<_>>(),
        ["./plain", "./plain/a"],
        "{shown}"
    );
    remove_unmounted(&work);
}

// ── A machine of our own ──
//
// What oxiclean does for a distribution rests on two things a test cannot hand
// to a child process: /etc/os-release says which distribution it is, and the
// system tools come from /usr/bin and the directories beside it, never from
// `$PATH` (`utils::resolve_trusted`). In a user and mount namespace of the
// test's own both can be made up. /usr/bin becomes a directory that holds only
// the tools the test wants to exist, /etc/os-release says what the test wants,
// and the child is "root" there, which is the developer's own user and nothing
// more. The machine itself is not touched, and the mounts are gone with the
// child. Where a user is not given a namespace (a hardened kernel, some
// containers) these skip, and so they do on an image-based system, whose /usr
// cannot be made writable for the run and which oxiclean leaves alone anyway.

/// Run before oxiclean starts, by `sh`: `$1` is the program, `$2` the machine's
/// directory and the rest is for the program. The directories that are not
/// links hold tools of the real machine and are covered by an empty file system
/// (on a merged-/usr system they are links to /usr/bin, the made-up one).
const MACHINE_PRELUDE: &str = r#"
set -eu
BIN=$1; W=$2; shift 2
M=$W/tools/mount
"$M" --bind "$W/bin" /usr/bin
"$M" --bind "$W/os-release" /etc/os-release
for d in /bin /sbin /usr/sbin /usr/local/bin /usr/local/sbin; do
  if [ -d "$d" ] && [ ! -L "$d" ]; then "$M" -t tmpfs tmpfs "$d"; fi
done
"$M" -t tmpfs tmpfs /run
. "$W/extra.sh"
export HOME="$W/home" PATH=/usr/bin LC_ALL=C NO_COLOR=1 TERM=dumb FAKE_LOG="$W/calls.log"
exec "$BIN" "$@"
"#;

/// The real tool called `name`, from where a system keeps its tools.
fn real_tool(name: &str) -> Option<PathBuf> {
    ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        .iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|path| path.is_file())
}

/// Whether the file system `/usr` is on is read-only, as `/proc/mounts` says.
fn usr_is_read_only() -> bool {
    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();
    mounts
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace().skip(1);
            let (at, _kind, options) = (fields.next()?, fields.next()?, fields.next()?);
            let holds_usr = at == "/" || at == "/usr" || "/usr".starts_with(&format!("{at}/"));
            holds_usr.then_some((at.len(), options))
        })
        .max_by_key(|(len, _)| *len)
        .is_some_and(|(_, options)| options.split(',').any(|o| o == "ro"))
}

/// A directory that stands in for the system, and what to run on it.
struct Machine {
    dir: PathBuf,
}

impl Machine {
    /// A machine whose /etc/os-release says `os_release`. It has `sh`, and so
    /// whatever script a tool of the test's own is made of, and nothing else.
    fn new(name: &str, os_release: &str) -> Machine {
        let dir = fs::canonicalize(scratch(name)).unwrap();
        for sub in ["bin", "tools", "home"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        fs::write(dir.join("os-release"), os_release).unwrap();
        fs::write(dir.join("extra.sh"), "").unwrap();
        fs::write(dir.join("calls.log"), "").unwrap();
        // The mount tool is copied out of reach of the /usr/bin that gets covered.
        if let Some(mount) = real_tool("mount") {
            fs::copy(mount, dir.join("tools/mount")).unwrap();
        }
        let machine = Machine { dir };
        machine.take_from_the_real_one(&["sh"]);
        machine
    }

    /// Copies of real tools, as the machine's own.
    fn take_from_the_real_one(&self, names: &[&str]) {
        for name in names {
            let real = real_tool(name).unwrap_or_else(|| panic!("this machine has no {name}"));
            fs::copy(real, self.dir.join("bin").join(name)).unwrap();
        }
    }

    /// A tool of the test's own: a script for the machine's `sh`. What it should
    /// leave behind it writes to `$FAKE_LOG`, which `calls` reads.
    fn tool(&self, name: &str, body: &str) {
        write_exec(
            &self.dir.join("bin").join(name),
            &format!("#!/usr/bin/sh\n{body}"),
        );
    }

    /// Shell to run in the machine before oxiclean starts, with `$M` the mount
    /// tool: more for it to find.
    fn also(&self, script: &str) {
        fs::write(self.dir.join("extra.sh"), script).unwrap();
    }

    /// What the machine's tools were asked, in order, one line each.
    fn calls(&self) -> Vec<String> {
        let log = fs::read_to_string(self.dir.join("calls.log")).unwrap();
        log.lines().map(String::from).collect()
    }

    /// `program` run on this machine with `stdin` on its input.
    fn start(&self, program: &Path, args: &[&str], stdin: &str) -> std::io::Result<Output> {
        let mut child = Command::new("unshare")
            .args(["-Urm", "sh", "-c", MACHINE_PRELUDE, "sh"])
            .arg(program)
            .arg(&self.dir)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut input = child.stdin.take().unwrap();
        let _ = input.write_all(stdin.as_bytes());
        drop(input);
        child.wait_with_output()
    }

    /// oxiclean on this machine, or `None` where one cannot be made.
    fn run(&self, args: &[&str], stdin: &str) -> Option<Output> {
        if !machines_can_be_made() {
            eprintln!("skipped: this machine cannot make one of its own to run on");
            return None;
        }
        let exe = Path::new(env!("CARGO_BIN_EXE_oxiclean"));
        Some(self.start(exe, args, stdin).unwrap())
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        remove_unmounted(&self.dir);
    }
}

/// Whether a machine can be made here: told once, by making a bare one.
fn machines_can_be_made() -> bool {
    static CAN: OnceLock<bool> = OnceLock::new();
    *CAN.get_or_init(|| {
        if usr_is_read_only() {
            return false;
        }
        let bare = Machine::new("machine_probe", "ID=probe\n");
        let sh = bare.dir.join("bin/sh");
        bare.start(&sh, &["-c", "exit 0"], "")
            .is_ok_and(|out| out.status.success())
    })
}

// What a distribution's orphaned packages are asked about, run on a made-up
// one: the question, `--yes`, and `--json`, which has no one to ask.

/// A pacman that knows two orphans and writes down what it is asked.
const ARCH_PACMAN: &str = r#"echo "pacman $*" >> "$FAKE_LOG"
case "$1" in -Qdtq) printf 'foo\nbar\n' ;; esac
"#;

/// A zypper that knows two orphans and writes down what it is asked.
const SUSE_ZYPPER: &str = r#"echo "zypper $*" >> "$FAKE_LOG"
case "$1" in
  packages) printf 'S | Repository | Name | Version | Arch\n--+------------+------+---------+-------\ni | repo | foo | 1.0 | x86_64\ni | repo | bar | 2.0 | x86_64\n' ;;
esac
"#;

const ARCH_REMOVAL: &str = "pacman -Rns --noconfirm foo bar";
const SUSE_REMOVAL: &str = "zypper remove -y --clean-deps foo bar";

fn arch_machine(name: &str) -> Machine {
    let machine = Machine::new(name, "ID=arch\nPRETTY_NAME=\"Arch Linux\"\n");
    machine.tool("pacman", ARCH_PACMAN);
    machine
}

fn suse_machine(name: &str) -> Machine {
    let machine = Machine::new(
        name,
        "ID=opensuse-tumbleweed\nID_LIKE=\"opensuse suse\"\nPRETTY_NAME=\"openSUSE Tumbleweed\"\n",
    );
    machine.tool("zypper", SUSE_ZYPPER);
    machine
}

/// `--json` with nothing to say yes with: not removed, and said as a failure.
fn assert_not_removed_for_want_of_a_yes(out: &Output, machine: &Machine, listing: &str) {
    let shown = report(out);
    assert_eq!(out.status.code(), Some(1), "{shown}");
    let doc = one_document(out);
    assert_eq!(doc["status"], "error", "{shown}");
    let message = doc["errors"][0]["message"].as_str().unwrap_or_default();
    assert!(message.contains("--yes"), "{shown}");
    assert_eq!(machine.calls(), [listing], "nothing is removed:\n{shown}");
}

#[test]
fn test_json_alone_removes_no_orphans_and_says_so() {
    // Whatever is on the input: there is no one to ask.
    let machine = arch_machine("orphans_arch_json");
    let Some(out) = machine.run(&["--orphans", "--json"], "y\ny\n") else {
        return;
    };
    assert_not_removed_for_want_of_a_yes(&out, &machine, "pacman -Qdtq");

    let machine = suse_machine("orphans_suse_json");
    let Some(out) = machine.run(&["--orphans", "--json"], "y\ny\n") else {
        return;
    };
    assert_not_removed_for_want_of_a_yes(&out, &machine, "zypper packages --orphaned");
}

#[test]
fn test_yes_removes_the_orphans_with_json_or_without() {
    for (flags, name) in [
        (&["--orphans", "--yes"][..], "orphans_yes"),
        (&["--orphans", "--yes", "--json"][..], "orphans_yes_json"),
    ] {
        let machine = arch_machine(name);
        let Some(out) = machine.run(flags, "") else {
            return;
        };
        assert!(out.status.success(), "{flags:?}: {}", report(&out));
        assert_eq!(
            machine.calls(),
            ["pacman -Qdtq", ARCH_REMOVAL],
            "{flags:?}: {}",
            report(&out)
        );

        let machine = suse_machine(&format!("{name}_suse"));
        let Some(out) = machine.run(flags, "") else {
            return;
        };
        assert!(out.status.success(), "{flags:?}: {}", report(&out));
        assert_eq!(
            machine.calls(),
            ["zypper packages --orphaned", SUSE_REMOVAL],
            "{flags:?}: {}",
            report(&out)
        );
    }
}

#[test]
fn test_a_person_asked_about_orphans_decides() {
    for (answer, removed) in [("y\n", true), ("yes\n", true), ("n\n", false), ("", false)] {
        let machine = arch_machine("orphans_asked");
        let Some(out) = machine.run(&["--orphans"], answer) else {
            return;
        };
        let shown = report(&out);
        assert!(out.status.success(), "{answer:?}: {shown}");
        let removals = machine
            .calls()
            .iter()
            .filter(|c| *c == ARCH_REMOVAL)
            .count();
        assert_eq!(removals, usize::from(removed), "{answer:?}: {shown}");
        assert!(
            text(&out.stdout).contains("Remove orphaned packages?"),
            "{shown}"
        );
    }
}

#[test]
fn test_a_dry_run_asks_nothing_and_removes_nothing() {
    let machine = arch_machine("orphans_dry_run");
    let Some(out) = machine.run(&["--orphans", "--dry-run", "--json"], "") else {
        return;
    };
    assert!(out.status.success(), "{}", report(&out));
    assert_eq!(machine.calls(), ["pacman -Qdtq"], "{}", report(&out));
}

// What Gentoo's distfiles are asked about when eclean is not installed. `eclean
// distfiles` keeps what an ebuild in the tree still wants; without it there is
// no telling the obsolete from the rest, and what is left is to remove them all,
// which costs a re-download and loses what had to be fetched by hand.

/// A made-up Gentoo with a portageq that says where DISTDIR is, and the `find`
/// that clears it. Nothing is in DISTDIR, which is not even there, until a test
/// puts something in it.
fn gentoo_machine(name: &str) -> (Machine, PathBuf) {
    let machine = Machine::new(name, "ID=gentoo\nPRETTY_NAME=\"Gentoo Linux\"\n");
    machine.take_from_the_real_one(&["find"]);
    let distdir = machine.dir.join("distfiles");
    machine.tool("portageq", &format!("echo '{}'\n", distdir.display()));
    (machine, distdir)
}

const DISTFILES: [&str; 3] = ["a-1.0.tar.gz", "b-2.1.tar.xz", "git3-src/c.pack"];

fn stock_distfiles(dir: &Path) {
    for name in DISTFILES {
        let file = dir.join(name);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, vec![1u8; 40_000]).unwrap();
    }
}

/// The files below `dir`, by their names from it, in order.
fn files_below(dir: &Path) -> Vec<String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                walk(&path, base, out);
            } else {
                out.push(path.strip_prefix(base).unwrap().display().to_string());
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

#[test]
fn test_without_eclean_the_distfiles_go_on_deep_or_on_a_yes_from_a_person() {
    // What is run, what a person types, and whether all of DISTDIR goes.
    let cases: [(&[&str], &str, bool); 8] = [
        (&["--packages"], "n\n", false),
        (&["--packages"], "", false),
        (&["--packages"], "y\n", true),
        (&["--packages", "--yes"], "y\n", false),
        (&["--packages", "--json"], "y\n", false),
        (&["--packages", "--deep"], "", true),
        (&["--packages", "--deep", "--yes"], "", true),
        (&["--packages", "--deep", "--json"], "", true),
    ];
    for (n, (args, typed, goes)) in cases.into_iter().enumerate() {
        let (machine, distdir) = gentoo_machine(&format!("gentoo_gate_{n}"));
        stock_distfiles(&distdir);
        let Some(out) = machine.run(args, typed) else {
            return;
        };
        let shown = format!("{args:?} with {typed:?} typed:\n{}", report(&out));
        // Leaving them is a choice, not a failure.
        assert!(out.status.success(), "{shown}");
        let left = files_below(&distdir);
        if goes {
            assert_eq!(left, Vec::<String>::new(), "{shown}");
            // Files, as before: the directories they were in stay.
            assert!(distdir.join("git3-src").is_dir(), "{shown}");
        } else {
            assert_eq!(left, DISTFILES.map(String::from).to_vec(), "{shown}");
        }
        let said = text(&out.stdout);
        if args.contains(&"--json") {
            assert_eq!(one_document(&out)["status"], "ok", "{shown}");
        } else if !goes {
            assert!(said.contains("--deep"), "{shown}");
        }
        // The question names what it is about.
        if args == ["--packages"] {
            assert!(said.contains(&distdir.display().to_string()), "{shown}");
        }
    }
}

#[test]
fn test_with_eclean_installed_the_distfiles_are_its_business() {
    for (args, calls) in [
        (&["--packages", "--json"][..], vec!["eclean distfiles"]),
        (
            &["--packages", "--deep"][..],
            vec!["eclean distfiles", "eclean packages"],
        ),
    ] {
        let (machine, distdir) = gentoo_machine("gentoo_with_eclean");
        machine.tool("eclean", "echo \"eclean $*\" >> \"$FAKE_LOG\"\n");
        stock_distfiles(&distdir);
        let Some(out) = machine.run(args, "") else {
            return;
        };
        let shown = format!("{args:?}:\n{}", report(&out));
        assert!(out.status.success(), "{shown}");
        assert_eq!(machine.calls(), calls, "{shown}");
        assert_eq!(files_below(&distdir).len(), DISTFILES.len(), "{shown}");
    }
}

#[test]
fn test_a_distdir_that_is_a_system_directory_is_refused_and_left_alone() {
    if !Path::new("/mnt").is_dir() {
        eprintln!("skipped: this machine has no /mnt to stand in for a system directory");
        return;
    }
    let machine = Machine::new("gentoo_refused", "ID=gentoo\n");
    machine.take_from_the_real_one(&["find"]);
    machine.tool("portageq", "echo /mnt\n");
    // /mnt is covered by a directory of ours, so that whatever is emptied by
    // mistake is a file of ours.
    let covering = machine.dir.join("mnt");
    fs::create_dir_all(&covering).unwrap();
    fs::write(covering.join("canary"), "still here").unwrap();
    machine.also(&format!("\"$M\" --bind '{}' /mnt\n", covering.display()));

    let Some(out) = machine.run(&["--packages", "--deep", "--json"], "") else {
        return;
    };
    let shown = report(&out);
    assert_eq!(out.status.code(), Some(1), "{shown}");
    let doc = one_document(&out);
    let message = doc["errors"][0]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("Refusing") && message.contains("/mnt"),
        "{shown}"
    );
    assert!(covering.join("canary").exists(), "{shown}");
}

#[test]
fn test_a_distdir_that_is_not_there_is_nothing_to_clean() {
    let (machine, distdir) = gentoo_machine("gentoo_no_distdir");
    let Some(out) = machine.run(&["--packages", "--deep", "--json"], "") else {
        return;
    };
    assert!(out.status.success(), "{}", report(&out));
    assert_eq!(one_document(&out)["status"], "ok", "{}", report(&out));
    assert!(!distdir.exists());
}

#[test]
fn test_a_distdir_that_is_a_link_is_cleared_where_it_leads() {
    let (machine, distdir) = gentoo_machine("gentoo_linked_distdir");
    let real = machine.dir.join("elsewhere");
    stock_distfiles(&real);
    std::os::unix::fs::symlink(&real, &distdir).unwrap();
    let Some(out) = machine.run(&["--packages", "--deep", "--json"], "") else {
        return;
    };
    assert!(out.status.success(), "{}", report(&out));
    assert_eq!(files_below(&real), Vec::<String>::new(), "{}", report(&out));
    assert!(fs::symlink_metadata(&distdir).unwrap().is_symlink());
}
