//! End-to-end checks for the hardening work: the real binary, a throwaway
//! `HOME`, a controlled `$PATH`, and fake tools standing in for the real ones.
//!
//! Nothing here touches the developer's own caches or tools: every child runs
//! under `env_clear()` plus the few variables a test chooses to set.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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
        let mut command = Command::new(env!("CARGO_BIN_EXE_oxiclean"));
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

/// A fake `uv`: logs every call, makes the noise `behaviour` asks for, and on
/// `cache clean` empties `cache` the way the real one does, provided it
/// succeeds. It pins its own PATH first because it needs `rm` whatever it was
/// handed.
fn fake_uv(sb: &Sandbox, cache: &Path, behaviour: &Behaviour) {
    let script = "#!/bin/sh\nPATH=/usr/bin:/bin\n\
                  echo \"$*\" >> '@LOG@'\n\
                  [ -n '@OUT@' ] && echo '@OUT@'\n\
                  [ -n '@ERR@' ] && echo '@ERR@' >&2\n\
                  if [ \"$*\" = 'cache clean' ] && [ @EXIT@ -eq 0 ]; then rm -rf '@CACHE@'/*; fi\n\
                  exit @EXIT@\n"
        .replace("@LOG@", sb.log.to_str().unwrap())
        .replace("@OUT@", behaviour.stdout)
        .replace("@ERR@", behaviour.stderr)
        .replace("@EXIT@", &behaviour.exit.to_string())
        .replace("@CACHE@", cache.to_str().unwrap());
    write_exec(&sb.bin.join("uv"), &script);
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
