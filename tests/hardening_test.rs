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
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_{}", std::process::id()));
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

/// The binary under test with a minimal environment: nothing leaks in from the
/// developer's shell, and nothing leaks out to their real `HOME`.
fn isolated(home: &Path, path: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oxiclean"));
    command
        .env_clear()
        .env("HOME", home)
        .env("PATH", path)
        .env("TERM", "dumb")
        .env("NO_COLOR", "1");
    command
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

#[test]
fn test_dev_runs_a_tool_installed_outside_the_trusted_dirs() {
    // The 1.8.0 regression, end to end. `uv` lives in ~/.local/bin, which no
    // trusted lookup can see, and `--dev` skipped it without a word: the cache
    // was measured, the cleaner "ran", and nothing was freed.
    let root = scratch("user_tool");
    let home = root.join("home");
    let bin = home.join(".local/bin");
    let cache = home.join(".cache/uv");
    let log = root.join("uv.log");
    fs::create_dir_all(cache.join("wheels")).unwrap();
    fs::write(cache.join("wheels/pkg.whl"), vec![7u8; 64 * 1024]).unwrap();

    // The fake behaves like the real one on `cache clean`: it empties its cache.
    // It pins its own PATH first, because it needs `rm` whatever we hand it.
    let script = "#!/bin/sh\nPATH=/usr/bin:/bin\necho \"$*\" >> '@LOG@'\n\
                  if [ \"$*\" = 'cache clean' ]; then rm -rf '@CACHE@'/*; fi\n"
        .replace("@LOG@", log.to_str().unwrap())
        .replace("@CACHE@", cache.to_str().unwrap());
    write_exec(&bin.join("uv"), &script);

    // PATH holds the user's bin and nothing else, so no real pnpm, go or gem on
    // the developer's machine can wander into the run.
    let out = isolated(&home, bin.to_str().unwrap())
        .args(["--dev", "--yes"])
        .output()
        .unwrap();

    assert!(out.status.success(), "{}", report(&out));
    let calls = fs::read_to_string(&log).unwrap_or_default();
    assert!(
        calls.lines().any(|l| l == "cache clean"),
        "uv was never asked to clean its cache\ncalls: {calls:?}\n{}",
        report(&out)
    );
    assert_eq!(
        fs::read_dir(&cache).unwrap().count(),
        0,
        "the cache should have been emptied\n{}",
        report(&out)
    );
    let _ = fs::remove_dir_all(&root);
}
