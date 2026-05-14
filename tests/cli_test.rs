use std::process::Command;

fn oxiclean() -> Command {
    Command::new(env!("CARGO_BIN_EXE_oxiclean"))
}

#[test]
fn test_help_flag() {
    let output = oxiclean().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("oxiclean"));
    assert!(stdout.contains("--cache"));
    assert!(stdout.contains("--all"));
}

#[test]
fn test_version_flag() {
    let output = oxiclean().arg("--version").output().unwrap();
    assert!(output.status.success());
}

#[test]
fn test_no_args_fails() {
    let output = oxiclean().output().unwrap();
    assert!(!output.status.success());
}

#[test]
fn test_dry_run_cache() {
    let output = oxiclean().args(["--cache", "--dry-run"]).output().unwrap();
    assert!(output.status.success());
}

#[test]
fn test_dry_run_trash() {
    let output = oxiclean().args(["--trash", "--dry-run"]).output().unwrap();
    assert!(output.status.success());
}

#[test]
fn test_dry_run_all() {
    let output = oxiclean().args(["--all", "--dry-run"]).output().unwrap();
    assert!(output.status.success());
}

#[test]
fn test_dry_run_deep() {
    let output = oxiclean()
        .args(["--all", "--dry-run", "--deep"])
        .output()
        .unwrap();
    assert!(output.status.success());
}

#[test]
fn test_short_flags() {
    let output = oxiclean().args(["-c", "-t", "-n"]).output().unwrap();
    assert!(output.status.success());
}

#[test]
fn test_multiple_flags() {
    let output = oxiclean()
        .args(["--cache", "--trash", "--journal", "--dry-run"])
        .output()
        .unwrap();
    assert!(output.status.success());
}

// ── v1.0.5: assert on actual output, not just exit code ──

#[test]
fn test_dry_run_output_contains_marker() {
    // --dry-run must emit the [DRY RUN] marker so users know nothing changed.
    // Cache is user-level (no sudo), so this works in CI without root.
    let output = oxiclean().args(["--cache", "--dry-run"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("[DRY RUN]") || stdout.contains("DRY RUN"),
        "dry-run output missing marker. stdout was:\n{}",
        stdout
    );
}

#[test]
fn test_no_args_shows_hint() {
    // When invoked with no flags, oxiclean must hint at --all
    // so the user knows how to proceed.
    let output = oxiclean().output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--all"),
        "no-args output should hint at --all. stdout was:\n{}",
        stdout
    );
}
