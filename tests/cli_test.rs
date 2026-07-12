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
    assert!(stdout.contains("--quiet"));
    assert!(stdout.contains("--generate-completion"));
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

#[test]
fn test_generate_completion_bash() {
    let output = oxiclean()
        .args(["--generate-completion", "bash"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("oxiclean"));
    assert!(
        stdout.contains("complete -F") || stdout.contains("_oxiclean"),
        "bash completion output looks wrong. stdout was:\n{}",
        stdout
    );
}

#[test]
fn test_quiet_hides_banner_and_info_lines() {
    let output = oxiclean()
        .args(["--quiet", "--cache", "--dry-run"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("Fast Cross-Distribution Linux System Cleaner"),
        "quiet mode should hide banner subtitle. stdout was:\n{}",
        stdout
    );
    assert!(
        !stdout.contains('ℹ'),
        "quiet mode should hide info lines. stdout was:\n{}",
        stdout
    );
}

// ── v1.6.0: --json output ──

#[test]
fn test_json_output_is_valid_json() {
    // The core contract of --json: stdout is a single, parseable JSON object
    // and nothing else. Cache is user-level so this runs without root in CI.
    let output = oxiclean()
        .args(["--cache", "--json", "--dry-run"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json output did not parse as JSON ({e}). stdout was:\n{stdout}")
    });

    // Shape checks: the keys automation would rely on must be present and typed.
    assert!(parsed["version"].is_string(), "version must be a string");
    assert!(
        parsed["dry_run"].as_bool() == Some(true),
        "dry_run must be true here"
    );
    assert!(
        parsed["total_freed_bytes"].is_number(),
        "total_freed_bytes must be numeric"
    );
    assert!(
        parsed["operations"].is_object(),
        "operations must be an object"
    );
    // We asked for --cache, so that operation must appear.
    assert!(
        parsed["operations"]["cache"].is_number(),
        "cache op must be reported. got:\n{stdout}"
    );
}

#[test]
fn test_json_output_has_no_banner_or_color() {
    // JSON mode must emit ONLY the object — no banner text, no ANSI escapes.
    let output = oxiclean()
        .args(["--cache", "--json", "--dry-run"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("Oxi"),
        "JSON mode must not print the banner. stdout was:\n{stdout}"
    );
    assert!(
        !stdout.contains('\u{1b}'),
        "JSON mode must not emit ANSI color codes. stdout was:\n{stdout}"
    );
    // Exactly one line of output.
    assert_eq!(
        stdout.trim().lines().count(),
        1,
        "JSON mode must print exactly one line. stdout was:\n{stdout}"
    );
}

#[test]
fn test_skip_without_all_errors() {
    // --skip only makes sense with --all; on its own it must fail loudly.
    let output = oxiclean()
        .args(["--cache", "--skip", "packages", "--dry-run"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "--skip without --all should be a non-zero exit"
    );
}

#[test]
fn test_skip_unknown_name_errors() {
    let output = oxiclean()
        .args(["--all", "--skip", "notarealop", "--dry-run"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "an unknown --skip name should be a non-zero exit"
    );
}
