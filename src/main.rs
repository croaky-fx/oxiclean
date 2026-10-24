mod clean;
mod detect;
mod dev;
mod roots;
mod update;
mod utils;

use clap::{CommandFactory, Parser};
use clap_complete::aot::{generate, Shell};
use colored::Colorize;
use std::time::Instant;

use crate::detect::{AurHelper, DiskType, Distro, Privilege};

/// Everything we detect once at startup. Keeping it in one struct avoids
/// threading six separate parameters through `main()` and the cleanup calls.
struct SystemInfo {
    pretty_name: String,
    distro: Distro,
    aur_helpers: Vec<AurHelper>,
    has_flatpak: bool,
    has_snap: bool,
    has_nix: bool,
    privilege: Privilege,
    disk_type: DiskType,
}

impl SystemInfo {
    fn detect() -> Self {
        Self {
            pretty_name: detect::pretty_name(),
            distro: detect::distro(),
            aur_helpers: {
                // AUR helpers are only meaningful on Arch-family distros.
                if detect::distro() == Distro::Arch {
                    detect::aur_helpers()
                } else {
                    Vec::new()
                }
            },
            has_flatpak: detect::has_flatpak(),
            has_snap: detect::has_snap(),
            has_nix: detect::has_nix(),
            privilege: detect::find_privilege(),
            disk_type: detect::detect_root_disk_type(),
        }
    }
}

/// ⚡ OxiClean — Fast Cross-Distribution Linux System Cleaner
#[derive(Parser)]
#[command(
    name = "oxiclean",
    version,
    about = "Fast cross-distribution Linux system cleaner",
    long_about = "⚡ OxiClean — Fast Cross-Distribution Linux System Cleaner\n\n\
        A comprehensive system cleanup tool that works across all major Linux\n\
        distributions. Detects your distro automatically and runs the\n\
        appropriate cleanup commands.\n\
        \n\
        EXAMPLES:\n  \
        oxiclean --all                  Clean everything (with prompts)\n  \
        oxiclean --all --yes            Clean everything (no prompts)\n  \
        oxiclean --all --yes --deep     Aggressive clean (no prompts)\n  \
        oxiclean --cache --trash        Only clean cache & trash\n  \
        oxiclean --all --dry-run        Preview what would be cleaned\n  \
        oxiclean --packages --orphans   Clean pkg cache & orphans only\n  \
        oxiclean --dev                  Clean dev-tool caches (npm, cargo, ...)\n  \
        oxiclean --all --dev --dry-run  Preview everything including dev caches\n  \
        oxiclean --generate-completion bash > ~/.local/share/bash-completion/completions/oxiclean"
)]
struct Cli {
    /// Clean user cache (~/.cache)
    #[arg(short = 'c', long)]
    cache: bool,

    /// Clean package manager cache
    #[arg(short = 'p', long)]
    packages: bool,

    /// Remove orphaned packages
    #[arg(short = 'o', long)]
    orphans: bool,

    /// Clean AUR helper cache (Arch-based only)
    #[arg(short = 'a', long)]
    aur: bool,

    /// Clean Flatpak unused runtimes & cache
    #[arg(short = 'f', long)]
    flatpak: bool,

    /// Clean Snap disabled revisions & cache
    #[arg(short = 's', long)]
    snap: bool,

    /// Vacuum systemd journal logs
    #[arg(short = 'j', long)]
    journal: bool,

    /// Empty trash
    #[arg(short = 't', long)]
    trash: bool,

    /// Clear saved crash dumps (systemd-coredump & Apport). May contain
    /// passwords/keys from crashed processes, so clearing them is a privacy win.
    #[arg(short = 'C', long)]
    coredumps: bool,

    /// Clean dev-tool caches (npm, pnpm, yarn, bun, deno, pip, uv, poetry,
    /// cargo, go, gradle, maven, composer, gem). Safe by default — caches
    /// that trigger re-downloads need --deep.
    #[arg(short = 'D', long)]
    dev: bool,

    /// TRIM SSD/NVMe filesystems (fstrim). Filesystem maintenance, not cache
    /// cleanup, so it is NOT included in --all. Trims only fstab-listed mounts
    /// (removable/USB drives are skipped). Needs root.
    #[arg(short = 'T', long)]
    trim: bool,

    /// Run all cleanup operations
    #[arg(short = 'A', long)]
    all: bool,

    /// Skip specific operations when using --all (comma-separated). Valid names:
    /// cache, packages, orphans, aur, flatpak, snap, journal, trash, coredumps.
    /// Only meaningful together with --all; using it otherwise is an error.
    #[arg(long, value_name = "OPS", value_delimiter = ',')]
    skip: Vec<String>,

    /// Enable aggressive/deep cleaning mode
    #[arg(short = 'd', long)]
    deep: bool,

    /// Skip all confirmation prompts
    #[arg(short = 'y', long)]
    yes: bool,

    /// Preview actions without making changes
    #[arg(short = 'n', long)]
    dry_run: bool,

    /// Reduce output: only section headers and action results,
    /// no banner sub-lines, no "info" hints, no "skipped" lines.
    /// Useful for cron and CI runs.
    #[arg(short = 'q', long)]
    quiet: bool,

    /// Emit a single machine-readable JSON object instead of the human report
    /// (implies non-interactive: no banner, no colors, no prompts). For
    /// automation and cron. Destructive prompts are treated as declined unless
    /// --yes/--deep is also given.
    #[arg(long)]
    json: bool,

    /// Show raw helper command output (captured by default)
    ///
    /// Helpers like pacman, paru, flatpak and journalctl each print several
    /// lines of their own; that output is captured so the report stays
    /// readable. A command that fails replays its stderr either way, so this is
    /// for debugging a package manager that is misbehaving. Ignored with --json,
    /// which must own stdout.
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Print shell completion script to stdout and exit.
    /// Supported values come from clap_complete (bash, zsh, fish, elvish, powershell).
    #[arg(long = "generate-completion", value_name = "SHELL")]
    generate_completion: Option<Shell>,

    /// Update oxiclean to the latest GitHub release (prebuilt-binary installs
    /// only; package-manager installs are told to use their package manager).
    #[arg(short = 'u', long)]
    update: bool,
}

/// The set of cleanup operations to run, resolved from the CLI flags.
///
/// Extracted from `main()` into a pure, testable value so the two safety-
/// critical invariants are guarded by unit tests rather than living as inline
/// `let do_x = ...` lines nobody can assert on:
///   1. `--all` enables the system operations but **never** `--dev` or `--trim`
///      (those have very different trade-offs and must be opt-in).
///   2. `--skip` only *subtracts* from `--all`, and only the recognised system
///      operations can be skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Ops {
    cache: bool,
    packages: bool,
    orphans: bool,
    aur: bool,
    flatpak: bool,
    snap: bool,
    journal: bool,
    trash: bool,
    coredumps: bool,
    dev: bool,
    trim: bool,
}

/// The operations `--all` turns on — and therefore the only names `--skip`
/// accepts. `dev` and `trim` are deliberately absent: they are never part of
/// `--all`, so skipping them would be meaningless.
const SKIPPABLE_OPS: &[&str] = &[
    "cache",
    "packages",
    "orphans",
    "aur",
    "flatpak",
    "snap",
    "journal",
    "trash",
    "coredumps",
];

impl Ops {
    /// Resolve the requested operations from parsed CLI flags.
    ///
    /// Returns `Err(message)` for user errors (`--skip` without `--all`, or an
    /// unknown skip name) so `main()` can report them uniformly.
    fn resolve(cli: &Cli) -> Result<Ops, String> {
        // `--skip` is a modifier on `--all`; on its own it's almost certainly a
        // mistake (the user listed things to skip but never asked to clean
        // everything). Reject it clearly instead of silently doing nothing.
        if !cli.skip.is_empty() && !cli.all {
            return Err("--skip only works together with --all".to_string());
        }
        for name in &cli.skip {
            let name = name.trim();
            if !SKIPPABLE_OPS.contains(&name) {
                return Err(format!(
                    "unknown --skip operation '{name}'. Valid: {}",
                    SKIPPABLE_OPS.join(", ")
                ));
            }
        }
        let skipped = |op: &str| cli.skip.iter().any(|s| s.trim() == op);

        Ok(Ops {
            cache: (cli.all || cli.cache) && !skipped("cache"),
            packages: (cli.all || cli.packages) && !skipped("packages"),
            orphans: (cli.all || cli.orphans) && !skipped("orphans"),
            aur: (cli.all || cli.aur) && !skipped("aur"),
            flatpak: (cli.all || cli.flatpak) && !skipped("flatpak"),
            snap: (cli.all || cli.snap) && !skipped("snap"),
            journal: (cli.all || cli.journal) && !skipped("journal"),
            trash: (cli.all || cli.trash) && !skipped("trash"),
            coredumps: (cli.all || cli.coredumps) && !skipped("coredumps"),
            // --dev and --trim are opt-in ONLY: --all must never enable them.
            // Dev caches carry re-download/rebuild costs, and --trim is SSD
            // maintenance rather than cache cleanup.
            dev: cli.dev,
            trim: cli.trim,
        })
    }

    /// True if at least one operation is selected.
    fn any(&self) -> bool {
        self.cache
            || self.packages
            || self.orphans
            || self.aur
            || self.flatpak
            || self.snap
            || self.journal
            || self.trash
            || self.coredumps
            || self.dev
            || self.trim
    }

    /// True if any selected operation needs elevated privileges.
    /// Operations that will reach for root at some point, so `main()` can cache
    /// credentials up front while it still owns the terminal.
    ///
    /// `aur` belongs here even though it looks user-level: an AUR helper's `-Sc`
    /// clears the *shared* pacman cache and calls `sudo` itself, and we sweep
    /// root-owned partial downloads out of the way first. Without the up-front
    /// prompt those calls hit a terminal that is no longer theirs to read from.
    fn needs_sudo(&self) -> bool {
        self.packages
            || self.orphans
            || self.journal
            || self.flatpak
            || self.snap
            || self.trim
            || self.coredumps
            || self.aur
    }
}

fn main() {
    let cli = Cli::parse();

    if let Some(shell) = cli.generate_completion {
        let mut cmd = Cli::command();
        let mut out = std::io::stdout();
        generate(shell, &mut cmd, "oxiclean", &mut out);
        return;
    }

    // Register --quiet BEFORE anything that might print (including the
    // banner and detection output). --json suppresses human output entirely
    // (only the final JSON object reaches stdout) and forces non-interactive.
    utils::set_quiet(cli.quiet);
    utils::set_json(cli.json);
    // --json must own stdout completely, so it beats --verbose: a machine
    // consumer parsing one JSON line cannot also receive pacman's chatter.
    utils::set_verbose(cli.verbose && !cli.json);

    // Self-update is a standalone mode — it ignores the cleanup flags.
    if cli.update {
        // --json promises one JSON document on stdout, and the update flow is a
        // conversation in plain text: it asks before it replaces the binary.
        // Run silently it would either do nothing or replace the binary with no
        // word to anyone, so refuse, in the same shape as every other refusal.
        if cli.json {
            println!(
                "{}",
                json_error("--update does not support --json: it asks first and reports in text")
            );
            std::process::exit(2);
        }
        std::process::exit(update::run(cli.yes));
    }

    let ops = match Ops::resolve(&cli) {
        Ok(o) => o,
        Err(msg) => {
            if cli.json {
                println!("{}", json_error(&msg));
            } else {
                utils::error(&msg);
            }
            std::process::exit(2);
        }
    };

    // --json implies non-interactive: destructive prompts must never block on
    // stdin, so treat them like --yes (they're still gated by --deep for the
    // truly aggressive ones via should_deep).
    let yes = cli.yes || cli.json;

    if !ops.any() {
        utils::banner(env!("CARGO_PKG_VERSION"));
        if cli.json {
            println!("{}", json_error("no operation selected"));
        } else {
            println!(
                "  {} No operation selected. Use {} for all, or select specific operations.",
                "✘".red().bold(),
                "--all".cyan()
            );
            println!();
            println!("  Quick start:  {} {}", "oxiclean".green(), "--all".cyan());
            println!("  See help:     {} {}", "oxiclean".green(), "--help".cyan());
            println!();
        }
        std::process::exit(1);
    }

    // ── Banner ──
    utils::banner(env!("CARGO_PKG_VERSION"));

    // ── Detect everything once ──
    let sys = SystemInfo::detect();

    // Register the chosen privilege helper globally so that `utils::sudo`
    // (called from every cleanup operation) uses `doas` on systems where
    // that's the available escalator.
    utils::set_privilege(sys.privilege);

    // ── System info ── Nothing is printed in JSON mode: only the final object
    // is. `--quiet` drops the description of the machine, as `--help` says it
    // does, and keeps the warnings after it, which say what this run will do.
    if !cli.json && !cli.quiet {
        println!(
            "  {} {}",
            "System:".white().bold(),
            utils::shown(&sys.pretty_name).cyan()
        );
        println!(
            "  {} {} ({})",
            "Distro:".white().bold(),
            sys.distro.name().cyan(),
            sys.distro.pkg_manager().dimmed()
        );
        if !sys.aur_helpers.is_empty() {
            let names: Vec<&str> = sys.aur_helpers.iter().map(|h| h.bin).collect();
            println!("  {} {}", "AUR:".white().bold(), names.join(", ").cyan());
        }
        if sys.has_flatpak {
            println!("  {} {}", "Flatpak:".white().bold(), "detected ✔".green());
        }
        if sys.has_snap {
            println!("  {} {}", "Snap:".white().bold(), "detected ✔".green());
        }
        if sys.has_nix && sys.distro != Distro::Nix {
            // Only mention Nix here on non-NixOS systems — on NixOS it's obvious.
            println!("  {} {}", "Nix:".white().bold(), "detected ✔".green());
        }

        // HDD warning: cleanup on a spinning disk can take noticeably longer,
        // and `nix-store --optimise` in particular can take hours.
        if sys.disk_type == DiskType::HDD {
            println!(
                "  {} {}",
                "⚠".yellow().bold(),
                "HDD detected — cleanup may take longer".yellow()
            );
        }
    }

    if !cli.json {
        if cli.dry_run {
            println!();
            println!(
                "  {}",
                "⚠  DRY RUN MODE — no changes will be made".yellow().bold()
            );
        }
        if cli.deep {
            println!();
            println!(
                "  {}",
                "⚠  DEEP CLEAN MODE — aggressive cleaning enabled"
                    .red()
                    .bold()
            );
        }
    }

    // ── Privilege acquisition ──
    if ops.needs_sudo() && !cli.dry_run {
        if sys.privilege == Privilege::None {
            if cli.json {
                println!(
                    "{}",
                    json_error("no privilege-escalation tool found (need root, sudo, or doas)")
                );
            } else {
                utils::error("No privilege-escalation tool found (need root, sudo, or doas).");
                utils::info("Install sudo or doas, or re-run as root, for system-level cleanup.");
                utils::info(
                    "User-level operations (--cache, --trash, --dev) work without privileges.",
                );
            }
            std::process::exit(1);
        }
        if !utils::acquire_sudo() {
            if cli.json {
                println!("{}", json_error("failed to acquire privileges"));
            } else {
                utils::error("Failed to acquire privileges. Exiting.");
            }
            std::process::exit(1);
        }
    }

    // ── Execute ──
    let timer = Instant::now();
    let mut run = Run::default();

    if ops.cache {
        // The helper list always goes in; `ops.aur` says whether the AUR section
        // will run. A command-driven helper's dir is deferred to that section
        // only when it runs, so the freed bytes land under the right heading
        // without ever leaving the dir uncleaned. A hand-pruned helper's dir is
        // held back either way — it stores state (aura's snapshots) that a
        // wholesale wipe would destroy.
        run.step("cache", || {
            clean::user_cache(cli.dry_run, cli.yes, &sys.aur_helpers, ops.aur)
        });
    }

    if ops.packages {
        run.step("packages", || {
            let mut f = clean::pkg_cache(&sys.distro, cli.deep, cli.dry_run, yes, sys.disk_type);

            // Nix can be installed on *any* distro (not just NixOS). Run its GC
            // alongside the native package-cache step when /nix/store is present.
            // On NixOS the existing pkg_cache path already handles Nix, so we
            // avoid running it twice.
            if sys.has_nix && sys.distro != Distro::Nix {
                f += clean::nix_gc(cli.deep, cli.dry_run, yes, sys.disk_type);
            }
            f
        });
    }

    if ops.orphans {
        run.step("orphans", || clean::orphans(&sys.distro, cli.dry_run, yes));
    }

    if ops.aur {
        run.step("aur", || {
            let mut f = 0u64;
            if sys.distro == Distro::Arch {
                // Empty-list handling lives in aur_cache so the skip line is
                // worded in one place.
                f = clean::aur_cache(&sys.aur_helpers, cli.deep, cli.dry_run, yes);
            } else if cli.aur {
                utils::section("AUR Cache");
                utils::skip("Not an Arch-based system — skipped");
            }
            f
        });
    }

    if ops.flatpak {
        run.step("flatpak", || {
            let mut f = 0u64;
            if sys.has_flatpak {
                f = clean::flatpak(cli.deep, cli.dry_run);
            } else if cli.flatpak {
                utils::section("Flatpak");
                utils::skip("Flatpak is not installed — skipped");
            }
            f
        });
    }

    if ops.snap {
        run.step("snap", || {
            let mut f = 0u64;
            if sys.has_snap {
                f = clean::snap(cli.dry_run);
            } else if cli.snap {
                utils::section("Snap");
                utils::skip("Snap is not installed — skipped");
            }
            f
        });
    }

    if ops.journal {
        run.step("journal", || clean::journal(cli.dry_run));
    }

    if ops.trash {
        run.step("trash", || clean::trash(cli.dry_run));
    }

    if ops.coredumps {
        run.step("coredumps", || clean::coredumps(cli.dry_run));
    }

    if ops.dev {
        run.step("dev", || dev::run(cli.deep, cli.dry_run, yes));
    }

    if ops.trim {
        run.step("trim", || clean::trim(cli.dry_run, sys.disk_type));
    }

    // ── Summary ──
    let elapsed = timer.elapsed();
    let failures = utils::failure_count();
    if cli.json {
        println!(
            "{}",
            json_report(
                sys.distro.name(),
                cli.dry_run,
                cli.deep,
                elapsed.as_secs_f64(),
                &run,
                failures > 0
            )
        );
    } else {
        println!();
        println!(
            "  {}",
            "══════════════════════════════════════════════"
                .cyan()
                .dimmed()
        );
        println!(
            "  {} {}",
            "⚡ Total freed:".white().bold(),
            utils::format_size(run.total_freed).green().bold()
        );
        if failures > 0 {
            println!("  {} {}", "✘".red().bold(), failure_summary(failures).red());
        }
        println!(
            "  {} {:.2}s",
            "⏱  Completed in:".white().bold(),
            elapsed.as_secs_f64()
        );
        if cli.dry_run {
            println!(
                "  {}",
                "📋 This was a dry run — no changes were made"
                    .yellow()
                    .bold()
            );
        }
        println!(
            "  {}",
            "══════════════════════════════════════════════"
                .cyan()
                .dimmed()
        );
        println!();
    }

    let status = exit_status(failures);
    if status != 0 {
        std::process::exit(status);
    }
}

/// Escape a string as a JSON string literal (including surrounding quotes).
/// Small hand-rolled encoder — we emit only a handful of known-short strings
/// (distro name, op names, error messages), so pulling in a serializer here
/// would be overkill.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Version of the shape of the `--json` documents, for consumers that want to
/// notice when it changes. Within a version fields are only ever added.
const JSON_SCHEMA: u32 = 1;

/// The document for a run that could not start: `{"error": "..."}`, with the
/// fields every document carries.
fn json_error(message: &str) -> String {
    format!(
        "{{\"error\":{},\"status\":\"error\",\"schema\":{JSON_SCHEMA}}}",
        json_string(message)
    )
}

/// What the operations did, in run order: the raw material of the report.
#[derive(Default)]
struct Run {
    total_freed: u64,
    /// Freed bytes per operation.
    results: Vec<(&'static str, u64)>,
    /// What each operation reported as failed, as (operation, message).
    failures: Vec<(&'static str, String)>,
}

impl Run {
    /// Run one operation, keeping its result and the failures it reported.
    fn step(&mut self, name: &'static str, operation: impl FnOnce() -> u64) {
        let mark = utils::failure_count();
        let freed = operation();
        self.record(name, freed, utils::failures_since(mark));
    }

    fn record(&mut self, name: &'static str, freed: u64, failures: Vec<String>) {
        self.total_freed += freed;
        self.results.push((name, freed));
        self.failures
            .extend(failures.into_iter().map(|message| (name, message)));
    }
}

/// The exit status of a run that reported `failures` failures: 0 when every step
/// did what it was asked, 1 otherwise. A command line that makes no sense exits
/// with 2, where it is found.
fn exit_status(failures: usize) -> i32 {
    i32::from(failures > 0)
}

/// The line under the total when something went wrong. The details are in the
/// lines marked ✘ above it.
fn failure_summary(failures: usize) -> String {
    format!(
        "{failures} error{} — see the lines marked ✘ above",
        if failures == 1 { "" } else { "s" }
    )
}

/// The single machine-readable JSON object for `--json`. One line, valid JSON,
/// nothing else on stdout — safe to pipe into `jq`.
///
/// `schema`, `status` and `errors` come last, so everything a consumer already
/// reads is where it was. `status` is `"ok"` or `"error"`, and `errors` lists
/// what each operation reported as failed.
fn json_report(
    distro: &str,
    dry_run: bool,
    deep: bool,
    elapsed_secs: f64,
    run: &Run,
    failed: bool,
) -> String {
    let operations: Vec<String> = run
        .results
        .iter()
        .map(|(name, bytes)| format!("{}:{}", json_string(name), bytes))
        .collect();
    let errors: Vec<String> = run
        .failures
        .iter()
        .map(|(operation, message)| {
            format!(
                "{{\"operation\":{},\"message\":{}}}",
                json_string(operation),
                json_string(message)
            )
        })
        .collect();
    format!(
        "{{\"version\":{},\"distro\":{},\"dry_run\":{},\"deep\":{},\"operations\":{{{}}},\"total_freed_bytes\":{},\"elapsed_secs\":{:.2},\"schema\":{},\"status\":{},\"errors\":[{}]}}",
        json_string(env!("CARGO_PKG_VERSION")),
        json_string(distro),
        dry_run,
        deep,
        operations.join(","),
        run.total_freed,
        elapsed_secs,
        JSON_SCHEMA,
        json_string(if failed { "error" } else { "ok" }),
        errors.join(",")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::parse_from(args)
    }

    // ── The core safety invariant: --all must NEVER pull in --dev or --trim ──

    #[test]
    fn test_all_enables_system_ops_but_not_dev_or_trim() {
        let ops = Ops::resolve(&parse(&["oxiclean", "--all"])).unwrap();
        // Everything --all is supposed to include:
        assert!(ops.cache && ops.packages && ops.orphans && ops.aur);
        assert!(ops.flatpak && ops.snap && ops.journal && ops.trash);
        assert!(ops.coredumps, "--all must include crash-dump cleanup");
        // The two opt-in-only operations must stay OFF. This is the guard that
        // stops a well-meaning `cli.all || cli.dev` regression from silently
        // wiping dev caches (and re-download-heavy model caches) on --all.
        assert!(!ops.dev, "--all must NEVER enable --dev");
        assert!(!ops.trim, "--all must NEVER enable --trim");
    }

    #[test]
    fn test_dev_and_trim_are_opt_in() {
        let ops = Ops::resolve(&parse(&["oxiclean", "--dev", "--trim"])).unwrap();
        assert!(ops.dev && ops.trim);
        // Nothing else got turned on.
        assert!(!ops.cache && !ops.packages && !ops.coredumps);
        assert!(ops.any());
    }

    #[test]
    fn test_no_flags_is_empty() {
        let ops = Ops::resolve(&parse(&["oxiclean"])).unwrap();
        assert!(!ops.any());
    }

    // ── --skip: subtraction, validation, and the --all requirement ──

    #[test]
    fn test_skip_subtracts_from_all() {
        let ops =
            Ops::resolve(&parse(&["oxiclean", "--all", "--skip", "packages,journal"])).unwrap();
        // Skipped ones are off...
        assert!(!ops.packages, "packages must be skipped");
        assert!(!ops.journal, "journal must be skipped");
        // ...everything else --all provides stays on.
        assert!(ops.cache && ops.orphans && ops.trash && ops.coredumps);
    }

    #[test]
    fn test_skip_without_all_is_error() {
        // --skip on its own is a user mistake, not a silent no-op.
        let err = Ops::resolve(&parse(&["oxiclean", "--cache", "--skip", "packages"]));
        assert!(err.is_err(), "--skip without --all must be rejected");
    }

    #[test]
    fn test_skip_unknown_name_is_error() {
        let err = Ops::resolve(&parse(&["oxiclean", "--all", "--skip", "pacakges"]));
        assert!(err.is_err(), "a misspelled skip name must be rejected");
        // The message should list the valid names so the user can self-correct.
        assert!(err.unwrap_err().contains("packages"));
    }

    #[test]
    fn test_skip_cannot_disable_dev_or_trim() {
        // dev/trim aren't part of --all, so they aren't valid skip names — a
        // user trying to skip them gets a clear error rather than a no-op.
        assert!(Ops::resolve(&parse(&["oxiclean", "--all", "--skip", "dev"])).is_err());
        assert!(Ops::resolve(&parse(&["oxiclean", "--all", "--skip", "trim"])).is_err());
    }

    #[test]
    fn test_needs_sudo_reflects_selection() {
        // A user-level-only selection needs no privileges...
        let ops = Ops::resolve(&parse(&["oxiclean", "--cache", "--trash"])).unwrap();
        assert!(!ops.needs_sudo());
        // ...but coredumps (root-owned dirs) does.
        let ops = Ops::resolve(&parse(&["oxiclean", "--coredumps"])).unwrap();
        assert!(ops.needs_sudo());
    }

    // ── JSON string encoder ──

    #[test]
    fn test_json_string_escapes() {
        assert_eq!(json_string("abc"), "\"abc\"");
        assert_eq!(json_string("a\"b"), "\"a\\\"b\"");
        assert_eq!(json_string("a\\b"), "\"a\\\\b\"");
        assert_eq!(json_string("a\nb"), "\"a\\nb\"");
    }

    // ── The report and the exit status ──

    fn parsed(text: &str) -> serde_json::Value {
        serde_json::from_str(text).unwrap_or_else(|e| panic!("not JSON ({e}): {text}"))
    }

    #[test]
    fn test_a_clean_run_reports_ok_and_no_errors() {
        let mut run = Run::default();
        run.record("cache", 100, Vec::new());
        run.record("trash", 50, Vec::new());

        let text = json_report("Arch Linux", false, true, 1.234, &run, false);

        assert!(!text.contains('\n'), "the report is one line: {text}");
        let doc = parsed(&text);
        assert_eq!(doc["status"], "ok");
        assert_eq!(doc["schema"], 1);
        assert_eq!(doc["errors"], serde_json::json!([]));
        assert_eq!(doc["operations"]["cache"], 100);
        assert_eq!(doc["operations"]["trash"], 50);
        assert_eq!(doc["total_freed_bytes"], 150);
        assert_eq!(doc["dry_run"], false);
        assert_eq!(doc["deep"], true);
        assert_eq!(doc["distro"], "Arch Linux");
        assert_eq!(doc["elapsed_secs"], 1.23);
    }

    #[test]
    fn test_failures_are_listed_under_the_operation_that_reported_them() {
        let mut run = Run::default();
        run.record("cache", 10, Vec::new());
        run.record(
            "flatpak",
            0,
            vec![
                "Flatpak repair failed".to_string(),
                "second \"quoted\"\nline".to_string(),
            ],
        );

        let doc = parsed(&json_report("X", false, false, 0.0, &run, true));

        assert_eq!(doc["status"], "error");
        let errors = doc["errors"].as_array().unwrap();
        assert_eq!(errors.len(), 2);
        assert_eq!(
            errors[0],
            serde_json::json!({"operation": "flatpak", "message": "Flatpak repair failed"})
        );
        assert_eq!(errors[1]["message"], "second \"quoted\"\nline");
        // A failed operation still says what it freed, and the others are untouched.
        assert_eq!(doc["operations"]["flatpak"], 0);
        assert_eq!(doc["operations"]["cache"], 10);
        assert_eq!(doc["total_freed_bytes"], 10);
    }

    #[test]
    fn test_the_fields_a_consumer_already_reads_keep_their_place() {
        // The new fields come last, so a consumer that matches on the raw line
        // (it should not, but one will) sees what it always saw.
        let mut run = Run::default();
        run.record("cache", 1, vec!["x".to_string()]);
        let text = json_report("D", true, false, 2.0, &run, true);
        let keys = [
            "version",
            "distro",
            "dry_run",
            "deep",
            "operations",
            "total_freed_bytes",
            "elapsed_secs",
            "schema",
            "status",
            "errors",
        ];
        let positions: Vec<usize> = keys
            .iter()
            .map(|k| {
                text.find(&format!("\"{k}\":"))
                    .unwrap_or_else(|| panic!("{k} missing: {text}"))
            })
            .collect();
        assert!(
            positions.windows(2).all(|w| w[0] < w[1]),
            "fields out of order: {text}"
        );
        assert!(text.starts_with("{\"version\":\""), "{text}");
    }

    #[test]
    fn test_a_run_that_could_not_start_is_one_document_with_the_common_fields() {
        let doc = parsed(&json_error("no operation selected"));
        assert_eq!(doc["error"], "no operation selected");
        assert_eq!(doc["status"], "error");
        assert_eq!(doc["schema"], 1);

        let doc = parsed(&json_error("a \"b\"\nc"));
        assert_eq!(doc["error"], "a \"b\"\nc");
    }

    #[test]
    fn test_the_summary_counts_the_errors_in_the_right_number() {
        assert_eq!(failure_summary(1), "1 error — see the lines marked ✘ above");
        assert_eq!(
            failure_summary(2),
            "2 errors — see the lines marked ✘ above"
        );
        assert_eq!(
            failure_summary(40),
            "40 errors — see the lines marked ✘ above"
        );
    }

    #[test]
    fn test_a_run_fails_exactly_when_something_was_reported() {
        assert_eq!(exit_status(0), 0);
        assert_eq!(exit_status(1), 1);
        assert_eq!(exit_status(250), 1);
    }
}
