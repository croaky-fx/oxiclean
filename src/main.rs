mod clean;
mod detect;
mod dev;
mod update;
mod utils;

use clap::{CommandFactory, Parser};
use clap_complete::aot::{generate, Shell};
use colored::Colorize;
use std::time::Instant;

use crate::detect::{DiskType, Distro, Privilege};

/// Everything we detect once at startup. Keeping it in one struct avoids
/// threading six separate parameters through `main()` and the cleanup calls.
struct SystemInfo {
    pretty_name: String,
    distro: Distro,
    aur_helper: Option<&'static str>,
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
            aur_helper: {
                // AUR helpers are only meaningful on Arch-family distros.
                if detect::distro() == Distro::Arch {
                    detect::aur_helper()
                } else {
                    None
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
    fn needs_sudo(&self) -> bool {
        self.packages
            || self.orphans
            || self.journal
            || self.flatpak
            || self.snap
            || self.trim
            || self.coredumps
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

    // Self-update is a standalone mode — it ignores the cleanup flags.
    if cli.update {
        std::process::exit(update::run(cli.yes));
    }

    let ops = match Ops::resolve(&cli) {
        Ok(o) => o,
        Err(msg) => {
            if cli.json {
                println!("{{\"error\":{}}}", json_string(&msg));
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
            println!("{{\"error\":\"no operation selected\"}}");
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

    // ── System info ── (suppressed in JSON mode: only the final object prints)
    if !cli.json {
        println!("  {} {}", "System:".white().bold(), sys.pretty_name.cyan());
        println!(
            "  {} {} ({})",
            "Distro:".white().bold(),
            sys.distro.name().cyan(),
            sys.distro.pkg_manager().dimmed()
        );
        if let Some(h) = sys.aur_helper {
            println!("  {} {}", "AUR:".white().bold(), h.cyan());
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
        // and `nix store --optimise` in particular can take hours.
        if sys.disk_type == DiskType::HDD {
            println!(
                "  {} {}",
                "⚠".yellow().bold(),
                "HDD detected — cleanup may take longer".yellow()
            );
        }

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
                println!("{{\"error\":\"no privilege-escalation tool found (need root, sudo, or doas)\"}}");
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
                println!("{{\"error\":\"failed to acquire privileges\"}}");
            } else {
                utils::error("Failed to acquire privileges. Exiting.");
            }
            std::process::exit(1);
        }
    }

    // ── Execute ──
    let timer = Instant::now();
    let mut total_freed = 0u64;
    // Per-operation freed bytes, in run order, for the JSON report.
    let mut results: Vec<(&str, u64)> = Vec::new();
    let record = |name: &'static str, bytes: u64, acc: &mut u64, out: &mut Vec<(&str, u64)>| {
        *acc += bytes;
        out.push((name, bytes));
    };

    if ops.cache {
        let f = clean::user_cache(cli.dry_run);
        record("cache", f, &mut total_freed, &mut results);
    }

    if ops.packages {
        let mut f = clean::pkg_cache(&sys.distro, cli.deep, cli.dry_run, yes);

        // Nix can be installed on *any* distro (not just NixOS). Run its GC
        // alongside the native package-cache step when /nix/store is present.
        // On NixOS the existing pkg_cache path already handles Nix, so we
        // avoid running it twice.
        if sys.has_nix && sys.distro != Distro::Nix {
            f += clean::nix_gc(cli.deep, cli.dry_run, yes, sys.disk_type);
        }
        record("packages", f, &mut total_freed, &mut results);
    }

    if ops.orphans {
        let f = clean::orphans(&sys.distro, cli.dry_run, yes);
        record("orphans", f, &mut total_freed, &mut results);
    }

    if ops.aur {
        let mut f = 0u64;
        if sys.distro == Distro::Arch {
            if let Some(helper) = sys.aur_helper {
                f = clean::aur_cache(helper, cli.deep, cli.dry_run, yes);
            } else {
                utils::section("AUR Cache");
                utils::skip("No AUR helper found (paru, yay, trizen...)");
            }
        } else if cli.aur {
            utils::section("AUR Cache");
            utils::skip("Not an Arch-based system — skipped");
        }
        record("aur", f, &mut total_freed, &mut results);
    }

    if ops.flatpak {
        let mut f = 0u64;
        if sys.has_flatpak {
            f = clean::flatpak(cli.deep, cli.dry_run);
        } else if cli.flatpak {
            utils::section("Flatpak");
            utils::skip("Flatpak is not installed — skipped");
        }
        record("flatpak", f, &mut total_freed, &mut results);
    }

    if ops.snap {
        let mut f = 0u64;
        if sys.has_snap {
            f = clean::snap(cli.dry_run);
        } else if cli.snap {
            utils::section("Snap");
            utils::skip("Snap is not installed — skipped");
        }
        record("snap", f, &mut total_freed, &mut results);
    }

    if ops.journal {
        let f = clean::journal(cli.dry_run);
        record("journal", f, &mut total_freed, &mut results);
    }

    if ops.trash {
        let f = clean::trash(cli.dry_run);
        record("trash", f, &mut total_freed, &mut results);
    }

    if ops.coredumps {
        let f = clean::coredumps(cli.dry_run);
        record("coredumps", f, &mut total_freed, &mut results);
    }

    if ops.dev {
        let f = dev::run(cli.deep, cli.dry_run, yes);
        record("dev", f, &mut total_freed, &mut results);
    }

    if ops.trim {
        let f = clean::trim(cli.dry_run, sys.disk_type);
        record("trim", f, &mut total_freed, &mut results);
    }

    // ── Summary ──
    let elapsed = timer.elapsed();
    if cli.json {
        print_json_report(&sys, cli.dry_run, cli.deep, total_freed, elapsed, &results);
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
            utils::format_size(total_freed).green().bold()
        );
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

/// Emit the single machine-readable JSON object for `--json`. One line, valid
/// JSON, nothing else on stdout — safe to pipe into `jq`.
fn print_json_report(
    sys: &SystemInfo,
    dry_run: bool,
    deep: bool,
    total_freed: u64,
    elapsed: std::time::Duration,
    results: &[(&str, u64)],
) {
    let ops_json: Vec<String> = results
        .iter()
        .map(|(name, bytes)| format!("{}:{}", json_string(name), bytes))
        .collect();
    println!(
        "{{\"version\":{},\"distro\":{},\"dry_run\":{},\"deep\":{},\"operations\":{{{}}},\"total_freed_bytes\":{},\"elapsed_secs\":{:.2}}}",
        json_string(env!("CARGO_PKG_VERSION")),
        json_string(sys.distro.name()),
        dry_run,
        deep,
        ops_json.join(","),
        total_freed,
        elapsed.as_secs_f64()
    );
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
}
