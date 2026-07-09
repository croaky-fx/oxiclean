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

    /// Print shell completion script to stdout and exit.
    /// Supported values come from clap_complete (bash, zsh, fish, elvish, powershell).
    #[arg(long = "generate-completion", value_name = "SHELL")]
    generate_completion: Option<Shell>,

    /// Update oxiclean to the latest GitHub release (prebuilt-binary installs
    /// only; package-manager installs are told to use their package manager).
    #[arg(short = 'u', long)]
    update: bool,
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
    // banner and detection output).
    utils::set_quiet(cli.quiet);

    // Self-update is a standalone mode — it ignores the cleanup flags.
    if cli.update {
        std::process::exit(update::run(cli.yes));
    }

    let do_cache = cli.all || cli.cache;
    let do_packages = cli.all || cli.packages;
    let do_orphans = cli.all || cli.orphans;
    let do_aur = cli.all || cli.aur;
    let do_flatpak = cli.all || cli.flatpak;
    let do_snap = cli.all || cli.snap;
    let do_journal = cli.all || cli.journal;
    let do_trash = cli.all || cli.trash;
    // --dev is opt-in: --all does NOT enable it. Dev caches behave very
    // differently from system caches (rebuild times, re-download warnings)
    // and the user should ask for them explicitly.
    let do_dev = cli.dev;
    // --trim is opt-in too: it's SSD maintenance, not cache cleanup, so it is
    // deliberately excluded from --all.
    let do_trim = cli.trim;

    if !do_cache
        && !do_packages
        && !do_orphans
        && !do_aur
        && !do_flatpak
        && !do_snap
        && !do_journal
        && !do_trash
        && !do_dev
        && !do_trim
    {
        utils::banner(env!("CARGO_PKG_VERSION"));
        println!(
            "  {} No operation selected. Use {} for all, or select specific operations.",
            "✘".red().bold(),
            "--all".cyan()
        );
        println!();
        println!("  Quick start:  {} {}", "oxiclean".green(), "--all".cyan());
        println!("  See help:     {} {}", "oxiclean".green(), "--help".cyan());
        println!();
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

    // ── System info ──
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

    // ── Privilege acquisition ──
    let needs_sudo = do_packages || do_orphans || do_journal || do_flatpak || do_snap || do_trim;
    if needs_sudo && !cli.dry_run {
        if sys.privilege == Privilege::None {
            utils::error("No privilege-escalation tool found (need root, sudo, or doas).");
            utils::info("Install sudo or doas, or re-run as root, for system-level cleanup.");
            utils::info("User-level operations (--cache, --trash, --dev) work without privileges.");
            std::process::exit(1);
        }
        if !utils::acquire_sudo() {
            utils::error("Failed to acquire privileges. Exiting.");
            std::process::exit(1);
        }
    }

    // ── Execute ──
    let timer = Instant::now();
    let mut total_freed = 0u64;

    if do_cache {
        total_freed += clean::user_cache(cli.dry_run);
    }

    if do_packages {
        total_freed += clean::pkg_cache(&sys.distro, cli.deep, cli.dry_run, cli.yes);

        // Nix can be installed on *any* distro (not just NixOS). Run its GC
        // alongside the native package-cache step when /nix/store is present.
        // On NixOS the existing pkg_cache path already handles Nix, so we
        // avoid running it twice.
        if sys.has_nix && sys.distro != Distro::Nix {
            total_freed += clean::nix_gc(cli.deep, cli.dry_run, cli.yes, sys.disk_type);
        }
    }

    if do_orphans {
        total_freed += clean::orphans(&sys.distro, cli.dry_run, cli.yes);
    }

    if do_aur {
        if sys.distro == Distro::Arch {
            if let Some(helper) = sys.aur_helper {
                total_freed += clean::aur_cache(helper, cli.deep, cli.dry_run, cli.yes);
            } else {
                utils::section("AUR Cache");
                utils::skip("No AUR helper found (paru, yay, trizen...)");
            }
        } else if cli.aur {
            utils::section("AUR Cache");
            utils::skip("Not an Arch-based system — skipped");
        }
    }

    if do_flatpak {
        if sys.has_flatpak {
            total_freed += clean::flatpak(cli.deep, cli.dry_run);
        } else if cli.flatpak {
            utils::section("Flatpak");
            utils::skip("Flatpak is not installed — skipped");
        }
    }

    if do_snap {
        if sys.has_snap {
            total_freed += clean::snap(cli.dry_run);
        } else if cli.snap {
            utils::section("Snap");
            utils::skip("Snap is not installed — skipped");
        }
    }

    if do_journal {
        total_freed += clean::journal(cli.dry_run);
    }

    if do_trash {
        total_freed += clean::trash(cli.dry_run);
    }

    if do_dev {
        total_freed += dev::run(cli.deep, cli.dry_run, cli.yes);
    }

    if do_trim {
        total_freed += clean::trim(cli.dry_run, sys.disk_type);
    }

    // ── Summary ──
    let elapsed = timer.elapsed();
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
