mod clean;
mod detect;
mod utils;

use clap::Parser;
use colored::Colorize;
use std::time::Instant;

/// ⚡ OxiClean — Fast Cross-Distribution Linux System Cleaner
///
/// A comprehensive system cleanup tool that works across all major
/// Linux distributions. Detects your distro automatically and runs
/// the appropriate cleanup commands.
///
/// EXAMPLES:
///   oxiclean --all                  Clean everything (with prompts)
///   oxiclean --all --yes            Clean everything (no prompts)
///   oxiclean --all --yes --deep     Aggressive clean (no prompts)
///   oxiclean --cache --trash        Only clean cache & trash
///   oxiclean --all --dry-run        Preview what would be cleaned
///   oxiclean --packages --orphans   Clean pkg cache & orphans only
#[derive(Parser)]
#[command(name = "oxiclean", version, about, long_about = None)]
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
}

fn main() {
    let cli = Cli::parse();

    let do_cache = cli.all || cli.cache;
    let do_packages = cli.all || cli.packages;
    let do_orphans = cli.all || cli.orphans;
    let do_aur = cli.all || cli.aur;
    let do_flatpak = cli.all || cli.flatpak;
    let do_snap = cli.all || cli.snap;
    let do_journal = cli.all || cli.journal;
    let do_trash = cli.all || cli.trash;

    if !do_cache
        && !do_packages
        && !do_orphans
        && !do_aur
        && !do_flatpak
        && !do_snap
        && !do_journal
        && !do_trash
        {
            utils::banner(env!("CARGO_PKG_VERSION"));
            println!(
                "  {} No operation selected. Use {} for all, or select specific operations.",
                "✘".red().bold(),
                     "--all".cyan()
            );
            println!();
            println!("  Quick start:  {} {}", "oxiclean".green(), "--all".cyan());
            println!(
                "  See help:     {} {}",
                "oxiclean".green(),
                     "--help".cyan()
            );
            println!();
            std::process::exit(1);
        }

        // ── Banner ──
        utils::banner(env!("CARGO_PKG_VERSION"));

        // ── Detect ──
        let distro = detect::distro();
        let pretty = detect::pretty_name();
        let aur = if distro == detect::Distro::Arch {
            detect::aur_helper()
        } else {
            None
        };
        let has_flatpak = detect::has_flatpak();
        let has_snap = detect::has_snap();

        // ── System info ──
        println!("  {} {}", "System:".white().bold(), pretty.cyan());
        println!(
            "  {} {} ({})",
                 "Distro:".white().bold(),
                 distro.name().cyan(),
                 distro.pkg_manager().dimmed()
        );
        if let Some(h) = aur {
            println!("  {} {}", "AUR:".white().bold(), h.cyan());
        }
        if has_flatpak {
            println!("  {} {}", "Flatpak:".white().bold(), "detected ✔".green());
        }
        if has_snap {
            println!("  {} {}", "Snap:".white().bold(), "detected ✔".green());
        }

        if cli.dry_run {
            println!();
            println!(
                "  {}",
                "⚠  DRY RUN MODE — no changes will be made"
                .yellow()
                .bold()
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

        // ── Sudo ──
        let needs_sudo = do_packages || do_orphans || do_journal || do_flatpak || do_snap;
        if needs_sudo && !cli.dry_run && !utils::acquire_sudo() {
            utils::error("Failed to acquire sudo privileges. Exiting.");
            std::process::exit(1);
        }

        // ── Execute ──
        let timer = Instant::now();
        let mut total_freed = 0u64;

        if do_cache {
            total_freed += clean::user_cache(cli.dry_run);
        }

        if do_packages {
            total_freed += clean::pkg_cache(&distro, cli.deep, cli.dry_run, cli.yes);
        }

        if do_orphans {
            total_freed += clean::orphans(&distro, cli.dry_run, cli.yes);
        }

        if do_aur {
            if distro == detect::Distro::Arch {
                if let Some(helper) = aur {
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
            if has_flatpak {

                total_freed += clean::flatpak(cli.deep, cli.dry_run);
            } else if cli.flatpak {
                utils::section("Flatpak");
                utils::skip("Flatpak is not installed — skipped");
            }
        }

        if do_snap {
            if has_snap {
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
            "═══════���══════════════════════════════════════"
            .cyan()
            .dimmed()
        );
        println!();
}
