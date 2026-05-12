<div align="center">

# ⚡ OxiClean

**Fast Cross-Distribution Linux System Cleaner — Written in Rust**

[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Linux](https://img.shields.io/badge/Platform-Linux-yellow?logo=linux&logoColor=white)](https://kernel.org)
[![AUR](https://img.shields.io/aur/version/oxiclean?logo=archlinux&label=AUR&color=1793D1)](https://aur.archlinux.org/packages/oxiclean)
[![CI](https://github.com/croaky-fx/oxiclean/actions/workflows/ci.yml/badge.svg)](https://github.com/croaky-fx/oxiclean/actions/workflows/ci.yml)

</div>

---

I hop between Linux distros a lot. Arch one month, Fedora the next, maybe Void when I'm feeling adventurous. And every single time I'd forget: *what's the command to clean orphaned packages here again? where does this distro put its package cache?*

So I wrote OxiClean. It figures out what distro you're on and does the right thing. That's basically it.

```
$ oxiclean -A -y

    ⚡ Oxi Clean  v1.0.4
    Fast Cross-Distribution Linux System Cleaner
    ──────────────────────────────────────────────

  System: CachyOS
  Distro: Arch Linux (pacman)
  AUR: paru
  Flatpak: detected ✔

  🔐 Requesting sudo privileges...

  ━━▶ User Cache (~/.cache)
    ℹ Cache size: 216.31 MB
    ✔ Freed 215.63 MB

  ━━▶ Package Cache (pacman)
    ✔ pacman cache cleaned

  ━━▶ Orphaned Packages
    ✔ No orphans found

  ━━▶ AUR Cache (paru)
    ✔ paru cache cleaned

  ━━▶ Flatpak Cleanup
    ✔ Flatpak cleanup done

  ━━▶ Systemd Journal
    ℹ Current usage: 45.9M
    ✔ Journal vacuumed

  ━━▶ Trash
    ✔ Trash is empty

  ══════════════════════════════════════════════
  ⚡ Total freed: 215.63 MB
  ⏱  Completed in: 9.62s
  ══════════════════════════════════════════════
```

*(Real output on CachyOS, spinning HDD at 5400rpm, right after a cleanup — so don't expect huge numbers every time)*

---

## What it cleans

- `~/.cache` — the obvious stuff
- Package manager cache (pacman, apt, dnf, zypper, xbps, apk, portage...)
- Orphaned packages — things nothing depends on anymore
- AUR helper cache (paru, yay, trizen, etc.)
- Flatpak unused runtimes
- Snap disabled revisions
- Systemd journal logs
- Trash

It handles **50+ distributions** across 10 package manager families. If you're on something obscure it doesn't know, it'll still clean the universal stuff (cache, trash, journal, Flatpak, Snap) without complaining.

## Installation

**Arch (AUR):**
```bash
paru -S oxiclean
# or yay -S oxiclean
```

**From source:**
```bash
git clone https://github.com/croaky-fx/oxiclean.git
cd oxiclean
cargo build --release
sudo cp target/release/oxiclean /usr/local/bin/
```

**Cargo:**
```bash
cargo install --git https://github.com/croaky-fx/oxiclean.git
```

**Pre-built binary:**
```bash
curl -LO https://github.com/croaky-fx/oxiclean/releases/latest/download/oxiclean-x86_64-linux-gnu
chmod +x oxiclean-x86_64-linux-gnu
sudo mv oxiclean-x86_64-linux-gnu /usr/local/bin/oxiclean
```

Requires: Rust 1.70+, Linux, sudo.

---

## Usage

I'd recommend running with `--dry-run` first, at least the first time:

```bash
# See what would happen, touch nothing
oxiclean --all --dry-run

# Run it
oxiclean --all

# Run it without asking questions
oxiclean --all --yes

# Go deeper (more aggressive — pacman -Scc, flatpak repair, etc.)
oxiclean --all --yes --deep
```

You can also target specific things if you don't want to clean everything:

```bash
oxiclean --cache --trash
oxiclean --packages --orphans
oxiclean --journal
oxiclean --flatpak --snap
```

### All flags

```
Options:
  -c, --cache       Clean user cache (~/.cache)
  -p, --packages    Clean package manager cache
  -o, --orphans     Remove orphaned packages
  -a, --aur         Clean AUR helper cache (Arch-based only)
  -f, --flatpak     Clean Flatpak unused runtimes & cache
  -s, --snap        Clean Snap disabled revisions & cache
  -j, --journal     Vacuum systemd journal logs
  -t, --trash       Empty trash
  -A, --all         Run all cleanup operations
  -d, --deep        Enable aggressive/deep cleaning mode
  -y, --yes         Skip all confirmation prompts
  -n, --dry-run     Preview actions without making changes
  -h, --help        Print help
  -V, --version     Print version
```

---

## Supported distros

| Family | Package Manager | Cache | Orphans |
|--------|----------------|:-----:|:-------:|
| Arch, Manjaro, EndeavourOS, Garuda, CachyOS, Artix... | `pacman` | ✅ | ✅ |
| Debian, Ubuntu, Mint, Pop!_OS, Kali, MX... | `apt` | ✅ | ✅ |
| Fedora, RHEL, CentOS, Rocky, Alma, Nobara... | `dnf` / `yum` | ✅ | ✅ |
| openSUSE Leap, Tumbleweed, MicroOS... | `zypper` | ✅ | ✅ |
| NixOS | `nix` | ✅ | ✅ |
| Void Linux | `xbps` | ✅ | ✅ |
| Alpine, postmarketOS | `apk` | ✅ | ⚠️ |
| Gentoo, Funtoo, Calculate | `portage` | ✅ | ✅ |
| Solus | `eopkg` | ✅ | ✅ |
| Clear Linux | `swupd` | ✅ | ℹ️ |

---

## A few things worth knowing

**It won't touch your personal files.** No documents, no downloads, no running app data, no boot files. Only caches, package leftovers, and logs. If you're still nervous, `--dry-run` exists for a reason.

**Results vary a lot.** Whether you free 5MB or 2GB depends on how long since you last cleaned, your distro, and your disk. The tool's value isn't in big numbers — it's in not having to remember 10 different commands for 10 different distros.

**`--deep` is a bit more aggressive.** Things like `pacman -Scc` (removes *all* cached packages, not just old ones) or `flatpak repair`. Useful for squeezing out more space, but worth knowing what you're getting into. Run `--dry-run --deep` first if unsure.

**It needs sudo for some things** — package cache, orphan removal, journal. For user-level stuff (your `~/.cache`, trash) it won't ask.

**Cron-friendly:**
```
0 3 * * 0 /usr/local/bin/oxiclean --all --yes
```
Avoid `--deep` in automated runs.

---

## How it works under the hood

It reads `/etc/os-release` to figure out your distro, then checks `$PATH` for which tools are available. Detection chain looks roughly like:

```
/etc/os-release
  ID=arch          → pacman
  ID=ubuntu        → apt
  ID=fedora        → dnf
  ID=opensuse-...  → zypper
  ID_LIKE=arch     → pacman  (for derivatives)
  (unknown)        → universal cleaning only
```

Freed space is measured by checking directory sizes before and after — not estimated. The one exception is orphan removal, since those files are scattered across the system.

The binary itself is ~800KB with no runtime dependencies. Just `clap` for CLI parsing and `colored` for the output colors.

---

## Project structure

```
oxiclean/
├── Cargo.toml
├── PKGBUILD
├── tests/
│   └── cli_test.rs
└── src/
    ├── main.rs     # CLI parsing, orchestration, summary
    ├── detect.rs   # Distro detection, tool discovery
    ├── clean.rs    # All cleaning operations
    └── utils.rs    # Command execution, file ops, helpers
```

---

## Testing

```bash
cargo test
cargo test -- --nocapture  # with output
cargo clippy -- -D warnings
cargo fmt -- --check
```

There are 20 unit tests covering formatting, directory sizing, file removal, distro detection, etc., and 9 integration tests for CLI flags and dry-run behavior.

---

## Contributing

```bash
git clone https://github.com/croaky-fx/oxiclean.git
cd oxiclean
cargo build && cargo test
```

**Adding a new distro** — the process is pretty mechanical:
1. Add a variant to the `Distro` enum in `detect.rs`
2. Add its ID to the detection arrays
3. Add cache cleaning in `clean.rs → pkg_cache()`
4. Add orphan removal in `clean.rs → orphans()`
5. Update the README table
6. Test it (a VM or container works fine)

**Things I'd love help with:**
- More distros (Guix, Slackware...)
- Shell completions (bash, zsh, fish)
- `doas` support as a sudo alternative
- `--quiet` mode
- Integration tests with Docker containers
- Logging to file (`--log`)

---

## FAQ

<details>
<summary>Is <code>--all --yes --deep</code> safe to run?</summary>

It removes cached packages (not installed ones), orphaned packages, old Nix generations, and vacuums journal logs. Your actual software and personal files are never touched. If you're unsure, run `--dry-run` first — that's what it's there for.
</details>

<details>
<summary>Does it work on my distro?</summary>

If your distro is based on any of the supported families (Arch, Debian, Fedora, etc.) — yes. Unknown distros get universal cleaning (cache, trash, journal, Flatpak, Snap) which is still useful.
</details>

<details>
<summary>How is this different from BleachBit?</summary>

BleachBit is GUI-based, Python-dependent, and focuses on cleaning inside specific applications. OxiClean is a single CLI binary focused on system-level cleanup that works the same way regardless of what distro you're on. Different tools for different needs — they don't really overlap much.
</details>

<details>
<summary>Why Rust?</summary>

Honestly, I wanted to learn it. Also: single static binary, no interpreter to install, fast, and the type system catches a lot of bugs before they ship.
</details>

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

*OxiClean = Oxide (Rust) + Clean — no connection to any commercial cleaning product.*

[⬆ Back to top](#-oxiclean)

</div>
