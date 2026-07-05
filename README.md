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

    ⚡ Oxi Clean  v1.4.0
    Fast Cross-Distribution Linux System Cleaner
    ──────────────────────────────────────────────

  System: CachyOS
  Distro: Arch Linux (pacman)
  AUR: paru
  Flatpak: detected ✔
  ⚠ HDD detected — cleanup may take longer

  🔐 Requesting privileges (sudo)...

  ━━▶ User Cache
    ✔ Freed 846.36 MB

  ━━▶ Package Cache
    ✔ pacman cache cleaned

  ━━▶ Orphaned Packages
    ✔ No orphans found

  ━━▶ AUR Cache
    ✔ paru cache cleaned

  ━━▶ Flatpak
    ✔ Flatpak cleanup done

  ━━▶ Journal
    ℹ Current usage: 47.8M
    ✔ Journal vacuumed

  ━━▶ Trash
    ✔ Trash is empty

  ══════════════════════════════════════════════
  ⚡ Total freed: 846.36 MB
  ⏱  Completed in: 21.30s
  ══════════════════════════════════════════════
```

*(Real run on CachyOS with a 5400rpm HDD. pacman/paru also print their own `[Y/n]` prompts during the run — those are pacman's, not oxiclean's, and they auto-answer with `--noconfirm`; they're trimmed here for clarity. A run that removes orphaned packages takes longer, mostly because snapper takes pre/post snapshots around the removal.)*

---

## What it cleans

**System stuff** (the default with `--all`):
- `~/.cache` — the obvious stuff
- Package manager cache (pacman, apt, dnf, zypper, xbps, apk, portage...)
- Orphaned packages — things nothing depends on anymore
- AUR helper cache (paru, yay, trizen, etc.)
- Flatpak unused runtimes
- Snap disabled revisions
- Systemd journal logs
- Trash
- Nix garbage collection — works on any distro that has `/nix/store`, not just NixOS

**Dev tool caches** (opt-in with `--dev`, not part of `--all`):
- Node ecosystem: npm, yarn (classic + berry), pnpm, bun, deno
- Python: pip, uv, pipenv, poetry (cache only — your virtualenvs stay), conda (`conda clean`, never your envs)
- Rust: cargo registry + git checkouts (your installed binaries in `~/.cargo/bin` are never touched)
- Go modules (needs `--deep` since it re-downloads)
- Ruby gems (old versions), PHP composer, Gradle caches, Maven
- C/C++: ccache, and .NET: NuGet global packages

It handles **50+ distributions** across 10 package manager families. If you're on something obscure it doesn't know, it'll still clean the universal stuff (cache, trash, journal, Flatpak, Snap) without complaining.

## Installation

**Quick install (prebuilt binary):**
```bash
curl -fsSL https://raw.githubusercontent.com/croaky-fx/oxiclean/main/install.sh | sh
```
Detects your CPU and libc (glibc/musl), downloads the latest release to a temp
dir, verifies it, and installs to `/usr/local/bin` (asks for sudo only for that
final step). Force a libc with `OXICLEAN_LIBC=musl` if auto-detection is wrong.

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
sudo install -Dm755 target/release/oxiclean /usr/local/bin/oxiclean
```

**Cargo:**
```bash
cargo install --git https://github.com/croaky-fx/oxiclean.git
```

**Manual (prebuilt binary):**
```bash
curl -LO https://github.com/croaky-fx/oxiclean/releases/latest/download/oxiclean-x86_64-linux-gnu
chmod +x oxiclean-x86_64-linux-gnu
sudo install -Dm755 oxiclean-x86_64-linux-gnu /usr/local/bin/oxiclean
```

Requires: Linux, and sudo or doas. Building from source needs Rust 1.70+.

---

## Updating

If you installed the prebuilt binary (via `install.sh` or by hand), update in
place:

```bash
oxiclean --update
```

It checks GitHub for a newer release, shows the release notes, and — after you
confirm — downloads the right binary for your CPU and libc, verifies it, and
swaps it in atomically. Use `oxiclean --update -y` to skip the prompt (handy in
a cron job). Networking is built in (via `ureq` + `rustls`), so no `curl` or
`wget` is required.

If oxiclean was installed by a **package manager** (AUR, apt, …), `--update`
won't touch it — self-updating a managed binary would corrupt the package
database. It tells you the right command instead (e.g. `paru -Syu oxiclean`).

Unsupported CPU architectures (anything other than x86_64 / aarch64) are asked
to build from source rather than downloading a binary that doesn't exist.

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

# Quieter output (nice for cron / CI)
oxiclean --all --yes --quiet

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

### Cleaning dev tool caches

If you're a developer your `~/.cargo`, `~/.npm`, `~/.cache/pip` and friends can
add up to several GB. The `--dev` flag scans them all and shows you what's
there before touching anything:

```bash
oxiclean --dev --dry-run    # scan and show the table, no changes
oxiclean --dev              # clean the safe stuff
oxiclean --dev --deep       # also clean caches that'll re-download
```

It looks like this:

```
  ━━▶ Dev Cache
    ℹ Scanning...
      • npm                    542.56 MB   ✓ safe
      • pnpm                     5.74 KB   ✓ store prune
      • pip                      9.83 MB   ✓ safe
      • uv                     305.98 MB   ✓ safe
      • nuget                   33.40 MB   ✓ safe
      • cargo registry/src     147.99 MB   ✓ re-extract only
      • cargo registry/cache    43.84 MB   ⚠ re-download on next build
      • go modules             230.37 MB   ⚠ re-download on next build
      ─ Total: 1.28 GB   |   Will clean now: 1.02 GB
      ℹ Pass --deep to also clean caches that trigger re-downloads
    ✔ Freed 1.02 GB
```

A few things it explicitly *won't* do (these are the ones that bite people):
- `~/.cargo/bin` is never touched (it has your installed binaries like `cargo-watch`, `rustfmt`)
- pnpm uses hardlinks to its store — wiping the directory breaks every `node_modules` on the system, so it runs `pnpm store prune` instead
- Poetry's `virtualenvs/` directory is preserved — only the package download `cache/` is cleaned
- Gradle's `wrapper/` (which holds the actual Gradle distributions) stays — only `caches/` goes
- npm globals (`~/.npm/lib/node_modules`) stay — only `_cacache/` goes

`--all` does *not* include `--dev` on purpose. Dev caches have very different
tradeoffs (some trigger gigabyte-scale re-downloads) and they should be an
explicit choice.

### All flags

```
Options:
  -c, --cache                        Clean user cache (~/.cache)
  -p, --packages                     Clean package manager cache
  -o, --orphans                      Remove orphaned packages
  -a, --aur                          Clean AUR helper cache (Arch-based only)
  -f, --flatpak                      Clean Flatpak unused runtimes & cache
  -s, --snap                         Clean Snap disabled revisions & cache
  -j, --journal                      Vacuum systemd journal logs
  -t, --trash                        Empty trash
  -D, --dev                          Clean dev-tool caches (npm, cargo, pip, ...)
  -A, --all                          Run all cleanup operations (not --dev)
  -d, --deep                         Enable aggressive/deep cleaning mode
  -y, --yes                          Skip all confirmation prompts
  -n, --dry-run                      Preview actions without making changes
  -q, --quiet                        Reduce output noise (good for cron / CI)
  -u, --update                       Update to the latest GitHub release
      --generate-completion <SHELL>  Print shell completion script and exit
  -h, --help                         Print help (see more with '--help')
  -V, --version                      Print version
```

### Shell completions

If you want tab completion, OxiClean can print the script for your shell and you
just redirect it where your distro expects it:

```bash
# bash
oxiclean --generate-completion bash > ~/.local/share/bash-completion/completions/oxiclean

# zsh
mkdir -p ~/.local/share/zsh/site-functions
oxiclean --generate-completion zsh > ~/.local/share/zsh/site-functions/_oxiclean

# fish
oxiclean --generate-completion fish > ~/.config/fish/completions/oxiclean.fish
```

Not glamorous, but it works fine and keeps the binary simple.

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

**`--deep` is a bit more aggressive.** Things like `pacman -Scc` (removes *all* cached packages, not just old ones), `flatpak repair`, or the cargo/go caches that'll re-download. Useful for squeezing out more space, but worth knowing what you're getting into. Run `--dry-run --deep` first if unsure.

**It needs sudo or doas for some things** — package cache, orphan removal, journal. Detected automatically at startup; on Alpine and Void where `doas` is the default, no configuration needed. For user-level stuff (your `~/.cache`, trash, dev caches) it won't ask.

**HDD warning.** If your root filesystem lives on a spinning disk, you'll see a heads-up at startup that cleanup may take a while. Reading directory sizes on an HDD with millions of small files (looking at you, `~/.cargo/registry`) is genuinely slow. Not a bug, just physics.

**Cron-friendly:**
```
0 3 * * 0 /usr/local/bin/oxiclean --all --yes --quiet
```
Avoid `--deep` in automated runs. And if you want dev caches included, add `--dev`.

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

The binary is a single self-contained file (~2 MB). It uses `clap` for CLI
parsing, `colored` for terminal colors, `clap_complete` for shell completions,
and `ureq` + `rustls` for the built-in `--update` command — the TLS stack is
what takes most of the size, but it means self-update needs no external `curl`
or `wget`. The `musl` build has no runtime dependencies at all (fully static).

---

## Project structure

```
oxiclean/
├── Cargo.toml
├── PKGBUILD
├── install.sh      # Prebuilt-binary installer (curl | sh)
├── tests/
│   └── cli_test.rs
└── src/
    ├── main.rs     # CLI parsing, orchestration, summary
    ├── detect.rs   # Distro detection, privilege/disk detection
    ├── clean.rs    # System cleaning operations
    ├── dev.rs      # Dev-tool cache cleanup (npm, cargo, pip, ...)
    ├── update.rs   # Self-update (--update): GitHub check, verify, swap
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

There are 68 unit tests and 13 integration tests. The interesting ones aren't the trivial "does this format correctly" checks — they're the regression guards: the dev cleaner never targeting `~/.cargo/bin`, `~/.cache/pypoetry/virtualenvs`, or `~/.gradle/wrapper`, and self-update refusing to overwrite a package-manager-owned binary. Those are the ones that would actually ruin someone's day.

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
- Integration tests with Docker containers
- More dev tools in `--dev` (mix, rebar, sbt...)
- Better distro-specific docs for Alpine / Void / Nix edge cases
- A couple more real-world smoke tests on HDD systems

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
<summary>Will <code>--dev</code> break my Rust/Node/Python projects?</summary>

No. Without `--deep` it only removes things that get rebuilt locally with no network (cargo's extracted sources, pip wheel cache, npm download cache, etc.). With `--deep` it also clears caches that *will* re-download next time you build, so don't run that on a metered connection.

The one thing it explicitly *cannot* break is your installed binaries — `~/.cargo/bin`, npm globals, poetry virtualenvs, and gradle's wrapper are all preserved by design, with unit tests that fail loudly if anyone tries to change that.
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
