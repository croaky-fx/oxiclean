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

OxiClean figures out what distro you're on and does the right thing. That's basically it.

```
$ oxiclean -A -y

    ⚡ Oxi Clean  v1.8.0
    Fast Cross-Distribution Linux System Cleaner
    ──────────────────────────────────────────────

  System: CachyOS
  Distro: Arch Linux (pacman)
  AUR: paru, yay
  Flatpak: detected ✔
  ⚠ HDD detected — cleanup may take longer

  🔐 Requesting privileges (sudo)...

  ━━▶ User Cache
    ⊘ Some dev-tool caches skipped — remove them with --dev
    ✔ Freed 113.30 MB

  ━━▶ Package Cache
    ✔ pacman cache cleaned

  ━━▶ Orphaned Packages
    ✔ No orphans found

  ━━▶ AUR Cache
    ✔ paru — already clean
    ✔ yay — already clean

  ━━▶ Flatpak
    ✔ No unused runtimes

  ━━▶ Journal
    ✔ Already under 50M (41.90 MB) — nothing to vacuum

  ━━▶ Trash
    ✔ Trash is empty

  ━━▶ Crash Dumps
    ✔ systemd-coredump: already empty

  ══════════════════════════════════════════════
  ⚡ Total freed: 113.30 MB
  ⏱  Completed in: 6.48s
  ══════════════════════════════════════════════
```

*(Real run on CachyOS with a 5400rpm HDD, on a system cleaned recently — hence the `already clean` lines. The `⊘` line is the safety guard in action: dev-tool caches under `~/.cache` are left for `--dev` to handle with the right per-tool command, and model weights (HuggingFace/torch) are kept silently — nothing here ever deletes them. Every installed AUR helper is cleaned and reports its own figure. The helpers print plenty of their own output during a run; it's captured so the report stays readable — pass `--verbose` if you want to see it, and a command that fails shows its stderr either way.)*

---

## What it cleans

**System stuff** (the default with `--all`):
- `~/.cache` — the obvious stuff, but it **spares expensive caches**: HuggingFace/torch
  model weights (multi-GB, and nobody clears a 40 GB model as routine cleanup) are kept
  silently, and dev-tool caches that `--dev` owns are left for `--dev` to handle (with a
  one-line hint so you know they were skipped).
- Package manager cache (pacman, apt, dnf, zypper, xbps, apk, portage...)
- Orphaned packages — things nothing depends on anymore
- AUR helper cache (paru, yay, trizen, etc.) — *every* helper you have installed,
  not just the first one found. Two helpers installed and one in use is common,
  and the unused one keeps accumulating clone/build caches.
- Flatpak unused runtimes
- Snap disabled revisions
- Systemd journal logs
- Trash
- Crash dumps — systemd-coredump and Apport reports (they can hold passwords/keys
  from the crashed process, so clearing them is a small privacy win too)
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
or
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
oxiclean --coredumps           # just clear saved crash dumps
```

Or run everything *except* a couple of things with `--skip` (only valid
alongside `--all`):

```bash
oxiclean --all --skip packages         # everything but the package cache
oxiclean --all --skip journal,orphans  # keep logs and orphaned packages
```

For scripts and cron, `--json` prints a single machine-readable line instead of
the human report — no banner, no colors, no prompts:

```bash
oxiclean --all --yes --json | jq .total_freed_bytes
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

A few things it explicitly *won't* do — the ones that bite people:
- `~/.cargo/bin` is never touched (your installed binaries, not a cache)
- pnpm's store is hardlinked into every `node_modules` on the disk, so wiping it
  breaks every project — it runs `pnpm store prune` instead
- poetry's `virtualenvs/`, gradle's `wrapper/`, npm globals and aura's restore
  points are all preserved

Each of those is enforced by a test. [Full list and rationale →](DETAILS.md#what-it-spares-and-why)

`--all` does *not* include `--dev` on purpose. Dev caches have very different
tradeoffs (some trigger gigabyte-scale re-downloads) and should be an explicit
choice.

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
  -C, --coredumps                    Clear crash dumps (systemd-coredump & Apport)
  -D, --dev                          Clean dev-tool caches (npm, cargo, pip, ...)
  -T, --trim                         TRIM SSD/NVMe filesystems (not in --all)
  -A, --all                          Run all cleanup operations (not --dev/--trim)
      --skip <OPS>                   Skip operations when using --all (comma-separated)
  -d, --deep                         Enable aggressive/deep cleaning mode
  -y, --yes                          Skip all confirmation prompts
  -n, --dry-run                      Preview actions without making changes
  -q, --quiet                        Reduce output noise (good for cron / CI)
      --json                         Machine-readable JSON output (implies non-interactive)
  -v, --verbose                      Show raw helper command output (captured by default)
  -u, --update                       Update to the latest GitHub release
      --generate-completion <SHELL>  Print shell completion script and exit
  -h, --help                         Print help (see more with '--help')
  -V, --version                      Print version
```

### Shell completions

```bash
oxiclean --generate-completion bash > ~/.local/share/bash-completion/completions/oxiclean
oxiclean --generate-completion zsh  > ~/.local/share/zsh/site-functions/_oxiclean
oxiclean --generate-completion fish > ~/.config/fish/completions/oxiclean.fish
```

Also supports `elvish` and `powershell`.

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
| Fedora Atomic (Silverblue, Kinoite, Bazzite) | `rpm-ostree` | ✅ | ℹ️ |
| Immutable / read-only (SteamOS, MicroOS…) | atomic image | ➖ | ➖ |

Atomic systems are handled specially: Fedora Atomic uses `rpm-ostree cleanup -bm`
(safe base + metadata only). Other immutable systems with a read-only `/usr`
skip package-cache cleanup entirely — their OS space is reclaimed by atomic
image swaps, not the package manager — while user-level cleanup still runs.

---

## Good to know

**It won't touch your personal files.** No documents, no downloads, no running app data, no boot files — only caches, package leftovers, and logs. `--dry-run` exists if you'd rather see first.

**Results vary a lot.** Whether you free 5 MB or 2 GB depends on how long since you last cleaned, your distro, and your disk. The value isn't the number — it's not having to remember ten commands for ten distros.

**`--deep` is more aggressive.** `pacman -Scc`, `flatpak repair`, cached packages that'll re-download. Run `--dry-run --deep` first if unsure.

**It needs sudo or doas for some things** — package cache, orphan removal, journal. Detected at startup; on Alpine and Void where `doas` is the default, no configuration needed. User-level operations (`--cache`, `--trash`, `--dev`) never ask.

**Privileged commands are resolved to absolute system paths**, never through `$PATH` — a binary you didn't install can't be run as root through this tool. See [DETAILS.md](DETAILS.md#security).

**HDD warning.** On a spinning root disk you'll get a heads-up that cleanup may take a while. Reading directory sizes across millions of small files (looking at you, `~/.cargo/registry`) is genuinely slow. Not a bug, just physics.

**Cron-friendly:**
```
0 3 * * 0 /usr/local/bin/oxiclean --all --yes --quiet
```
Avoid `--deep` in automated runs. Add `--dev` if you want dev caches included.

---

## More documentation

**[DETAILS.md](DETAILS.md)** covers the longer story:

- [Everything it deliberately spares, and why](DETAILS.md#what-it-spares-and-why) — model weights, pnpm's store, aura's restore points, immutable systems
- [Security design](DETAILS.md#security) — trusted binary resolution (CWE-426), child environment hardening, self-update guards, the portage build-tmp guards
- [How it works under the hood](DETAILS.md#how-it-works-under-the-hood) — detection, how freed space is measured, why captured output
- [Testing](DETAILS.md#testing) — the 132 unit + 17 integration tests, and which ones matter
- [Contributing](DETAILS.md#contributing) — adding a distro, and what I'd love help with

---

## FAQ

<details>
<summary>Is <code>--all --yes --deep</code> safe to run?</summary>

It removes cached packages (not installed ones), orphaned packages, old Nix generations, and vacuums journal logs. Your software and personal files are never touched. If unsure, run `--dry-run` first.
</details>

<details>
<summary>Does it work on my distro?</summary>

If it's based on any supported family (Arch, Debian, Fedora, openSUSE, Void, Alpine, Gentoo, Solus, Clear, NixOS) — yes. Unknown distros still get universal cleaning: cache, trash, journal, Flatpak, Snap.
</details>

<details>
<summary>Will <code>--dev</code> break my Rust/Node/Python projects?</summary>

No. Without `--deep` it only removes things rebuilt locally with no network (cargo's extracted sources, pip's wheel cache, npm's download cache). With `--deep` it also clears caches that *will* re-download, so don't run that on a metered connection.

What it explicitly *cannot* break is your installed binaries — `~/.cargo/bin`, npm globals, poetry virtualenvs and gradle's wrapper are preserved by design, with tests that fail loudly if anyone changes that.
</details>

<details>
<summary>How is this different from BleachBit?</summary>

BleachBit is GUI-based, Python-dependent, and focuses on cleaning inside specific applications. OxiClean is a single CLI binary for system-level cleanup that works the same way whatever distro you're on. Different tools for different jobs.
</details>

<details>
<summary>Why Rust?</summary>

Honestly, I wanted to learn it. Also: single static binary, no interpreter to install, fast, and the type system catches a lot of bugs before they ship.
</details>

<details>
<summary>Did you use AI?</summary>

Yes — this project is AI-assisted, alongside my own work, across docs, code, and test-writing.
</details>

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

*OxiClean = Oxide (Rust) + Clean — no connection to any commercial cleaning product.*

[⬆ Back to top](#-oxiclean)

</div>
