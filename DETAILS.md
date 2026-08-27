# OxiClean — Details

Longer-form documentation: what gets cleaned and what is deliberately spared,
security design, internals, testing, and contributing.

For installation and everyday usage, see the [README](README.md).

---

## What it spares, and why

The rule the whole tool is built on: **clean caches that come back on their own,
never touch data a user would grieve over.** Every entry below is enforced by a
unit test that fails loudly if a refactor breaks it.

| Kept | Why |
|---|---|
| `~/.cache/huggingface`, `~/.cache/torch` | Model weights. Multi-GB deliberate downloads — nobody clears a 40 GB model as routine cleanup. Kept silently, since neither `--cache` nor `--dev` removes them. |
| `~/.cargo/bin` | Your installed binaries (`cargo-watch`, `rustfmt`), not a cache. |
| pnpm store | Hardlinked into every `node_modules` on the disk. Deleting the directory silently breaks every project you have, so `pnpm store prune` is used instead. |
| `~/.cache/pypoetry/virtualenvs` | Your environments. Only the download `cache/` is cleaned. |
| `~/.gradle/wrapper` | Holds the actual Gradle distributions. Only `caches/` goes. |
| `~/.npm/lib/node_modules` | Globally installed packages. Only `_cacache/` goes. |
| `~/.cache/aura/snapshots` | Package restore points that `aura -B` restores from — state, not cache. `hashes/` (build bookkeeping) is kept for the same reason. |
| Everything under `--dev` | Not part of `--all`. Some of it triggers gigabyte-scale re-downloads, so it must be an explicit choice. |

Dev-tool caches that live under `~/.cache` are skipped by `--cache` and left to
`--dev`, which cleans each with its own correct per-tool command. A one-line hint
tells you when that happened, so a skip is never silent.

### Immutable and atomic systems

Silverblue, Kinoite, Bazzite, SteamOS and MicroOS are handled specially. On
OSTree systems the package cache is cleared with `rpm-ostree cleanup -bm` —
only the `-b` (temporary) and `-m` (cached metadata) flags. `-p` (pending) and
`-r` (rollback) alter *bootable deployments*, which is system state, and are
never touched. Other read-only-rootfs systems skip package-cache cleanup
entirely with an explanation, since their OS is managed by image swaps rather
than a package manager.

---

## Security

### Trusted binary resolution (CWE-426)

Every command that runs with privileges is resolved to an absolute path inside a
fixed allowlist — `/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`, `/usr/local/bin`,
`/usr/local/sbin` — and `$PATH` is not consulted.

`/nix/var/nix/profiles/default/bin` is on that list too, because Nix installs its
tools into the store and exposes them only through profile symlinks, so
`nix-collect-garbage` is never in `/usr/bin`. That is the *system* profile, owned
by root; per-user profiles (`~/.nix-profile`, `/nix/var/nix/profiles/per-user/…`)
are excluded, and a test rejects any path naming them.

This closes a real local privilege-escalation hole. Passing a bare name to the
privilege helper (`doas pacman -Sc`) leaves the lookup to the helper. `sudo` is
usually safe because a default `secure_path` in `/etc/sudoers` replaces the
caller's `$PATH` — but that is administrator-configurable, and **`doas` has no
equivalent at all**. So a binary named `pacman` in a directory that precedes
`/usr/bin` (`~/.local/bin` is added to `$PATH` by pip, cargo and several shells)
would be executed **as root**. Void and Alpine, where `doas` is the norm, were
the most exposed.

Verified by exploit: on 1.7.2 a planted `pacman` ran with `uid=0`. On 1.8.0 the
same attack — with `pacman`, `id`, `pgrep`, `find` and `rm` all planted — runs
nothing.

Resolution is applied to every gate that a shadowed binary could subvert, not
just to execution:

- **`capture_trusted`** for output we act on: `pacman -Qdtq` and
  `zypper packages --orphaned` produce the package list fed to a privileged
  removal. A shadowed binary there does not need root itself — it just has to
  name packages, and we delete them.
- **`which_trusted`** for availability checks that gate privileged branches, so
  the gate agrees with what will actually run.
- **`emerge_running()`** — a shadowed `pgrep` reporting "no build running" would
  let the sweep delete a live build tree. Fails closed.
- **`query_owner()`** in self-update — a shadowed `pacman` exiting 1 would report
  "not owned" and let us overwrite a package-managed binary, corrupting its
  database.
- **`is_root()`** reads `/proc/self/status` instead of `id -u`, which cannot be
  spoofed by the caller.

`--dev` deliberately keeps the *unrestricted* lookup: rustup puts `cargo` in
`~/.cargo/bin`, and the install scripts for `uv`, `deno`, `pnpm` and `bun`
default to `~/.local/bin`. Those commands run with your own privileges against
your own cache, so a binary you control is not an escalation — it is just your
tool. Requiring a system path there would break `--dev` for those users and buy
nothing.

### Child environment

Every child process is handed the trusted `PATH` rather than the inherited one.
Package managers shell out themselves — pacman runs hooks, emerge runs ebuilds,
apk runs triggers — and those inherit our environment. With a poisoned `PATH`
still in place, a hook running as root could pick up an attacker's `sed`.

Only `PATH` is replaced; the rest of the environment is needed (`HOME` for
per-user caches, `XDG_CACHE_HOME`, `DENO_DIR`, locale for readable output).
`LD_PRELOAD` needs no handling: the dynamic loader ignores it across a setuid
boundary, and both sudo and doas strip it — verified in a container.

### Self-update

- **Never updates a package-manager install.** pacman/dpkg/rpm are queried for
  ownership; if any owns the binary — or is installed but its query failed — the
  update is refused and the correct command is printed instead.
- **Atomic and ETXTBSY-safe.** A running executable cannot be opened for
  writing, so the new binary is copied to a temp file *in the same directory*
  and `rename(2)`d over the target.
- **Verified before trusted.** The download must be a real ELF and must run
  `--version` reporting the expected release, which also proves the libc flavour
  matched.

### Portage build-tmp cleanup

The most destructive path in the codebase — it clears the contents of
`$PORTAGE_TMPDIR/portage`. Four guards must all pass: the directory exists, no
`emerge` is running, the path resolves from `make.conf` (not a hard-coded
guess), and it ends in a `portage` component nested at least two levels deep. A
malformed `PORTAGE_TMPDIR` of `/` or `//` is rejected rather than expanded to
`/portage`. Only contents are removed; the directory itself survives, because
deleting it changes ownership and mode that a running emerge would trip over.

---

## How it works under the hood

`/etc/os-release` is read to identify the distro, then available tools are
detected. The chain looks roughly like:

```
/etc/os-release
  ID=arch          → pacman
  ID=ubuntu        → apt
  ID=fedora        → dnf
  ID=opensuse-...  → zypper
  ID_LIKE=arch     → pacman  (for derivatives)
  (unknown)        → universal cleaning only
```

Values may be quoted with either `"` or `'` — the os-release spec permits both,
and Gentoo ships `ID='gentoo'`. Handling only double quotes dropped Gentoo into
`Unknown`; that was a real bug, reported by a user, fixed in 1.7.2.

Freed space is **measured** — directory size before and after — not estimated.
Three exceptions: orphan removal, whose files are scattered across the
filesystem; `fstrim`, which frees blocks on the device rather than measurable
cache bytes; and Nix, which reports its own exact total (see below).

Nix is the one case where the tool's own number beats measuring.
`nix-collect-garbage` ends with `1576 store paths deleted, 454.8 MiB freed`,
counted from each store path as it deletes it — exact, and unaffected by CoW or
thin provisioning, unlike anything inferred from the filesystem. It also avoids
walking a store that on a real NixOS install is tens of gigabytes across hundreds
of thousands of files. Before this, the walk ran unprivileged against a root-owned
store and measured 0 both times, so Nix always reported `0 B` freed.

Each measured cache path must match what its clean command actually clears.
Measuring a subdirectory silently under-reports, which was a real bug on both
openSUSE (`zypper clean --all` also wipes `raw/` and `solv/`) and Solus
(`eopkg delete-cache` also clears `archives/`). Gentoo's `DISTDIR` is resolved
via `portageq distdir`, then `make.conf`, then the default — `eclean` reads the
live portage config, so assuming the path was wrong for anyone who overrides it.

Helper output is captured rather than inherited, so the report reads as a report.
A command that **fails** replays its stderr under the error line, and
`--verbose` restores the raw output. Package removal, Nix GC and
`fstrim --verbose` still print live: the first two are slow enough that silence
would read as a hang, and `fstrim`'s output *is* the result.

The binary is a single self-contained file (~2 MB) using `clap` for CLI parsing,
`colored` for terminal colors, `clap_complete` for completions, and
`ureq` + `rustls` for `--update`. The TLS stack is most of the size, but it means
self-update needs no external `curl` or `wget`. The `musl` build is fully static
with no runtime dependencies.

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
    └── utils.rs    # Command execution, trusted resolution, file ops
```

---

## Testing

```bash
cargo test
cargo test -- --nocapture  # with output
cargo clippy -- -D warnings
cargo fmt -- --check
```

132 unit tests and 17 integration tests. The interesting ones are not the
"does this format correctly" checks — they are the regression guards:

- A binary reachable only through `$PATH` never resolves for a privileged call
- No trusted directory is user-writable, no entry names a per-user Nix profile,
  and children receive the trusted `PATH`
- `is_root()` agrees with the kernel rather than an `id` binary
- Directory sizes skip symlinks and never follow one out of the tree being
  cleaned — the rewrite that made scanning 2.4× faster reads type and size from
  the directory entry, and reporting a link target's bytes would inflate every
  freed figure
- Nix's reported total is read from its own output, taking the size rather than
  the store-path count that precedes it on the same line
- The dev cleaner never targets `~/.cargo/bin`, `~/.cache/pypoetry/virtualenvs`,
  or `~/.gradle/wrapper`
- `--cache` never selects a HuggingFace/torch model cache, and never claims a
  model can be cleaned with `--dev` (it cannot)
- `--all` never enables `--dev` or `--trim`
- trizen's clean stays scoped to the AUR cache, so a plain run cannot wipe every
  cached pacman package
- aura's prune lists never name `snapshots/` or `hashes/`, and its cache dir is
  never wiped wholesale in either mode
- Deferring an AUR helper's cache to the AUR section never strands it when that
  section is not running
- Each measured cache path matches what its clean command clears
- Hostile `PORTAGE_TMPDIR` values never resolve to a deletable path, and the
  build-tmp cleanup clears contents while leaving the directory
- Distro detection survives single-quoted, double-quoted and unquoted values
- `--json` output parses as valid JSON
- Read-only-rootfs detection matches only the exact `ro` mount flag
- Self-update refuses to overwrite a package-manager-owned binary

The package-cache path for every family has been checked by **running the tool in
a container for that distro**, not read off documentation — that is how the Void,
Alpine and openSUSE bugs in 1.7.1 were found. Both Void and Alpine are documented
as "cleans the cache"; the gap only appears when you run it and diff the
directory.

---

## Contributing

```bash
git clone https://github.com/croaky-fx/oxiclean.git
cd oxiclean
cargo build && cargo test
```

**Adding a new distro:**

1. Add a variant to the `Distro` enum in `detect.rs`
2. Add its ID to the detection arrays
3. Add cache cleaning in `clean.rs → pkg_cache()`
4. Add orphan removal in `clean.rs → orphans()` (skip if the distro is
   atomic/immutable — it has no orphans)
5. Update the supported-distros table in the README
6. Test it in a container or VM, and verify the freed figure against
   `du -sh` before and after — that check is what caught three real bugs

**Things I'd love help with:**

- **Immutable systems** (Silverblue, Kinoite, Bazzite, SteamOS, MicroOS) — the
  atomic/read-only paths are the newest code and least battle-tested. Containers
  cannot cover them, since detection depends on `/run/ostree-booted`.
- **A real `aura` install.** aura has no command that cleans its own cache
  (`-Sc` passes through to pacman; `-Cc` is the downgrade namespace, takes a
  mandatory version count, and also targets the pacman cache), so oxiclean
  clears `~/.cache/aura/builds` directly, with built tarballs and AUR git clones
  behind `--deep`. That logic is covered by unit tests but has only been
  exercised against a stubbed binary and a hand-made directory tree — a check
  that the directory names still match on a real install would be genuinely
  useful.
- More dev tools in `--dev` (mix, rebar, sbt...)
- Better distro-specific docs for Alpine / Void / Nix edge cases
- More real-world smoke tests on HDD systems
