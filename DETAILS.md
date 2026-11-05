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
| Maven artifacts installed on this machine | `mvn install` and `install:install-file` put things in `~/.m2/repository` that exist nowhere else. Maven records where it fetched each version (`_remote.repositories`), and only a version whose record names a repository for every file is removed. No record, a record that cannot be trusted, files it does not list: kept, and counted in one line. |
| Gentoo's `DISTDIR`, without `eclean` | Hand-fetched files (what a `RESTRICT=fetch` package needs) are in there, and every other file costs a download. Emptied only with `--deep` or a "y"; `--yes` and `--json` are not an answer. |
| What is mounted inside a directory being emptied | A bind mount, a network share, a container volume. See [What a cleanup will not follow or empty](#what-a-cleanup-will-not-follow-or-empty). |
| What `--dev` cleans, when you run `--all` | `--all` leaves it alone. Some of it means gigabyte-scale re-downloads, so you have to ask for `--dev` yourself. |

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

On NixOS the setuid wrappers (`sudo`, `doas`) are in `/run/wrappers/bin` and the
system's tools in `/run/current-system/sw/bin`. Both are used — the wrappers first,
as in a NixOS `PATH`, so the setuid `sudo` is the one found — but only where they
are root's: owner root, and neither group nor others can write. A link is followed
(the second is reached through `/run/current-system`) and what counts is the
directory it leads to. Any other owner or mode and the directory is simply not on
the list. The standard directories are not put to that test: they never were, and
a group-writable `/usr/local/bin` would otherwise be lost.

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
- **`emerge_builds()`** — a shadowed `pgrep` reporting "no build running" would
  let the sweep delete a live build tree. It is asked as root, through the helper
  the sweep deletes with, and fails closed (see
  [Portage build-tmp cleanup](#portage-build-tmp-cleanup)).
- **`query_owner()`** in self-update — a shadowed `pacman` exiting 1 would report
  "not owned" and let us overwrite a package-managed binary, corrupting its
  database.
- **`is_root()`** reads `/proc/self/status` instead of `id -u`, which cannot be
  spoofed by the caller.

### Two kinds of tool

oxiclean starts two kinds of program, and treats them differently.

- **System tools** — everything that touches packages, plus `find`, `rm` and
  `pgrep` — are resolved to an absolute path in the trusted directories and
  started with the trusted `PATH`. `$PATH` is not consulted. Everything that runs
  with privileges is one of these.
- **Your own tools** — what `--dev` drives (`cargo`, `uv`, `deno`, `pnpm`, `bun`,
  `npm`, `go`…) and the Nix user profile — live where you put them: rustup installs
  `cargo` into `~/.cargo/bin`, the installers of `uv`, `deno`, `pnpm` and `bun`
  default to `~/.local/bin`, a version manager has its shims. Each name is
  resolved once, through *your* `PATH`, to an absolute path (relative and empty
  entries are ignored, and only an executable regular file matches), and that path
  is what is started, with your environment. These commands run with your own
  rights against your own caches, so a binary you control gains nothing, and
  requiring a system path would only break `--dev` for you. (For root that
  sentence stops being true: see [Root and `$PATH`](#root-and-path).)

1.8.0 handed every child the trusted `PATH`, and a program searches its child's
`PATH` for a bare name too, so the second kind disappeared completely. Hence the
split.

### Child environment

Every system tool is handed the trusted `PATH` rather than the inherited one.
Package managers shell out themselves — pacman runs hooks, emerge runs ebuilds,
apk runs triggers — and those inherit our environment. With a poisoned `PATH`
still in place, a hook running as root could pick up an attacker's `sed`.

Only `PATH` is replaced; the rest of the environment is needed (`HOME` for
per-user caches, `XDG_CACHE_HOME`, `DENO_DIR`, locale for readable output).
`LD_PRELOAD` needs no handling: the dynamic loader ignores it across a setuid
boundary, and both sudo and doas strip it — verified in a container.

Your own tools keep your environment. For dotnet oxiclean adds the defaults that
keep a first command from doing more than it was asked (`DOTNET_NOLOGO`,
`DOTNET_CLI_TELEMETRY_OPTOUT`, `DOTNET_GENERATE_ASPNET_CERTIFICATE=false`,
`DOTNET_ADD_GLOBAL_TOOLS_TO_PATH=false`, `DOTNET_SKIP_WORKLOAD_INTEGRITY_CHECK=1`),
never over a value you set. The SDK still counts that run as the first one: your
own next `dotnet` command shows no welcome or telemetry message and skips the
workload check, which the SDK runs only on a first run and which can reinstall
workloads over the network. The certificate and the `PATH` change keep markers of
their own and are done then. With workloads installed, `dotnet workload update`
does what the check would have. (Checked with SDK 10.0.114, in a fresh home.)

### Root and `$PATH`

"A binary you control gains nothing" holds while the caller is the user whose
caches these are. It stops holding when the caller is root: `sudo` keeps the
caller's `PATH` unless sudoers sets `secure_path`, and `sudo -E` always keeps it,
so a `pip` that something running as you had left in `~/.local/bin` is started as
root. Shown with the real root of a container: the planted `pip` printed `uid=0`.

So when root is running, oxiclean cuts `$PATH` once, at start-up, before anything
looks for a tool (`utils::harden_path_for_root`). The tools it starts search the
same variable (`#!/usr/bin/env node`), so it is the `PATH` the children inherit
that changes, not only oxiclean's own lookup.

- **Kept**, in their order: entries that are absolute, exist, are directories and
  can be changed by root alone — owner root, not writable by group or others. A
  link is followed, as the lookup follows it.
- **Dropped without a word:** relative or empty entries (a shell reads them as the
  current directory), entries that do not exist, entries that are not directories.
- **Dropped and named**, in a single warning under the banner: directories that
  somebody other than root can write to, and ones that cannot be looked at. It is
  a warning, not a failure, and `--json` stays one document.
- With nothing left, the trusted directories are used: never an empty `PATH`,
  which whatever searches it reads as the current directory. A `PATH` that is
  already all root's is not rewritten, and an ordinary user's is not looked at.

Each entry is looked at itself, not the directories above it, as the trusted
directories are. A group-writable entry — a `/usr/local/bin` that is
`2775 root:staff`, as on some Debian installs, or a prefix owned by a user — is
left out for root and named on every run. That is deliberate.

### Root in a home directory that is not root's

`sudo -E`, a sudoers file that keeps `HOME`, and some older releases start root
with the `HOME` of whoever ran sudo. Steps that work in the home directory then run
as root in a tree the user controls, and where a removal ends up is theirs to say:
a link they left as `~/.cache`, or put there during the run, makes root remove what
it leads to. Shown with the real root of a container: with a link `~/.cache ->
/srv/victim` planted by uid 1000, `--cache --yes` emptied `/srv/victim` ("Freed
8.00 KB", exit status 0).

So when root is running, `$HOME` itself must be a directory only root can change:
owner root, not writable by group or others, a link followed
(`utils::foreign_home`). If it is not, `--cache`, `--trash`, `--dev`, `--aur` and
the user part of `--flatpak` are not run. Each says so under its own heading, as a
failure that says what to do (exit status 1, `errors` in `--json`, the same in a
dry run). A step that would only have said "nothing to do" — no flatpak, no AUR
helper, not Arch — is not made a failure. The steps that are root's own
(packages, orphans, journal, snap, coredumps, trim) go on.

A home that does not exist or is not a directory has nothing in it to clean and is
not refused; one that cannot be looked at is, as nothing is known about it. An
ordinary user in their own home, which is what the tool is for, is not looked at.
The environment-roots rule no longer lets the owner of `$HOME` stand in for root:
an `XDG_CACHE_HOME` in somebody else's home is theirs to clean as themselves.

Only `$HOME` itself is looked at, not the directories above it. A root-owned home
below a place others can rename is not how root is set up, and a check of every
ancestor would refuse homes inside the tests' own namespaces and under `/tmp` for
no gain.

### What a cleanup will not follow or empty

- **Mounts.** `rm -r`, and Rust's `remove_dir_all`, go into a mount point and
  remove what is mounted there. The kernel's list (`/proc/self/mountinfo`, read in
  `src/mounts.rs`) says where something is mounted: comparing device numbers, as
  `rm --one-file-system` does, misses a bind mount, which is the same file system
  on both sides. Paths are compared as real paths, since the kernel lists those
  (`/home` is a link to `/var/home` on Fedora Silverblue). A mount point is
  neither entered nor removed, and a tree with one inside is removed around it;
  what was left is said, in path order, and is not a failure. If the list cannot be
  read, nothing is emptied and that is an error. A cache directory that is itself a
  mount (a tmpfs, say) is ordinary and is emptied as before. The `find` sweeps that
  run as root (`utils::sudo_sweep`) use the same list. They are also given `-xdev`,
  which keeps `find` out of a different file system that is mounted after the list
  was read; a bind mount made in that window has the device number of its source,
  and `-xdev` cannot tell it apart. They get the real path too, because `find` does
  not follow a link given as its starting point.
- **Links.** A link inside a tree is removed; it is never entered, and what it
  leads to is never touched. A root that the environment names is resolved before
  it is judged (below), so a link cannot launder a target.
- **Roots from the environment.** `XDG_CACHE_HOME`, `UV_CACHE_DIR`, `DENO_DIR`,
  `CCACHE_DIR`, `GOMODCACHE`, `GOPATH`, `PIP_CACHE_DIR`, `COMPOSER_CACHE_DIR`,
  `NUGET_PACKAGES` (and Gentoo's `DISTDIR`, which portage reads from the
  environment before `make.conf`) name directories that are emptied, by oxiclean or
  by a tool it starts. `roots::check` is the gate they pass. It resolves links
  first, so a link cannot launder a target, and refuses what can never be a cache:
  a relative path, anything that is not a directory, `/`, the home directory and
  its parents, system directories and trees, and the places settings, data, state,
  keys and personal folders live. A root that came from the environment must also be
  owned by the user running oxiclean and writable by nobody else. A refused root is
  reported and left alone, nothing is cleaned in its place, and a tool that would
  have emptied it is not started (`go clean -modcache` and `ccache -C` do their own
  deleting). A home directory inside a system tree, as service accounts have,
  exempts what lies under it. `DISTDIR` is held to the first part only, since it is
  root's and portage's, not the user's.
- **Read-only trees.** Removing a directory means unlinking its entries, which needs
  write permission on it. When a directory refuses, `remove_entry` gives its owner
  rwx on the real directories of *that tree* and tries once more; the entry is about
  to be deleted, so its modes are not worth keeping, while the directory being
  emptied is not touched. The repair never follows a link: each directory is looked
  at without following, opened, and changed through the open handle only if it is
  still a directory with the same device and inode as the look found.
- **A directory replaced during the run.** A cleanup resolves the path of a cache
  once. A process of the same user that can rewrite a directory *on the path to* a
  cache — not below it — between the check and the removal can redirect the removal
  elsewhere: the exposure `rm -r` has for the path it is given. Below the start path
  nothing is followed. oxiclean does not anchor the whole path with `openat` as
  coreutils does, for four reasons: a process of the same user already has that
  power; a link to a directory that is not protected is followed by design; an
  anchor would not close the follow done when the path is canonicalised; and the
  code would sit in the core deletion path for no real gain. What remains is a
  confined process of the same user with write access to a directory on the path to
  a cache — a Flatpak app granted `xdg-cache` can rewrite `~/.cache/yarn` and
  similar, which `--dev` cleans. Run oxiclean as yourself, and remember that a
  cache is only as safe as the people who can write the path to it.

### Text that comes from outside

A file name can hold anything but `/`: an escape sequence that clears the screen
or retitles the window, a newline followed by `✔ Freed 4 GB`, a right-to-left
override that makes `gnp.exe` read as `exe.png`. Such a name reaches the terminal
in the message for a failed removal and, more often, in what a tool complains about
and we replay. Every helper that prints a message (`success`, `warning`, `error`,
`info`, `skip`, `plain`, `section`, the replay of a failed command's stderr, the
dimmed notes, the confirmation prompt) passes it through `utils::shown`, which
spells out whatever a terminal would act on: control characters (ESC and the C1
range among them), newlines, bidirectional overrides and isolates, line and
paragraph separators, the byte-order mark. Text without any of them is returned as
it is. The one thing let through is the colour sequence ESC `[` digits `;` `m`,
which is what `colored` writes into our own messages. It is done in the helpers,
not where a path is formatted, because there are far too many of those places for a
forgotten one to be noticed, and a message added later is covered too. `--json`
already escapes its strings.

### Self-update

- **Never updates a package-manager install.** pacman/dpkg/rpm are queried for
  ownership; if any owns the binary — or is installed but its query failed — the
  update is refused and the correct command is printed instead.
- **Installs only what the maintainer's key has signed.** TLS shows that a download
  came from GitHub, not that the maintainer published it. Every release carries
  `SHA256SUMS` and `SHA256SUMS.minisig`, made offline, and the public key is built
  into the binary from `minisign.pub` (several keys are allowed, for rotation).
  Before it installs anything, a client requires all of this:
  - the signature verifies against a built-in key; prehashed signatures only, the
    legacy format is refused;
  - the signed trusted comment is exactly `oxiclean X.Y.Z`, equal to the release's
    tag and newer than the running version, so a genuine old release replayed as
    "latest" is refused;
  - the checksum list is read only after its signature passed, in the strict
    `sha256sum` format; malformed and duplicate lines are refused;
  - the binary matches the signed digest and is an ELF file, and only then, never
    before, is it run (cleaned environment, 10-second limit) to answer `--version`
    with exactly `oxiclean X.Y.Z`, which also proves the libc flavour matched.

  With no key built in, `--update` refuses to run. How a release is made and
  signed is in [RELEASING.md](RELEASING.md).
- **A strict transport.** https only, at most five redirects, a deadline per
  request, and a cap on the bytes kept for each reply: the API 1 MiB, the checksum
  list 64 KiB, the signature 4 KiB, the binary 64 MiB. ureq's default features are
  off (rustls only), so a reply can neither be inflated past its cap nor set
  cookies.
- **Nothing an unprivileged process could change is trusted.** The download stays
  in memory. Files we write are created exclusively (`O_EXCL`), in a private 0700
  directory or beside the target. When the target's directory is not writable, the
  verified bytes reach a root `sh` script through sudo/doas on stdin
  (`utils::elevate_with_input`): the script checks the length, writes beside the
  target and renames over it, so root never reads a file an unprivileged process
  could have changed, and file names arrive as positional parameters, never as
  code.
- **Atomic and ETXTBSY-safe.** A running executable cannot be opened for writing,
  so the new binary is written to a temp file *in the same directory* and
  `rename(2)`d over the target.
- **The release notes are not signed.** They come from the GitHub API and are
  printed with control characters removed and a label saying so. `--update --json`
  is refused with one JSON document and exit status 2: the command asks first, and
  reports in text.

What this does not cover is listed in
[RELEASING.md](RELEASING.md#what-this-does-not-cover): `install.sh` still trusts
TLS and GitHub, and releases up to 1.8.0 have the old updater.

### Portage build-tmp cleanup

The most destructive path in the codebase — it clears the contents of
`$PORTAGE_TMPDIR/portage`. Every guard must pass, in this order:

1. The directory is a portage tree: the path resolves from `make.conf` (not a
   hard-coded guess) and ends in a `portage` component nested at least two levels
   deep. A malformed `PORTAGE_TMPDIR` of `/` or `//` is rejected rather than
   expanded to `/portage`.
2. It has something in it. A healthy system has an empty tree and is not asked, or
   warned, for nothing.
3. Not in a dry run: no emerge is running.
4. Nothing is mounted inside it (see
   [What a cleanup will not follow or empty](#what-a-cleanup-will-not-follow-or-empty)).

The emerge question is asked of **root**, through the helper the sweep deletes with. A
`pgrep` run as the user cannot see another user's processes when `/proc` is mounted
`hidepid=1`, `2` or `4`, and emerge runs as root: it prints 0 and exits 1, exactly
what it does when nothing is running. `pgrep -c -f '[e]merge'` makes pgrep say how
many it found, 0 included, and only two things count as an answer: a count above 0
with status 0 (a build, so the tree is left alone) and a printed 0 with status 1
(idle). Anything else is no answer: status 2 or 3, a sudo that refused or wanted a
password, a signal, a count that contradicts the status, a pgrep that does not know
`-c` (busybox's). The tree is then left alone and a warning says why. It is a
warning, not a failure, since nothing is wrong with the system, and it shows under
`--quiet`. The bracket in the pattern keeps pgrep from matching the command line it
is part of, and the pattern stays wide on purpose, since a wrong match only leaves a
tree alone.

Only contents are removed; the directory itself survives, because deleting it
changes ownership and mode that a running emerge would trip over.

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

Freed space is **measured** — what the cleaned trees occupy before and after —
not estimated, and it is space on disk. A file counts the blocks its filesystem
gave it (`st_blocks`: what `du` adds up, and what `df` shows as free once they are
released), and a file with several names counts only when every one of them is
among what is being removed, since another name keeps the data: a pnpm store that
projects link into is worth nothing
until those projects go, and says so. Directories are not counted, so a tree of
empty directories is 0 and "nothing to clean" stays true of it. On a filesystem
that shares extents (a snapshot, a reflink copy) the figure is an upper bound, and
because a directory's own blocks are left out, the real gain on ext4 or xfs is a
little larger than reported. Three exceptions: orphan removal, whose files are scattered across the
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

A step says "✔" only for work that happened. What each step reports is a verdict —
done, skipped (nothing to do, or deliberately left alone) or failed — decided by a
pure function from what the commands returned, and printed afterwards, so it can be
tested without a package manager. The result of every command helper is
`#[must_use]`, so a command whose outcome nobody looked at does not compile.
`utils::error` is the one place failures are counted: it records the message even
when it prints nothing, `main` notes the count before each operation so a failure is
filed under the operation that reported it, and the run ends with status 1 if there
was one. `--json` carries the same as `status` and `errors`; the first 100 messages
are kept for the report, while the count, and with it the exit status, stays exact.
A warning is for what deserves a look without stopping the step from doing its job.

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
├── install.sh          # Prebuilt-binary installer (curl | sh)
├── minisign.pub        # Release-signing public key, built into the binary
├── RELEASING.md        # How a release is built and signed
├── scripts/
│   ├── sign-release.sh        # Signs a draft release, on the maintainer's machine
│   └── test-sign-release.sh   # Tests that script against throwaway keys
├── tests/
│   ├── cli_test.rs
│   └── hardening_test.rs      # The real binary: namespaces, a made-up machine
└── src/
    ├── main.rs     # CLI parsing, orchestration, summary
    ├── detect.rs   # Distro detection, privilege/disk detection
    ├── clean.rs    # System cleaning operations
    ├── dev.rs      # Dev-tool cache cleanup (npm, cargo, pip, ...)
    ├── mounts.rs   # What is mounted where (/proc/self/mountinfo)
    ├── roots.rs    # Which directories may be emptied
    ├── update.rs   # Self-update (--update): GitHub check, signature, swap
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

407 unit tests, 17 tests of the command line (`tests/cli_test.rs`) and 68 that run
the real binary (`tests/hardening_test.rs`), plus two that only a release runs.
The interesting ones are not the "does this format correctly" checks — they are the
regression guards:

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
- Self-update accepts only a release signed by a built-in key, with the exact
  trusted comment, a newer version, the signed digest, and an ELF that reports the
  right version — checked against real minisign signatures
- A failed run ends with status 1 and says so in `--json`, and a step prints "✔"
  only for work that happened
- Emptying a directory never goes into what is mounted inside it, and an unreadable
  list of mounts leaves it alone — with real tmpfs and bind mounts
- A root named by the environment (`XDG_CACHE_HOME=$HOME` and the like) is refused,
  with one test for each rule of the gate
- A tree of read-only directories is emptied without following a link or changing a
  directory other than the one that was looked at
- As root: no step works inside a home that is not root's, and no tool is started
  from a `PATH` entry that others can write to
- Escape sequences, forged lines and bidirectional overrides in a name are spelled
  out by every helper that prints
- `--deep` removes only the Maven versions that Maven fetched, and empties Gentoo's
  `DISTDIR` only with `--deep` or a "y"
- `--json` alone never removes orphaned packages

The package-cache path for every family has been checked by **running the tool in
a container for that distro**, not read off documentation — that is how the Void,
Alpine and openSUSE bugs in 1.7.1 were found. Both Void and Alpine are documented
as "cleans the cache"; the gap only appears when you run it and diff the
directory.

**Tests that run the real binary.** Many of those in `tests/hardening_test.rs` run
inside a user and mount namespace of their own (`unshare -Urm`): a tmpfs, bind
mounts and "root" — which there is only the developer's own user — cost the machine
nothing, and the mounts go with the child. Others run on a *made-up machine*. What
oxiclean does for a distribution rests on two things a child process cannot simply
be handed: `/etc/os-release` says which distribution it is, and the system tools are
looked up in `/usr/bin` and the directories beside it, never in `$PATH`. In a
namespace both can be made up: `/usr/bin` holds only what the test wants to exist
(stand-in tools that write down what they are asked), and `/etc/os-release` says
what the test wants. Orphans on Arch and openSUSE, distfiles on Gentoo, root in a
home that is not root's, and root with a `PATH` that others can write to all run
end to end this way. These tests skip where a user cannot have a namespace, where
`/usr` cannot be made writable for the run (image-based systems), and, for the
"home that is not root's" ones, where the tests already run as real root.

Two tests are ignored by default and run in the release workflow: that the binary
carries a signing key, and that its TLS stack accepts the certificates of the hosts
`--update` talks to (it needs the network).

New guards were checked by breaking each one on purpose, one at a time, to see that
a test fails. That is done by hand, not in CI.

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
- **Real machines for what containers cannot show.** NixOS (the directories privileged
  tools are looked up in follow its documented layout; no NixOS machine was
  available); Gentoo and Solus (what `eclean packages` and `eopkg remove-orphans`
  exit with when they have nothing to do, which is why a failure of either is a
  warning and not a failed run, and `pgrep` from the real procps); `doas` on a real
  Void or Alpine; Flatpak behind polkit; and conda (its output is read as JSON, but
  no real install was at hand).
- **A disk-space test on ext4 or xfs.** The tests that would notice a directory's own
  blocks being counted cannot show on tmpfs or btrfs, where a directory occupies
  none.
