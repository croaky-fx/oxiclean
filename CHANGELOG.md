# Changelog

## [Unreleased]

### Security
- **`--update` installs only releases the maintainer's key has signed.** TLS shows
  that a download came from GitHub, not that the maintainer published it, and
  nothing else was checked before the running binary was replaced — as root, when
  it lives in `/usr/local/bin`. Every release now carries `SHA256SUMS` and
  `SHA256SUMS.minisig`, made offline with
  [minisign](https://jedisct1.github.io/minisign/), and the public key is built
  into the binary. A client goes ahead only when:
  - the signature verifies against a built-in key (prehashed signatures only);
  - the signed comment reads exactly `oxiclean X.Y.Z`: the release's own version,
    and newer than the running one, so a genuine old release replayed as "latest"
    is refused;
  - the checksum list, read only after its signature passed, gives the digest of
    the binary that arrived;
  - the binary is an ELF file and, run once with `--version` in a cleaned
    environment, prints exactly `oxiclean X.Y.Z`.

  The transport is stricter too: https only, at most five redirects, a deadline
  and a size cap on every reply, the download kept in memory, files created
  exclusively in a private directory. When the target's directory needs root, the
  verified bytes reach a root `sh` through sudo/doas on stdin, so root never reads
  a file an unprivileged process could have changed. Release notes are printed
  with control characters removed and marked as not signed. `--update --json` is
  refused (exit status 2), and a build with no key refuses to update at all.
  [RELEASING.md](RELEASING.md) is the release procedure.

  Not covered: `install.sh` still trusts TLS and GitHub, and 1.8.0 and earlier keep
  the old updater, which is how they receive the first signed release.
- **A deletion root named by an environment variable must plainly be a cache.**
  `XDG_CACHE_HOME`, `UV_CACHE_DIR`, `DENO_DIR`, `CCACHE_DIR`, `GOMODCACHE`,
  `GOPATH`, `PIP_CACHE_DIR`, `COMPOSER_CACHE_DIR` and `NUGET_PACKAGES` name
  directories that get emptied, by oxiclean or by a tool it starts, and none was
  checked. `XDG_CACHE_HOME=$HOME` — a typo in a profile is enough — made `--cache`
  delete everything in the home directory that was not on the protected list, and
  `UV_CACHE_DIR=$HOME` did the same through `--dev`. Every such directory now goes
  through one check. Symlinks are resolved first, so a link cannot launder a
  target. Refused are: a relative path, anything that is not a directory, `/`,
  your home directory and its parents, system directories, and the places where
  settings, data, state, keys and personal folders live. A directory that came
  from the environment must also belong to you and be writable by nobody else.

  A refused directory is reported and left alone. Nothing is cleaned in its place
  (your tools follow the variable, so `~/.cache` is not where their caches are),
  and a tool that would have emptied it is not started. A relative
  `XDG_CACHE_HOME` is ignored with a note, as the XDG spec says; an empty or
  relative `$HOME` counts as unset. A cache moved with `XDG_CACHE_HOME` is cleaned
  after a prompt or with `--yes`; `--json` alone is not an answer. `GOPATH` is a
  list, and the module cache lives under its first entry.
- **Cleaning no longer goes into what is mounted inside a cache.** `rm -r` and
  Rust's `remove_dir_all` do not stop at a mount point. A `~/.cache` with a
  project bind-mounted in it, a network share or a container volume lost that
  something's files on a run that was only meant to empty a cache, and then
  reported a failure. The kernel's list of mounts (`/proc/self/mountinfo`) is now
  read first. A mount point is neither entered nor removed, and
  `Kept <path>: another file system is mounted there` says so: a note, not a
  failure. A dry run leaves out what a real run leaves alone, so the two figures
  agree. If the list cannot be read, nothing is emptied and that is an error.

  This covers every cleaner that empties a directory (cache, trash, thumbnails,
  the Flatpak and AUR caches, the dev caches) and the `find` sweeps that run as
  root: portage's build tree, apk's cache, Gentoo's distfiles, Flatpak's repo
  tmp, snapd's cache, systemd's coredumps. `find -xdev` stops at another file
  system but not at a bind mount, so those sweeps use the mount list too. A cache
  directory that is itself a symlink is now really cleaned:
  `find` does not follow a link given as its starting point, and used to report
  "cleaned" after removing nothing.
- **As root, oxiclean no longer works inside a home directory that is not root's.**
  `sudo -E`, a sudoers file that keeps `HOME`, and some older releases start root
  with the home of whoever ran sudo. `--cache`, `--trash`, `--dev`, `--aur` and the
  user part of `--flatpak` then did their work as root in a tree the user
  controls, and where a removal ends up is theirs to say: a link they left as
  `~/.cache` made root empty whatever it pointed to (shown in a container, with a
  link planted by an ordinary user: "Freed 8.00 KB", exit status 0).

  When `$HOME` is not a directory that only root can change, those five steps are
  not run. Each says so under its own heading as a failure — exit status 1, listed
  under `errors` in `--json`, the same in a dry run — and the steps that are root's
  own (packages, orphans, journal, snap, coredumps, trim) go on. Run oxiclean as
  yourself, without sudo: it asks for sudo itself where a step needs it.
- **As root, oxiclean starts the tools it finds through `$PATH` only from
  directories that only root can change.** `sudo` keeps the caller's `PATH` unless
  sudoers sets `secure_path`, and `sudo -E` always keeps it, so a `pip` that
  something running as you had left in `~/.local/bin` was started as root (it
  printed `uid=0`). For root the `PATH` is now cut once, at start-up, for
  oxiclean and for everything its tools start (`#!/usr/bin/env node` and the
  like). Relative entries and entries that are not there are dropped without a
  word; a directory that anybody but root can write to is dropped and named in a
  single warning, which is not a failure. With nothing left, the trusted system
  directories are used. A run as an ordinary user is not touched.
- **`install.sh` refuses a download that is sent on over plain http.** A release
  download is always redirected, and `curl -L` would have followed a redirect to
  `http://`; TLS older than 1.2 was accepted too. curl now gets
  `--proto '=https' --tlsv1.2`. The wget fallback gets no flag on purpose: its
  `--https-only` does not limit redirects, and a flag that looks like a protection
  and is not one is worse than none. That is why curl is tried first.
- **Text that comes from outside is shown, not obeyed.** A file name can hold
  anything but `/`: an escape sequence that clears the screen or retitles the
  window, a newline followed by `✔ Freed 4 GB`, a right-to-left override that
  makes `gnp.exe` read as `exe.png`. Such a name reached the terminal raw, in the
  message for a failed removal and in what a tool complains about, which is
  replayed under our failure line. Every message oxiclean prints now spells out
  what a terminal would act on (`\u{1b}`, `\n`). Ordinary text, in any script, is
  printed as it is, and the colours oxiclean writes itself still work. `--json`
  already escaped its strings.

### Changed
- **The exit status says whether the run worked.** A step that failed printed its
  red line and the run still exited 0, so `oxiclean --all && next-step`, a cron
  job or a CI script heard "success" whatever had happened. It is now 0 when every
  step did what it was asked and 1 when any step reported a failure. Unchanged: 1
  for "no operation selected" and for missing privileges, 2 for a command line
  that makes no sense. The text report adds `✘ N error(s) — see the lines marked ✘
  above`. `--json` gains three fields after the existing ones, so nothing a
  consumer already reads moves: `schema` (1), `status` (`"ok"` or `"error"`) and
  `errors` (a list of `{operation, message}`, the first 100). The document of a
  run that cannot start carries `status` and `schema` too. A warning is not a
  failure.
- **`--json` is no longer a yes to removing orphaned packages.** On Arch and
  openSUSE the question "Remove orphaned packages?" counted as answered under
  `--json`, so a run that only asked for its report as JSON removed packages
  nobody had been asked about. Removing them now takes `--yes`. With `--json`
  alone nothing is removed, and that is an error, not a quiet skip: "Orphaned
  packages not removed without --yes (--json cannot ask)". `--json --yes` removes,
  a terminal asks as before, and a dry run asks nothing. Debian, Fedora, Void,
  Gentoo and Solus run their own autoremove with `--orphans`/`--all` and never
  asked; they are unchanged.
- **"Freed" and "Would free" are space on disk**, not the sum of file lengths. A
  small file occupies a whole block, so a cache of many small files (a browser's,
  npm's, pip's) was under-reported. A sparse file occupies less than its length,
  and a file with several names frees nothing until the last one goes, so a pnpm
  store that projects link into was over-reported. A file now counts the blocks
  its filesystem gave it, which is what `du` adds up and what `df` shows as free
  afterwards, and one with several names counts only when every name is among
  what is being removed. On a copy of
  a source tree (1 810 files, 1 105 of them with several names) `--dry-run` says
  4.70 MB, as `du` does; the length sum said 2.05 MB. On a filesystem that shares
  extents (snapshots, reflinks) the figure is an upper bound.
- **A dev cache whose own tool is missing is left alone.** pnpm, go, conda,
  ccache, dotnet (NuGet) and composer are scanned only when their tool is found.
  A cache that is there while its tool is not gets one dim line — `⊘ pnpm: found a
  cache, but pnpm is not in your PATH — left alone` — and no row in the summary,
  no share of "Will clean now" and no failure. Before, a pnpm store left behind by
  a pnpm that is gone ended the run with "`pnpm store prune` failed" and status 1
  on a machine where nothing was wrong (deleting that store by hand would break
  every project that links into it), and the others were listed and counted
  although nothing could clean them.
- **Gentoo without `eclean`: `DISTDIR` is no longer emptied unasked.** The step
  removed every distfile with `find` and asked nothing, hand-fetched files
  included — what a `RESTRICT=fetch` package needs its user to put there. It now
  takes `--deep` or a "y" to a question that names the real path and what is
  lost; `--yes` and `--json` alone leave the files, with a note that `--deep` does
  it, and do not fail the run. Installing `eclean` (gentoolkit) is still the
  better way, as it keeps what the tree still wants. `DISTDIR`, which portage
  reads from the environment before `make.conf`, goes through the same check as the
  other environment-supplied roots: `/`, `/var`, `/usr` and the other system
  directories, your home and anything inside a system tree are refused with the
  reason, as a failure. The old `/usr/portage/...` home of distfiles stays
  allowed, and a `DISTDIR` that is not there is now said.
- **`--deep` keeps the Maven artifacts that were installed on this machine.** It
  emptied `~/.m2/repository`, and with it what cannot be downloaded again: a
  library put there with `mvn install`, a jar from `install:install-file`. Maven
  records where it got each version in `_remote.repositories`; only a version
  whose record names a repository for every file is removed. Everything else is
  kept — installed here, no record (Gradle's `publishToMavenLocal` writes none),
  a record that is not text or over 64 KiB, files the record does not list,
  sub-directories — and one line says how many, and that they cannot be
  downloaded again. The summary figure is what a clean frees, not what the whole
  repository weighs. Links inside are neither entered nor removed, mount points
  are left, and group directories the removal empties are pruned, never the
  repository itself.
- **`--quiet` drops the description of the machine,** as `--help` says it does.
  The System, Distro, AUR helper, Flatpak, Snap, Nix and HDD lines are banner
  sub-lines and were printed whatever the flag, so a cron job began with seven
  lines nobody asked for. DRY RUN and DEEP CLEAN stay: they say what the run is
  about to do.
- **Building from source needs Rust 1.85.** The README said 1.70+, which was
  never true: the locked dependencies (ureq 3.3, zeroize 1.9) need 1.85.
  `Cargo.toml` now says `rust-version = "1.85"` and CI builds with that version.

### Fixed
- **`--dev` found no tool installed in your home directory (a regression in 1.8.0).**
  1.8.0 gave every child process the trusted `PATH`, and a program searches its
  child's `PATH` for a bare name, so `uv` in `~/.local/bin`, `cargo` in
  `~/.cargo/bin` and a version manager's shims were invisible: the call failed,
  nothing said why, and the total read 0 B. There are now two kinds of tool. System
  tools keep the absolute path from the trusted directories and the trusted `PATH`.
  Your own (`--dev`, the Nix user profile) are found once through your `PATH`,
  relative and empty entries ignored, only executable regular files accepted, and
  they keep your environment.
- **`--dev` keeps tool chatter and first-run side effects out of the run.** The
  .NET SDK answers a first command — often `dotnet nuget locals all --clear` — with
  a welcome banner, a telemetry notice, an HTTPS development certificate, a `PATH`
  change and a workload check. For dotnet, oxiclean now sets `DOTNET_NOLOGO`,
  `DOTNET_CLI_TELEMETRY_OPTOUT`, `DOTNET_GENERATE_ASPNET_CERTIFICATE=false`,
  `DOTNET_ADD_GLOBAL_TOOLS_TO_PATH=false` and `DOTNET_SKIP_WORKLOAD_INTEGRITY_CHECK=1`,
  never over a value you set. The SDK still counts that run as the first one, so
  your own next `dotnet` command shows no welcome or telemetry message and skips
  the workload check; the certificate and the `PATH` change are done then, and
  `dotnet workload update` does what the check would have. The output of each
  tool-driven cleaner is captured; a failure replays what the tool said, and
  `--verbose` shows it all. `--json` is one
  document again: visible children get no stdout in JSON mode, and the orphan list
  and the dev table no longer print straight to it.
- **A "✔" means the step did its work.** Many success lines followed a command whose
  result nobody had looked at, or one that exits 0 without having done anything:
  - Arch `--deep`: `pacman -Scc --noconfirm` answers "remove all files from cache?"
    with its default, which is no (pacman 7.1), so it removed nothing and "deep
    clean done" was printed. Both questions are now answered.
  - Nix: `nix store --optimise` is not a command; in a single-user install the
    working one lives in the user's profile, which root cannot see, so it now runs as
    the user.
  - Void: `xbps-remove -O` exits 1 when `/var/cache/xbps` does not exist. That is
    nothing to clean, not a failure.
  - Alpine: `apk cache clean` exits 0 whatever it did and keeps the cached current
    versions, so "cleaned" was said after removing zero bytes. The report says what
    was kept, and `--deep` deletes the rest and checks.
  - Gentoo, Flatpak (`--user` and `--system` each on their own), snap, coredumps,
    Apport, the portage tmp sweep and pacman's partial downloads: a success line
    only when the removal worked, and an error naming what could not be cleared
    when it did not.
  - A listing that failed (`pacman -Qdtq`, `zypper packages --orphaned`,
    `snap list`) was read as "nothing found" — "No orphans found" for a locked
    package database. The two are told apart now.
  - A privileged command that was never started (no sudo or doas, or the tool
    outside the trusted directories) says why, and no longer looks like one that
    failed.

  `Freed 0 B` after a failed cleanup is gone too, as is "already clean" after a
  failed deep clean of an AUR cache: the line is left out only when nothing was
  freed *and* something failed; a clean zero still says `Freed 0 B`.
- **Caches and the trash with read-only directories are really emptied.** `~/.cache`
  and the trash are emptied one entry at a time, and an entry that could not be
  removed was skipped without a word: the run ended with a tick, `Freed 0 B` and
  status 0, and the tree was still there. Read-only directories are common in just
  these places — the Go module cache extracts every directory read-only, an AUR
  build that downloads Go modules leaves them in the helper's cache, a tree put in
  the trash keeps its modes — and in the trash the info files went while the files
  they describe stayed. A directory that refuses is now given its owner's rwx, once,
  and removed. The repair never follows a link and never touches a directory that
  is not the one it looked at; the directory being emptied keeps its own mode. What
  stays is one error per directory ("Could not remove 2 of 5 item(s) in DIR: PATH:
  Permission denied"), counted in the exit status and in `--json`. `gem cleanup`,
  which printed nothing when it worked, now says "cleaned (size not measured)".
- **NixOS: sudo and the system tools were not found.** NixOS has none of the
  directories privileged commands were looked up in: the setuid wrappers are in
  `/run/wrappers/bin` and `nix-collect-garbage` is in
  `/run/current-system/sw/bin`, so "No privilege-escalation tool found" came
  before anything ran. Both directories are now used, but only where they are
  root's (owner root, not writable by group or others; a link is followed). The
  standard directories are not put to that check — Debian's group-writable
  `/usr/local/bin` would be lost. Detection now agrees with launch: flatpak and
  snap are announced only when the system lookup finds them, and an AUR helper
  that is not in a system directory is reported as not run, not as a failed `-Sc`.
  `PIP_CACHE_DIR`, `COMPOSER_CACHE_DIR` and `NUGET_PACKAGES` are checked like the
  other relocated caches and scanned where the tool looks (pip and Composer keep
  their cache under `XDG_CACHE_HOME` when it is set). Tried against a made-up NixOS
  layout in a container; a real NixOS machine was not available.
- **The "is an emerge running?" guard could answer "no" when it did not know.** The
  sweep of failed-build leftovers under `PORTAGE_TMPDIR` runs only when no emerge
  is running. `pgrep` ran as the user, and every status except "found" read as an
  idle tree: pgrep's own errors, and a root emerge that a `/proc` mounted
  `hidepid=2` hides (reproduced: "Cleared portage build leftovers" while one ran).
  Root is now asked — `pgrep -c -f '[e]merge'` — and only a count above 0 (a build;
  the tree is left alone) or a printed 0 with status 1 (idle) is an answer.
  Anything else, a sudo that refused or one that wanted a password, leaves the tree
  alone with a warning that says why; it is not a failure.
- **Flatpak's leftovers were swept from everything under `/var/tmp`.** The sweep was
  `find /var/tmp -name 'flatpak-cache-*'` as root, and removed anything with that
  name at any depth — a project's `flatpak-cache-notes` directory went with the
  leftovers. It is limited to the top of `/var/tmp` now (`-maxdepth 1`), where
  Flatpak puts them.
- **A snap called `disabled-notes` was taken for a disabled revision.** The word was
  looked for anywhere on a line of `snap list --all`, and `snap remove --revision`
  was then run against an active snap's current revision. A note must now be
  exactly `disabled` in the Notes column (`disabled`, `base,disabled` and
  `disabled,classic` all qualify).
- **conda in a home directory with non-ASCII characters.** `conda info --json`
  writes every such character as an escape, and `--dev` read the package directory
  by looking for the quotes, so the "path" was the escaped text, which does not
  exist. The reply is parsed as JSON now.
- **NixOS ran `nix-store --optimise` on a spinning disk,** which can take hours.
  Every other distribution already skipped it there and said how to run it
  yourself; NixOS now does the same.

### Internal
- **Releases are signed offline before anyone can see them.** `release.yml` now makes
  a draft, which GitHub's "latest release" never returns, so neither `--update` nor
  `install.sh` sees a release before `scripts/sign-release.sh` has signed it on the
  maintainer's machine. A preflight job runs before the four builds: the tag must
  equal the `Cargo.toml` version, `minisign.pub` must hold a key, and the build
  must be able to verify the certificates of the hosts `--update` talks to (the
  ignored tests `release_builds_must_ship_an_update_key` and
  `release_builds_must_verify_the_hosts_they_update_from`). The second needs the
  network: without it, a build whose TLS roots do not cover GitHub would pass every
  test and ship a release that can neither update itself nor be updated.
  `scripts/test-sign-release.sh` runs the signing script against throwaway keys
  and a fake `gh`, and CI runs it. [RELEASING.md](RELEASING.md) is the procedure.
- **CI builds with a read-only token and from the locked dependencies.** The
  workflow has `contents: read`; only the job that creates the draft release asks to
  write. Checkouts no longer leave the token in `.git/config`, and builds, tests and
  clippy run with `--locked`, so a change to `Cargo.toml` that does not bring
  `Cargo.lock` along fails the pull request and not the release. A new `msrv` job
  builds with the Rust version `Cargo.toml` names. The actions are still pinned by
  tag, not by commit.
- **Tests that run the real binary** (`tests/hardening_test.rs`). Some run it in a
  user and mount namespace of its own (`unshare -Urm`), where a tmpfs, bind mounts
  and "root" — the developer's own user — cost the machine nothing. Others run it
  on a made-up machine: `/usr/bin` and `/etc/os-release` are replaced for the run,
  so the flows that belong to one distribution (orphans on Arch and openSUSE,
  distfiles on Gentoo) and the checks on root run end to end against stand-in
  tools that write down what they were asked. They skip where a user cannot have a
  namespace or `/usr` cannot be made writable.
- The results of `run`, `run_user`, `run_quiet`, `elevate`, `sudo` and their
  variants are `#[must_use]`: a command whose outcome is ignored no longer compiles.
- Comments that said what the code did not were corrected.

## [1.8.0] - 2026-08-27

### Security
- **Privileged commands are no longer looked up in `$PATH`.** Every command run
  with elevated privileges is now resolved to an absolute path inside a fixed
  allowlist (`/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`, `/usr/local/bin`,
  `/usr/local/sbin`).

  Handing a bare name to the privilege helper — `doas pacman -Sc` — leaves the
  lookup to the helper. `sudo` is usually protected by a default `secure_path` in
  `/etc/sudoers`, but that is administrator-configurable (clearing `env_reset`,
  adding `env_keep += "PATH"`, or a build without `SECURE_PATH` all pass the
  caller's `PATH` through) and **`doas` has no equivalent at all**. So a binary
  named `pacman` in a directory preceding `/usr/bin` — and `~/.local/bin` is put
  on `PATH` by pip, cargo and several shells — was executed **as root**. Void and
  Alpine, where `doas` is the norm, were the most exposed. CWE-426.

  Confirmed by exploit rather than inspection: on 1.7.2 a planted `pacman` ran
  with `uid=0`; on 1.8.0 the same attack, with `pacman`, `id`, `pgrep`, `find`
  and `rm` all planted, executes nothing.

  The same resolution now covers every gate a shadowed binary could subvert, not
  just execution: the package lists we feed to a privileged removal
  (`pacman -Qdtq`, `zypper packages --orphaned`), the availability checks that
  pick a privileged branch, the `pgrep` behind the "is an emerge running" guard
  (a false negative there would delete a live build tree), and the
  package-ownership query that decides whether self-update may proceed (a false
  "not owned" would overwrite a package-managed binary and corrupt its database).
  `is_root()` now reads `/proc/self/status` instead of trusting an `id` binary
  that could print `0`.
- **Child processes are handed a trusted `PATH`.** Package managers shell out
  themselves — pacman runs hooks, emerge runs ebuilds, apk runs triggers — and
  inherit our environment, so a poisoned `PATH` could still reach a root-running
  hook. Only `PATH` is replaced; the rest of the environment is left intact
  because the cleanup commands need it. `LD_PRELOAD` requires no handling: the
  dynamic loader ignores it across a setuid boundary and both helpers strip it
  (verified in a container).

### Changed
- A command that cannot be resolved to a trusted system directory is now treated
  as unavailable, and its step is skipped rather than run. On a normal system
  nothing changes — every package manager and coreutil we drive already lives
  there — but a tool installed *only* somewhere like `~/bin` will no longer be
  used for privileged work.
- `--dev` deliberately keeps the unrestricted lookup. rustup installs `cargo` to
  `~/.cargo/bin`, and the `uv`/`deno`/`pnpm`/`bun` installers default to
  `~/.local/bin`; those commands run with your own privileges against your own
  cache, so restricting them would break `--dev` for those users and prevent
  nothing.

### Fixed
- **Nix reported `0 B` freed, always.** The freed figure came from walking
  `/nix/store` before and after, but the store is root-owned and the walk runs
  unprivileged, so it measured 0 both times. `nix-collect-garbage` prints the
  real number itself — `1576 store paths deleted, 454.8 MiB freed` — computed
  from each store path as it deletes, which is exact rather than inferred from
  the filesystem. That line is now parsed instead. Verified against a real Nix
  container: oxiclean reports 454.80 MB where Nix reports 454.8 MiB.
- **Nix tooling is reachable again after the hardening above.** Nix installs its
  binaries into the store and exposes them only through profile symlinks, so
  `nix-collect-garbage` is never in `/usr/bin` — the trusted-path change would
  have disabled Nix cleanup entirely. The root-owned system profile
  (`/nix/var/nix/profiles/default/bin`) is now part of the trusted set; per-user
  profiles are deliberately excluded, and a test rejects any path containing
  `per-user` or `.nix-profile`.

### Performance
- **`~/.cache` scanning is 2.4× faster** — 88 ms → 36 ms on a 40 000-file tree,
  which is what `du` costs for the same walk. `dir_size` asked
  `is_symlink()`, then `is_dir()`, then `metadata()` for every entry, and each of
  those re-resolves the path: three syscalls per file. Type and size now come
  from the directory read that already happened. It is also iterative now, so a
  deep tree cannot overflow the stack.
- **Deletion stopped re-measuring what it had just measured.** `rm_contents` made
  five path resolutions per entry — three to size it, two more to choose between
  `remove_dir_all` and `remove_file`. One `lstat` answers all of it.
- **`--dev` scanning is 4.1× faster** — 442 ms → 108 ms, and no longer spawns any
  subprocess. It asked `pnpm store path` before looking at the default location,
  and pnpm is a Node program: 280 ms of the 442 was interpreter startup for a path
  we could have found ourselves. The default is checked first now, with the tool
  asked only when the cache has been relocated; `uv` and `go` likewise read
  `UV_CACHE_DIR`, `GOMODCACHE` and `GOPATH` from the environment first.
- **`--dev` cleanup reuses the sizes from its own scan.** Nine cleaners re-walked
  their cache directory to establish a "before" size that `scan_all` had measured
  moments earlier — including `~/.npm/_cacache`, which is routinely hundreds of
  megabytes.

## [1.7.2] - 2026-08-13

### Fixed
- **Distro detection handled only double-quoted `os-release` values.** The spec
  permits either quote style, and Gentoo ships `ID='gentoo'` — the single quotes
  stayed attached, matched nothing in the detection table, and the distro
  silently fell through to `Unknown`, so Gentoo and Funtoo systems got universal
  cleaning only instead of portage handling. `PRETTY_NAME` had the same gap, and
  so did `ID_LIKE`, which affects hand-edited derivative entries. Reported by a
  user. Regression tests cover single-quoted, double-quoted and unquoted values.

## [1.7.1] - 2026-08-11

Package-cache handling audited against every supported family by running the
tool in containers. Three distros were reporting success for work they had not
done; two more were measuring the wrong directory.

### Fixed
- **Void: the package cache was never actually cleaned.** `xbps-remove -O` only
  drops *outdated* cached packages. On a system whose cached packages are all
  current — which is every freshly-installed box — it removes nothing and still
  exits 0, so the tool reported `xbps cache cleaned` after freeing zero bytes.
  Confirmed in a container: 139 MB before, 139 MB after. `-OO` (which also
  removes cached packages that are no longer installed) now runs under `--deep`,
  and a normal run says what it kept instead of implying it cleaned everything.
  It stays behind `--deep` because that cache is what makes a downgrade
  possible: a version dropped from the repo index can still be reinstalled from
  `/var/cache/xbps`. After the fix, `--deep` frees 119.29 MB (139 MB → 20 MB,
  the still-installed versions xbps keeps by design).
- **Alpine: the same bug, same shape.** `apk cache clean` only prunes superseded
  versions; the cached package for every installed version stays, as do the
  `APKINDEX` files. Container check: 224.4 MB before, 224.4 MB after, reported
  as cleaned. (`apk cache --purge` is not the answer either — it also keeps the
  installed versions.) Clearing the rest costs a re-download, so it now runs
  under `--deep`, which frees the full 224.30 MB. The dead fallback that only
  triggered when the command *failed* — which it never did — is gone.
- **openSUSE: freed size was measured on a subdirectory.** `zypper clean --all`
  clears downloaded packages *and* the `raw/` + `solv/` repository metadata, but
  the measurement only read `/var/cache/zypp/packages`. The cleanup worked; the
  report just left the metadata out — on a refreshed Tumbleweed that is ~65 MB
  of ~147 MB. It now measures `/var/cache/zypp`, verified at 63.99 MB against
  65 MB actual.
- **Solus: the same under-reporting.** `eopkg delete-cache` clears `packages/`,
  `archives/` and the db `.cache` files beside them, so measuring `packages/`
  alone missed the rest. Now measures `/var/cache/eopkg`.
- **Gentoo: `DISTDIR` is resolved instead of assumed.** `eclean distfiles` reads
  the live portage config, so a system that overrides `DISTDIR` in `make.conf`
  was measured at the wrong path — and the no-`eclean` fallback would have run
  `find -delete` against a hard-coded `/var/cache/distfiles` that may not be the
  real one. The path now comes from `portageq distdir`, then `make.conf`, then
  the default (with the pre-2.3.8 `/usr/portage/distfiles` honoured only if it
  actually exists). Funtoo, which defaults to `/var/cache/portage`, is covered
  by the same lookup.

### Internal
- The `make.conf` parser used for `PORTAGE_TMPDIR` is now shared with `DISTDIR`
  lookup rather than duplicated.
- New guards: each measured cache path is pinned to what its clean command
  actually clears; hostile `PORTAGE_TMPDIR` values (`/`, `//`, traversal) can
  never resolve to a deletable path; and the portage build-tmp cleanup is proven
  to clear contents while leaving the directory itself in place. The `emerge`
  guard was verified live — with a build running, the sweep refuses and the
  tree is left untouched.

## [1.7.0] - 2026-08-09

### Changed
- **The report is the output again.** Every helper we drive — pacman, the AUR
  helpers, flatpak, journalctl — printed its own several lines into the middle
  of the report. A full `--all` run was around 62 lines, of which roughly 35
  belonged to other programs, so the section results they were meant to
  summarise got buried. Their output is now captured instead of inherited: on
  success nothing is printed, and on **failure** the captured stderr is replayed
  under the error line, which is strictly more visible than before — an error
  used to scroll past inside a screenful of unrelated success chatter. The same
  run is now about 33 lines.

  Three kinds of command deliberately still print: package *removal*
  (`pacman -Rns`, `apt-get autoremove`, `emerge --depclean`, …), which is slow
  enough that silence would read as a hang; Nix garbage collection, for the same
  reason; and `fstrim --verbose`, whose output *is* the result.
- **Journal skips work it cannot do.** `--vacuum-size` bounds the archived
  journals and `--disk-usage` reports archived + active, so a total already under
  the limit proves there is nothing to vacuum. That case now says so in one line
  instead of spawning a privileged subprocess and printing three
  `freed 0B of archived journals from …` lines. The usage figure is parsed out of
  journalctl's sentence rather than echoed whole; systemd translates that
  sentence, so an unrecognised locale falls back to vacuuming unconditionally —
  the old behaviour — rather than guessing.
- **Flatpak reports what changed.** It counted on flatpak's English
  "Nothing unused to uninstall" text; it now counts installed refs before and
  after, which works in any locale and yields a better line
  (`No unused runtimes` / `Removed 3 unused runtime(s)`).
- **AUR helper caches are attributed to the AUR section.** `--all` runs
  `--cache` first, and `~/.cache/paru` is under `~/.cache`, so the helper's cache
  was deleted there and counted as user cache — leaving the AUR section to
  measure an already-empty directory and always report `already clean`, on every
  machine, no matter how large the cache was. A helper with its own clean command
  is now left to the AUR section when that section is going to run; when it is
  not (`--cache` alone, or `--all --skip aur`) it is cleaned in place as before,
  so deferring never means nobody cleans it.

  A helper that we prune by hand instead (aura) is held back **unconditionally**,
  because its cache directory also holds state — see below.

### Added
- **`--verbose` / `-v`.** Restores the raw helper output that is now captured by
  default — the escape hatch for debugging a package manager that is
  misbehaving. Ignored with `--json`, which must own stdout.

### Fixed
- **Every installed AUR helper is cleaned, not just one.** Helper detection took
  the first match from a hard-coded list, so the *array order* silently decided
  the winner: with both paru and yay installed, paru won for no reason beyond
  being written first, and yay's cache was never touched on any machine. Having
  two helpers installed and using one is common, and the unused one keeps
  accumulating clone and build caches. All of them are cleaned now, one result
  line each, so a helper that stops working is visible next to one that works.
- **trizen no longer wipes the whole pacman cache on a normal run.** Its `-Sc`
  cleans trizen's cache *and* pacman's, via `pacman -Scc` — which removes every
  cached package including currently-installed ones. That is the aggressive
  behaviour `--deep` exists to gate, and it was also redundant with the
  `pacman -Sc` run moments earlier. It now uses `-Sca`, which scopes the clean to
  trizen's own AUR cache.
- **aura's cache is actually cleaned, and its restore points are protected.**
  The previous `-Sc` was passed straight through to pacman (aura is a pacman
  superset), so it re-cleaned the pacman cache and never touched aura's own. Its
  `-C` family is the *downgrade* namespace and its `-Cc` takes a mandatory
  version count while still operating on the pacman cache, so no aura command
  does this job — the directories are pruned directly instead: `builds/` on a
  normal run, `cache/` (built tarballs) and `packages/` (AUR git clones) behind
  `--deep`, since those cost a rebuild or a re-clone.

  Two siblings are never touched, in any mode: `snapshots/` holds the package
  restore points `aura -B` restores from, and `hashes/` is the bookkeeping that
  records when each AUR package was last built. Both are state, not cache. Since
  `~/.cache/aura` mixes cache and state like this, the whole directory is also
  held back from the blanket `--cache` sweep even when the AUR section is not
  running — `--cache` alone now says `⊘ AUR helper cache skipped — clean it with
  --aur` rather than quietly cleaning less than you asked. Cleaning less is the
  right trade against deleting someone's restore points.
- **`--aur` acquires privileges up front.** It was missing from the set of
  operations that request root at startup, even though an AUR helper's `-Sc`
  clears the shared pacman cache and invokes `sudo` itself, and the partial-
  download sweep needs root too. The password prompt therefore arrived partway
  through the run instead of at the beginning.
- **`~/.cache` is no longer walked twice.** `user_cache` summed every entry's
  size and then re-measured each one inside the delete loop, so the most
  expensive step in a run — a recursive walk of the deepest tree we touch — cost
  exactly double. Noticeable on a spinning disk.
- **AUR cache paths honour `XDG_CACHE_HOME`.** The helper cache directory was
  built as `~/.cache/<helper>` by hand, so a relocated cache was measured at the
  wrong path and every run reported 0 B freed.

## [1.6.2] - 2026-07-17

### Fixed
- **Fedora/RHEL: package-cache size was measured at the wrong path on dnf5.**
  dnf5 (the default since Fedora 41) keeps its cache under `/var/cache/libdnf5`,
  but the freed-size measurement still read the legacy `/var/cache/dnf`. The
  cleanup itself worked, but the report showed `0 B` freed because it measured
  an empty directory. It now measures whichever backend is active — libdnf5,
  then dnf4, then yum — so the freed total is accurate again.

## [1.6.1] - 2026-07-12

### Changed
- **`--cache` reports spared caches more honestly.** The old line named every
  protected entry and told you to "clean with --dev" — but model weights
  (HuggingFace, torch) aren't cleaned by `--dev` either, so that hint was a
  false lead, and listing them was just noise. Now model caches are kept
  **silently**, and the `--dev` hint prints only when a dev-tool cache was
  actually spared (`⊘ Some dev-tool caches skipped — remove them with --dev`),
  and only then. The protection itself is unchanged — nothing about which
  directories are kept has changed.

## [1.6.0] - 2026-07-11

### Added
- **`--json` output.** Emits a single machine-readable JSON object instead of
  the human report — one line, no banner, no colors, no prompts — so cron jobs
  and scripts can parse the result. Includes the version, distro, dry-run/deep
  flags, per-operation freed bytes, the total, and elapsed time. Implies
  non-interactive: destructive prompts are declined unless `--yes`/`--deep` is
  also given, so it never blocks on stdin.
- **Crash-dump cleanup (`--coredumps` / `-C`, also part of `--all`).** Clears
  saved crash dumps from systemd-coredump (`/var/lib/systemd/coredump`) and
  Apport (`/var/crash`), each detected by directory existence. Dumps hold a
  copy of a crashed process's memory — often megabytes each, and a potential
  home for passwords and keys — so clearing them reclaims space and is a small
  privacy win. For Apport only the top-level report files are removed; kdump's
  `vmcore` subdirectories are left alone. Non-systemd/non-Apport inits have no
  central dump directory and are skipped cleanly.
- **`--skip <ops>` (with `--all`).** Run everything except the named operations,
  e.g. `oxiclean --all --skip packages,journal` — handy on a metered connection
  or to keep journal logs. Comma-separated; only the `--all` operations are
  valid names. Using `--skip` without `--all`, or with an unknown name, is a
  clear error rather than a silent no-op.

### Changed
- **Gentoo also clears `$PORTAGE_TMPDIR/portage`.** Interrupted or failed
  `emerge` runs leave gigabytes of half-built trees there that portage never
  reuses. Four guards make this safe: it does nothing while an `emerge` is
  running, reads `PORTAGE_TMPDIR` from `make.conf` (defaulting to `/var/tmp`),
  removes only the directory's *contents*, and refuses any path that doesn't
  resolve to a nested `…/portage`. The distfiles cleanup (`eclean`) is
  unchanged.
- **Clear Linux uses `swupd clean`** (and `swupd clean --all` under `--deep`)
  instead of a raw `rm` of the staged directory, so swupd's own bookkeeping
  stays consistent.
- **Nix deep clean also runs `nix profile wipe-history`**, dropping flake-profile
  generations that `nix-collect-garbage -d` leaves behind so their store paths
  become collectable.
- **Alpine's orphan message is now accurate.** apk prunes unused dependencies
  automatically on `apk del`, so the step reports that there's nothing to do
  instead of the old misleading "not supported".

### Internal
- Operation resolution moved out of `main()` into a small, unit-tested `Ops`
  type. This locks down the invariant that `--all` never enables `--dev` or
  `--trim` (they stay opt-in), guarded by tests rather than an inline comment.

## [1.5.0] - 2026-07-08

### Fixed
- **`--cache` no longer destroys expensive caches.** Wiping `~/.cache` wholesale
  also deleted HuggingFace/torch model weights — multi-gigabyte downloads a user
  grabbed on purpose — plus dev-tool caches (`uv`, `pip`, `pipenv`, `pypoetry`,
  `deno`, `ccache`, `yarn`) that `--dev` already manages with the correct
  per-tool commands. `--cache`/`--all` now **skip** these (in every mode,
  including `--deep`) and say so: `⊘ Protected (clean with --dev): …`. They stay
  removable via `--dev`. Honours `XDG_CACHE_HOME`, and `HF_HOME`/`HF_HUB_CACHE`
  when the model cache is relocated inside the cache dir.
- **Self-update guards rpm installs too.** `managed_by()` now also probes
  `rpm -qf`, so a self-update refuses to overwrite an rpm-owned binary (which
  would corrupt the rpm database), matching the existing pacman/dpkg guards.
- **Clear message when no privilege tool exists.** With no root, `sudo`, or
  `doas`, system-level cleanup now explains what to install instead of failing
  with a generic "couldn't acquire privileges" after a silent `sudo` fallback.
  User-level operations (`--cache`, `--trash`, `--dev`) still run.

### Added
- **Immutable / atomic system support.**
  - **Fedora Atomic** (Silverblue, Kinoite, Bazzite): detected via
    `/run/ostree-booted`; package cleanup uses `rpm-ostree cleanup -bm` (base
    deployments + cached metadata only — never the destructive `-p`/`-r` that
    touch bootable deployments).
  - **Image-based read-only systems** (SteamOS, openSUSE MicroOS, …): detected
    by a read-only `/usr`; package-cache cleanup is skipped with a clear note,
    since those systems reclaim OS space through atomic image swaps. User-level
    cleanup still runs.
- **`--trim` / `-T` — SSD/NVMe TRIM (`fstrim`).** Filesystem maintenance, so it
  is **not** part of `--all`. Trims only fstab-listed mounts (removable/USB
  drives are skipped by construction) and is a safe no-op on HDDs.

## [1.4.2] - 2026-07-05

### Added
- **`--update` / `-u` — built-in self-update.** Checks GitHub for a newer
  release, prints the release notes, and (after you confirm, or with `-y` for
  cron) downloads the matching prebuilt binary for your CPU and libc, verifies
  it's a real ELF that reports the expected version, and swaps it in atomically
  (ETXTBSY-safe: copy to a sibling temp file, then `rename` over the target).
  - **Refuses to touch package-manager installs.** If pacman/dpkg owns the
    binary, self-updating would corrupt their database — so it prints the right
    command instead (`paru -Syu oxiclean`, `apt install --only-upgrade`, …).
  - **Networking is built in** (`ureq` + `rustls`), so no external `curl`/`wget`
    is needed. The musl build stays fully static.
  - Unsupported architectures are told to build from source.
- **ARM64 prebuilt binaries.** The release workflow now also builds
  `aarch64-linux-gnu` and `aarch64-linux-musl` (via a cross toolchain).

### Changed
- The binary is now ~2 MB (was ~1 MB) — the cost of a bundled TLS stack for
  dependency-free self-update. Release profile switched to `opt-level = "z"`
  and `panic = "abort"` to claw back what it can.
- Release notes are no longer auto-generated from PRs by the workflow (they were
  consistently wrong); they're written per release instead.

## [1.4.1] - 2026-07-02

### Added
- `install.sh` — a prebuilt-binary installer you can pipe from curl. It detects
  your CPU arch and libc (glibc vs musl, via the musl loader file with an `ldd`
  fallback), downloads the latest release to a temp dir, verifies it's a real
  ELF binary and runs `--version` before touching anything, then installs to
  `/usr/local/bin` — asking for sudo/doas only for that final step, not for the
  whole script. Override detection with `OXICLEAN_LIBC=musl|gnu`.

### Fixed
- `--help` no longer prints the EXAMPLES block as one collapsed line. The long
  help is now an explicit string with real line breaks, so each example sits on
  its own line. (`-h` stays a concise summary.)

### Docs
- README: new curl-based install method, fixed the misaligned "All flags"
  block, and refreshed the `--help` line text.

## [1.4.0] - 2026-06-28

### Added
- **Three more dev-tool caches** in `--dev`, all command-based and safe:
  - **conda**: `conda clean --all --yes` (removes tarballs, index cache, and
    unused packages — never touches your `envs/`).
  - **ccache**: `ccache -C` clears the C/C++ compiler cache. Especially handy
    on Arch, where `makepkg` uses it and it can grow to several GB.
  - **NuGet / .NET**: `dotnet nuget locals all --clear` clears the global
    package cache (`~/.nuget/packages`), restored on next restore/build.
- **Distinct short vs long help.** `-h` prints a concise flag summary;
  `--help` now prints the full description with usage examples. (Previously
  both printed the same short text.)

### Tests
- Path-shape / safety guards for the three new tools: conda never targets
  `envs/`, ccache resolves to a ccache dir, NuGet targets `.nuget/packages`.

## [1.3.1] - 2026-06-14

### Fixed
- **Pacman partial-download leftovers were never actually removed.** The
  v1.3.0 sweep filtered on `find -type f`, but modern pacman (6.1+, which
  downloads in a sandbox as the `alpm` user — the default on Arch/CachyOS)
  leaves leftovers as **directories** (`download-XXXXXX`, mode `0700`, owned
  by `alpm`), not files. The filter skipped them, so `pacman -Sc` / `paru -Sc`
  kept printing `error: could not open file ... Error reading fd 7`. The sweep
  now matches both files and directories and removes them with `sudo rm -rf`,
  guarded by a `.pkg.tar` check so a real cached package is never touched.
- The sweep now also runs before the AUR helper's `-Sc` (paru/yay clean the
  same shared pacman cache), so the AUR Cache section no longer prints the
  leftover error either.

## [1.3.0] - 2026-06-09

### Added
- `--quiet` / `-q` to suppress banner text, info lines, and skip lines while keeping the important action results visible.
- `--generate-completion <SHELL>` to print shell completion scripts for bash, zsh, fish, elvish, and powershell.
- CLI regression tests for quiet mode and shell-completion output.

### Changed
- Shorter section titles in the output (`User Cache`, `Package Cache`, `AUR Cache`, `Flatpak`, `Journal`).
- Less noisy cleanup output: removed a bunch of "Cleaning ..." info lines so normal runs read more naturally.
- Pinned `clap_complete` to `4.5.20` for compatibility with the Rust/Cargo toolchain used in CI and minimal environments.

### Fixed
- Arch cleanup now quietly removes leftover `/var/cache/pacman/pkg/download-*` partial downloads before `pacman -Sc`, avoiding the noisy `Error reading fd 7` pacman messages seen after interrupted downloads.

## [1.2.0] - 2026-05-24

### Added
- **`--dev` / `-D` flag**: clean caches of every dev tool we can find,
  with safety baked in. Detected automatically:
  - **Node**: npm (`~/.npm/_cacache`), yarn classic (`~/.cache/yarn`),
    yarn berry (`~/.yarn/berry/cache`), bun (`~/.bun/install/cache`),
    **pnpm** (via `pnpm store prune` — see below), deno (`deno clean`).
  - **Python**: pip (`pip cache purge`), uv (`uv cache clean`), pipenv,
    poetry (cache only — virtualenvs preserved).
  - **Rust**: `~/.cargo/registry/src`, `~/.cargo/git/checkouts` (safe —
    re-extract only). With `--deep`, also `~/.cargo/registry/cache` and
    `~/.cargo/git/db` (will trigger re-download).
  - **Go**: `go clean -modcache` (Go marks module files read-only, so a
    plain `rm -rf` fails; we use the official command). `--deep` only —
    re-downloads.
  - **Ruby**: `gem cleanup` (removes old versions only).
  - **PHP**: `composer clear-cache`.
  - **JVM**: Gradle (`~/.gradle/caches` only, never `wrapper/`),
    Maven (`~/.m2/repository`, deep only).
- Pre-cleanup **scan summary** prints every detected cache with size and
  a safety marker, plus a total and a "will clean now" line. `--deep`
  unlocks the re-download caches; without it they’re listed but skipped.

### Safety — things this release explicitly does NOT do
- **pnpm**: the store is hard-linked into every `node_modules` on disk;
  deleting it manually silently breaks active projects. We call
  `pnpm store prune` instead.
- **Cargo**: `~/.cargo/bin` is **never** touched — it holds
  user-installed binaries (cargo-watch, rustfmt, etc.). Our cleanup
  targets sibling subdirectories only.
- **Poetry**: `~/.cache/pypoetry/virtualenvs` is preserved — only the
  `cache/` subdir is wiped.
- **Gradle**: `~/.gradle/wrapper` (which holds downloaded Gradle
  distributions) is preserved — only `caches/` is wiped.
- **npm**: `~/.npm/lib/node_modules` (global packages) is preserved —
  only `_cacache/` is wiped.
- `--all` does **not** enable `--dev`. Dev caches have very different
  trade-offs (rebuild times, re-downloads) so the user must opt in.

### Tests (10+ new)
- `scan_simple` returns `None` for missing directories and 0-byte
  directories, and reports correct size for non-empty ones.
- `scan_redownload` sets the `needs_redownload` flag.
- `cleanable_size`: with `deep=false`, redownload caches are excluded;
  with `deep=true`, everything is included.
- `clean_dir_contents_except`: regression guard — keeps named children
  and removes the rest, with byte-accurate freed accounting.
- Path-shape assertions for cargo (`bin/` never targeted), poetry
  (`virtualenvs/` never targeted), gradle (`wrapper/` never targeted),
  and npm (`node_modules` never targeted). These tests are cheap
  but catch the most damaging refactor mistakes.

## [1.1.0] - 2026-05-13

### Added
- **`doas` support**: a new `Privilege` enum (`Doas` / `Sudo` / `Root`)
  picked automatically at startup. On systems where `doas` is the default
  (Alpine 3.15+, many Void setups) we no longer fail because `sudo` is
  missing. The header now shows which helper is in use:
  `🔐 Requesting privileges (doas)…`
- **Disk type detection** (`DiskType` enum: `NVMe` / `SSD` / `HDD` /
  `Unknown`). We resolve the device that backs `/home` (falling back to
  `/`) via `/proc/mounts`, walk to the parent block device, and read
  `/sys/block/<name>/queue/rotational`. NVMe is detected from the device
  name to dodge the well-known “rotational=1” kernel quirk on some NVMe
  controllers.
- **HDD warning** printed in the startup header when a spinning disk is
  detected. SSD/NVMe stay quiet — the goal is information, not noise.
- **Nix garbage collection on any distro**: `nix_gc()` runs as a separate
  cleanup step whenever `/nix/store` exists, even on Arch / Fedora /
  Debian. Multi-user installs (`/nix/var/nix/daemon-socket/socket`) get
  both a user-level and a `sudo nix-collect-garbage`. On NixOS the
  existing `pkg_cache` path keeps handling Nix so we don’t double-run.
- **`SystemInfo` struct** consolidates all detection into a single
  `SystemInfo::detect()` call. `main()` no longer juggles six separate
  detection variables.

### Changed
- New public API in `utils`: `elevate(privilege, cmd, args)` and
  `acquire_privilege(privilege)`. `utils::sudo()` is now a thin backwards
  -compatible wrapper that delegates to `elevate()` using the privilege
  helper recorded once at startup via `utils::set_privilege()`. No call
  sites in `clean.rs` needed to change — they automatically benefit
  from doas support.
- On HDDs, `nix store --optimise` is **skipped** during deep clean (it can
  take hours on spinning storage). A hint tells the user how to run it
  manually.
- `should_deep()` is now `pub(crate)` so its destructive decision logic
  can be unit-tested. Behaviour unchanged.

### Tests (15+ new)
- `Privilege::name()` and equality; `find_privilege()` smoke test.
- `disk_type_from_rotational()`: SSD (`"0"`), HDD (`"1"`), newline
  trimming, NVMe-by-name overriding rotational, garbage/empty input.
- `extract_block_name()`: SATA partitions, NVMe partitions (`nvme0n1p2`),
  eMMC/SD (`mmcblk0p1`), empty input.
- `find_mount_device_in()`: parses `/proc/mounts`-format text purely;
  resolves `/` and `/home`; returns `None` for missing mount points.
- `elevate(Privilege::Root, …)` runs the command directly and propagates
  both success and failure exit codes.
- `should_deep()`: `deep=true` always wins (with and without `yes`);
  `yes=true && deep=false` returns `false` without prompting (a hang
  here would itself be the failure signal).

## [1.0.5] - 2026-05-13

### Fixed
- `which()` no longer spawns a `which` subprocess on every check — walks `$PATH`
  directly via `env::split_paths`. Faster, more reliable, and works on systems
  where the `which` binary itself is not installed (e.g. minimal Alpine).
- Corrected `authors` field in `Cargo.toml` (was placeholder `"You"`).

### Changed
- Refactored `detect::distro()` to delegate parsing to a pure
  `distro_from_str(content: &str)` function. Detection logic is now testable
  in isolation without requiring a real `/etc/os-release`.

### Tests
- Removed 4 trivial tests that only exercised `derive(PartialEq/Clone)` or
  hard-coded string literals (`test_distro_equality`, `test_distro_clone`,
  `test_distro_names`, `test_pkg_managers`).
- Added 6 real detection tests: direct Arch ID, CachyOS via ID, derivative
  resolution via `ID_LIKE`, openSUSE variants matched by `starts_with`,
  unknown distros, and empty `/etc/os-release`.
- Added `format_size` boundary tests at the KB/MB and MB/GB cutoffs
  (1 048 575 stays KB, 1 048 576 flips to MB; same for MB/GB).
- Added integration tests that assert on actual stdout (`[DRY RUN]` marker,
  `--all` hint when no flags) instead of only the exit code.

## [1.0.4] - 2026-05-11

### Fixed
- Improved Unicode handling and text display

## [1.0.3] - 2026-03-28

### Fixed
- Accurate freed space reporting for package cache, AUR cache, and journal
- Resolved all clippy warnings (collapsible_if, manual_find)
- Removed build artifacts from repository

### Changed
- Package cache measures `/var/cache/pacman/pkg` (or equivalent) before/after cleanup
- AUR cache measures `~/.cache/{helper}` before/after cleanup
- Journal measures `/var/log/journal` before/after vacuum
- `aur_helper()` uses idiomatic iterator pattern

## [1.0.2] - 2026-03-28

### Fixed
- Include Cargo.lock for reproducible builds
- Fix release workflow

## [1.0.1] - 2026-03-27

### Added
- Unit tests (20 tests for utils.rs and detect.rs)
- Integration tests (9 CLI tests)
- GitHub Actions CI workflow (test, clippy, fmt on every push)
- GitHub Actions Release workflow (auto-build binaries on tag)
- CHANGELOG.md
- Issue templates (bug report, feature request)

## [1.0.0] - 2026-03-26

### Added
- Initial release
- Cross-distribution support (50+ distros)
- User cache cleanup (~/.cache)
- Package manager cache cleanup (basic + deep modes)
- Orphaned packages detection and removal
- AUR helper support (paru, yay, trizen, pikaur, aura)
- Flatpak cleanup with repair in deep mode
- Snap disabled revisions removal and cache cleanup
- Systemd journal vacuum (50MB limit)
- Trash cleanup (XDG standard)
- Dry-run mode for safe preview
- Interactive confirmation prompts
- Colored terminal output
- Sudo privilege management
