# Changelog

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
