# Changelog

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
