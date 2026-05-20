# Changelog

## [1.1.0] - 2026-05-19

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
