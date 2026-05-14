# Changelog

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
