# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Refreshed every dependency requirement to the latest stable release. This
  includes the cross-version upgrades `thiserror` 1.0 to 2.0, `reqwest` 0.12 to
  0.13, `rand` 0.8 to 0.10, `env_logger` 0.10 to 0.11, `serial_test` 3.5 to
  4.0, and `criterion` 0.5 to 0.8. No source change was required.
- Pinned the development toolchain to Rust 1.97.1 with `rust-toolchain.toml`.

### Added

- `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, and `CODE_OF_CONDUCT.md`,
  matching the documentation set used across ThreatFlux crates.

### Fixed

- Replaced the README, which documented ThreatFlux Cache rather than this
  crate, with accurate detection-engine, configuration, and result
  documentation, including the behavior `scan_directory`, `max_file_size`,
  `max_concurrent_scans`, and `ScanStatistics` do not yet implement.
- Restored `readme = "README.md"` in the package manifest so crates.io and
  docs.rs render it.
- Removed a copy of the ThreatFlux Cache source tree (`src-wrong-cache/`,
  `Cargo.toml.wrong-cache-version`) and a stale `CI_STATUS_CHECK.md`, all left
  behind when this repository was split out of the cache project.

## [0.2.0] - 2026-08-11

### Added

- Initial published release of the threat detection library with pattern
  matching, built-in rules, and optional YARA, ClamAV, rule-update, and metrics
  support.
