# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.3] - 2026-10-06

### Changed

- Releases are cut by the ThreatFlux automation GitHub App, and `release.yml`
  publishes only through crates.io trusted publishing; the long-lived registry
  token fallback is gone. Each release now also builds and tests on Linux
  arm64 and macOS x86_64, attaches a CycloneDX SBOM and `SHA256SUMS`, skips a
  version that is already on crates.io, and can be rehearsed with `dry_run`.
- Every workflow runs with least-privilege permissions, and every action is
  pinned to a full commit SHA.
- Dependabot now proposes Cargo and GitHub Actions updates, replacing the
  scheduled dependency-update workflow.
- Raised the minimum versions of `yara-x` (1.21), `clamav-client` (2.3),
  `uuid` (1.27), `reqwest` (0.13.5), `tokio` (1.53.2), `thiserror` (2.0.21),
  and `log` (0.4.34), and of the development dependencies `rstest` (0.27),
  `test-case` (3.4), `tokio-test` (0.4.6), `futures` (0.3.34), and `rand`
  (0.10.3).

### Security

- `cargo audit` and `cargo deny` ignore RUSTSEC-2026-0269, RUSTSEC-2026-0316,
  and RUSTSEC-2026-0327. They affect `wasmtime` 45, which is reached only
  through `yara-x` 1.21 behind the optional `yara-engine` feature, and no
  patched 45.x release exists. `yara-x` enables neither `wasmtime-wasi` nor the
  `component-model` feature, so the affected code is not compiled in. The
  ignores will be removed once `yara-x` moves to a patched `wasmtime`.

## [0.2.2] - 2026-08-11

### Fixed

- No release had ever reached crates.io. Every `Release` run since `v0.1.0`
  failed in its first job, because it installed Rust 1.95.0 without the
  `rustfmt` and `clippy` components and then ran `cargo fmt`. Replaced the
  workflow with the SHA-pinned template used across the fleet, which verifies
  tag provenance, tests the release build on Linux, macOS, and Windows,
  packages the crate, and publishes through crates.io trusted publishing, with
  the org token as a fallback that 0.2.3 removed. The `v0.2.0` and `v0.2.1`
  tags stay unpublished; 0.2.2 is the first crate on crates.io.
- The README install snippet named an unpublished version.

## [0.2.1] - 2026-08-11

This version was tagged but never published to crates.io.

### Added

- `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, and `CODE_OF_CONDUCT.md`,
  matching the documentation set used across ThreatFlux crates.

### Changed

- Refreshed every dependency requirement to the latest stable release. This
  includes the cross-version upgrades `thiserror` 1.0 to 2.0, `reqwest` 0.12 to
  0.13, `rand` 0.8 to 0.10, `env_logger` 0.10 to 0.11, `serial_test` 3.5 to
  4.0, and `criterion` 0.5 to 0.8. No source change was required.
- Pinned the development toolchain to Rust 1.97.1 with `rust-toolchain.toml`.

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

## [0.2.0] - 2026-08-10

This version was tagged but never published to crates.io.

### Added

- Initial release of the threat detection library with pattern matching,
  built-in rules, and optional YARA, ClamAV, rule-update, and metrics support.

[Unreleased]: https://github.com/ThreatFlux/threatflux-threat-detection/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/ThreatFlux/threatflux-threat-detection/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/ThreatFlux/threatflux-threat-detection/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/ThreatFlux/threatflux-threat-detection/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/ThreatFlux/threatflux-threat-detection/releases/tag/v0.2.0
