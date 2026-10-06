# ThreatFlux Threat Detection

[![CI](https://github.com/ThreatFlux/threatflux-threat-detection/actions/workflows/ci.yml/badge.svg)](https://github.com/ThreatFlux/threatflux-threat-detection/actions/workflows/ci.yml)
[![Security](https://github.com/ThreatFlux/threatflux-threat-detection/actions/workflows/security.yml/badge.svg)](https://github.com/ThreatFlux/threatflux-threat-detection/actions/workflows/security.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.95.0-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An async Rust library that runs a file or byte buffer through one or more
detection engines and returns a single combined verdict: matches, a threat
level, classifications, indicators, and recommendations.

The result is evidence for a security review. It is not a malware verdict, a
sandbox, or a guarantee of coverage. A clean result only means the enabled
engines and rules found nothing.

## Detection engines

| Engine           | Cargo feature      | Default | Requirements                                            |
| ---------------- | ------------------ | :-----: | ------------------------------------------------------- |
| Pattern matching | `pattern-matching` |   yes   | None; uses `aho-corasick` and `regex`                   |
| Built-in rules   | `builtin-rules`    |   yes   | None; ships a small offline rule set                    |
| YARA             | `yara-engine`      |   no    | `yara-x`                                                |
| ClamAV           | `clamav-engine`    |   no    | A reachable `clamd` instance                            |
| Rule updates     | `rule-management`  |   no    | Network access; uses `git2` and `reqwest`               |
| Metrics          | `metrics`          |   no    | `prometheus`                                            |
| Serialization    | `serde-support`    |   yes   | Serde derives on the public result types                |

`ThreatDetectorConfig` enables engines at runtime, but a runtime flag cannot
enable an engine that was not compiled in. `enable_yara` defaults to `true` and
is ignored unless the `yara-engine` feature is on.

## Install

```toml
[dependencies]
threatflux-threat-detection = "0.2"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

0.2.2 is the first release on crates.io. The `v0.2.0` and `v0.2.1` tags were
cut before the release workflow could publish, so no crate exists for them.

The minimum supported Rust version is 1.95.0.

## Quick start

```rust,no_run
use threatflux_threat_detection::ThreatDetector;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let detector = ThreatDetector::new().await?;
    let analysis = detector.scan_data(b"sample bytes", Some("sample.bin")).await?;

    println!("threat level: {}", analysis.threat_level);
    println!("matches: {}", analysis.matches.len());
    for classification in &analysis.classifications {
        println!("classification: {classification:?}");
    }

    Ok(())
}
```

## Scanning targets

`scan_file` reads a path, `scan_data` takes bytes you already hold, and
`scan_with_rule` runs one custom YARA rule against a target.

```rust,no_run
use threatflux_threat_detection::ThreatDetector;
use std::path::Path;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let detector = ThreatDetector::new().await?;
    let analysis = detector.scan_file(Path::new("./sample.bin")).await?;

    println!("{} matches", analysis.matches.len());
    Ok(())
}
```

Walk directories yourself and call `scan_file` per entry. `scan_directory` is
present but unfinished: no engine accepts a directory target, so it reports a
single empty analysis rather than scanning the tree.

## Configuration

```rust,no_run
use threatflux_threat_detection::{ThreatDetector, ThreatDetectorConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: true,
        max_file_size: 32 * 1024 * 1024,
        scan_timeout: 60,
        max_concurrent_scans: 8,
        rule_sources: Vec::new(),
    };

    let detector = ThreatDetector::with_config(config).await?;
    println!("{} engines active", detector.engine_count());
    Ok(())
}
```

Defaults: YARA and pattern matching enabled, ClamAV disabled, a 100 MiB file
limit, a 300 second timeout, and 4 concurrent scans.

## Result model

`scan_file`, `scan_data`, `scan_directory`, and `scan_with_rule` all return a
`ThreatAnalysis`:

- `matches`: per-engine rule matches.
- `threat_level`: `None`, `Clean`, `Suspicious`, `Malicious`, or `Critical`.
- `classifications`: threat categories derived from the matches.
- `indicators`: individual indicators with a type and severity.
- `scan_stats`: counts and timing for the scan.
- `recommendations`: suggested follow-up actions.

## Limitations

- `scan_directory` does not walk a directory yet, as described above.
- `max_file_size` and `max_concurrent_scans` are carried in `ScanConfig` but no
  engine enforces them today. `scan_timeout` is applied by the ClamAV engine
  only.
- `ScanStatistics::rules_evaluated` and `patterns_matched` are always zero;
  engines do not report them yet.
- An engine failure is logged and skipped rather than failing the scan, so a
  clean result can mean an engine never ran.
- The built-in rule set is a small offline baseline, not a maintained feed. Use
  `rule-management` to pull external rules.
- ClamAV support requires a reachable `clamd`; the library does not start one.
- Pattern and rule matches are heuristics and produce both false positives and
  false negatives.

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for the local toolchain setup and
[CONTRIBUTING.md](CONTRIBUTING.md) for the contribution workflow. Report
vulnerabilities privately as described in [SECURITY.md](SECURITY.md);
participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.
