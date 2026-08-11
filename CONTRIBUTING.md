# Contributing

Thank you for improving ThreatFlux Threat Detection. Bug reports, documentation fixes,
tests, and focused implementation changes are welcome.

By participating, you agree to follow the
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Report security issues privately as
described in [`SECURITY.md`](SECURITY.md).

## Before opening an issue

- Search existing issues and pull requests.
- Confirm the behavior on the latest release or `main`.
- Reduce bugs to a small reproducible example when possible.
- Include the Rust version, crate version, enabled features, detection engine,
  and platform.

Do not attach live malware, customer samples, or private rule content to a
public report. Describe the trigger instead, or request a private channel.

## Development workflow

1. Fork the repository and create a branch from `main`.
2. Make one focused change with tests and documentation.
3. Run the checks described in [`DEVELOPMENT.md`](DEVELOPMENT.md).
4. Review the diff for generated files, credentials, and unrelated edits.
5. Open a pull request explaining the problem, approach, compatibility impact,
   and validation performed.

Use clear commit messages written in the imperative mood. Commit subjects follow
[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/), because
release automation derives the next version from them: `fix:` produces a patch,
`feat:` a minor, and a `!` suffix or `BREAKING CHANGE:` trailer a major release.

## Local checks

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo test --no-default-features
```

The `yara-engine` and `clamav-engine` features need system components, so CI
exercises the default feature set plus `pattern-matching`, `builtin-rules`, and
`serde-support`.

## Pull-request checklist

- [ ] Public behavior and compatibility impact are documented.
- [ ] Tests cover new behavior and regressions.
- [ ] Default, no-default, and all-feature configurations pass.
- [ ] Detection behavior changes are called out, including any change to threat
      levels or classifications for existing inputs.
- [ ] Formatting, Clippy, test, and dependency-policy checks pass.
- [ ] No generated build output, live malware, or sensitive sample data is
      included.

## Release process

Releases are automated. Merging to `main` runs the ThreatFlux auto-release
workflow, which derives the version from the conventional commits since the last
tag, updates `Cargo.toml`, and publishes the tag and GitHub Release. Do not bump
the version by hand in a pull request.
