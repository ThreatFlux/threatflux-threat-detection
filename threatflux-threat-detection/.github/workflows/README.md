# GitHub Actions Workflows

This directory contains GitHub Actions workflows for the ThreatFlux Threat Detection library.

## Workflows Overview

### 🧪 CI Pipeline (`ci.yml`)

**Triggers:** Push to main/develop, Pull Requests, Scheduled (nightly)

**Purpose:** Main continuous integration pipeline ensuring code quality and functionality.

**Features:**
- **Multi-platform testing:** Ubuntu, Windows, macOS
- **Multi-rust version:** stable, beta, nightly
- **Comprehensive testing:** All features, no features, feature combinations
- **Code quality:** rustfmt, clippy with strict linting
- **Coverage reporting:** Code coverage with Codecov integration
- **Performance benchmarks:** Automated benchmark running
- **Security auditing:** cargo-audit integration
- **MSRV checking:** Minimum Supported Rust Version validation
- **Integration testing:** Real malware sample testing (EICAR)

**Key Steps:**
1. Install YARA dependencies on all platforms
2. Format and lint checking
3. Build with different feature combinations
4. Run comprehensive test suite
5. Generate coverage reports
6. Run security audits

### 🚀 Release Pipeline (`release.yml`)

**Triggers:** Git tags (v*.*.*), Manual workflow dispatch

**Purpose:** Automated release process with semantic versioning and multi-platform builds.

**Features:**
- **Version validation:** Ensures tag matches Cargo.toml version
- **Multi-platform builds:** Linux, Windows, macOS artifacts
- **Automated testing:** Full test suite before release
- **Crates.io publishing:** Automatic crate publishing
- **GitHub releases:** Automated release creation with artifacts
- **Documentation deployment:** Updates GitHub Pages
- **Changelog generation:** Automatic release notes

**Release Process:**
1. Validate version format and consistency
2. Build release artifacts for all platforms
3. Run full test suite
4. Publish to crates.io
5. Create GitHub release with artifacts
6. Deploy documentation

### 🔒 Security Pipeline (`security.yml`)

**Triggers:** Push to main/develop, Pull Requests, Scheduled (daily), Manual

**Purpose:** Comprehensive security scanning and vulnerability assessment.

**Features:**
- **Dependency auditing:** cargo-audit for known vulnerabilities
- **Security linting:** Clippy with security-focused rules
- **Supply chain analysis:** Publisher and dependency tracking
- **Static analysis:** Semgrep for pattern-based security issues
- **CodeQL analysis:** GitHub's advanced semantic analysis
- **OSV scanning:** Open Source Vulnerability database scanning
- **Dependency checking:** cargo-deny for license and security compliance

**Security Tools:**
- `cargo-audit`: Known vulnerability detection
- `cargo-deny`: License and dependency policy enforcement
- `semgrep`: Static analysis security patterns
- `codeql`: Advanced code analysis
- `osv-scanner`: Comprehensive vulnerability scanning
- `cargo-supply-chain`: Publisher and supply chain analysis

### 📚 Documentation Pipeline (`docs.yml`)

**Triggers:** Push to main/develop (src changes), Pull Requests, Manual

**Purpose:** Documentation building, validation, and deployment.

**Features:**
- **Documentation building:** cargo-doc with all features
- **Link validation:** Broken link detection
- **Spell checking:** Documentation spell checking
- **Doc coverage:** Documentation coverage reporting
- **GitHub Pages deployment:** Automatic documentation deployment
- **Enhanced styling:** Custom CSS and improved navigation
- **Sitemap generation:** SEO-friendly documentation structure

**Documentation Quality:**
- Validates all documentation builds successfully
- Checks for broken internal and external links
- Runs spell check on source code and documentation
- Generates coverage reports for undocumented items
- Creates enhanced documentation site with custom styling

## Workflow Dependencies

### Required Secrets

#### Release Workflow
- `CRATES_IO_TOKEN`: For publishing to crates.io
- `CODECOV_TOKEN`: For coverage reporting

#### Security Workflow
- GitHub token permissions for CodeQL analysis

### Required Permissions

#### Documentation Deployment
- `contents: read`
- `pages: write` 
- `id-token: write`

#### Release Creation
- `contents: write`

### System Dependencies

All workflows install YARA as a system dependency:

**Ubuntu/Linux:**
```bash
sudo apt-get update
sudo apt-get install -y libyara-dev yara
```

**macOS:**
```bash
brew install yara
```

**Windows:**
```cmd
vcpkg install yara:x64-windows
```

## Workflow Configuration

### Matrix Strategy

The CI workflow uses a matrix strategy for comprehensive testing:

```yaml
matrix:
  os: [ubuntu-latest, windows-latest, macos-latest]
  rust: [stable, beta, nightly]
  exclude:
    # Reduce matrix size for performance
    - os: windows-latest
      rust: beta
    - os: macos-latest
      rust: beta
```

### Caching Strategy

All workflows use Rust caching for improved performance:

```yaml
- name: Setup Rust cache
  uses: Swatinem/rust-cache@v2
  with:
    key: ${{ matrix.os }}-${{ matrix.rust }}
```

### Feature Testing

Comprehensive feature combination testing:

```yaml
# Test different feature combinations
- cargo test --verbose --features "yara-engine"
- cargo test --verbose --features "pattern-matching" 
- cargo test --verbose --features "async-scanning"
- cargo test --verbose --features "serde-support"
```

## Security Considerations

### Safe Malware Testing

The integration tests use the standard EICAR test file:
- Non-malicious test file recognized by all antivirus engines
- Safe for testing antivirus and security software
- Automatically cleaned up after tests

### Dependency Security

- **cargo-audit**: Scans for known vulnerabilities
- **cargo-deny**: Enforces security and license policies
- **Dependabot**: Automated dependency updates
- **OSV scanning**: Comprehensive vulnerability database

### Supply Chain Security

- **Publisher analysis**: Tracks dependency publishers
- **Supply chain monitoring**: Identifies high-risk dependencies
- **License compliance**: Ensures compatible licensing

## Performance Monitoring

### Benchmarking

Performance benchmarks run on main branch pushes:
- Criterion-based benchmarking (when implemented)
- Historical performance tracking
- Regression detection

### Coverage Tracking

Code coverage integration with Codecov:
- Line coverage reporting
- Branch coverage analysis
- Coverage trend tracking
- PR coverage comparison

## Badge Integration

The workflows generate status badges for the README:

```markdown
![CI](https://github.com/ThreatFlux/threatflux-threat-detection/workflows/CI/badge.svg)
![Security](https://github.com/ThreatFlux/threatflux-threat-detection/workflows/Security/badge.svg)
![Documentation](https://github.com/ThreatFlux/threatflux-threat-detection/workflows/Documentation/badge.svg)
[![Crates.io](https://img.shields.io/crates/v/threatflux-threat-detection.svg)](https://crates.io/crates/threatflux-threat-detection)
[![Docs.rs](https://img.shields.io/docsrs/threatflux-threat-detection.svg)](https://docs.rs/threatflux-threat-detection)
[![Coverage](https://img.shields.io/codecov/c/github/ThreatFlux/threatflux-threat-detection)](https://codecov.io/gh/ThreatFlux/threatflux-threat-detection)
```

## Troubleshooting

### Common Issues

#### YARA Installation Failures
- Ensure system package managers are up to date
- Check for conflicting YARA installations
- Verify platform-specific installation commands

#### Permission Errors
- Ensure required GitHub permissions are set
- Check secret availability in repository settings
- Verify token scopes match requirements

#### Dependency Conflicts
- Review cargo-deny configuration in `deny.toml`
- Check for version compatibility issues
- Update dependency constraints if needed

### Debug Commands

For local testing of workflow components:

```bash
# Install dependencies locally
sudo apt-get install -y libyara-dev yara  # Ubuntu
brew install yara                          # macOS

# Run security checks locally
cargo audit
cargo clippy --all-features --all-targets -- -W clippy::suspicious

# Test documentation build
cargo doc --all-features --no-deps --document-private-items

# Run with specific features
cargo test --features "yara-engine,async-scanning"
```

## Maintenance

### Regular Updates

1. **Update GitHub Actions versions** in workflow files
2. **Review and update cargo-deny configuration** 
3. **Update Rust version matrix** as new versions are released
4. **Review security scanning tools** for updates
5. **Monitor workflow performance** and optimize as needed

### Monitoring

- **Workflow run times**: Monitor for performance regressions
- **Failure rates**: Track and address recurring failures  
- **Security scan results**: Review and act on security findings
- **Dependency updates**: Monitor Dependabot PRs and updates