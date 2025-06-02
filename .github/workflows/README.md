# GitHub Workflows Documentation

This directory contains automated workflows for building, testing, and releasing the File Scanner project.

## Workflows Overview

### 1. Release Workflow (`release.yml`)

**Trigger**: 
- Git tags matching `v*` (e.g., `v1.0.0`, `v2.1.3`)
- Manual dispatch with tag input

**What it does**:
- ✅ Creates a GitHub release with comprehensive release notes
- 🏗️ Builds cross-platform binaries for 5 targets
- 🐳 Builds and pushes multi-architecture Docker images
- 🧪 Tests all release assets automatically
- 🔒 Performs security scanning with Trivy

**Supported Platforms**:
| Platform | Architecture | Asset Name |
|----------|-------------|------------|
| Linux | x86_64 | `file-scanner-linux-amd64` |
| Linux | ARM64 | `file-scanner-linux-arm64` |
| macOS | Intel | `file-scanner-macos-amd64` |
| macOS | Apple Silicon | `file-scanner-macos-arm64` |
| Windows | x86_64 | `file-scanner-windows-amd64.exe` |
| Docker | Multi-arch | `ghcr.io/owner/file-scanner:tag` |

### 2. Docker Workflow (`docker.yml`)

**Trigger**:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop`
- Changes to source code, Cargo files, or Dockerfile
- Manual dispatch

**What it does**:
- 🏗️ Builds Docker images for development
- 🧪 Tests Docker functionality
- 🔒 Performs security scanning
- 🧹 Cleans up old container images
- 📦 Pushes to GitHub Container Registry

**Image Tags**:
- `dev` - Latest main branch
- `main-<sha>` - Specific commit from main
- `develop-<sha>` - Specific commit from develop
- `pr-<number>` - Pull request builds (not pushed)

## Usage Instructions

### Creating a Release

#### Method 1: Git Tag (Recommended)
```bash
# Create and push a new tag
git tag v1.0.0
git push origin v1.0.0

# The workflow will automatically:
# 1. Create a GitHub release
# 2. Build all platform binaries
# 3. Build and push Docker images
# 4. Test all assets
# 5. Perform security scans
```

#### Method 2: Manual Dispatch
1. Go to Actions → Release → Run workflow
2. Enter the tag name (e.g., `v1.0.0`)
3. Click "Run workflow"

### Using Released Assets

#### Download Binaries
```bash
# Linux AMD64
wget https://github.com/owner/file-scanner/releases/download/v1.0.0/file-scanner-linux-amd64
chmod +x file-scanner-linux-amd64

# macOS (Intel)
wget https://github.com/owner/file-scanner/releases/download/v1.0.0/file-scanner-macos-amd64
chmod +x file-scanner-macos-amd64

# Windows
# Download file-scanner-windows-amd64.exe from releases page
```

#### Docker Images
```bash
# Production release
docker pull ghcr.io/owner/file-scanner:v1.0.0
docker pull ghcr.io/owner/file-scanner:latest

# Development builds
docker pull ghcr.io/owner/file-scanner:dev
docker pull ghcr.io/owner/file-scanner:main-abc123

# Run the scanner
docker run --rm -v /path/to/files:/data ghcr.io/owner/file-scanner:v1.0.0 /data/file.bin
```

### Development Workflow

#### Pull Request Testing
When you create a PR:
- Docker images are built but not pushed
- All tests run automatically
- Security scans are performed
- Results show in PR checks

#### Branch Development
Pushing to `main` or `develop`:
- Builds and pushes development Docker images
- Performs full testing and security scanning
- Images tagged with branch name and commit SHA

## Workflow Features

### 🚀 Performance Optimizations
- **Caching**: Cargo registry and target directories cached
- **Parallel Builds**: Matrix strategy for multiple platforms
- **Multi-stage Docker**: Optimized image layers
- **Build Cache**: Docker buildx cache for faster builds

### 🔒 Security Features
- **Vulnerability Scanning**: Trivy scans all Docker images
- **SARIF Upload**: Results integrated with GitHub Security tab
- **Pinned Actions**: All actions pinned to specific SHA for security
- **Minimal Permissions**: Each job has minimal required permissions

### 🧪 Quality Assurance
- **Binary Testing**: Each binary tested for basic functionality
- **Docker Testing**: Container functionality validated
- **Cross-compilation**: ARM64 builds tested on x86_64
- **Format Validation**: JSON/YAML output tested

### 📦 Release Automation
- **Semantic Versioning**: Automatic semver tag parsing
- **Release Notes**: Auto-generated with features and usage
- **Asset Organization**: Consistent naming and organization
- **Multi-format**: Binaries and containers in single release

## Troubleshooting

### Common Issues

#### Build Failures
```bash
# Check build logs in GitHub Actions
# Common fixes:
- Update Rust toolchain
- Check cross-compilation dependencies
- Verify Cargo.lock is committed
```

#### Docker Build Issues
```bash
# Test locally:
docker build -t test-build .
docker run --rm test-build --version

# Check for:
- Dockerfile syntax
- Build dependencies
- Multi-stage build issues
```

#### Release Asset Missing
```bash
# Check if:
- Tag format is correct (v*.*.*)
- All matrix jobs completed
- Upload permissions are correct
```

### Debugging Commands

```bash
# Test release workflow locally (with act)
act -W .github/workflows/release.yml --secret GITHUB_TOKEN=<token>

# Build specific target locally
cargo build --release --target x86_64-unknown-linux-gnu

# Test Docker build
docker buildx build --platform linux/amd64,linux/arm64 .
```

## Configuration

### Required Secrets
- `GITHUB_TOKEN` - Automatically provided by GitHub

### Required Permissions
- `contents: write` - For creating releases
- `packages: write` - For pushing to GHCR

### Environment Variables
- `CARGO_TERM_COLOR: always` - Colorized cargo output
- `RUST_BACKTRACE: 1` - Debug information on build failures

## Maintenance

### Updating Actions
All actions are pinned to specific SHAs. To update:

1. Check for newer versions on GitHub Marketplace
2. Update the SHA in workflow files
3. Test thoroughly before merging

### Adding New Platforms
To add a new build target:

1. Add to matrix in `release.yml`
2. Add any required dependencies
3. Test cross-compilation
4. Update documentation

### Customizing Release Notes
Edit the release body template in `release.yml` under the "Create Release" step.

## Security Considerations

- All third-party actions are pinned to specific commit SHAs
- Container images are scanned for vulnerabilities
- Build artifacts are signed (checksums available)
- Minimal required permissions for each workflow
- Secrets are not exposed in logs

## Monitoring

Check workflow status:
- GitHub Actions tab for real-time status
- Security tab for vulnerability reports
- Packages tab for container registry
- Releases page for published assets