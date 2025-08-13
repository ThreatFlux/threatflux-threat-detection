#!/bin/bash
# Verification script for file-scanner code quality setup

set -e

echo "🔍 Verifying file-scanner code quality setup..."
echo "=============================================="

# Check required files exist
echo "1. Checking configuration files..."
required_files=(
    ".rustfmt.toml"
    ".clippy.toml" 
    ".cargo/config.toml"
    "deny.toml"
    ".editorconfig"
    ".git/hooks/pre-commit"
)

for file in "${required_files[@]}"; do
    if [[ -f "$file" ]]; then
        echo "  ✅ $file exists"
    else
        echo "  ❌ $file missing"
        exit 1
    fi
done

# Check workspace configuration
echo "2. Checking workspace configuration..."
if grep -q "\[workspace\]" Cargo.toml; then
    echo "  ✅ Workspace configured"
else
    echo "  ❌ Workspace not configured"
    exit 1
fi

# Test rustfmt
echo "3. Testing rustfmt..."
if cargo fmt --check; then
    echo "  ✅ Code is properly formatted"
else
    echo "  ⚠️  Code needs formatting"
fi

# Test basic compilation
echo "4. Testing compilation..."
if cargo check --lib; then
    echo "  ✅ Project compiles successfully"
else
    echo "  ❌ Compilation failed"
    exit 1
fi

# Check if quality tools are available
echo "5. Checking quality tools availability..."
tools=("cargo-audit" "cargo-deny" "cargo-outdated" "cargo-machete")

for tool in "${tools[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "  ✅ $tool is available"
    else
        echo "  ⚠️  $tool not installed (install with: cargo install $tool)"
    fi
done

# Test Makefile targets
echo "6. Testing Makefile targets..."
makefile_targets=("fmt" "lint" "security-audit" "quality-check")

for target in "${makefile_targets[@]}"; do
    if grep -q "^${target}:" Makefile; then
        echo "  ✅ Makefile target '$target' exists"
    else
        echo "  ❌ Makefile target '$target' missing"
    fi
done

# Check git hooks
echo "7. Checking git hooks..."
if [[ -x ".git/hooks/pre-commit" ]]; then
    echo "  ✅ Pre-commit hook is executable"
else
    echo "  ❌ Pre-commit hook is not executable"
    exit 1
fi

echo ""
echo "🎉 Code quality setup verification complete!"
echo ""
echo "📋 Quick start commands:"
echo "  make fmt           # Format code"
echo "  make lint          # Run linting"
echo "  make quality-check # Run all quality checks"
echo "  make help          # Show all available commands"
echo ""
echo "🛠️  To install missing tools:"
echo "  cargo install cargo-audit cargo-deny cargo-outdated cargo-machete"