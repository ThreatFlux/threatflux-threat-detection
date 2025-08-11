#!/bin/bash
# Parallel test runner optimized for CI environments with limited disk space
# Uses controlled parallelism and disk space management

set -e

echo "⚡ Running parallel test suite for CI environment..."

# Detect number of CPU cores
if [[ "$OSTYPE" == "darwin"* ]]; then
    CORES=$(sysctl -n hw.ncpu)
else
    CORES=$(nproc)
fi

# In CI, limit parallelism to avoid disk space issues
if [ -n "$CI" ]; then
    # GitHub Actions has limited disk space, reduce parallelism
    MAX_JOBS=2
    echo "🔧 CI environment detected, limiting to $MAX_JOBS parallel jobs (available cores: $CORES)"
    
    # Free up disk space before tests
    if [ "$RUNNER_OS" == "Linux" ]; then
        echo "🧹 Freeing up disk space..."
        df -h
        
        # Clean up unnecessary files
        sudo rm -rf /usr/local/lib/android || true
        sudo rm -rf /usr/share/dotnet || true
        sudo rm -rf /opt/ghc || true
        sudo rm -rf /usr/local/.ghcup || true
        sudo apt-get clean || true
        
        # Clean cargo cache selectively
        cargo clean -p file-scanner --release || true
        
        echo "📊 Disk space after cleanup:"
        df -h
    fi
else
    MAX_JOBS=$CORES
    echo "🔧 Using $MAX_JOBS CPU cores for testing"
fi

# Set optimization environment variables for CI
if [ -n "$CI" ]; then
    # Reduce debug info to save space
    export CARGO_PROFILE_TEST_DEBUG=0
    # Use fewer codegen units to reduce disk usage
    export CARGO_PROFILE_TEST_CODEGEN_UNITS=1
    # Keep optimization for faster tests
    export CARGO_PROFILE_TEST_OPT_LEVEL=2
    # Disable incremental compilation in CI
    export CARGO_PROFILE_TEST_INCREMENTAL=false
    # Use thin LTO to reduce binary size
    export CARGO_PROFILE_TEST_LTO="thin"
else
    # Development settings
    export CARGO_PROFILE_TEST_OPT_LEVEL=2
    export CARGO_PROFILE_TEST_DEBUG=1
    export CARGO_PROFILE_TEST_INCREMENTAL=true
    export CARGO_PROFILE_TEST_CODEGEN_UNITS=16
fi

# Set test thread count
export RUST_TEST_THREADS=$MAX_JOBS

# CI-specific flags to reduce binary size
if [ -n "$CI" ]; then
    export RUSTFLAGS="-C link-arg=-s"  # Strip symbols
else
    export RUSTFLAGS="-C target-cpu=native"
fi

# Run tests in batches if in CI to manage disk space
if [ -n "$CI" ]; then
    echo "🔄 Running tests in batches to manage disk space..."
    
    # First batch: Unit tests only
    echo "📦 Batch 1: Unit tests"
    time cargo test \
        --lib \
        --bins \
        --profile test \
        --jobs $MAX_JOBS \
        --quiet \
        "$@"
    
    # Clean up test artifacts between batches
    echo "🧹 Cleaning test artifacts..."
    find target/debug -name "*.d" -delete || true
    find target/debug -name "*.rmeta" -delete || true
    find target/debug/deps -name "*-*" -type f ! -name "*.rlib" -delete || true
    
    # Second batch: Integration tests
    echo "📦 Batch 2: Integration tests"
    time cargo test \
        --test "*" \
        --profile test \
        --jobs $MAX_JOBS \
        --quiet \
        "$@"
    
    # Third batch: Doc tests
    echo "📦 Batch 3: Doc tests"
    time cargo test \
        --doc \
        --profile test \
        --jobs $MAX_JOBS \
        --quiet \
        "$@"
else
    # Development: Run all tests at once
    time cargo test \
        --profile test \
        --jobs $MAX_JOBS \
        --quiet \
        "$@"
fi

echo "✅ Parallel tests completed!"