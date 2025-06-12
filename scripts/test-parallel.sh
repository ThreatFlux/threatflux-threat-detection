#!/bin/bash
# Parallel test runner with maximum performance
# Uses all CPU cores and optimized build settings

set -e

echo "⚡ Running parallel test suite with maximum performance..."

# Detect number of CPU cores
if [[ "$OSTYPE" == "darwin"* ]]; then
    CORES=$(sysctl -n hw.ncpu)
else
    CORES=$(nproc)
fi

echo "🔧 Using $CORES CPU cores for testing"

# Set optimization environment variables
export CARGO_PROFILE_TEST_OPT_LEVEL=2
export CARGO_PROFILE_TEST_DEBUG=1
export CARGO_PROFILE_TEST_INCREMENTAL=true
export CARGO_PROFILE_TEST_CODEGEN_UNITS=16

# Maximum parallelism
export RUST_TEST_THREADS=$CORES
export RUSTFLAGS="-C target-cpu=native"

# Run tests with parallel execution
time cargo test \
    --profile test \
    --jobs $CORES \
    --quiet \
    "$@"

echo "✅ Parallel tests completed!"