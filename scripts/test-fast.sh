#!/bin/bash
# Fast test runner for development
# Runs only unit tests, skips expensive integration tests

set -e

echo "🚀 Running fast test suite..."

# Build with optimizations
export CARGO_PROFILE_TEST_OPT_LEVEL=2
export CARGO_PROFILE_TEST_DEBUG=1

# Run tests with increased parallelism
# Detect number of CPU cores
if [[ "$OSTYPE" == "darwin"* ]]; then
    CORES=$(sysctl -n hw.ncpu)
else
    CORES=$(nproc)
fi

RUST_TEST_THREADS=$CORES cargo test \
    --profile test \
    --lib \
    --bins \
    --quiet \
    "$@"

echo "✅ Fast tests completed successfully!"