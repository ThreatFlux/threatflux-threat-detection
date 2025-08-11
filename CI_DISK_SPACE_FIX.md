# CI Disk Space Fix for Parallel Tests

## Problem
GitHub Actions runners were running out of disk space during parallel test compilation with the error:
```
/usr/bin/ld: final link failed: No space left on device
```

## Solution
Created a CI-optimized test runner that:

1. **Reduces parallelism** - Limits to 2 parallel jobs instead of all CPU cores
2. **Frees disk space** - Removes unnecessary pre-installed software
3. **Optimizes binary size** - Uses minimal debug info and thin LTO
4. **Runs tests in batches** - Cleans artifacts between test types
5. **Adds swap space** - Creates 4GB swap file for more virtual memory

## Changes Made

### 1. New CI-optimized test script: `scripts/test-parallel-ci.sh`
- Detects CI environment and applies optimizations
- Runs tests in batches with cleanup between
- Uses space-saving compiler flags

### 2. Updated `scripts/test-parallel.sh`
- Automatically delegates to CI script when `$CI` is set
- Preserves original behavior for local development

### 3. Modified `.github/workflows/ci.yml`
- Added swap space setup (4GB)
- Added disk cleanup before tests
- Uses new CI-optimized script

### 4. Created `.cargo/config.toml`
- Documents CI-specific settings
- Maintains development-friendly defaults

## Key Optimizations

### Compiler Flags (CI only)
- `CARGO_PROFILE_TEST_DEBUG=0` - No debug symbols
- `CARGO_PROFILE_TEST_CODEGEN_UNITS=1` - Single codegen unit
- `CARGO_PROFILE_TEST_LTO="thin"` - Thin link-time optimization
- `CARGO_PROFILE_TEST_INCREMENTAL=false` - No incremental compilation
- `RUSTFLAGS="-C link-arg=-s"` - Strip symbols

### Resource Management
- Max 2 parallel jobs in CI (vs all cores locally)
- 4GB swap space for linking
- Cleanup of 10GB+ of pre-installed software
- Artifact cleanup between test batches

## Testing
The changes preserve full test coverage while working within GitHub Actions' resource constraints. Local development remains unchanged with full parallelism and debug capabilities.