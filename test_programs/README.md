# Test Programs Documentation

This directory contains malicious behavior simulation programs in multiple compiled languages for testing the file scanner's detection capabilities.

## ⚠️ WARNING

These programs simulate malicious behaviors for testing purposes only. They:

- Target non-existent domains (msftupdater.com)
- Use fake credentials and data
- Include anti-analysis techniques that may trigger security software
- Should ONLY be run in isolated testing environments

## Supported Languages

### Successfully Compiled (9 languages)

| Language | Source File | Binary | Compiler | Key Features |
|----------|-------------|---------|----------|--------------|
| **C** | `c_advanced.c` | `c_advanced_binary` | gcc | Buffer overflows, format strings, ptrace |
| **C++** | `cpp_test.cpp` | `cpp_test_binary` | g++ | Templates, polymorphism, anti-debug |
| **Go** | `go_test.go` | `go_test_binary` | go | Goroutines, network ops, VM detection |
| **Go** | `crypto_miner.go` | `crypto_miner_binary` | go | CPU exhaustion, mining simulation |
| **Rust** | `rust_test.rs` | `rust_test_binary` | rustc | Unsafe blocks, memory manipulation |
| **Rust** | `packed_rust.rs` | `packed_rust_binary` | rustc | Self-modification, packing |
| **Nim** | `nim_test.nim` | `nim_test_binary` | nim | Compile-time obfuscation, polymorphic |
| **D** | `d_test.d` | `d_test_binary` | gdc-13 | Template obfuscation, parallelism |
| **Fortran** | `fortran_test.f90` | `fortran_test_binary` | gfortran | Matrix operations, resource burn |

### Partial Implementation

| Language | Source File | Status | Issue |
|----------|-------------|---------|-------|
| **Pascal** | `pascal_test.pas` | Source only | Compilation errors with modern FPC |
| **Ada** | `ada_test.adb` | Source only | Type system conflicts |
| **Zig** | `zig_test.zig` | Source only | Compiler not installed |

## Common Malicious Patterns

All test programs implement variations of:

### 1. Anti-Analysis Techniques

- **Debugger Detection**: ptrace checks, timing analysis, TracerPid monitoring
- **VM/Sandbox Detection**: Environment checks, CPU count, DMI info
- **Sleep Acceleration**: Detect time manipulation

### 2. Network Operations

- **C2 Communication**: Beaconing to msftupdater.com (fake domain)
- **Data Exfiltration**: Simulated credential theft
- **Encrypted Channels**: XOR obfuscation

### 3. Persistence Mechanisms

- **Cron Jobs**: Scheduled execution
- **Auto-start**: Boot persistence simulation
- **Self-replication**: Copy operations

### 4. Resource Attacks

- **CPU Exhaustion**: Infinite loops, complex calculations
- **Memory Consumption**: Large allocations
- **Parallel Threading**: Multi-core saturation

### 5. Code Obfuscation

- **String Encryption**: XOR, compile-time obfuscation
- **Polymorphic Code**: Runtime generation
- **Self-modification**: Dynamic code changes

## Compilation Instructions

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y build-essential

# Language-specific compilers
sudo apt-get install -y fpc           # Pascal
sudo apt-get install -y gfortran      # Fortran
sudo apt-get install -y gnat          # Ada
sudo apt-get install -y gdc-13        # D

# Nim (via choosenim)
curl https://nim-lang.org/choosenim/init.sh -sSf | sh -s -- -y
export PATH=$HOME/.nimble/bin:$PATH

# Rust (via rustup)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Go
sudo apt-get install -y golang-go
```

### Automated Compilation

```bash
./compile_all.sh
```

### Manual Compilation Examples

```bash
# C
gcc -O2 c_advanced.c -o c_advanced_binary -lpthread

# C++
g++ -O2 cpp_test.cpp -o cpp_test_binary

# Go
go build -o go_test_binary go_test.go

# Rust
rustc -O rust_test.rs -o rust_test_binary

# Nim
nim c -d:release --opt:speed -o:nim_test_binary nim_test.nim

# D
gdc-13 -O2 -frelease -o d_test_binary d_test.d

# Fortran
gfortran -O2 fortran_test.f90 -o fortran_test_binary
```

## Testing with File Scanner

### Basic Scan

```bash
../target/release/file-scanner <binary_name>
```

### Full Analysis

```bash
../target/release/file-scanner <binary_name> --strings --hex-dump --verify-signatures
```

### Detection Examples

```bash
# Find suspicious strings
../target/release/file-scanner nim_test_binary --strings --format json | \
  jq '.extracted_strings.interesting_strings[] | select(.value | test("msftupdater|debug|malware"))'

# Check binary info
../target/release/file-scanner d_test_binary --format yaml | grep -A5 binary_info
```

## Expected Detection Results

The file scanner should detect:

1. **Suspicious Strings**:
   - "msftupdater.com"
   - "Debugger detected!"
   - "TracerPid:"
   - "BEACON|"
   - Obfuscated strings

2. **Binary Indicators**:
   - Non-stripped binaries with debug symbols
   - Import of sensitive APIs (ptrace, socket, etc.)
   - Unusual entropy in sections

3. **Behavioral Patterns**:
   - Anti-debugging function names
   - Network communication functions
   - File system manipulation
   - Process injection markers

## Adding New Test Programs

When adding new test programs:

1. Include standard malicious patterns
2. Add language-specific evasion techniques
3. Document compilation requirements
4. Test with the scanner before committing
5. Update this README

## Security Notes

- These programs are for testing only
- Do not run on production systems
- Some may trigger antivirus software
- Network operations target non-existent domains
- No actual malicious payloads are included
