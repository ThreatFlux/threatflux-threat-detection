# Usage Guide

Comprehensive guide for using File Scanner's features and capabilities.

## Table of Contents

- [Command Line Interface](#command-line-interface)
- [Basic Usage](#basic-usage)
- [Analysis Options](#analysis-options)
- [Output Formats](#output-formats)
- [Advanced Examples](#advanced-examples)
- [Batch Processing](#batch-processing)
- [Integration with Other Tools](#integration-with-other-tools)
- [Real-World Scenarios](#real-world-scenarios)

## Command Line Interface

### Synopsis

```bash
file-scanner [OPTIONS] <FILE_PATH | COMMAND>
```

### Global Options

```
-h, --help                    Print help information
-V, --version                 Print version information
-f, --format <FORMAT>         Output format [json|yaml|pretty] (default: pretty)
-o, --output <FILE>           Write output to file instead of stdout
    --no-color                Disable colored output
    --quiet                   Suppress non-essential output
```

### Analysis Options

```
-s, --strings                 Extract ASCII and Unicode strings
    --min-string-len <N>      Minimum string length (default: 4)
    --max-strings <N>         Maximum strings to extract (default: 10000)

-x, --hex-dump                Generate hex dump
    --hex-dump-size <N>       Hex dump size in bytes (default: 256)
    --hex-dump-offset <N>     Hex dump offset (-N for end offset)

-v, --verify-signatures       Verify digital signatures
    --sig-check-all           Check all signature types

-a, --all                     Enable all analysis features
    --fast                    Fast mode (skip time-intensive checks)
```

### MCP Server Commands

```
mcp-stdio                     Start MCP server with STDIO transport
mcp-http --port <PORT>        Start MCP server with HTTP transport
mcp-sse --port <PORT>         Start MCP server with SSE transport
```

## Basic Usage

### Simple File Scan

```bash
# Basic metadata and hashes
file-scanner /path/to/file.exe

# With string extraction
file-scanner --strings /path/to/file.exe

# With hex dump
file-scanner --hex-dump /path/to/file.exe

# All features
file-scanner --all /path/to/file.exe
```

### Output Examples

#### Default (Pretty) Output

```bash
$ file-scanner /bin/ls

File Scanner Analysis Report
==========================

File: /bin/ls
Size: 142,848 bytes
Type: ELF 64-bit executable
Modified: 2024-01-15 10:30:00

Hashes:
  MD5:    d41d8cd98f00b204e9800998ecf8427e
  SHA256: e3b0c44298fc1c149afbf4c8996fb924
  SHA512: cf83e1357eefb8bdf1542850d66d8007
  BLAKE3: af1349b9f5f9a1a6a0404dea36dcc949

Binary Info:
  Format: ELF
  Arch:   x86_64
  Compiler: GCC 9.3.0
```

#### JSON Output

```bash
file-scanner --format json /bin/ls > analysis.json
```

#### YAML Output

```bash
file-scanner --format yaml /bin/ls
```

## Analysis Options

### String Extraction

```bash
# Basic string extraction
file-scanner --strings malware.exe

# Custom minimum length
file-scanner --strings --min-string-len 8 malware.exe

# Limit number of strings
file-scanner --strings --max-strings 100 malware.exe

# Combine with other options
file-scanner --strings --hex-dump malware.exe
```

### Hex Dump Options

```bash
# Default header dump (256 bytes)
file-scanner --hex-dump file.bin

# Custom size
file-scanner --hex-dump --hex-dump-size 512 file.bin

# Footer dump (last 256 bytes)
file-scanner --hex-dump --hex-dump-offset=-256 file.bin

# Specific offset
file-scanner --hex-dump --hex-dump-offset=1024 --hex-dump-size 128 file.bin
```

### Signature Verification

```bash
# Verify all signatures
file-scanner --verify-signatures signed.exe

# Windows Authenticode
file-scanner --verify-signatures setup.exe

# macOS code signature
file-scanner --verify-signatures app.dmg

# GPG signature
file-scanner --verify-signatures package.tar.gz.sig
```

## Advanced Examples

### Malware Analysis

```bash
# Comprehensive malware scan
file-scanner --all suspicious.exe --format json > report.json

# Focus on behavioral indicators
file-scanner --strings --hex-dump suspicious.exe | \
  grep -E "(CreateRemoteThread|VirtualAlloc|WriteProcessMemory)"

# Extract and analyze strings
file-scanner --strings --min-string-len 10 malware.bin | \
  jq '.strings[] | select(.category == "suspicious")'
```

### Binary Comparison

```bash
# Compare two binaries
diff <(file-scanner --format json file1.exe) \
     <(file-scanner --format json file2.exe)

# Hash comparison
file-scanner file1.exe file2.exe | grep SHA256
```

### Forensic Investigation

```bash
# Scan with timestamp preservation
file-scanner --all evidence.bin --format json \
  --output "evidence_$(date +%Y%m%d_%H%M%S).json"

# Chain of custody documentation
file-scanner evidence.bin | tee -a investigation.log
```

## Batch Processing

### Using GNU Parallel

```bash
# Process multiple files in parallel
find /samples -name "*.exe" | \
  parallel -j 8 file-scanner --format json {} \> {.}_analysis.json

# With progress bar
find /samples -type f | \
  parallel --bar -j 4 file-scanner --strings {} \> results/{/.}.txt
```

### Shell Loops

```bash
# Process directory of files
for file in /path/to/samples/*; do
  echo "Analyzing: $file"
  file-scanner --all "$file" --format json > "${file%.exe}_report.json"
done

# With error handling
for file in samples/*.bin; do
  if file-scanner "$file" > "reports/$(basename "$file").txt" 2>&1; then
    echo "✓ Processed: $file"
  else
    echo "✗ Failed: $file"
  fi
done
```

### Batch Script Example

```bash
#!/bin/bash
# batch_scan.sh - Scan directory of samples

SAMPLES_DIR="${1:-./samples}"
OUTPUT_DIR="${2:-./reports}"
mkdir -p "$OUTPUT_DIR"

echo "Scanning files in $SAMPLES_DIR..."
for file in "$SAMPLES_DIR"/*; do
  if [ -f "$file" ]; then
    basename=$(basename "$file")
    echo "Processing: $basename"
    file-scanner --all "$file" --format json \
      > "$OUTPUT_DIR/${basename}.json" 2>&1
  fi
done
echo "Scan complete. Reports in $OUTPUT_DIR"
```

## Integration with Other Tools

### With jq for JSON Processing

```bash
# Extract specific fields
file-scanner --format json malware.exe | \
  jq '{name: .file_name, md5: .hashes.md5, strings: .strings.total_count}'

# Filter suspicious strings
file-scanner --strings --format json malware.exe | \
  jq '.strings[] | select(.value | test("cmd|powershell|http"))'

# Create CSV report
file-scanner --format json *.exe | \
  jq -r '[.file_name, .file_size, .hashes.md5] | @csv' > report.csv
```

### With grep and awk

```bash
# Find files with specific imports
for file in *.exe; do
  if file-scanner --strings "$file" | grep -q "VirtualAlloc"; then
    echo "$file contains VirtualAlloc"
  fi
done

# Extract hash values
file-scanner file.exe | awk '/SHA256:/ {print $2}'
```

### YARA Integration

```bash
# Generate YARA rule from analysis
file-scanner --all --format json malware.exe | \
  python3 generate_yara.py > malware.yar

# Scan with existing YARA rules
file-scanner --strings malware.exe | \
  yara -s rules.yar -
```

### VirusTotal Integration

```bash
# Get hash and check with VT
MD5=$(file-scanner file.exe --format json | jq -r .hashes.md5)
curl -s -X GET "https://www.virustotal.com/api/v3/files/$MD5" \
  -H "x-apikey: $VT_API_KEY"
```

## Real-World Scenarios

### Incident Response

```bash
# Quick triage of suspicious process
file-scanner /proc/$(pgrep suspicious)/exe --all

# Memory dump analysis
file-scanner --strings --hex-dump memory.dmp | \
  tee incident_$(date +%Y%m%d).log

# Collect IoCs
file-scanner --all --format json suspicious.exe | \
  jq '.strings[] | select(.category == "url" or .category == "ip")'
```

### Security Research

```bash
# Analyze malware family
for sample in malware_family/*.exe; do
  file-scanner --all --format json "$sample"
done | jq -s 'group_by(.binary_info.compiler) | 
  map({compiler: .[0].binary_info.compiler, count: length})'

# Extract common strings
file-scanner --strings family/*.exe | \
  sort | uniq -c | sort -nr | head -20
```

### Compliance Scanning

```bash
# Verify all executables are signed
find /usr/local/bin -type f -executable | while read file; do
  if ! file-scanner --verify-signatures "$file" | grep -q "Valid signature"; then
    echo "Unsigned: $file"
  fi
done

# Generate software inventory
find / -name "*.exe" -o -name "*.dll" 2>/dev/null | \
  parallel -j 4 file-scanner --format json {} | \
  jq -s '[.[] | {path: .file_path, hash: .hashes.sha256, signed: .signatures.valid}]' \
  > software_inventory.json
```

### Development & CI/CD

```bash
# Pre-commit hook
#!/bin/bash
for file in $(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(exe|dll|so)$'); do
  echo "Scanning: $file"
  file-scanner --verify-signatures "$file" || exit 1
done

# Build verification
file-scanner --all ./target/release/myapp --format json | \
  jq '{size: .file_size, hash: .hashes.sha256, stripped: .binary_info.is_stripped}'
```

## Performance Tips

### Large Files

```bash
# Use fast mode for quick analysis
file-scanner --fast large_file.bin

# Limit string extraction
file-scanner --strings --max-strings 1000 large_file.bin

# Skip expensive operations
file-scanner --no-signatures large_file.bin
```

### Multiple Files

```bash
# Use parallel processing
find . -type f | parallel -j $(nproc) file-scanner {} \> {.}.json

# Batch with rate limiting
find . -type f | parallel -j 4 --delay 0.5 file-scanner {}
```

## Troubleshooting

### Common Issues

```bash
# Debug mode
RUST_LOG=debug file-scanner file.exe

# Verbose output
file-scanner -vvv file.exe

# Test specific feature
file-scanner --strings --max-strings 10 test.exe
```

### Error Messages

- `Permission denied`: Run with appropriate permissions or sudo
- `File not found`: Check file path and permissions
- `Invalid UTF-8`: File may be corrupted or use --no-strings
- `Timeout`: Use --fast mode or increase limits

## Next Steps

- Learn about [MCP Integration](MCP.md) for AI tools
- Understand the [Architecture](ARCHITECTURE.md)
- Check [Performance Guide](PERFORMANCE.md) for optimization
- Read the [FAQ](FAQ.md) for common questions