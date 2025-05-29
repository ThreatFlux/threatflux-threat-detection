# File Scanner

A comprehensive native file scanner written in Rust that provides detailed metadata, hashes, strings extraction, and binary analysis. Includes advanced static analysis capabilities for security research and malware detection.

## Features

### Core Scanning
- **File Metadata**: Size, timestamps, permissions, ownership
- **Hash Calculation**: MD5, SHA256, SHA512, BLAKE3 (async for performance)
- **String Extraction**: ASCII and Unicode strings with intelligent categorization
- **Binary Analysis**: PE/ELF/Mach-O parsing with compiler detection
- **Digital Signatures**: Authenticode, GPG, and macOS code signature verification
- **Hex Dumping**: Header, footer, or custom offset hex dumps
- **Multiple Output Formats**: JSON, YAML, and pretty-printed JSON

### Advanced Analysis
- **Behavioral Analysis**: Anti-debugging detection, evasion techniques, persistence mechanisms
- **Call Graph Generation**: Function relationship analysis with Graphviz output
- **Control Flow Analysis**: Basic block detection, cyclomatic complexity
- **Code Metrics**: Function complexity, code patterns, suspicious API usage
- **Vulnerability Detection**: Buffer overflows, format strings, use-after-free
- **Entropy Analysis**: Packed/encrypted section detection
- **Threat Detection**: Malware patterns, suspicious strings, IoCs
- **Disassembly**: x86/x64 instruction analysis with Capstone

### MCP Server Integration
- **Model Context Protocol**: Full MCP server implementation with 15 analysis tools
- **Transport Modes**: STDIO, HTTP, and SSE support
- **AI Integration**: Works with Claude Code, Cursor, and other MCP clients
- **Tool Interface**: Programmatic access to all scanner features via JSON-RPC

## Installation

```bash
cd file-scanner
cargo build --release
```

## Usage

Basic scan:
```bash
./target/release/file-scanner /path/to/file
```

With string extraction:
```bash
./target/release/file-scanner /path/to/file --strings
```

With signature verification:
```bash
./target/release/file-scanner /path/to/file --verify-signatures
```

With hex dump:
```bash
./target/release/file-scanner /path/to/file --hex-dump
```

Footer hex dump:
```bash
./target/release/file-scanner /path/to/file --hex-dump --hex-dump-offset=-256
```

JSON output:
```bash
./target/release/file-scanner /path/to/file --format json
```

YAML output:
```bash
./target/release/file-scanner /path/to/file --format yaml
```

## MCP Server Mode

Run as an MCP server for AI integration:

```bash
# STDIO transport (recommended for Claude Code)
./target/release/file-scanner mcp-stdio

# HTTP transport
./target/release/file-scanner mcp-http --port 3000

# SSE transport  
./target/release/file-scanner mcp-sse --port 3000
```

### Testing with MCP Inspector

```bash
# CLI mode for testing individual tools
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/list
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/call --tool-name get_file_metadata --tool-arg file_path=/bin/ls

# UI mode for interactive testing
npx @modelcontextprotocol/inspector ./target/release/file-scanner mcp-stdio

# HTTP/SSE testing
npx @modelcontextprotocol/inspector http://localhost:3000/mcp
npx @modelcontextprotocol/inspector http://localhost:3000/sse
```

### Available MCP Tools

1. **calculate_file_hashes** - Calculate cryptographic hashes
2. **extract_file_strings** - Extract ASCII and Unicode strings  
3. **hex_dump_file** - Generate hex dump of file contents
4. **analyze_binary_file** - Analyze binary file formats
5. **get_file_metadata** - Extract file system metadata
6. **verify_file_signatures** - Verify digital signatures
7. **analyze_function_symbols** - Analyze function symbols and cross-references
8. **analyze_control_flow_graph** - Analyze control flow and complexity
9. **detect_vulnerabilities** - Detect security vulnerabilities
10. **analyze_code_quality** - Analyze code quality metrics
11. **analyze_dependencies** - Analyze library dependencies
12. **analyze_entropy_patterns** - Detect packing and obfuscation
13. **disassemble_code** - Disassemble binary code
14. **detect_threats** - Detect malware patterns
15. **analyze_behavioral_patterns** - Analyze behavioral patterns

### Claude Code Configuration

Add to your MCP configuration:

```json
{
  "mcpServers": {
    "file-scanner": {
      "command": "./target/release/file-scanner",
      "args": ["mcp-stdio"]
    }
  }
}
```

## Example Output

```json
{
  "file_path": "/usr/bin/ls",
  "file_name": "ls",
  "file_size": 142848,
  "created": "2024-01-15T10:30:00Z",
  "modified": "2024-01-15T10:30:00Z",
  "permissions": "755",
  "is_executable": true,
  "mime_type": "application/x-elf",
  "hashes": {
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "sha512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
    "blake3": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
  },
  "binary_info": {
    "format": "ELF",
    "architecture": "x86_64",
    "compiler": "GCC/GNU",
    "entry_point": 16960,
    "is_stripped": false,
    "has_debug_info": true
  }
}
```

## Test Programs

The project includes comprehensive test programs in multiple compiled languages for testing detection capabilities:

### Supported Languages
- **C** - Buffer overflows, format strings, anti-debugging
- **C++** - Polymorphism, templates, advanced anti-analysis
- **Go** - Goroutines, network operations, crypto mining simulation
- **Rust** - Memory safety bypasses, unsafe operations
- **Nim** - Compile-time obfuscation, metaprogramming
- **D** - Template-based obfuscation, parallel processing
- **Fortran** - Scientific computing patterns, resource exhaustion
- **Pascal** - Classic techniques, Windows API simulation (partial)
- **Ada** - Strong typing with malicious patterns (partial)

### Compiling Test Programs
```bash
cd test_programs
./compile_all.sh  # Requires language compilers to be installed
```

### Installing Additional Compilers
```bash
# Ubuntu/Debian
sudo apt-get install fpc           # Pascal
sudo apt-get install gfortran      # Fortran
sudo apt-get install gnat          # Ada
sudo apt-get install gdc-13        # D Language

# Nim (via choosenim)
curl https://nim-lang.org/choosenim/init.sh -sSf | sh -s -- -y
export PATH=$HOME/.nimble/bin:$PATH
```

## Requirements

- Rust 1.87.0 or later
- Optional: osslsigncode (for Authenticode verification)
- Optional: gpg (for GPG signature verification)
- Optional: codesign (for macOS signature verification on macOS)
- Optional: Language compilers for test programs (see above)