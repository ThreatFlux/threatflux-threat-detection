# File Scanner - Claude Code Project

## Project Overview

A comprehensive native file scanner written in Rust that provides detailed metadata, hash calculations, string extraction, binary analysis, hex dumping, and digital signature verification. Built using Rust 1.87.0 with modern async capabilities and multiple output formats.

## Key Features

- **File Metadata Extraction**: Complete file system metadata including timestamps, permissions, ownership
- **Cryptographic Hashing**: MD5, SHA256, SHA512, and BLAKE3 hash calculations with async processing
- **String Analysis**: ASCII and Unicode string extraction with intelligent pattern matching
- **Binary Format Analysis**: PE/ELF/Mach-O parsing with compiler detection and section analysis
- **Digital Signature Verification**: Support for Authenticode, GPG, and macOS code signatures
- **Hex Dumping**: Flexible hex dump capabilities for headers, footers, or custom offsets
- **Multiple Output Formats**: JSON, YAML, and pretty-printed JSON support
- **Performance Optimized**: Concurrent hash calculation and efficient memory usage
- **MCP Server Support**: Model Context Protocol server with STDIO, HTTP, and SSE transports

## Build and Test Commands

```bash
# Build the project
cargo build --release

# Regular file scanning mode
./target/release/file-scanner /path/to/file

# Full analysis with all features
./target/release/file-scanner /path/to/file --strings --hex-dump --verify-signatures --format yaml

# Test with different output formats
./target/release/file-scanner /bin/ls --format json
./target/release/file-scanner /bin/ls --format yaml

# Hex dump examples
./target/release/file-scanner /bin/ls --hex-dump --hex-dump-size 256
./target/release/file-scanner /bin/ls --hex-dump --hex-dump-offset=-128  # footer dump

# String extraction
./target/release/file-scanner /bin/ls --strings --min-string-len 8

# MCP Server Modes
./target/release/file-scanner mcp-stdio              # STDIO transport
./target/release/file-scanner mcp-http --port 3000   # HTTP transport
./target/release/file-scanner mcp-sse --port 3000    # SSE transport

# Test MCP server with inspector (FIXED - now working!)
npx @modelcontextprotocol/inspector ./target/release/file-scanner mcp-stdio
npx @modelcontextprotocol/inspector http://localhost:3000/mcp
npx @modelcontextprotocol/inspector http://localhost:3000/sse

# CLI testing mode for individual tools
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/list
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/call --tool-name get_file_metadata --tool-arg file_path=/bin/ls
```

## Project Structure

```
src/
├── main.rs              # CLI interface and main application logic
├── metadata.rs          # File metadata extraction and core data structures
├── hash.rs              # Cryptographic hash calculations (async)
├── strings.rs           # String extraction and pattern matching
├── binary_parser.rs     # PE/ELF/Mach-O binary format parsing
├── signature.rs         # Digital signature verification
├── hexdump.rs           # Hex dump generation and formatting
├── mcp_server.rs        # MCP server implementation with file scanner tools
└── mcp_transport.rs     # MCP transport implementations (STDIO, HTTP, SSE)
```

## Dependencies

- **Core**: `tokio` (async runtime), `anyhow` (error handling), `clap` (CLI)
- **Hashing**: `sha2`, `md-5`, `blake3`
- **Binary Parsing**: `goblin`, `object`
- **String Processing**: `regex`, `encoding_rs`
- **Serialization**: `serde`, `serde_json`, `serde_yaml`
- **System Info**: `chrono`, `filetime`
- **MCP**: `rmcp` (Model Context Protocol SDK), `schemars`
- **HTTP Server**: `axum`, `tower`, `hyper`

## Testing Examples

The scanner has been tested on various file types:

1. **ELF Binaries** (`/bin/ls`): Successfully extracts metadata, hashes, binary info, and strings
2. **Text Files** (`/etc/passwd`): Proper MIME type detection and hex dumping
3. **Self-Analysis**: Can analyze its own binary for comprehensive testing

### Test Program Suite

The project includes comprehensive test programs in 9 compiled languages to validate detection capabilities:

- **C** (`c_advanced_binary`): Buffer overflows, format strings, anti-debugging
- **C++** (`cpp_test_binary`): Polymorphism, templates, anti-analysis
- **Go** (`go_test_binary`, `crypto_miner_binary`): Goroutines, crypto mining
- **Rust** (`rust_test_binary`, `packed_rust_binary`): Unsafe operations, packing
- **Nim** (`nim_test_binary`): Compile-time obfuscation, metaprogramming
- **D** (`d_test_binary`): Template obfuscation, parallel processing
- **Fortran** (`fortran_test_binary`): Scientific computing, resource exhaustion

All test binaries simulate malicious behaviors including:
- Anti-debugging techniques (ptrace, timing checks)
- Network C2 communication (msftupdater.com)
- Process injection simulation
- Persistence mechanisms
- Resource exhaustion
- Data exfiltration
- Polymorphic code generation

## Development Notes

- Built with Rust 1.87.0 (latest stable as of May 2025)
- Uses async processing for hash calculations to improve performance on large files
- Modular design allows easy extension for new file formats or analysis types
- Comprehensive error handling with descriptive messages
- Memory-efficient processing with configurable limits for large files

## Common Use Cases

1. **Security Analysis**: Hash verification, signature validation, string analysis
2. **Reverse Engineering**: Binary format analysis, hex dumps, compiler detection
3. **Forensics**: Complete file metadata, hex dumps at specific offsets
4. **File Classification**: MIME type detection, format identification
5. **Compliance**: Digital signature verification, integrity checking
6. **MCP Integration**: Use as a tool in AI assistants and coding environments

## Output Formats

### JSON (Compact)
```bash
./target/release/file-scanner file.bin --format json
```

### YAML (Human-readable)
```bash
./target/release/file-scanner file.bin --format yaml
```

### Pretty JSON (Default)
```bash
./target/release/file-scanner file.bin
```

## Performance Considerations

- Hash calculations run concurrently using tokio tasks
- String extraction limited to prevent memory exhaustion on large files
- Hex dumps configurable with size limits for performance
- Binary parsing optimized for common formats

## MCP Server Integration

The file-scanner can run as an MCP (Model Context Protocol) server, exposing its capabilities as tools for AI assistants. **The MCP server is now fully functional and tested!**

### Available MCP Tools (15 Total)

1. **calculate_file_hashes**: Calculate cryptographic hashes (MD5, SHA256, SHA512, BLAKE3)
2. **extract_file_strings**: Extract ASCII and Unicode strings
3. **hex_dump_file**: Generate hex dump of file contents
4. **analyze_binary_file**: Analyze binary file formats (PE, ELF, Mach-O)
5. **get_file_metadata**: Extract file system metadata
6. **verify_file_signatures**: Verify digital signatures
7. **analyze_function_symbols**: Analyze function symbols and cross-references
8. **analyze_control_flow_graph**: Analyze control flow graphs and complexity
9. **detect_vulnerabilities**: Detect security vulnerabilities using static analysis
10. **analyze_code_quality**: Analyze code quality metrics and maintainability
11. **analyze_dependencies**: Analyze library dependencies and license compliance
12. **analyze_entropy_patterns**: Detect packing, encryption, and obfuscation
13. **disassemble_code**: Disassemble binary code with multi-architecture support
14. **detect_threats**: Detect malware using comprehensive pattern matching
15. **analyze_behavioral_patterns**: Analyze anti-analysis and evasion techniques

### MCP Configuration for Claude Code

**STDIO Transport (Recommended):**
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

**HTTP Transport:**
```json
{
  "mcpServers": {
    "file-scanner-http": {
      "type": "http",
      "url": "http://localhost:3000/mcp"
    }
  }
}
```

**SSE Transport:**
```json
{
  "mcpServers": {
    "file-scanner-sse": {
      "type": "sse",
      "url": "http://localhost:3000/sse"
    }
  }
}
```

### MCP Testing Status

✅ **FIXED**: JSON-RPC protocol compliance issues resolved  
✅ **WORKING**: All 15 MCP tools functional via STDIO transport  
✅ **TESTED**: MCP Inspector CLI and UI modes working  
✅ **VERIFIED**: Tool calls return proper formatted responses  

**Known Working Commands:**
```bash
# List all available tools
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/list

# Test file metadata extraction
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/call --tool-name get_file_metadata --tool-arg file_path=/bin/ls

# Interactive UI testing
npx @modelcontextprotocol/inspector ./target/release/file-scanner mcp-stdio
```

See `MCP_TESTING.md` for comprehensive testing instructions.

## Future Enhancement Ideas

- Support for additional binary formats (Java class files, .NET assemblies)
- Extended signature verification (jar signing, etc.)
- File content classification using machine learning
- Batch processing capabilities
- Plugin architecture for custom analyzers
- Enhanced MCP features (resources, prompts)