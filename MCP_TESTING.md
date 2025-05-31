# MCP Inspector Testing Guide

This document explains how to test the file-scanner MCP server using the MCP Inspector tool.

## Prerequisites

- Node.js ^22.7.5
- Rust 1.87.0 or later
- Built file-scanner binary

## Building the Project

```bash
# Build the project in release mode
cargo build --release
```

## MCP Server Modes

The file-scanner supports three MCP transport modes:

### 1. STDIO Transport (Default for MCP)

```bash
# Run MCP server with stdio transport
./target/release/file-scanner mcp-stdio
```

### 2. HTTP Transport

```bash
# Run MCP server with HTTP transport on port 3000 (default)
./target/release/file-scanner mcp-http

# Run on custom port
./target/release/file-scanner mcp-http --port 8080
```

### 3. SSE (Server-Sent Events) Transport

```bash
# Run MCP server with SSE transport on port 3000 (default)
./target/release/file-scanner mcp-sse

# Run on custom port
./target/release/file-scanner mcp-sse --port 8080
```

## Testing with MCP Inspector

### STDIO Transport Testing

```bash
# Test the STDIO MCP server
npx @modelcontextprotocol/inspector ./target/release/file-scanner mcp-stdio
```

### HTTP Transport Testing

```bash
# Start the HTTP MCP server in one terminal
./target/release/file-scanner mcp-http --port 3000

# Test with MCP Inspector
npx @modelcontextprotocol/inspector http://localhost:3000/mcp

# Or test individual endpoints with curl
curl -X GET http://localhost:3000/health
curl -X POST http://localhost:3000/initialize
curl -X POST http://localhost:3000/tools/list
```

### SSE Transport Testing

```bash
# Start the SSE MCP server in one terminal
./target/release/file-scanner mcp-sse --port 3000

# Test with MCP Inspector
npx @modelcontextprotocol/inspector http://localhost:3000/sse

# Or test SSE endpoint directly
curl -X GET http://localhost:3000/sse
curl -X GET http://localhost:3000/health
```

## Available MCP Tools

The file-scanner MCP server exposes 2 comprehensive tools:

### 1. `analyze_file`
Comprehensive file analysis tool with configurable analysis options.

**Parameters:**
- `file_path` (string, required): Path to the file to analyze
- **Analysis flags (all optional, default to false):**
  - `metadata`: Include file metadata
  - `hashes`: Calculate cryptographic hashes
  - `strings`: Extract ASCII and Unicode strings
  - `min_string_length`: Minimum string length (default: 4)
  - `hex_dump`: Generate hex dump
  - `hex_dump_size`: Hex dump size in bytes (default: 256)
  - `hex_dump_offset`: Hex dump offset from start
  - `binary_info`: Analyze binary format
  - `signatures`: Verify digital signatures
  - `symbols`: Analyze function symbols
  - `control_flow`: Analyze control flow
  - `vulnerabilities`: Detect vulnerabilities
  - `code_quality`: Analyze code quality metrics
  - `dependencies`: Analyze dependencies
  - `entropy`: Analyze entropy patterns
  - `disassembly`: Disassemble code
  - `threats`: Detect threats and malware
  - `behavioral`: Analyze behavioral patterns
  - `yara_indicators`: Extract YARA rule indicators

### 2. `llm_analyze_file`
LLM-optimized analysis tool for focused analysis with token limits.

- `file_path` (string, required): Path to the file to analyze
- `token_limit` (number, optional): Maximum response size in characters (default: 25000)
- `min_string_length` (number, optional): Minimum string length to extract (default: 6)
- `max_strings` (number, optional): Maximum number of strings to return (default: 50)
- `max_imports` (number, optional): Maximum number of imports to return (default: 30)
- `max_opcodes` (number, optional): Maximum number of opcodes to return (default: 10)
- `hex_pattern_size` (number, optional): Size of hex patterns to extract (default: 32)
- `suggest_yara_rule` (boolean, optional): Generate YARA rule suggestion (default: true)

## Example Test Commands

### Using CLI Mode

```bash
# List available tools (should show 2 tools)
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/list

# Basic file analysis (metadata only)
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/call --tool-name analyze_file --tool-arg file_path=/bin/ls --tool-arg metadata=true

# Calculate hashes
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/call --tool-name analyze_file --tool-arg file_path=/bin/ls --tool-arg hashes=true

# Extract strings
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/call --tool-name analyze_file --tool-arg file_path=/bin/ls --tool-arg strings=true --tool-arg min_string_length=8

# Comprehensive analysis (multiple flags)
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/call --tool-name analyze_file --tool-arg file_path=/bin/ls --tool-arg metadata=true --tool-arg hashes=true --tool-arg strings=true --tool-arg binary_info=true --tool-arg entropy=true

# LLM-optimized analysis
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/call --tool-name llm_analyze_file --tool-arg file_path=/bin/ls --tool-arg token_limit=10000 --tool-arg suggest_yara_rule=true
```

## Configuration Export

The MCP Inspector provides buttons to export server configurations:

### STDIO Configuration

```json
{
  "command": "./target/release/file-scanner",
  "args": ["mcp-stdio"],
  "note": "Standard input/output transport for direct process communication"
}
```

### HTTP Configuration  

```json
{
  "type": "http",
  "url": "http://localhost:3000/mcp",
  "note": "Full HTTP JSON-RPC transport with multiple endpoints and REST-like API"
}
```

### SSE Configuration

```json
{
  "type": "sse", 
  "url": "http://localhost:3000/sse",
  "note": "Server-Sent Events transport with real-time bidirectional communication"
}
```

## Testing Workflow

1. **Build the project**: `cargo build --release`

2. **Start MCP server** in chosen transport mode

3. **Open MCP Inspector**: The inspector runs on `http://localhost:6274` by default

4. **Test tools**: Use the UI or CLI to test individual tools

5. **Verify responses**: Check that file analysis results are returned correctly

6. **Export configuration**: Use the export buttons to generate `mcp.json` configurations

## Debugging

- Check server logs for errors
- Verify file paths exist and are accessible
- Test with simple files first (e.g., `/bin/ls`)
- Use the Inspector's request history to debug issues
- Check network connectivity for HTTP/SSE modes

## Integration with Claude Code

To use with Claude Code, add the exported configuration to your `mcp.json`:

### STDIO Transport (Recommended)
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

### HTTP Transport
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

### SSE Transport
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

## Transport Comparison

| Transport | Pros | Cons | Use Case |
|-----------|------|------|----------|
| **STDIO** | Direct process communication, no network overhead, most compatible | Single client, process lifecycle tied to client | Local development, Claude Code integration |
| **HTTP** | Multiple clients, REST-like endpoints, easy testing with curl | Network overhead, stateless | Multi-client environments, testing, debugging |
| **SSE** | Real-time communication, multiple clients, server push | More complex, requires persistent connections | Real-time monitoring, streaming responses |