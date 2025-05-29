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

The file-scanner MCP server exposes the following tools:

### 1. `calculate_file_hashes`
Calculate cryptographic hashes for a file.

**Parameters:**
- `file_path` (string): Path to the file to hash

### 2. `extract_file_strings`
Extract ASCII and Unicode strings from a file.

**Parameters:**
- `file_path` (string): Path to the file
- `min_length` (number, optional): Minimum string length

### 3. `hex_dump_file`
Generate a hex dump of a file.

**Parameters:**
- `file_path` (string): Path to the file
- `size` (number, optional): Number of bytes to dump
- `offset` (number, optional): Offset from start of file

### 4. `analyze_binary_file`
Analyze binary file format (PE, ELF, Mach-O).

**Parameters:**
- `file_path` (string): Path to the binary file

### 5. `get_file_metadata`
Extract file system metadata.

**Parameters:**
- `file_path` (string): Path to the file

### 6. `verify_file_signatures`
Verify digital signatures on a file.

**Parameters:**
- `file_path` (string): Path to the file

## Example Test Commands

### Using CLI Mode

```bash
# List available tools
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/list

# Calculate hashes
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/call --tool-name calculate_file_hashes --tool-arg file_path=/bin/ls

# Extract strings
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/call --tool-name extract_file_strings --tool-arg file_path=/bin/ls --tool-arg min_length=8

# Hex dump
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/call --tool-name hex_dump_file --tool-arg file_path=/bin/ls --tool-arg size=256

# Binary analysis
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/call --tool-name analyze_binary_file --tool-arg file_path=/bin/ls

# Get metadata
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/call --tool-name get_file_metadata --tool-arg file_path=/bin/ls
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