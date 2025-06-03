# MCP (Model Context Protocol) Integration

File Scanner includes a full MCP server implementation, enabling seamless integration with AI assistants like Claude, Cursor, and other MCP-compatible tools.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Transport Modes](#transport-modes)
- [Available Tools](#available-tools)
- [Configuration](#configuration)
- [Testing](#testing)
- [Advanced Features](#advanced-features)
- [Troubleshooting](#troubleshooting)

## Overview

The Model Context Protocol (MCP) allows AI assistants to interact with external tools through a standardized JSON-RPC interface. File Scanner implements MCP to provide its analysis capabilities as tools that AI assistants can call.

### Key Benefits

- **Direct Integration**: AI assistants can analyze files without manual commands
- **Structured Output**: JSON responses perfect for AI processing
- **Smart Caching**: Automatic result caching for performance
- **Multiple Transports**: STDIO, HTTP, and SSE support
- **Comprehensive Tools**: Full scanner functionality exposed via MCP

## Quick Start

### With Claude Code

1. Add to your MCP configuration:

```json
{
  "mcpServers": {
    "file-scanner": {
      "command": "/path/to/file-scanner",
      "args": ["mcp-stdio"]
    }
  }
}
```

2. Restart Claude Code
3. Use commands like: "Analyze /path/to/file.exe for malware"

### With Cursor

1. Add to `.cursor/mcp.json`:

```json
{
  "servers": {
    "file-scanner": {
      "command": "file-scanner",
      "args": ["mcp-stdio"]
    }
  }
}
```

2. Restart Cursor
3. File Scanner tools will be available in the AI assistant

## Transport Modes

### STDIO Transport (Recommended)

Best for local AI assistants like Claude Code and Cursor.

```bash
# Start server
file-scanner mcp-stdio

# Test manually
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | file-scanner mcp-stdio
```

**Advantages:**

- Simple setup
- Low latency
- No network configuration
- Secure by default

### HTTP Transport

Best for remote access and web integrations.

```bash
# Start HTTP server
file-scanner mcp-http --port 3000

# Configuration
{
  "mcpServers": {
    "file-scanner-http": {
      "type": "http",
      "url": "http://localhost:3000/mcp"
    }
  }
}
```

**Additional Endpoints:**

- `/health` - Health check
- `/cache/stats` - Cache statistics
- `/cache/clear` - Clear cache
- `/strings/stats` - String tracking stats

### SSE Transport

Best for real-time streaming updates.

```bash
# Start SSE server
file-scanner mcp-sse --port 3000

# Configuration
{
  "mcpServers": {
    "file-scanner-sse": {
      "type": "sse",
      "url": "http://localhost:3000/sse"
    }
  }
}
```

## Available Tools

### 1. analyze_file

Comprehensive file analysis with configurable options.

**Tool Name:** `analyze_file`

**Description:** Performs comprehensive file analysis with selectable features

**Parameters:**

```typescript
{
  // Required
  file_path: string;           // Path to file to analyze

  // Optional analysis flags (all default to false)
  metadata?: boolean;          // File metadata
  hashes?: boolean;           // Cryptographic hashes
  strings?: boolean;          // String extraction
  hex_dump?: boolean;         // Hex dump
  binary_info?: boolean;      // Binary format analysis
  signatures?: boolean;       // Digital signatures
  symbols?: boolean;          // Symbol analysis
  control_flow?: boolean;     // Control flow analysis
  vulnerabilities?: boolean;  // Vulnerability detection
  code_quality?: boolean;     // Code quality metrics
  dependencies?: boolean;     // Dependency analysis
  entropy?: boolean;          // Entropy analysis
  disassembly?: boolean;      // Disassembly
  threats?: boolean;          // Threat detection
  behavioral?: boolean;       // Behavioral analysis
  yara_indicators?: boolean;  // YARA indicators

  // String extraction options
  min_string_length?: number;  // Min string length (default: 4)

  // Hex dump options
  hex_dump_size?: number;      // Bytes to dump (default: 256)
  hex_dump_offset?: number;    // Offset to start dump
}
```

**Example Usage:**

```json
{
  "tool": "analyze_file",
  "arguments": {
    "file_path": "/path/to/malware.exe",
    "metadata": true,
    "hashes": true,
    "strings": true,
    "threats": true,
    "behavioral": true
  }
}
```

**Example Response:**

```json
{
  "file_path": "/path/to/malware.exe",
  "file_name": "malware.exe",
  "file_size": 524288,
  "metadata": {
    "created": "2024-01-15T10:30:00Z",
    "modified": "2024-01-15T10:30:00Z",
    "permissions": "755",
    "is_executable": true,
    "mime_type": "application/x-msdownload"
  },
  "hashes": {
    "md5": "098f6bcd4621d373cade4e832627b4f6",
    "sha256": "5994471abb01112afcc18159f6cc74b4f511b993",
    "sha512": "3c9909afec25354d551dae21590bb26e38d53f21",
    "blake3": "b3a0c442fbf52960f76a6db5e73f235e2c2d8"
  },
  "strings": [
    {
      "value": "CreateRemoteThread",
      "offset": 4096,
      "encoding": "ASCII",
      "category": "api"
    }
  ],
  "threats": {
    "malware_indicators": ["process_injection", "persistence"],
    "risk_level": "high",
    "suspicious_apis": ["CreateRemoteThread", "VirtualAllocEx"]
  }
}
```

### 2. llm_analyze_file

Optimized analysis for LLM consumption with token limits.

**Tool Name:** `llm_analyze_file`

**Description:** Analyzes files with LLM-optimized output and YARA rule generation

**Parameters:**

```typescript
{
  // Required
  file_path: string;              // Path to file to analyze

  // Optional
  token_limit?: number;           // Max response size (default: 25000)
  min_string_length?: number;     // Min string length (default: 6)
  max_strings?: number;           // Max strings to return (default: 50)
  max_imports?: number;           // Max imports to return (default: 30)
  max_opcodes?: number;           // Max opcodes to return (default: 10)
  hex_pattern_size?: number;      // Size of hex patterns (default: 32)
  suggest_yara_rule?: boolean;    // Generate YARA rule (default: true)
}
```

**Example Usage:**

```json
{
  "tool": "llm_analyze_file",
  "arguments": {
    "file_path": "/suspicious/file.exe",
    "token_limit": 20000,
    "suggest_yara_rule": true
  }
}
```

**Example Response:**

```json
{
  "md5": "098f6bcd4621d373cade4e832627b4f6",
  "file_size": 45056,
  "key_strings": [
    "CreateRemoteThread",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
  ],
  "hex_patterns": [
    "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00"
  ],
  "imports": ["kernel32.dll", "ntdll.dll", "advapi32.dll"],
  "opcodes": ["E8 00 00 00 00", "48 8B 05 00"],
  "entropy": 7.8,
  "behavioral_indicators": [
    "Process injection capability",
    "Registry persistence mechanism"
  ],
  "yara_rule_suggestion": "rule suspicious_file {\n    meta:\n        md5 = \"098f6bcd4621d373cade4e832627b4f6\"\n    strings:\n        $api1 = \"CreateRemoteThread\"\n        $api2 = \"VirtualAllocEx\"\n    condition:\n        uint16(0) == 0x5A4D and all of ($api*)\n}"
}
```

## Configuration

### Claude Code Configuration

Location: `~/Library/Application Support/Claude/mcp.json` (macOS)
or `%APPDATA%\Claude\mcp.json` (Windows)

```json
{
  "mcpServers": {
    "file-scanner": {
      "command": "/usr/local/bin/file-scanner",
      "args": ["mcp-stdio"],
      "env": {
        "RUST_LOG": "info"
      }
    }
  }
}
```

### Environment Variables

```bash
# Logging level
export RUST_LOG=debug

# Cache directory
export FILE_SCANNER_CACHE_DIR=/tmp/scanner-cache

# String tracking database
export FILE_SCANNER_DB_PATH=/var/lib/file-scanner/strings.db
```

### Advanced Configuration

```json
{
  "mcpServers": {
    "file-scanner": {
      "command": "file-scanner",
      "args": ["mcp-stdio"],
      "env": {
        "RUST_LOG": "file_scanner=debug",
        "FILE_SCANNER_CACHE_SIZE": "1000",
        "FILE_SCANNER_CACHE_TTL": "3600"
      },
      "timeout": 30000,
      "maxRetries": 3
    }
  }
}
```

## Testing

### MCP Inspector

```bash
# Install MCP Inspector
npm install -g @modelcontextprotocol/inspector

# Interactive UI
mcp-inspector file-scanner mcp-stdio

# CLI testing
mcp-inspector --cli file-scanner mcp-stdio --method tools/list

# Test specific tool
mcp-inspector --cli file-scanner mcp-stdio \
  --method tools/call \
  --tool-name analyze_file \
  --tool-arg file_path=/bin/ls \
  --tool-arg metadata=true
```

### Manual Testing

```bash
# List tools
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | \
  file-scanner mcp-stdio | jq

# Call analyze_file
echo '{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "analyze_file",
    "arguments": {
      "file_path": "/bin/ls",
      "metadata": true,
      "hashes": true
    }
  },
  "id": 2
}' | file-scanner mcp-stdio | jq
```

### HTTP Testing

```bash
# Health check
curl http://localhost:3000/health

# List tools via HTTP
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'

# Call tool via HTTP
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "analyze_file",
      "arguments": {
        "file_path": "/bin/ls",
        "hashes": true
      }
    },
    "id": 2
  }'
```

## Advanced Features

### Cache Management

The MCP server includes automatic caching for improved performance.

```bash
# View cache statistics (HTTP only)
curl http://localhost:3000/cache/stats

# Response
{
  "total_entries": 42,
  "total_size_bytes": 1048576,
  "hit_rate": 0.85,
  "oldest_entry": "2024-01-15T10:30:00Z"
}

# Clear cache
curl -X POST http://localhost:3000/cache/clear

# Search cache
curl -X POST http://localhost:3000/cache/search \
  -H "Content-Type: application/json" \
  -d '{"file_path": "/bin/ls"}'
```

### String Tracking

Advanced string analysis and tracking across files.

```bash
# String statistics
curl http://localhost:3000/strings/stats

# Search strings
curl -X POST http://localhost:3000/strings/search \
  -H "Content-Type: application/json" \
  -d '{"query": "CreateThread", "limit": 10}'

# Find related strings
curl -X POST http://localhost:3000/strings/related \
  -H "Content-Type: application/json" \
  -d '{"value": "kernel32.dll", "limit": 5}'
```

### Performance Optimization

```bash
# Enable aggressive caching
export FILE_SCANNER_CACHE_MODE=aggressive

# Increase worker threads
export FILE_SCANNER_THREADS=8

# Enable memory mapping for large files
export FILE_SCANNER_USE_MMAP=true
```

## Troubleshooting

### Common Issues

#### Tool Not Found

```bash
# Check if MCP server is running
ps aux | grep file-scanner

# Verify tool listing
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | \
  file-scanner mcp-stdio
```

#### Permission Errors

```bash
# Ensure file-scanner is executable
chmod +x /path/to/file-scanner

# Check file permissions
ls -la /path/to/analyze/file
```

#### Timeout Issues

```json
{
  "mcpServers": {
    "file-scanner": {
      "command": "file-scanner",
      "args": ["mcp-stdio"],
      "timeout": 60000  // Increase timeout to 60s
    }
  }
}
```

### Debug Mode

```bash
# Enable debug logging
export RUST_LOG=debug
file-scanner mcp-stdio

# Log to file
export RUST_LOG=debug
file-scanner mcp-stdio 2> mcp-debug.log
```

### Error Messages

- `Method not found`: Update to latest file-scanner version
- `Invalid params`: Check parameter names and types
- `File not found`: Verify file path is absolute
- `Timeout`: Large file analysis may need timeout increase

## Best Practices

1. **Use Absolute Paths**: Always provide absolute file paths
2. **Select Only Needed Analysis**: Don't use all flags unnecessarily
3. **Monitor Cache Size**: Clear cache periodically for long-running servers
4. **Set Appropriate Timeouts**: Increase for large file analysis
5. **Use Token Limits**: With `llm_analyze_file` for AI contexts

## Integration Examples

### With Claude Code

```python
# In Claude Code, you can say:
"Analyze /home/user/suspicious.exe for malware indicators"
"Check if /usr/bin/app is digitally signed"
"Extract strings from /tmp/unknown.bin"
```

### With Custom Scripts

```python
import json
import subprocess

def analyze_file(file_path):
    request = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "analyze_file",
            "arguments": {
                "file_path": file_path,
                "metadata": True,
                "hashes": True,
                "threats": True
            }
        },
        "id": 1
    }

    result = subprocess.run(
        ["file-scanner", "mcp-stdio"],
        input=json.dumps(request),
        capture_output=True,
        text=True
    )

    return json.loads(result.stdout)
```

## Next Steps

- Review [Architecture](ARCHITECTURE.md) to understand internals
- Check [Performance Guide](PERFORMANCE.md) for optimization
- See [API Documentation](API.md) for Rust integration
- Read [FAQ](FAQ.md) for common questions
