# Architecture

This document describes the internal architecture and design of File Scanner.

## Table of Contents

- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Core Components](#core-components)
- [Data Flow](#data-flow)
- [Module Design](#module-design)
- [Concurrency Model](#concurrency-model)
- [Error Handling](#error-handling)
- [Extension Points](#extension-points)

## Overview

File Scanner follows a modular, async-first architecture designed for:

- **Performance**: Parallel processing and async I/O
- **Extensibility**: Easy to add new analysis modules
- **Maintainability**: Clear separation of concerns
- **Reliability**: Comprehensive error handling
- **Flexibility**: Multiple output formats and transports

## System Architecture

```text
┌────────────────────────────────────────────────────────────┐
│                      CLI Interface                          │
│                    (main.rs, clap)                         │
└────────────────────┬──────────────────────────────────────┘
                     │
┌────────────────────▼──────────────────────────────────────┐
│                   Core Scanner Engine                      │
│              (orchestration, coordination)                 │
└────────────────────┬──────────────────────────────────────┘
                     │
     ┌───────────────┼───────────────┬─────────────────┐
     │               │               │                 │
┌────▼─────┐ ┌──────▼──────┐ ┌─────▼──────┐ ┌───────▼────┐
│Metadata  │ │   Hashing   │ │  Strings   │ │   Binary   │
│Extractor │ │   Engine    │ │ Extractor  │ │   Parser   │
└──────────┘ └─────────────┘ └────────────┘ └────────────┘
     │               │               │                 │
┌────▼─────┐ ┌──────▼──────┐ ┌─────▼──────┐ ┌───────▼────┐
│Signature │ │   Entropy   │ │  HexDump   │ │Disassembly │
│Verifier  │ │  Analyzer   │ │ Generator  │ │   Engine   │
└──────────┘ └─────────────┘ └────────────┘ └────────────┘
                     │
┌────────────────────▼──────────────────────────────────────┐
│                    Cache Layer                             │
│              (results, string tracking)                    │
└────────────────────┬──────────────────────────────────────┘
                     │
┌────────────────────▼──────────────────────────────────────┐
│                 Output Formatters                          │
│              (JSON, YAML, Pretty)                          │
└───────────────────────────────────────────────────────────┘
```

## Core Components

### Main Entry Point (`main.rs`)

Responsibilities:

- CLI argument parsing with clap
- Mode selection (scan vs MCP server)
- Top-level error handling
- Output formatting

```rust
fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { options } => run_scanner(options),
        Commands::McpStdio => run_mcp_stdio(),
        Commands::McpHttp { port } => run_mcp_http(port),
    }
}
```

### Metadata Module (`metadata.rs`)

Core data structures and file system metadata extraction:

```rust
pub struct FileMetadata {
    pub file_path: PathBuf,
    pub file_name: String,
    pub file_size: u64,
    pub created: Option<SystemTime>,
    pub modified: Option<SystemTime>,
    pub permissions: String,
    pub is_executable: bool,
    pub mime_type: String,
}
```

Key functions:

- `extract_metadata()` - Gathers file system information
- `detect_mime_type()` - MIME type detection
- `format_permissions()` - Unix permission formatting

### Hash Engine (`hash.rs`)

Async hash calculation with multiple algorithms:

```rust
pub struct HashResult {
    pub md5: String,
    pub sha256: String,
    pub sha512: String,
    pub blake3: String,
}
```

Features:

- Concurrent hash calculation using tokio
- Streaming API for large files
- Progress tracking support

### String Extractor (`strings.rs`)

Pattern-based string extraction and categorization:

```rust
pub struct ExtractedString {
    pub value: String,
    pub offset: u64,
    pub encoding: StringEncoding,
    pub category: StringCategory,
}

pub enum StringCategory {
    Url,
    Path,
    Import,
    Registry,
    Command,
    Suspicious,
    Generic,
}
```

Processing pipeline:

1. Raw byte scanning
2. Encoding detection (ASCII/UTF-16)
3. Pattern matching for categorization
4. Entropy calculation
5. Suspicious indicator detection

### Binary Parser (`binary_parser.rs`)

Format-specific binary analysis using goblin:

```rust
pub struct BinaryInfo {
    pub format: BinaryFormat,
    pub architecture: String,
    pub compiler: String,
    pub entry_point: u64,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
}
```

Supported formats:

- PE (Windows executables)
- ELF (Linux/Unix executables)
- Mach-O (macOS executables)

### MCP Server (`mcp_server.rs`)

Model Context Protocol implementation:

```rust
pub struct FileAnalysisServer {
    cache: Arc<Mutex<AnalysisCache>>,
    string_tracker: Arc<Mutex<StringTracker>>,
}

impl McpServer for FileAnalysisServer {
    async fn handle_tool_call(&self, name: &str, args: Value) -> Result<Value> {
        match name {
            "analyze_file" => self.analyze_file(args).await,
            "llm_analyze_file" => self.llm_analyze_file(args).await,
            _ => Err(Error::MethodNotFound),
        }
    }
}
```

### Cache System (`cache.rs`)

Persistent caching for analysis results:

```rust
pub struct AnalysisCache {
    entries: HashMap<String, CacheEntry>,
    db_path: PathBuf,
    max_size: usize,
    ttl: Duration,
}

pub struct CacheEntry {
    pub file_hash: String,
    pub analysis_results: HashMap<String, Value>,
    pub timestamp: SystemTime,
    pub access_count: u32,
}
```

Features:

- SHA256-based file identification
- LRU eviction policy
- Disk persistence
- Automatic cleanup

### String Tracker (`string_tracker.rs`)

Advanced string analysis and statistics:

```rust
pub struct StringTracker {
    strings: HashMap<String, StringInfo>,
    file_associations: HashMap<String, HashSet<String>>,
    statistics: StringStatistics,
}

pub struct StringInfo {
    pub value: String,
    pub occurrences: u32,
    pub files: HashSet<String>,
    pub entropy: f64,
    pub category: StringCategory,
    pub is_suspicious: bool,
}
```

## Data Flow

### Analysis Pipeline

```text
Input File
    │
    ├─► Metadata Extraction
    │      └─► Basic file info
    │
    ├─► Hash Calculation (Async)
    │      ├─► MD5
    │      ├─► SHA256
    │      ├─► SHA512
    │      └─► BLAKE3
    │
    ├─► Content Analysis
    │      ├─► String Extraction
    │      ├─► Binary Parsing
    │      └─► Entropy Analysis
    │
    ├─► Advanced Analysis
    │      ├─► Signature Verification
    │      ├─► Disassembly
    │      └─► Threat Detection
    │
    └─► Output Formatting
           ├─► JSON
           ├─► YAML
           └─► Pretty Print
```

### MCP Request Flow

```text
MCP Client Request
    │
    ├─► JSON-RPC Parse
    │
    ├─► Tool Router
    │      ├─► analyze_file
    │      └─► llm_analyze_file
    │
    ├─► Cache Check
    │      ├─► Hit → Return cached
    │      └─► Miss → Continue
    │
    ├─► File Analysis
    │      └─► Reuse scanner pipeline
    │
    ├─► Result Processing
    │      ├─► Cache storage
    │      └─► String tracking
    │
    └─► JSON-RPC Response
```

## Module Design

### Design Principles

1. **Single Responsibility**: Each module has one clear purpose
2. **Dependency Injection**: Modules receive dependencies via constructor
3. **Error Propagation**: Use `Result<T, Error>` throughout
4. **Async by Default**: I/O operations are async
5. **Zero-Copy Where Possible**: Use references and slices

### Module Template

```rust
pub struct ModuleName {
    config: ModuleConfig,
    dependencies: Arc<Dependencies>,
}

impl ModuleName {
    pub fn new(config: ModuleConfig, deps: Arc<Dependencies>) -> Self {
        Self {
            config,
            dependencies: deps,
        }
    }

    pub async fn analyze(&self, input: &[u8]) -> Result<ModuleOutput> {
        // Implementation
    }
}
```

## Concurrency Model

### Tokio Runtime

- Main runtime for async operations
- Default thread pool size: CPU cores
- Configurable via `TOKIO_WORKER_THREADS`

### Parallel Processing

```rust
// Hash calculation example
let handles: Vec<_> = vec![
    tokio::spawn(calculate_md5(data.clone())),
    tokio::spawn(calculate_sha256(data.clone())),
    tokio::spawn(calculate_sha512(data.clone())),
    tokio::spawn(calculate_blake3(data.clone())),
];

let results = futures::future::join_all(handles).await;
```

### Synchronization

- `Arc<Mutex<T>>` for shared mutable state
- `RwLock` for read-heavy workloads
- Channels for task communication

## Error Handling

### Error Types

```rust
#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Analysis failed: {0}")]
    Analysis(String),

    #[error("MCP error: {0}")]
    Mcp(#[from] MpcError),
}
```

### Error Strategy

1. Use `?` for propagation
2. Convert to user-friendly messages at boundaries
3. Log detailed errors for debugging
4. Never panic in library code

## Extension Points

### Adding New Analysis Modules

1. Create module in `src/analyzers/`
2. Define input/output types
3. Implement analyzer trait
4. Register in scanner pipeline
5. Add MCP tool binding

### Adding Output Formats

1. Implement `OutputFormatter` trait
2. Add format enum variant
3. Register in format selection
4. Update CLI arguments

### Adding MCP Tools

1. Define tool in `tool_definitions()`
2. Implement handler method
3. Add to tool router
4. Update documentation

## Performance Considerations

### Memory Management

- Stream large files instead of loading
- Use memory mapping for random access
- Implement chunked processing
- Clear caches periodically

### CPU Optimization

- Parallel hash calculation
- SIMD for string scanning (where available)
- Lazy evaluation of expensive operations
- Result caching

### I/O Optimization

- Async file operations
- Buffered reading
- Minimize syscalls
- Use sendfile for zero-copy

## Security Considerations

### Input Validation

- Path traversal prevention
- Size limits for operations
- Timeout for long operations
- Resource usage limits

### Process Isolation

- Drop privileges when possible
- Sanitize file paths
- Validate binary formats
- Limit recursion depth

## Future Architecture Goals

1. **Plugin System**: Dynamic loading of analyzers
2. **Distributed Processing**: Multi-machine scanning
3. **GPU Acceleration**: For pattern matching
4. **Real-time Monitoring**: File system watches
5. **Web UI**: Browser-based interface

## Testing Architecture

### Unit Tests

- Module-level testing
- Mock dependencies
- Property-based testing

### Integration Tests

- End-to-end scenarios
- Real file testing
- Performance benchmarks

### Fuzz Testing

- Input fuzzing for parsers
- Protocol fuzzing for MCP
- Format fuzzing for outputs
