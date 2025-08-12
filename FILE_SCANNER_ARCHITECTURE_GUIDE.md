# File Scanner Architecture Guide

## Overview

File Scanner is a comprehensive Rust-based file analysis tool that combines security scanning, metadata extraction, and vulnerability detection into a unified system. It operates in both standalone CLI mode and as an MCP (Model Context Protocol) server.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                   USER INTERFACE                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│  CLI Mode                    │  MCP Server Mode                                 │
│  ┌─────────────────┐        │  ┌──────────────┬────────────┬────────────┐     │
│  │   clap Parser   │        │  │    STDIO     │    HTTP    │    SSE     │     │
│  │  (standalone)   │        │  │  Transport   │ Transport  │ Transport  │     │
│  └────────┬────────┘        │  └──────┬───────┴─────┬──────┴─────┬──────┘     │
│           │                 │          │             │             │            │
│           ▼                 │          ▼             ▼             ▼            │
│  ┌─────────────────┐        │  ┌─────────────────────────────────────────┐     │
│  │  Direct File    │        │  │          MCP Request Handler            │     │
│  │   Analysis      │        │  │  ┌─────────────────────────────────┐   │     │
│  └────────┬────────┘        │  │  │        Tool Dispatcher          │   │     │
│           │                 │  │  └─────────────────────────────────┘   │     │
└───────────┼─────────────────┴──┴──────────────────┬─────────────────────┴─────┘
            │                                        │
            ▼                                        ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│                           ANALYSIS ORCHESTRATOR                                │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                         FileMetadata Builder                             │ │
│  │  ┌──────────┬──────────┬───────────┬──────────┬────────────────────┐   │ │
│  │  │ Metadata │   Hash   │  String   │  Binary  │ Signature/Package  │   │ │
│  │  │ Extractor│ Calculator│ Extractor │  Parser  │    Analyzers      │   │ │
│  │  └──────────┴──────────┴───────────┴──────────┴────────────────────┘   │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────┬───────────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼───────────────────────────────────────────┐
│                           CORE ANALYSIS MODULES                                │
├─────────────────┬─────────────────┬─────────────────┬───────────────────────┤
│   Metadata.rs   │    Hash.rs      │   Strings.rs    │  Binary_parser.rs     │
│ ┌─────────────┐ │ ┌─────────────┐ │ ┌─────────────┐ │ ┌─────────────────┐  │
│ │ File Stats  │ │ │   Async     │ │ │ASCII/Unicode│ │ │ ELF/PE/Mach-O  │  │
│ │ MIME Type   │ │ │ Concurrent  │ │ │ Extraction  │ │ │ Import/Export  │  │
│ │ Permissions │ │ │   MD5       │ │ │ Categories  │ │ │ Compiler Info  │  │
│ │ Timestamps  │ │ │  SHA256     │ │ │  Entropy    │ │ │ Architecture   │  │
│ └─────────────┘ │ │  SHA512     │ │ └─────────────┘ │ └─────────────────┘  │
│                 │ │  BLAKE3     │ │                 │                       │
│                 │ └─────────────┘ │                 │                       │
├─────────────────┴─────────────────┴─────────────────┴───────────────────────┤
│                        SPECIALIZED ANALYZERS                                  │
├────────────────┬────────────────┬─────────────────┬──────────────────────────┤
│ Signature.rs   │ NPM_analysis   │ Python_analysis │    Java_analysis         │
│ ┌────────────┐ │ ┌────────────┐ │ ┌─────────────┐ │ ┌──────────────────┐   │
│ │Authenticode│ │ │Package.json│ │ │  Setup.py   │ │ │  JAR/Class File  │   │
│ │    GPG     │ │ │Dependencies│ │ │Requirements │ │ │  Manifest Info   │   │
│ │  macOS     │ │ │  Scripts   │ │ │  Wheel/Tar  │ │ │  Dependencies    │   │
│ │   Certs    │ │ │Typosquatting│ │ │Typosquatting│ │ │  Bytecode Stats  │   │
│ └────────────┘ │ └────────────┘ │ └─────────────┘ │ └──────────────────┘   │
├────────────────┴────────────────┴─────────────────┴──────────────────────────┤
│                      PERFORMANCE & PERSISTENCE                                 │
├──────────────────────────────┬────────────────────────────────────────────────┤
│         Cache.rs             │            String_tracker.rs                   │
│ ┌──────────────────────────┐ │ ┌────────────────────────────────────────┐   │
│ │  SHA256 File Identity    │ │ │   Global String Occurrence Tracking    │   │
│ │  LRU Eviction Policy     │ │ │   Similarity Analysis & Clustering     │   │
│ │  Async Persistence       │ │ │   Suspicious Pattern Detection         │   │
│ │  Search & Statistics     │ │ │   Category-based Filtering             │   │
│ └──────────────────────────┘ │ └────────────────────────────────────────┘   │
└──────────────────────────────┴────────────────────────────────────────────────┘
```

## Data Flow Diagram

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  Input File │────▶│ File Reader  │────▶│ Metadata Extract│
└─────────────┘     └──────┬───────┘     └────────┬────────┘
                           │                       │
                           ▼                       ▼
                    ┌──────────────┐       ┌──────────────┐
                    │ Hash Workers │       │ MIME Detector│
                    │  (Parallel)  │       └──────┬───────┘
                    └──────┬───────┘              │
                           │                      ▼
                           ▼              ┌───────────────┐
                    ┌──────────────┐      │ Binary Parser │──┐
                    │String Extract│      └───────────────┘  │
                    └──────┬───────┘                         │
                           │         ┌─────────────────┐     │
                           ▼         │Package Analyzers│◀────┘
                    ┌──────────────┐ └────────┬────────┘
                    │String Tracker│          │
                    └──────┬───────┘          ▼
                           │         ┌─────────────────┐
                           └────────▶│ FileMetadata    │
                                    │ (Aggregated)     │
                                    └────────┬─────────┘
                                             │
                           ┌─────────────────┼─────────────────┐
                           ▼                 ▼                 ▼
                    ┌──────────┐      ┌──────────┐     ┌──────────┐
                    │  Cache   │      │   JSON   │     │   MCP    │
                    │  Store   │      │  Output  │     │ Response │
                    └──────────┘      └──────────┘     └──────────┘
```

## Component Deep Dive

### 1. Entry Point & CLI (main.rs)

**What it does well:**
- Clean separation between CLI and MCP modes
- Flexible output formatting options
- Comprehensive error handling
- Well-structured command-line interface

**Architecture Pattern:**
```rust
match args.command {
    Commands::McpStdio => run_mcp_stdio_server(),
    Commands::McpHttp { port } => run_mcp_http_server(port),
    Commands::McpSse { port } => run_mcp_sse_server(port),
    None => run_standalone_analysis(args),
}
```

### 2. Concurrent Hash Calculation

**What it does well:**
- Parallel processing with controlled concurrency
- Resource-aware with global semaphore (limit: 10)
- Efficient memory usage with buffered reading

**Implementation:**
```rust
// Semaphore prevents system overload
static HASH_SEMAPHORE: Lazy<Semaphore> = Lazy::new(|| Semaphore::new(10));

// Concurrent hash calculation
let tasks = vec![
    tokio::spawn(calculate_hash::<Md5>()),
    tokio::spawn(calculate_hash::<Sha256>()),
    tokio::spawn(calculate_hash::<Sha512>()),
    tokio::spawn(calculate_blake3()),
];
```

### 3. String Analysis Architecture

**What it does well:**
- Multi-encoding support (ASCII, UTF-16 LE/BE)
- Intelligent categorization system
- Memory-bounded processing

**Categories Detected:**
- URLs and domains
- File paths and registry keys
- API imports and function names
- Commands and credentials
- Suspicious patterns

### 4. Cache System Design

**What it does well:**
- SHA256-based file identification (content-aware)
- Async persistence without blocking
- LRU eviction with configurable limits
- Rich search and filtering API

**Performance Features:**
```rust
// Non-blocking save operations
tokio::spawn(async move {
    let _permit = SAVE_SEMAPHORE.acquire().await;
    // Save to disk
});

// Efficient memory management
if self.entries.len() > MAX_CACHE_ENTRIES {
    self.evict_oldest();
}
```

### 5. MCP Server Integration

**What it does well:**
- Multiple transport options (STDIO, HTTP, SSE)
- Comprehensive tool set with focused responsibilities
- Token-aware responses for LLM integration
- OpenAPI 3.0 documentation

**Tool Architecture:**
```
┌────────────────────┐
│   analyze_file     │ ← Comprehensive analysis with flags
├────────────────────┤
│ llm_analyze_file   │ ← Optimized for LLM consumption
├────────────────────┤
│  yara_scan_file    │ ← Custom YARA rule scanning
├────────────────────┤
│analyze_java_file   │ ← Java-specific analysis
├────────────────────┤
│analyze_npm_package │ ← NPM security analysis
├────────────────────┤
│analyze_python_pkg  │ ← Python security analysis
└────────────────────┘
```

## Strengths of the Architecture

### 1. **Modularity & Separation of Concerns**
- Each module has a single, well-defined responsibility
- Easy to test individual components
- Clear interfaces between modules

### 2. **Performance Optimization**
- Async/await throughout for non-blocking I/O
- Resource pooling with semaphores
- Intelligent caching with persistence
- Memory-bounded operations

### 3. **Security-First Design**
- Comprehensive malware detection patterns
- Vulnerability databases for packages
- Typosquatting detection
- Supply chain risk assessment

### 4. **Extensibility**
- Easy to add new file formats
- Plugin-ready architecture
- Multiple output formats
- Transport-agnostic MCP server

### 5. **Error Handling**
- Graceful degradation
- Detailed error messages
- No panics in production code
- Proper resource cleanup

## Areas for Improvement

### 1. **Architecture Enhancements**

**Plugin System:**
```rust
// Proposed plugin trait
trait FileAnalyzer {
    fn analyze(&self, file: &Path) -> Result<AnalysisResult>;
    fn supported_types(&self) -> Vec<String>;
}

// Dynamic loading
let analyzers = load_plugins("/usr/local/lib/file-scanner/plugins");
```

**Configuration Management:**
```yaml
# Proposed config.yaml
analysis:
  default_hash_algorithms: [sha256, blake3]
  max_string_length: 1000
  cache_size: 10000
  
security:
  enable_yara_rules: true
  custom_rules_path: "/etc/file-scanner/rules"
```

### 2. **Performance Improvements**

**Streaming Analysis for Large Files:**
```rust
// Current: Load entire file
let contents = fs::read(&path)?;

// Proposed: Stream processing
let reader = BufReader::new(File::open(&path)?);
for chunk in reader.chunks(CHUNK_SIZE) {
    analyze_chunk(chunk)?;
}
```

**Distributed Analysis:**
```rust
// Proposed distributed architecture
trait DistributedAnalyzer {
    async fn submit_job(&self, file: FileRef) -> JobId;
    async fn get_results(&self, job_id: JobId) -> Result<Analysis>;
}
```

### 3. **Enhanced Features**

**Machine Learning Integration:**
```rust
// Proposed ML-based detection
struct MalwareDetector {
    model: TensorFlowModel,
    feature_extractor: FeatureExtractor,
}

impl MalwareDetector {
    fn predict_malicious(&self, features: &Features) -> f32 {
        self.model.predict(features)
    }
}
```

**Real-time Monitoring:**
```rust
// Proposed file system watcher
let watcher = FileWatcher::new("/monitored/path");
watcher.on_change(|event| {
    match event {
        Created(path) => analyze_new_file(path),
        Modified(path) => reanalyze_file(path),
        _ => {}
    }
});
```

### 4. **API Improvements**

**GraphQL Support:**
```graphql
type Query {
  analyzeFile(path: String!, options: AnalysisOptions): FileAnalysis
  searchCache(query: CacheQuery): [CacheEntry]
  getStringStats: StringStatistics
}

type Subscription {
  analysisProgress(jobId: ID!): AnalysisProgress
}
```

**Rate Limiting:**
```rust
// Proposed rate limiter
let rate_limiter = RateLimiter::new(100, Duration::from_secs(60));

async fn handle_request(req: Request) -> Result<Response> {
    rate_limiter.check_key(&req.client_ip).await?;
    process_request(req).await
}
```

## Best Practices Demonstrated

1. **Async-First Design**: Tokio runtime with proper task management
2. **Resource Management**: Semaphores, memory limits, and cleanup
3. **Type Safety**: Strong typing with serde for serialization
4. **Error Propagation**: Consistent use of Result types
5. **Documentation**: Comprehensive inline documentation
6. **Testing Strategy**: Unit tests for core components

## Conclusion

File Scanner demonstrates excellent architectural design with:
- Clear separation of concerns
- Robust error handling
- Performance-conscious implementation
- Security-focused features
- Extensible design

The modular architecture makes it easy to maintain and extend while the comprehensive analysis capabilities make it suitable for various use cases from security research to compliance auditing. The suggested improvements would further enhance its capabilities while maintaining the strong foundation already in place.