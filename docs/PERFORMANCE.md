# Performance Guide

This guide covers performance characteristics, benchmarks, and optimization strategies for File Scanner.

## Table of Contents

- [Benchmarks](#benchmarks)
- [Performance Characteristics](#performance-characteristics)
- [Optimization Strategies](#optimization-strategies)
- [Resource Management](#resource-management)
- [Tuning Parameters](#tuning-parameters)
- [Profiling](#profiling)
- [Best Practices](#best-practices)

## Benchmarks

### Standard Benchmark Suite

Performance on common file types (Intel i7-9700K, 32GB RAM, NVMe SSD):

| File Type | Size | Basic Scan | Full Analysis | Memory Usage |
|-----------|------|------------|---------------|--------------|
| Text | 1 MB | 12ms | 45ms | 8 MB |
| Text | 100 MB | 150ms | 800ms | 120 MB |
| Binary | 1 MB | 15ms | 120ms | 12 MB |
| Binary | 100 MB | 200ms | 2.5s | 180 MB |
| Binary | 1 GB | 1.8s | 18s | 450 MB |
| PE/EXE | 10 MB | 80ms | 350ms | 45 MB |
| ELF | 10 MB | 75ms | 320ms | 42 MB |

### Operation Breakdown

Time spent in each component for a typical 10MB executable:

```
Total: 350ms
├── File I/O: 25ms (7%)
├── Metadata: 5ms (1%)
├── Hashing: 120ms (34%)
│   ├── MD5: 28ms
│   ├── SHA256: 32ms
│   ├── SHA512: 35ms
│   └── BLAKE3: 25ms
├── Strings: 80ms (23%)
├── Binary Parse: 45ms (13%)
├── Signatures: 60ms (17%)
└── Other: 15ms (5%)
```

### Concurrent Performance

Parallel file processing scaling:

| Files | Sequential | 2 Threads | 4 Threads | 8 Threads |
|-------|------------|-----------|-----------|-----------|
| 10 | 3.5s | 1.8s | 1.0s | 0.8s |
| 100 | 35s | 18s | 9.5s | 5.2s |
| 1000 | 350s | 178s | 92s | 48s |

## Performance Characteristics

### Memory Usage

Memory consumption patterns:

```
Base overhead: ~5MB
Per-file overhead: ~2MB
String extraction: ~1MB per 1000 strings
Binary parsing: ~10% of file size
Hash calculation: ~64KB buffer per algorithm
Cache overhead: ~1KB per cached result
```

### CPU Usage

CPU utilization by operation:

- **Hash Calculation**: CPU-bound, benefits from SIMD
- **String Extraction**: Memory-bound, cache-friendly
- **Binary Parsing**: Mixed, depends on format complexity
- **Entropy Calculation**: CPU-bound, vectorizable
- **Signature Verification**: I/O-bound for external tools

### I/O Patterns

File access patterns:

```
Metadata: 1 stat() call
Hashing: Sequential read, full file
Strings: Sequential read, full file
Binary: Random access, header + sections
Hex dump: Single read at offset
```

## Optimization Strategies

### 1. Selective Analysis

Only enable needed features:

```rust
// Fast mode - minimal analysis
let options = ScanOptions {
    metadata: true,
    hashes: false,  // Skip expensive hashing
    strings: false, // Skip string extraction
    binary_info: true,
    ..Default::default()
};

// Benchmark: 10MB file
// Full analysis: 350ms
// Fast mode: 45ms (87% faster)
```

### 2. Hash Algorithm Selection

Choose appropriate hash algorithms:

```rust
// For integrity checking only
let options = HashOptions {
    md5: false,     // Skip if not needed
    sha256: true,   // Good balance
    sha512: false,  // Skip if not needed
    blake3: true,   // Fastest option
};

// Performance comparison (100MB file):
// All hashes: 480ms
// SHA256 only: 120ms
// BLAKE3 only: 95ms
```

### 3. String Extraction Limits

Configure string extraction:

```rust
let options = StringOptions {
    min_length: 8,      // Increase to reduce results
    max_strings: 1000,  // Limit total strings
    max_memory: 10_000_000, // 10MB limit
};

// Impact on 50MB binary:
// Default (min=4): 2.5s, 50K strings
// Optimized (min=8): 0.8s, 5K strings
```

### 4. Memory Mapping

Use memory mapping for large files:

```bash
# Enable via environment
export FILE_SCANNER_USE_MMAP=true
export FILE_SCANNER_MMAP_THRESHOLD=10485760  # 10MB

# Performance gain on 1GB file:
# Regular I/O: 8.2s
# Memory mapped: 5.1s (38% faster)
```

### 5. Parallel Processing

Process multiple files concurrently:

```rust
use rayon::prelude::*;

let results: Vec<_> = files
    .par_iter()
    .map(|file| scanner.analyze_file(file))
    .collect();

// Scaling efficiency:
// 1 thread: 100%
// 2 threads: 195%
// 4 threads: 380%
// 8 threads: 720%
```

## Resource Management

### Memory Limits

Configure memory usage:

```rust
// Global memory limit
std::env::set_var("FILE_SCANNER_MAX_MEMORY", "1073741824"); // 1GB

// Per-operation limits
let options = ScanOptions {
    max_file_size: 500_000_000,     // 500MB
    string_extraction_limit: 10_000_000, // 10MB
    binary_parse_limit: 50_000_000,      // 50MB
};
```

### CPU Throttling

Control CPU usage:

```rust
// Limit thread pool size
std::env::set_var("RAYON_NUM_THREADS", "4");

// Add delays for rate limiting
let options = ScanOptions {
    rate_limit: Some(Duration::from_millis(10)),
};
```

### Timeout Configuration

Prevent hanging on problematic files:

```rust
let options = ScanOptions {
    timeout: Some(Duration::from_secs(30)),
    per_operation_timeout: Some(Duration::from_secs(10)),
};
```

## Tuning Parameters

### Environment Variables

```bash
# Threading
export RAYON_NUM_THREADS=8
export TOKIO_WORKER_THREADS=4

# Memory
export FILE_SCANNER_MAX_MEMORY=2147483648  # 2GB
export FILE_SCANNER_USE_MMAP=true
export FILE_SCANNER_MMAP_THRESHOLD=10485760  # 10MB

# Caching
export FILE_SCANNER_CACHE_SIZE=10000
export FILE_SCANNER_CACHE_TTL=3600  # 1 hour

# Debugging
export RUST_LOG=file_scanner=info
export FILE_SCANNER_PROFILE=true
```

### Configuration File

Create `.file-scanner.toml`:

```toml
[performance]
thread_count = 8
use_mmap = true
mmap_threshold = 10_485_760

[limits]
max_file_size = 1_073_741_824  # 1GB
max_memory = 2_147_483_648     # 2GB
timeout_seconds = 60

[cache]
enabled = true
max_entries = 10000
ttl_seconds = 3600

[string_extraction]
min_length = 6
max_strings = 50000
max_memory = 104_857_600  # 100MB
```

## Profiling

### CPU Profiling

Using flamegraph:

```bash
# Install flamegraph
cargo install flamegraph

# Profile execution
flamegraph -o profile.svg -- file-scanner /path/to/large/file

# View results
firefox profile.svg
```

### Memory Profiling

Using Valgrind:

```bash
# Memory usage analysis
valgrind --tool=massif --massif-out-file=massif.out \
    ./target/release/file-scanner /path/to/file

# Visualize results
ms_print massif.out > memory_profile.txt
```

### Built-in Metrics

Enable performance metrics:

```bash
# Run with metrics
FILE_SCANNER_METRICS=true file-scanner /path/to/file

# Output includes:
# - Operation timings
# - Memory usage
# - Cache statistics
# - Thread utilization
```

## Best Practices

### 1. File Type Optimization

```rust
// Optimize based on file type
match mime_type.as_str() {
    "text/plain" => {
        // Skip binary analysis for text files
        options.binary_info = false;
        options.signatures = false;
    }
    "application/x-executable" => {
        // Full analysis for executables
        options = ScanOptions::full();
    }
    _ => {
        // Balanced defaults
        options = ScanOptions::default();
    }
}
```

### 2. Batch Processing

```rust
// Process files in batches
const BATCH_SIZE: usize = 100;

for chunk in files.chunks(BATCH_SIZE) {
    let results = process_batch(chunk).await;
    save_results(results).await?;

    // Clear caches between batches
    scanner.clear_cache();
}
```

### 3. Progressive Analysis

```rust
// Start with fast analysis
let quick_result = scanner.quick_scan(file).await?;

// Only do full analysis if needed
if quick_result.is_suspicious() {
    let full_result = scanner.full_analysis(file).await?;
}
```

### 4. Cache Strategy

```rust
// Implement smart caching
let cache_key = format!("{}-{}", file_hash, options_hash);

if let Some(cached) = cache.get(&cache_key) {
    return Ok(cached);
}

let result = expensive_analysis(file).await?;
cache.insert(cache_key, result.clone());
```

### 5. Resource Pooling

```rust
// Reuse expensive resources
lazy_static! {
    static ref HASH_POOL: ObjectPool<Hasher> = ObjectPool::new(|| {
        Hasher::new()
    });
}

// Use pooled hasher
let mut hasher = HASH_POOL.pull();
hasher.update(data);
let hash = hasher.finalize();
```

## Performance Monitoring

### Metrics Collection

```rust
#[derive(Debug)]
struct PerformanceMetrics {
    total_time: Duration,
    operation_times: HashMap<String, Duration>,
    memory_peak: usize,
    cache_hits: u64,
    cache_misses: u64,
}

impl Scanner {
    pub fn with_metrics(self) -> MetricsScanner {
        MetricsScanner::new(self)
    }
}
```

### Real-time Monitoring

```bash
# Monitor scanner performance
watch -n 1 'ps aux | grep file-scanner'

# Monitor system resources
htop -p $(pgrep file-scanner)

# Monitor I/O
iotop -p $(pgrep file-scanner)
```

## Optimization Checklist

Before deploying to production:

- [ ] Profile typical workloads
- [ ] Set appropriate resource limits
- [ ] Configure optimal thread counts
- [ ] Enable caching where beneficial
- [ ] Test timeout configurations
- [ ] Monitor memory usage patterns
- [ ] Benchmark against requirements
- [ ] Document performance characteristics

## Next Steps

- Read [Architecture](ARCHITECTURE.md) for design details
- Check [API Documentation](API.md) for programmatic usage
- See [Troubleshooting](FAQ.md) for common issues
