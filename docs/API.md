# API Documentation

File Scanner can be used as a Rust library for programmatic file analysis.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core API](#core-api)
- [Analysis Modules](#analysis-modules)
- [Data Types](#data-types)
- [Error Handling](#error-handling)
- [Async Operations](#async-operations)
- [Examples](#examples)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
file-scanner = "0.1.0"

# Optional features
[dependencies.file-scanner]
version = "0.1.0"
features = ["mcp", "advanced-analysis"]
```

## Quick Start

```rust
use file_scanner::{Scanner, ScanOptions};
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create scanner with default options
    let scanner = Scanner::new();

    // Analyze a file
    let result = scanner.analyze_file(Path::new("/path/to/file")).await?;

    // Print results
    println!("File: {}", result.file_name);
    println!("Size: {} bytes", result.file_size);
    println!("MD5: {}", result.hashes.md5);

    Ok(())
}
```

## Core API

### Scanner

The main entry point for file analysis.

```rust
pub struct Scanner {
    options: ScanOptions,
    cache: Option<AnalysisCache>,
}

impl Scanner {
    /// Create a new scanner with default options
    pub fn new() -> Self;

    /// Create a scanner with custom options
    pub fn with_options(options: ScanOptions) -> Self;

    /// Analyze a single file
    pub async fn analyze_file(&self, path: &Path) -> Result<AnalysisResult>;

    /// Analyze multiple files in parallel
    pub async fn analyze_files(&self, paths: &[PathBuf]) -> Result<Vec<AnalysisResult>>;
}
```

### ScanOptions

Configuration for the scanner.

```rust
pub struct ScanOptions {
    /// Enable metadata extraction
    pub metadata: bool,

    /// Enable hash calculation
    pub hashes: bool,

    /// Enable string extraction
    pub strings: bool,

    /// String extraction options
    pub string_options: StringOptions,

    /// Enable hex dump
    pub hex_dump: bool,

    /// Hex dump options
    pub hex_dump_options: HexDumpOptions,

    /// Enable binary analysis
    pub binary_info: bool,

    /// Enable signature verification
    pub signatures: bool,

    /// Enable advanced analysis
    pub advanced: AdvancedOptions,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            metadata: true,
            hashes: true,
            strings: false,
            string_options: StringOptions::default(),
            hex_dump: false,
            hex_dump_options: HexDumpOptions::default(),
            binary_info: true,
            signatures: false,
            advanced: AdvancedOptions::default(),
        }
    }
}
```

### AnalysisResult

The complete result of file analysis.

```rust
pub struct AnalysisResult {
    /// File metadata
    pub metadata: FileMetadata,

    /// Hash results (if enabled)
    pub hashes: Option<HashResult>,

    /// Extracted strings (if enabled)
    pub strings: Option<Vec<ExtractedString>>,

    /// Hex dump (if enabled)
    pub hex_dump: Option<String>,

    /// Binary information (if enabled)
    pub binary_info: Option<BinaryInfo>,

    /// Digital signatures (if enabled)
    pub signatures: Option<SignatureInfo>,

    /// Advanced analysis results
    pub advanced: Option<AdvancedAnalysis>,
}
```

## Analysis Modules

### Metadata Extraction

```rust
use file_scanner::metadata::{extract_metadata, FileMetadata};

let metadata = extract_metadata(Path::new("/path/to/file"))?;
println!("File size: {} bytes", metadata.file_size);
println!("MIME type: {}", metadata.mime_type);
```

### Hash Calculation

```rust
use file_scanner::hash::{calculate_hashes, HashResult};

let hashes = calculate_hashes(Path::new("/path/to/file")).await?;
println!("MD5: {}", hashes.md5);
println!("SHA256: {}", hashes.sha256);
println!("SHA512: {}", hashes.sha512);
println!("BLAKE3: {}", hashes.blake3);
```

### String Extraction

```rust
use file_scanner::strings::{extract_strings, StringOptions};

let options = StringOptions {
    min_length: 6,
    max_strings: 1000,
    encoding: vec![StringEncoding::Ascii, StringEncoding::Utf16Le],
};

let strings = extract_strings(Path::new("/path/to/file"), &options)?;
for s in strings {
    println!("{}: {} (category: {:?})", s.offset, s.value, s.category);
}
```

### Binary Analysis

```rust
use file_scanner::binary_parser::{parse_binary, BinaryInfo};

let binary_info = parse_binary(Path::new("/path/to/binary"))?;
match binary_info {
    Some(info) => {
        println!("Format: {:?}", info.format);
        println!("Architecture: {}", info.architecture);
        println!("Entry point: 0x{:x}", info.entry_point);
    }
    None => println!("Not a recognized binary format"),
}
```

### Signature Verification

```rust
use file_scanner::signature::{verify_signatures, SignatureInfo};

let signatures = verify_signatures(Path::new("/path/to/signed/file"))?;
if signatures.valid {
    println!("Valid signature from: {}", signatures.signer.unwrap_or_default());
} else {
    println!("Invalid or no signature");
}
```

## Data Types

### FileMetadata

```rust
pub struct FileMetadata {
    pub file_path: PathBuf,
    pub file_name: String,
    pub file_size: u64,
    pub created: Option<SystemTime>,
    pub modified: Option<SystemTime>,
    pub accessed: Option<SystemTime>,
    pub permissions: String,
    pub is_executable: bool,
    pub is_hidden: bool,
    pub mime_type: String,
}
```

### HashResult

```rust
pub struct HashResult {
    pub md5: String,
    pub sha256: String,
    pub sha512: String,
    pub blake3: String,
}
```

### ExtractedString

```rust
pub struct ExtractedString {
    pub value: String,
    pub offset: u64,
    pub length: usize,
    pub encoding: StringEncoding,
    pub category: StringCategory,
    pub entropy: f64,
}

pub enum StringEncoding {
    Ascii,
    Utf16Le,
    Utf16Be,
}

pub enum StringCategory {
    Url,
    Path,
    Email,
    IpAddress,
    Import,
    Registry,
    Command,
    Suspicious,
    Generic,
}
```

### BinaryInfo

```rust
pub struct BinaryInfo {
    pub format: BinaryFormat,
    pub architecture: String,
    pub bits: u8,
    pub endianness: Endianness,
    pub compiler: String,
    pub entry_point: u64,
    pub is_stripped: bool,
    pub has_debug_info: bool,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
}

pub enum BinaryFormat {
    PE,
    ELF,
    MachO,
    Unknown,
}

pub struct Section {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub entropy: f64,
    pub flags: Vec<SectionFlag>,
}
```

## Error Handling

File Scanner uses a unified error type:

```rust
use file_scanner::Error;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Analysis error: {0}")]
    Analysis(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Timeout")]
    Timeout,
}

// Result type alias
pub type Result<T> = std::result::Result<T, Error>;
```

### Error Handling Example

```rust
use file_scanner::{Scanner, Error};

match scanner.analyze_file(path).await {
    Ok(result) => {
        // Process result
    }
    Err(Error::Io(e)) => {
        eprintln!("Failed to read file: {}", e);
    }
    Err(Error::Parse(msg)) => {
        eprintln!("Failed to parse file: {}", msg);
    }
    Err(e) => {
        eprintln!("Analysis failed: {}", e);
    }
}
```

## Async Operations

Most I/O operations are async for better performance:

```rust
use file_scanner::{Scanner, ScanOptions};
use futures::stream::{self, StreamExt};

// Analyze files concurrently
async fn analyze_directory(dir: &Path) -> Result<Vec<AnalysisResult>> {
    let scanner = Scanner::new();
    let files: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();

    // Process in parallel with concurrency limit
    let results = stream::iter(files)
        .map(|path| {
            let scanner = scanner.clone();
            async move { scanner.analyze_file(&path).await }
        })
        .buffer_unordered(4)  // Process 4 files concurrently
        .collect::<Vec<_>>()
        .await;

    results.into_iter().collect()
}
```

## Examples

### Complete Analysis Example

```rust
use file_scanner::{Scanner, ScanOptions, StringOptions, HexDumpOptions};
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = ScanOptions {
        metadata: true,
        hashes: true,
        strings: true,
        string_options: StringOptions {
            min_length: 8,
            max_strings: 5000,
            ..Default::default()
        },
        hex_dump: true,
        hex_dump_options: HexDumpOptions {
            size: 512,
            offset: 0,
        },
        binary_info: true,
        signatures: true,
        ..Default::default()
    };

    let scanner = Scanner::with_options(options);
    let result = scanner.analyze_file(Path::new("/path/to/file")).await?;

    // Process results
    if let Some(strings) = &result.strings {
        println!("Found {} strings", strings.len());
        for s in strings.iter().filter(|s| s.category == StringCategory::Suspicious) {
            println!("Suspicious string: {}", s.value);
        }
    }

    Ok(())
}
```

### Custom Analysis Pipeline

```rust
use file_scanner::*;
use std::path::Path;

pub struct CustomAnalyzer {
    scanner: Scanner,
}

impl CustomAnalyzer {
    pub fn new() -> Self {
        Self {
            scanner: Scanner::new(),
        }
    }

    pub async fn analyze_malware(&self, path: &Path) -> Result<MalwareReport> {
        // Get basic analysis
        let result = self.scanner.analyze_file(path).await?;

        // Build custom report
        let report = MalwareReport {
            file_name: result.metadata.file_name.clone(),
            risk_score: self.calculate_risk_score(&result),
            indicators: self.extract_indicators(&result),
            recommendations: self.generate_recommendations(&result),
        };

        Ok(report)
    }

    fn calculate_risk_score(&self, result: &AnalysisResult) -> u8 {
        let mut score = 0;

        // Check for suspicious strings
        if let Some(strings) = &result.strings {
            score += strings.iter()
                .filter(|s| s.category == StringCategory::Suspicious)
                .count() as u8 * 10;
        }

        // Check for packing
        if let Some(binary) = &result.binary_info {
            if binary.sections.iter().any(|s| s.entropy > 7.0) {
                score += 20;
            }
        }

        score.min(100)
    }
}
```

### Integration with External Systems

```rust
use file_scanner::{Scanner, AnalysisResult};
use serde_json;

async fn scan_and_report(path: &Path) -> Result<()> {
    let scanner = Scanner::new();
    let result = scanner.analyze_file(path).await?;

    // Convert to JSON
    let json = serde_json::to_string_pretty(&result)?;

    // Send to external API
    let client = reqwest::Client::new();
    client.post("https://api.example.com/scan-results")
        .json(&result)
        .send()
        .await?;

    // Save to database
    save_to_database(&result).await?;

    Ok(())
}
```

## Advanced Usage

### Custom String Patterns

```rust
use file_scanner::strings::{StringMatcher, Pattern};

let custom_matcher = StringMatcher::builder()
    .add_pattern(Pattern::regex(r"MALWARE_\w+"))
    .add_pattern(Pattern::exact("evil.exe"))
    .add_category_rule(|s| {
        if s.contains("ransomware") {
            Some(StringCategory::Suspicious)
        } else {
            None
        }
    })
    .build();
```

### Performance Tuning

```rust
use file_scanner::{Scanner, ScanOptions};

let options = ScanOptions {
    // Use memory mapping for large files
    use_mmap: true,

    // Limit resource usage
    max_file_size: 100 * 1024 * 1024,  // 100MB
    timeout: Duration::from_secs(30),

    // Parallel processing
    thread_count: num_cpus::get(),

    ..Default::default()
};
```

## Thread Safety

All public types are thread-safe:

```rust
use std::sync::Arc;
use tokio::task;

let scanner = Arc::new(Scanner::new());

let handles: Vec<_> = paths.into_iter()
    .map(|path| {
        let scanner = scanner.clone();
        task::spawn(async move {
            scanner.analyze_file(&path).await
        })
    })
    .collect();

let results = futures::future::join_all(handles).await;
```

## Next Steps

- See [Architecture](ARCHITECTURE.md) for internal design
- Check [Examples](https://github.com/ThreatFlux/file-scanner/tree/main/examples) directory
- Read [Performance Guide](PERFORMANCE.md) for optimization
- Join our [Discord](https://discord.gg/threatflux) for help
