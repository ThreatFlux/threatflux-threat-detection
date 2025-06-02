use file_scanner::mcp_server::{FileScannerMcp, FileAnalysisRequest};
use tempfile::TempDir;
use std::fs;

#[tokio::main]
async fn main() {
    println!("Creating test file...");
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.elf");
    
    // Create test ELF file
    let mut content = vec![0x7f, 0x45, 0x4c, 0x46]; // ELF magic
    content.extend(b"test content test test");
    fs::write(&test_file, &content).unwrap();
    
    println!("File created at: {}", test_file.display());
    println!("File size: {} bytes", content.len());
    
    let server = FileScannerMcp;
    
    let params = FileAnalysisRequest {
        file_path: test_file.to_str().unwrap().to_string(),
        metadata: Some(true),
        hashes: Some(true),
        strings: Some(true),
        min_string_length: Some(4),
        hex_dump: Some(true),
        hex_dump_size: Some(32),
        hex_dump_offset: Some(0),
        binary_info: Some(true),
        signatures: Some(true),
        symbols: Some(true),
        control_flow: Some(true),
        vulnerabilities: Some(true),
        code_quality: Some(true),
        dependencies: Some(true),
        entropy: Some(true),
        disassembly: Some(true),
        threats: Some(true),
        behavioral: Some(true),
        yara_indicators: Some(true),
    };
    
    println!("\nCalling analyze_file with all options enabled...");
    
    match server.analyze_file(params).await {
        Ok(result) => {
            let response = result.0;
            println!("\n=== ANALYSIS RESULTS ===");
            println!("File path: {}", response.file_path);
            println!("Metadata present: {}", response.metadata.is_some());
            println!("Hashes present: {}", response.hashes.is_some());
            println!("Strings present: {}", response.strings.is_some());
            println!("Hex dump present: {}", response.hex_dump.is_some());
            println!("Binary info present: {}", response.binary_info.is_some());
            println!("Signatures present: {}", response.signatures.is_some());
            
            if response.hashes.is_none() {
                println!("\nWARNING: Hashes are None despite being requested!");
            }
            
            // Print full JSON for debugging
            if let Ok(json) = serde_json::to_string_pretty(&response) {
                println!("\nFull response JSON:\n{}", json);
            }
        }
        Err(e) => {
            println!("ERROR: {}", e);
        }
    }
}