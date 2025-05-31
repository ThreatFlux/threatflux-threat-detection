use file_scanner::mcp_server::{FileScannerMcpServer, AnalyzeFileParams, LlmAnalyzeFileParams};
use rmcp::{Tool, Router, Response};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;
use tokio;

async fn create_test_server() -> FileScannerMcpServer {
    FileScannerMcpServer
}

fn create_test_file(dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, content).unwrap();
    path
}

#[tokio::test]
async fn test_analyze_file_metadata_only() {
    let server = create_test_server().await;
    let temp_dir = TempDir::new().unwrap();
    let test_file = create_test_file(&temp_dir, "test.txt", b"Hello, World!");
    
    let params = AnalyzeFileParams {
        file_path: test_file.to_str().unwrap().to_string(),
        metadata: Some(true),
        hashes: None,
        strings: None,
        min_string_length: None,
        hex_dump: None,
        hex_dump_size: None,
        hex_dump_offset: None,
        binary_info: None,
        signatures: None,
        symbols: None,
        control_flow: None,
        vulnerabilities: None,
        code_quality: None,
        dependencies: None,
        entropy: None,
        disassembly: None,
        threats: None,
        behavioral: None,
        yara_indicators: None,
    };
    
    let result = server.analyze_file(params).await;
    assert!(result.is_ok());
    
    let response = result.unwrap();
    assert!(response.get("file_path").is_some());
    assert!(response.get("file_size").is_some());
    assert_eq!(response.get("file_size").unwrap(), &13);
}

#[tokio::test]
async fn test_analyze_file_with_hashes() {
    let server = create_test_server().await;
    let temp_dir = TempDir::new().unwrap();
    let test_file = create_test_file(&temp_dir, "test.bin", b"Test content");
    
    let params = AnalyzeFileParams {
        file_path: test_file.to_str().unwrap().to_string(),
        metadata: Some(true),
        hashes: Some(true),
        strings: None,
        min_string_length: None,
        hex_dump: None,
        hex_dump_size: None,
        hex_dump_offset: None,
        binary_info: None,
        signatures: None,
        symbols: None,
        control_flow: None,
        vulnerabilities: None,
        code_quality: None,
        dependencies: None,
        entropy: None,
        disassembly: None,
        threats: None,
        behavioral: None,
        yara_indicators: None,
    };
    
    let result = server.analyze_file(params).await;
    assert!(result.is_ok());
    
    let response = result.unwrap();
    let hashes = response.get("hashes").unwrap().as_object().unwrap();
    assert!(hashes.contains_key("md5"));
    assert!(hashes.contains_key("sha256"));
    assert!(hashes.contains_key("sha512"));
    assert!(hashes.contains_key("blake3"));
}

#[tokio::test]
async fn test_analyze_file_with_strings() {
    let server = create_test_server().await;
    let temp_dir = TempDir::new().unwrap();
    let content = b"Hello World\x00\x01\x02This is a test string\x00More text";
    let test_file = create_test_file(&temp_dir, "strings.bin", content);
    
    let params = AnalyzeFileParams {
        file_path: test_file.to_str().unwrap().to_string(),
        metadata: None,
        hashes: None,
        strings: Some(true),
        min_string_length: Some(5),
        hex_dump: None,
        hex_dump_size: None,
        hex_dump_offset: None,
        binary_info: None,
        signatures: None,
        symbols: None,
        control_flow: None,
        vulnerabilities: None,
        code_quality: None,
        dependencies: None,
        entropy: None,
        disassembly: None,
        threats: None,
        behavioral: None,
        yara_indicators: None,
    };
    
    let result = server.analyze_file(params).await;
    assert!(result.is_ok());
    
    let response = result.unwrap();
    let strings = response.get("extracted_strings").unwrap();
    assert!(strings.get("total_count").is_some());
    assert!(strings.get("ascii_strings").is_some());
}

#[tokio::test]
async fn test_analyze_file_with_hex_dump() {
    let server = create_test_server().await;
    let temp_dir = TempDir::new().unwrap();
    let test_file = create_test_file(&temp_dir, "hex.bin", b"ABCDEFGHIJKLMNOP");
    
    let params = AnalyzeFileParams {
        file_path: test_file.to_str().unwrap().to_string(),
        metadata: None,
        hashes: None,
        strings: None,
        min_string_length: None,
        hex_dump: Some(true),
        hex_dump_size: Some(8),
        hex_dump_offset: Some(4),
        binary_info: None,
        signatures: None,
        symbols: None,
        control_flow: None,
        vulnerabilities: None,
        code_quality: None,
        dependencies: None,
        entropy: None,
        disassembly: None,
        threats: None,
        behavioral: None,
        yara_indicators: None,
    };
    
    let result = server.analyze_file(params).await;
    assert!(result.is_ok());
    
    let response = result.unwrap();
    let hex_dump = response.get("hex_dump").unwrap();
    assert_eq!(hex_dump.get("offset").unwrap(), &4);
    assert_eq!(hex_dump.get("length").unwrap(), &8);
}

#[tokio::test]
async fn test_analyze_file_nonexistent() {
    let server = create_test_server().await;
    
    let params = AnalyzeFileParams {
        file_path: "/nonexistent/file/path".to_string(),
        metadata: Some(true),
        hashes: None,
        strings: None,
        min_string_length: None,
        hex_dump: None,
        hex_dump_size: None,
        hex_dump_offset: None,
        binary_info: None,
        signatures: None,
        symbols: None,
        control_flow: None,
        vulnerabilities: None,
        code_quality: None,
        dependencies: None,
        entropy: None,
        disassembly: None,
        threats: None,
        behavioral: None,
        yara_indicators: None,
    };
    
    let result = server.analyze_file(params).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_llm_analyze_file() {
    let server = create_test_server().await;
    let temp_dir = TempDir::new().unwrap();
    
    // Create a test file with various content
    let mut content = Vec::new();
    content.extend_from_slice(b"MZ"); // PE header
    content.extend_from_slice(&[0x90; 60]); // Padding
    content.extend_from_slice(b"This is a test string");
    content.extend_from_slice(&[0x00; 10]);
    content.extend_from_slice(b"CreateProcess");
    content.extend_from_slice(&[0x00; 10]);
    content.extend_from_slice(b"kernel32.dll");
    
    let test_file = create_test_file(&temp_dir, "malware_test.exe", &content);
    
    let params = LlmAnalyzeFileParams {
        file_path: test_file.to_str().unwrap().to_string(),
        token_limit: Some(10000),
        min_string_length: Some(4),
        max_strings: Some(20),
        max_imports: Some(10),
        max_opcodes: Some(5),
        hex_pattern_size: Some(16),
        suggest_yara_rule: Some(true),
    };
    
    let result = server.llm_analyze_file(params).await;
    assert!(result.is_ok());
    
    let response = result.unwrap();
    assert!(response.get("md5").is_some());
    assert!(response.get("file_size").is_some());
    assert!(response.get("key_strings").is_some());
    assert!(response.get("hex_patterns").is_some());
    
    // Check if YARA rule suggestion is included
    if let Some(yara_rule) = response.get("yara_rule_suggestion") {
        let rule_str = yara_rule.as_str().unwrap();
        assert!(rule_str.contains("rule"));
        assert!(rule_str.contains("strings:"));
        assert!(rule_str.contains("condition:"));
    }
}

#[tokio::test]
async fn test_llm_analyze_file_token_limit() {
    let server = create_test_server().await;
    let temp_dir = TempDir::new().unwrap();
    
    // Create a large file with many strings
    let mut content = Vec::new();
    for i in 0..1000 {
        content.extend_from_slice(format!("String number {}\x00", i).as_bytes());
    }
    
    let test_file = create_test_file(&temp_dir, "large_file.bin", &content);
    
    let params = LlmAnalyzeFileParams {
        file_path: test_file.to_str().unwrap().to_string(),
        token_limit: Some(1000), // Very small limit
        min_string_length: Some(4),
        max_strings: Some(10), // Limit strings
        max_imports: None,
        max_opcodes: None,
        hex_pattern_size: None,
        suggest_yara_rule: Some(false),
    };
    
    let result = server.llm_analyze_file(params).await;
    assert!(result.is_ok());
    
    let response = result.unwrap();
    let response_str = serde_json::to_string(&response).unwrap();
    assert!(response_str.len() <= 1500); // Allow some overhead
    
    // Check that strings are limited
    let key_strings = response.get("key_strings").unwrap().as_array().unwrap();
    assert!(key_strings.len() <= 10);
}

#[tokio::test]
async fn test_mcp_tool_registration() {
    let server = create_test_server().await;
    let router = Router::new();
    
    // Register tools
    let tools = server.tools();
    assert_eq!(tools.len(), 2); // analyze_file and llm_analyze_file
    
    // Check tool names
    let tool_names: Vec<&str> = tools.iter().map(|t| t.name()).collect();
    assert!(tool_names.contains(&"analyze_file"));
    assert!(tool_names.contains(&"llm_analyze_file"));
    
    // Check tool descriptions
    for tool in &tools {
        assert!(!tool.description().is_empty());
        match tool.name() {
            "analyze_file" => {
                assert!(tool.description().contains("Analyze a file"));
            }
            "llm_analyze_file" => {
                assert!(tool.description().contains("LLM-optimized"));
            }
            _ => panic!("Unexpected tool name"),
        }
    }
}

#[tokio::test]
async fn test_analyze_file_all_options() {
    let server = create_test_server().await;
    let temp_dir = TempDir::new().unwrap();
    
    // Create an ELF-like file
    let mut content = vec![0x7f, 0x45, 0x4c, 0x46]; // ELF magic
    content.extend_from_slice(&[0x02, 0x01, 0x01, 0x00]); // 64-bit, little endian
    content.extend_from_slice(&[0x00; 100]); // Padding
    content.extend_from_slice(b"Test string in ELF");
    
    let test_file = create_test_file(&temp_dir, "test.elf", &content);
    
    let params = AnalyzeFileParams {
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
    
    let result = server.analyze_file(params).await;
    assert!(result.is_ok());
    
    let response = result.unwrap();
    
    // Check all requested fields are present
    assert!(response.get("file_path").is_some());
    assert!(response.get("file_size").is_some());
    assert!(response.get("hashes").is_some());
    assert!(response.get("extracted_strings").is_some());
    assert!(response.get("hex_dump").is_some());
    assert!(response.get("binary_info").is_some());
    
    // Binary info should detect ELF
    if let Some(binary_info) = response.get("binary_info") {
        if let Some(format) = binary_info.get("format") {
            assert_eq!(format.as_str().unwrap(), "ELF");
        }
    }
}

#[test]
fn test_analyze_file_params_defaults() {
    let params = AnalyzeFileParams {
        file_path: "/test/path".to_string(),
        metadata: None,
        hashes: None,
        strings: None,
        min_string_length: None,
        hex_dump: None,
        hex_dump_size: None,
        hex_dump_offset: None,
        binary_info: None,
        signatures: None,
        symbols: None,
        control_flow: None,
        vulnerabilities: None,
        code_quality: None,
        dependencies: None,
        entropy: None,
        disassembly: None,
        threats: None,
        behavioral: None,
        yara_indicators: None,
    };
    
    // All options should be None by default
    assert!(params.metadata.is_none());
    assert!(params.hashes.is_none());
    assert!(params.strings.is_none());
}

#[test]
fn test_llm_analyze_file_params_defaults() {
    let params = LlmAnalyzeFileParams {
        file_path: "/test/path".to_string(),
        token_limit: None,
        min_string_length: None,
        max_strings: None,
        max_imports: None,
        max_opcodes: None,
        hex_pattern_size: None,
        suggest_yara_rule: None,
    };
    
    // Check that defaults will be applied in the implementation
    assert!(params.token_limit.is_none());
    assert!(params.min_string_length.is_none());
    assert!(params.max_strings.is_none());
}