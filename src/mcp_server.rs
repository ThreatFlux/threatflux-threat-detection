use anyhow::Result;
use rmcp::{
    handler::server::wrapper::Json,
    model::{ServerCapabilities, ServerInfo, ProtocolVersion, Implementation},
    schemars, tool, ServerHandler,
};
use serde::Deserialize;
use std::path::PathBuf;

use crate::{
    behavioral_analysis::{analyze_behavior, BehavioralAnalysis},
    binary_parser::{parse_binary, BinaryInfo},
    call_graph::{generate_call_graph, CallGraph},
    code_metrics::{analyze_code_quality, CodeQualityAnalysis},
    control_flow::{analyze_control_flow, ControlFlowAnalysis},
    dependency_analysis::{analyze_dependencies, DependencyAnalysisResult},
    disassembly::{disassemble_binary, DisassemblyResult},
    entropy_analysis::{analyze_entropy, EntropyAnalysis},
    function_analysis::{analyze_symbols, SymbolTable},
    hash::{calculate_all_hashes, Hashes},
    hexdump::{format_hex_dump_text, generate_hex_dump, HexDumpOptions},
    metadata::FileMetadata,
    signature::verify_signature,
    strings::extract_strings,
    threat_detection::{analyze_threats, ThreatAnalysis},
    vulnerability_detection::{analyze_vulnerabilities, VulnerabilityDetectionResult},
};

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HashRequest {
    #[schemars(description = "Path to the file to hash")]
    pub file_path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StringsRequest {
    #[schemars(description = "Path to the file to extract strings from")]
    pub file_path: String,
    #[schemars(description = "Minimum string length")]
    pub min_length: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HexDumpRequest {
    #[schemars(description = "Path to the file to hex dump")]
    pub file_path: String,
    #[schemars(description = "Number of bytes to dump")]
    pub size: Option<usize>,
    #[schemars(description = "Offset from start of file")]
    pub offset: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BinaryAnalysisRequest {
    #[schemars(description = "Path to the binary file to analyze")]
    pub file_path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MetadataRequest {
    #[schemars(description = "Path to the file to get metadata for")]
    pub file_path: String,
}

#[derive(Debug, Clone)]
pub struct FileScannerMcp;

#[tool(tool_box)]
impl FileScannerMcp {
    #[tool(description = "Calculate cryptographic hashes (MD5, SHA256, SHA512, BLAKE3) for a file")]
    async fn calculate_file_hashes(&self, #[tool(aggr)] request: HashRequest) -> Result<Json<Hashes>, String> {
        let path = PathBuf::from(&request.file_path);
        
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        let hashes = calculate_all_hashes(&path).await.map_err(|e| e.to_string())?;
        Ok(Json(hashes))
    }

    #[tool(description = "Extract ASCII and Unicode strings from a file")]
    fn extract_file_strings(&self, #[tool(aggr)] request: StringsRequest) -> Result<Json<Vec<String>>, String> {
        let path = PathBuf::from(&request.file_path);
        
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        let min_len = request.min_length.unwrap_or(4);
        let strings = extract_strings(&path, min_len).map_err(|e| e.to_string())?;
        let all_strings = [strings.ascii_strings, strings.unicode_strings].concat();
        Ok(Json(all_strings))
    }

    #[tool(description = "Generate a hex dump of a file or part of a file")]
    fn hex_dump_file(&self, #[tool(aggr)] request: HexDumpRequest) -> Result<String, String> {
        let path = PathBuf::from(&request.file_path);
        
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        let size = request.size.unwrap_or(256);
        let hex_options = HexDumpOptions {
            offset: request.offset.unwrap_or(0),
            length: Some(size),
            bytes_per_line: 16,
            max_lines: None,
        };
        let hex_dump = generate_hex_dump(&path, hex_options).map_err(|e| e.to_string())?;
        Ok(format_hex_dump_text(&hex_dump))
    }

    #[tool(description = "Analyze binary file format (PE, ELF, Mach-O) and extract metadata")]
    fn analyze_binary_file(&self, #[tool(aggr)] request: BinaryAnalysisRequest) -> Result<Json<BinaryInfo>, String> {
        let path = PathBuf::from(&request.file_path);
        
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        let binary_info = parse_binary(&path).map_err(|e| e.to_string())?;
        Ok(Json(binary_info))
    }

    #[tool(description = "Extract file system metadata including timestamps, permissions, and file type")]
    async fn get_file_metadata(&self, #[tool(aggr)] request: MetadataRequest) -> Result<Json<FileMetadata>, String> {
        let path = PathBuf::from(&request.file_path);
        
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        let mut metadata = FileMetadata::new(&path).map_err(|e| e.to_string())?;
        metadata.extract_basic_info().map_err(|e| e.to_string())?;
        metadata.calculate_hashes().await.map_err(|e| e.to_string())?;
        Ok(Json(metadata))
    }

    #[tool(description = "Verify digital signatures on a file")]
    fn verify_file_signatures(&self, #[tool(aggr)] request: MetadataRequest) -> Result<String, String> {
        let path = PathBuf::from(&request.file_path);
        
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        match verify_signature(&path) {
            Ok(sig_info) => Ok(format!("Signatures verified: {:?}", sig_info)),
            Err(e) => Err(e.to_string()),
        }
    }

    #[tool(description = "Analyze function symbols and cross-references in a binary file")]
    fn analyze_function_symbols(&self, #[tool(aggr)] request: MetadataRequest) -> Result<Json<SymbolTable>, String> {
        let path = PathBuf::from(&request.file_path);
        
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        let symbol_table = analyze_symbols(&path).map_err(|e| e.to_string())?;
        Ok(Json(symbol_table))
    }

    #[tool(description = "Analyze control flow graphs, basic blocks, and complexity metrics in a binary file")]
    fn analyze_control_flow_graph(&self, #[tool(aggr)] request: MetadataRequest) -> Result<Json<ControlFlowAnalysis>, String> {
        let path = PathBuf::from(&request.file_path);
        
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // First get symbol table for function analysis
        let symbol_table = analyze_symbols(&path).map_err(|e| e.to_string())?;
        
        // Then analyze control flow
        let cfg_analysis = analyze_control_flow(&path, &symbol_table).map_err(|e| e.to_string())?;
        Ok(Json(cfg_analysis))
    }

    #[tool(description = "Detect security vulnerabilities using static analysis patterns and rules")]
    fn detect_vulnerabilities(&self, #[tool(aggr)] request: MetadataRequest) -> Result<Json<VulnerabilityDetectionResult>, String> {
        let path = PathBuf::from(&request.file_path);
        
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // Get symbol table and CFG analysis first
        let symbol_table = analyze_symbols(&path).map_err(|e| e.to_string())?;
        let cfg_analysis = analyze_control_flow(&path, &symbol_table).map_err(|e| e.to_string())?;
        
        // Perform vulnerability detection
        let vuln_result = analyze_vulnerabilities(&path, &symbol_table, &cfg_analysis).map_err(|e| e.to_string())?;
        Ok(Json(vuln_result))
    }

    #[tool(description = "Analyze code quality metrics including complexity, maintainability, and technical debt")]
    fn analyze_code_quality(&self, #[tool(aggr)] request: MetadataRequest) -> Result<Json<CodeQualityAnalysis>, String> {
        let path = PathBuf::from(&request.file_path);
        
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // Get symbol table and CFG analysis first
        let symbol_table = analyze_symbols(&path).map_err(|e| e.to_string())?;
        let cfg_analysis = analyze_control_flow(&path, &symbol_table).map_err(|e| e.to_string())?;
        
        // Perform code quality analysis
        let quality_result = analyze_code_quality(&path, &symbol_table, &cfg_analysis).map_err(|e| e.to_string())?;
        Ok(Json(quality_result))
    }

    #[tool(description = "Analyze library dependencies, detect vulnerable libraries, and check license compliance")]
    fn analyze_dependencies(&self, #[tool(aggr)] request: MetadataRequest) -> Result<Json<DependencyAnalysisResult>, String> {
        let path = PathBuf::from(&request.file_path);
        
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // Get symbol table first
        let symbol_table = analyze_symbols(&path).map_err(|e| e.to_string())?;
        
        // Extract strings for additional analysis
        let strings = extract_strings(&path, 4).ok();
        
        // Perform dependency analysis
        let dep_result = analyze_dependencies(&path, &symbol_table, strings.as_ref()).map_err(|e| e.to_string())?;
        Ok(Json(dep_result))
    }

    #[tool(description = "Analyze entropy patterns to detect packing, encryption, and obfuscation techniques")]
    fn analyze_entropy_patterns(&self, #[tool(aggr)] request: MetadataRequest) -> Result<Json<EntropyAnalysis>, String> {
        let path = PathBuf::from(&request.file_path);
        
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // Perform entropy analysis
        let entropy_result = analyze_entropy(&path).map_err(|e| e.to_string())?;
        Ok(Json(entropy_result))
    }

    #[tool(description = "Disassemble binary code with multi-architecture support and advanced instruction analysis")]
    fn disassemble_code(&self, #[tool(aggr)] request: MetadataRequest) -> Result<Json<DisassemblyResult>, String> {
        let path = PathBuf::from(&request.file_path);
        
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // Get symbol table first for function boundaries
        let symbol_table = analyze_symbols(&path).map_err(|e| e.to_string())?;
        
        // Perform disassembly
        let disassembly_result = disassemble_binary(&path, &symbol_table).map_err(|e| e.to_string())?;
        Ok(Json(disassembly_result))
    }

    #[tool(description = "Detect threats and malware using YARA-X rules with comprehensive pattern matching")]
    fn detect_threats(&self, #[tool(aggr)] request: MetadataRequest) -> Result<Json<ThreatAnalysis>, String> {
        let path = PathBuf::from(&request.file_path);
        
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // Perform threat analysis
        let threat_result = analyze_threats(&path).map_err(|e| e.to_string())?;
        Ok(Json(threat_result))
    }

    #[tool(description = "Analyze behavioral patterns including anti-analysis, persistence, and evasion techniques")]
    fn analyze_behavioral_patterns(&self, #[tool(aggr)] request: MetadataRequest) -> Result<Json<BehavioralAnalysis>, String> {
        let path = PathBuf::from(&request.file_path);
        
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // Extract strings for analysis
        let strings = extract_strings(&path, 4).ok();
        
        // Get symbol table
        let symbols = analyze_symbols(&path).ok();
        
        // Get disassembly if possible
        let disassembly = if let Some(ref syms) = symbols {
            disassemble_binary(&path, syms).ok()
        } else {
            None
        };
        
        // Perform behavioral analysis
        let behavioral_result = analyze_behavior(&path, strings.as_ref(), symbols.as_ref(), disassembly.as_ref())
            .map_err(|e| e.to_string())?;
        Ok(Json(behavioral_result))
    }

    #[tool(description = "Generate inter-procedural call graph with function relationships and dead code detection")]
    fn generate_call_graph(&self, #[tool(aggr)] request: MetadataRequest) -> Result<Json<CallGraph>, String> {
        let path = PathBuf::from(&request.file_path);
        
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // Get symbol table
        let symbols = analyze_symbols(&path).map_err(|e| e.to_string())?;
        
        // Get disassembly for call analysis
        let disassembly = disassemble_binary(&path, &symbols).map_err(|e| e.to_string())?;
        
        // Generate call graph
        let call_graph = generate_call_graph(&path, &disassembly, &symbols)
            .map_err(|e| e.to_string())?;
        Ok(Json(call_graph))
    }
}

#[tool(tool_box)]
impl ServerHandler for FileScannerMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            server_info: Implementation {
                name: "file-scanner".into(),
                version: "0.1.0".into(),
            },
            instructions: Some("A comprehensive file scanner that provides detailed metadata, hash calculations, string extraction, binary analysis, hex dumping, and digital signature verification for files.".into()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
        }
    }
}