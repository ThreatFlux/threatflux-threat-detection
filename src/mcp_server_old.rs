use anyhow::Result;
use rmcp::{
    handler::server::wrapper::Json,
    model::{Implementation, ProtocolVersion, ServerCapabilities, ServerInfo},
    schemars, tool, ServerHandler,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{
    behavioral_analysis::{analyze_behavior, BehavioralAnalysis},
    binary_parser::{parse_binary, BinaryInfo},
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
pub struct FileAnalysisRequest {
    #[schemars(description = "Path to the file to analyze")]
    pub file_path: String,
    
    // Analysis options
    #[schemars(description = "Include file metadata (size, timestamps, permissions)")]
    pub metadata: Option<bool>,
    #[schemars(description = "Include cryptographic hashes (MD5, SHA256, SHA512, BLAKE3)")]
    pub hashes: Option<bool>,
    #[schemars(description = "Extract strings from the file")]
    pub strings: Option<bool>,
    #[schemars(description = "Minimum string length (default: 4)")]
    pub min_string_length: Option<usize>,
    #[schemars(description = "Generate hex dump")]
    pub hex_dump: Option<bool>,
    #[schemars(description = "Hex dump size in bytes (default: 256)")]
    pub hex_dump_size: Option<usize>,
    #[schemars(description = "Hex dump offset from start")]
    pub hex_dump_offset: Option<u64>,
    #[schemars(description = "Analyze binary format (PE/ELF/Mach-O)")]
    pub binary_info: Option<bool>,
    #[schemars(description = "Verify digital signatures")]
    pub signatures: Option<bool>,
    #[schemars(description = "Analyze function symbols")]
    pub symbols: Option<bool>,
    #[schemars(description = "Analyze control flow")]
    pub control_flow: Option<bool>,
    #[schemars(description = "Detect vulnerabilities")]
    pub vulnerabilities: Option<bool>,
    #[schemars(description = "Analyze code quality metrics")]
    pub code_quality: Option<bool>,
    #[schemars(description = "Analyze dependencies")]
    pub dependencies: Option<bool>,
    #[schemars(description = "Analyze entropy patterns")]
    pub entropy: Option<bool>,
    #[schemars(description = "Disassemble code")]
    pub disassembly: Option<bool>,
    #[schemars(description = "Detect threats and malware")]
    pub threats: Option<bool>,
    #[schemars(description = "Analyze behavioral patterns")]
    pub behavioral: Option<bool>,
    #[schemars(description = "Extract YARA rule indicators")]
    pub yara_indicators: Option<bool>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FileAnalysisResult {
    pub file_path: String,
    pub metadata: Option<FileMetadata>,
    pub hashes: Option<Hashes>,
    pub strings: Option<Vec<String>>,
    pub hex_dump: Option<String>,
    pub binary_info: Option<BinaryInfo>,
    pub signatures: Option<serde_json::Value>,
    pub symbols: Option<SymbolTable>,
    pub control_flow: Option<ControlFlowAnalysis>,
    pub vulnerabilities: Option<VulnerabilityDetectionResult>,
    pub code_quality: Option<CodeQualityAnalysis>,
    pub dependencies: Option<DependencyAnalysisResult>,
    pub entropy: Option<EntropyAnalysis>,
    pub disassembly: Option<DisassemblyResult>,
    pub threats: Option<ThreatAnalysis>,
    pub behavioral: Option<BehavioralAnalysis>,
    pub yara_indicators: Option<YaraIndicators>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct YaraIndicators {
    pub sha256: String,
    pub md5: String,
    pub file_size: u64,
    pub magic_bytes: String,
    pub entropy: f64,
    pub unique_strings: Vec<String>,
    pub imports: Vec<String>,
    pub sections: Vec<String>,
    pub is_packed: bool,
}

#[derive(Debug, Clone)]
pub struct FileScannerMcp;

#[tool(tool_box)]
impl FileScannerMcp {
    #[tool(description = "Comprehensive file analysis tool - use flags to control which analyses to perform (metadata, hashes, strings, hex_dump, binary_info, signatures, symbols, control_flow, vulnerabilities, code_quality, dependencies, entropy, disassembly, threats, behavioral, yara_indicators)")]
    async fn analyze_file(
        &self,
        #[tool(aggr)] request: FileAnalysisRequest,
    ) -> Result<Json<FileAnalysisResult>, String> {
        let path = PathBuf::from(&request.file_path);

        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        let mut result = FileAnalysisResult {
            file_path: request.file_path.clone(),
            metadata: None,
            hashes: None,
            strings: None,
            hex_dump: None,
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

        // Metadata
        if request.metadata.unwrap_or(false) {
            let mut metadata = FileMetadata::new(&path).map_err(|e| e.to_string())?;
            metadata.extract_basic_info().map_err(|e| e.to_string())?;
            metadata.calculate_hashes().await.map_err(|e| e.to_string())?;
            result.metadata = Some(metadata);
        }

        // Hashes
        if request.hashes.unwrap_or(false) {
            let hashes = calculate_all_hashes(&path).await.map_err(|e| e.to_string())?;
            result.hashes = Some(hashes);
        }

        // Strings
        if request.strings.unwrap_or(false) {
            let min_len = request.min_string_length.unwrap_or(4);
            let strings = extract_strings(&path, min_len).map_err(|e| e.to_string())?;
            let all_strings = [strings.ascii_strings, strings.unicode_strings].concat();
            result.strings = Some(all_strings);
        }

        // Hex dump
        if request.hex_dump.unwrap_or(false) {
            let size = request.hex_dump_size.unwrap_or(256);
            let hex_options = HexDumpOptions {
                offset: request.hex_dump_offset.unwrap_or(0),
                length: Some(size),
                bytes_per_line: 16,
                max_lines: None,
            };
            let hex_dump = generate_hex_dump(&path, hex_options).map_err(|e| e.to_string())?;
            result.hex_dump = Some(format_hex_dump_text(&hex_dump));
        }

        // Binary info
        if request.binary_info.unwrap_or(false) {
            if let Ok(binary_info) = parse_binary(&path) {
                result.binary_info = Some(binary_info);
            }
        }

        // Signatures
        if request.signatures.unwrap_or(false) {
            let sig_result = verify_signature(&path);
            result.signatures = Some(serde_json::to_value(sig_result).unwrap_or(serde_json::Value::Null));
        }

        // Symbols
        if request.symbols.unwrap_or(false) {
            if let Ok(symbols) = analyze_symbols(&path) {
                result.symbols = Some(symbols);
            }
        }

        // Control flow
        if request.control_flow.unwrap_or(false) {
            if let Ok(control_flow) = analyze_control_flow(&path) {
                result.control_flow = Some(control_flow);
            }
        }

        // Vulnerabilities
        if request.vulnerabilities.unwrap_or(false) {
            if let Ok(symbols) = analyze_symbols(&path) {
                if let Ok(disassembly) = disassemble_binary(&path, &symbols) {
                    if let Ok(vulns) = analyze_vulnerabilities(&path, &disassembly) {
                        result.vulnerabilities = Some(vulns);
                    }
                }
            }
        }

        // Code quality
        if request.code_quality.unwrap_or(false) {
            if let Ok(quality) = analyze_code_quality(&path) {
                result.code_quality = Some(quality);
            }
        }

        // Dependencies
        if request.dependencies.unwrap_or(false) {
            if let Ok(deps) = analyze_dependencies(&path) {
                result.dependencies = Some(deps);
            }
        }

        // Entropy
        if request.entropy.unwrap_or(false) {
            if let Ok(entropy) = analyze_entropy(&path) {
                result.entropy = Some(entropy);
            }
        }

        // Disassembly
        if request.disassembly.unwrap_or(false) {
            if let Ok(symbols) = analyze_symbols(&path) {
                if let Ok(disassembly) = disassemble_binary(&path, &symbols) {
                    result.disassembly = Some(disassembly);
                }
            }
        }

        // Threats
        if request.threats.unwrap_or(false) {
            if let Ok(threats) = analyze_threats(&path) {
                result.threats = Some(threats);
            }
        }

        // Behavioral
        if request.behavioral.unwrap_or(false) {
            let strings = extract_strings(&path, 4).ok();
            let symbols = analyze_symbols(&path).ok();
            let disassembly = if let Some(ref syms) = symbols {
                disassemble_binary(&path, syms).ok()
            } else {
                None
            };
            
            if let Ok(behavioral) = analyze_behavior(&path, strings.as_ref(), symbols.as_ref(), disassembly.as_ref()) {
                result.behavioral = Some(behavioral);
            }
        }

        // YARA indicators
        if request.yara_indicators.unwrap_or(false) {
            let file_metadata = std::fs::metadata(&path).map_err(|e| e.to_string())?;
            let file_size = file_metadata.len();

            // Get hashes if not already calculated
            let hashes = if let Some(ref h) = result.hashes {
                h.clone()
            } else {
                calculate_all_hashes(&path).await.map_err(|e| e.to_string())?
            };

            // Get magic bytes
            let hex_options = HexDumpOptions {
                offset: 0,
                length: Some(8),
                bytes_per_line: 8,
                max_lines: Some(1),
            };
            let hex_dump = generate_hex_dump(&path, hex_options).map_err(|e| e.to_string())?;
            let magic_bytes = hex_dump.lines.first()
                .map(|line| line.raw_bytes.iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(" "))
                .unwrap_or_default();

            // Get entropy if not already calculated
            let entropy_analysis = if let Some(ref e) = result.entropy {
                e.clone()
            } else {
                analyze_entropy(&path).map_err(|e| e.to_string())?
            };

            // Extract unique strings
            let strings = extract_strings(&path, 8).map_err(|e| e.to_string())?;
            let mut unique_strings: Vec<String> = strings.interesting_strings
                .iter()
                .filter(|s| s.value.len() >= 8 && s.value.len() <= 50)
                .map(|s| s.value.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .take(20)
                .collect();
            unique_strings.sort();

            // Get imports and sections
            let (imports, sections) = if let Some(ref bi) = result.binary_info {
                (bi.imports.clone(), bi.sections.iter().map(|s| s.name.clone()).collect())
            } else if let Ok(bi) = parse_binary(&path) {
                (bi.imports.clone(), bi.sections.iter().map(|s| s.name.clone()).collect())
            } else {
                (vec![], vec![])
            };

            result.yara_indicators = Some(YaraIndicators {
                sha256: hashes.sha256,
                md5: hashes.md5,
                file_size,
                magic_bytes,
                entropy: entropy_analysis.overall_entropy,
                unique_strings,
                imports,
                sections,
                is_packed: entropy_analysis.packed_indicators.likely_packed || entropy_analysis.overall_entropy > 7.0,
            });
        }

        Ok(Json(result))
    }

    #[tool(description = "Extract ASCII and Unicode strings from a file")]
    fn extract_file_strings(
        &self,
        #[tool(aggr)] request: StringsRequest,
    ) -> Result<Json<Vec<String>>, String> {
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

    #[tool(description = "Extract key indicators for YARA rule creation - supports filtering by indicator type (hashes, strings, imports, entropy)")]
    async fn extract_yara_indicators(
        &self,
        #[tool(aggr)] request: YaraRuleRequest,
    ) -> Result<Json<YaraIndicators>, String> {
        let path = PathBuf::from(&request.file_path);

        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // Get file metadata for size (always included)
        let file_metadata = std::fs::metadata(&path).map_err(|e| e.to_string())?;
        let file_size = file_metadata.len();

        // Check which indicators to include
        let include_all = request.indicators.as_ref()
            .map(|ind| ind.contains(&"all".to_string()))
            .unwrap_or(true);
        
        let include_hashes = include_all || request.indicators.as_ref()
            .map(|ind| ind.contains(&"hashes".to_string()))
            .unwrap_or(false);
            
        let include_strings = include_all || request.indicators.as_ref()
            .map(|ind| ind.contains(&"strings".to_string()))
            .unwrap_or(false);
            
        let include_imports = include_all || request.indicators.as_ref()
            .map(|ind| ind.contains(&"imports".to_string()))
            .unwrap_or(false);
            
        let include_entropy = include_all || request.indicators.as_ref()
            .map(|ind| ind.contains(&"entropy".to_string()))
            .unwrap_or(false);

        // Calculate hashes if requested
        let (sha256, md5) = if include_hashes {
            let hashes = calculate_all_hashes(&path)
                .await
                .map_err(|e| e.to_string())?;
            (Some(hashes.sha256), Some(hashes.md5))
        } else {
            (None, None)
        };

        // Get magic bytes (always included as it's lightweight)
        let hex_options = HexDumpOptions {
            offset: 0,
            length: Some(8),
            bytes_per_line: 8,
            max_lines: Some(1),
        };
        let hex_dump = generate_hex_dump(&path, hex_options).map_err(|e| e.to_string())?;
        let magic_bytes = Some(hex_dump
            .lines
            .first()
            .map(|line| {
                line.raw_bytes
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default());

        // Get entropy if requested
        let (entropy, is_packed) = if include_entropy {
            let entropy_analysis = analyze_entropy(&path).map_err(|e| e.to_string())?;
            let is_packed = entropy_analysis.packed_indicators.likely_packed
                || entropy_analysis.overall_entropy > 7.0;
            (Some(entropy_analysis.overall_entropy), Some(is_packed))
        } else {
            (None, None)
        };

        // Extract unique strings if requested
        let unique_strings = if include_strings {
            let strings = extract_strings(&path, 8).map_err(|e| e.to_string())?;
            let max_strings = request.max_strings.unwrap_or(20);
            let mut unique_strings: Vec<String> = strings.interesting_strings
                .iter()
                .filter(|s| s.value.len() >= 8 && s.value.len() <= 50)
                .map(|s| s.value.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .take(max_strings)
                .collect();
            unique_strings.sort();
            Some(unique_strings)
        } else {
            None
        };

        // Get imports and sections if requested
        let (imports, sections) = if include_imports {
            if let Ok(binary_info) = parse_binary(&path) {
                let sections = binary_info.sections
                    .iter()
                    .map(|s| s.name.clone())
                    .collect();
                (Some(binary_info.imports.clone()), Some(sections))
            } else {
                (Some(vec![]), Some(vec![]))
            }
        } else {
            (None, None)
        };

        Ok(Json(YaraIndicators {
            sha256,
            md5,
            file_size,
            magic_bytes,
            entropy,
            unique_strings,
            imports,
            sections,
            is_packed,
        }))
    }

    #[tool(description = "Analyze binary file format (PE, ELF, Mach-O) and extract metadata")]
    fn analyze_binary_file(
        &self,
        #[tool(aggr)] request: BinaryAnalysisRequest,
    ) -> Result<Json<BinaryInfo>, String> {
        let path = PathBuf::from(&request.file_path);

        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        let binary_info = parse_binary(&path).map_err(|e| e.to_string())?;
        Ok(Json(binary_info))
    }

    #[tool(
        description = "Extract file system metadata including timestamps, permissions, and file type"
    )]
    async fn get_file_metadata(
        &self,
        #[tool(aggr)] request: MetadataRequest,
    ) -> Result<Json<FileMetadata>, String> {
        let path = PathBuf::from(&request.file_path);

        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        let mut metadata = FileMetadata::new(&path).map_err(|e| e.to_string())?;
        metadata.extract_basic_info().map_err(|e| e.to_string())?;
        metadata
            .calculate_hashes()
            .await
            .map_err(|e| e.to_string())?;
        Ok(Json(metadata))
    }

    #[tool(description = "Verify digital signatures on a file")]
    fn verify_file_signatures(
        &self,
        #[tool(aggr)] request: MetadataRequest,
    ) -> Result<String, String> {
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
    fn analyze_function_symbols(
        &self,
        #[tool(aggr)] request: MetadataRequest,
    ) -> Result<Json<SymbolTable>, String> {
        let path = PathBuf::from(&request.file_path);

        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        let symbol_table = analyze_symbols(&path).map_err(|e| e.to_string())?;
        Ok(Json(symbol_table))
    }

    #[tool(
        description = "Analyze control flow graphs, basic blocks, and complexity metrics in a binary file"
    )]
    fn analyze_control_flow_graph(
        &self,
        #[tool(aggr)] request: MetadataRequest,
    ) -> Result<Json<ControlFlowAnalysis>, String> {
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

    #[tool(
        description = "Detect security vulnerabilities using static analysis patterns and rules"
    )]
    fn detect_vulnerabilities(
        &self,
        #[tool(aggr)] request: MetadataRequest,
    ) -> Result<Json<VulnerabilityDetectionResult>, String> {
        let path = PathBuf::from(&request.file_path);

        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // Get symbol table and CFG analysis first
        let symbol_table = analyze_symbols(&path).map_err(|e| e.to_string())?;
        let cfg_analysis = analyze_control_flow(&path, &symbol_table).map_err(|e| e.to_string())?;

        // Perform vulnerability detection
        let vuln_result = analyze_vulnerabilities(&path, &symbol_table, &cfg_analysis)
            .map_err(|e| e.to_string())?;
        Ok(Json(vuln_result))
    }

    #[tool(
        description = "Analyze code quality metrics including complexity, maintainability, and technical debt"
    )]
    fn analyze_code_quality(
        &self,
        #[tool(aggr)] request: MetadataRequest,
    ) -> Result<Json<CodeQualityAnalysis>, String> {
        let path = PathBuf::from(&request.file_path);

        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // Get symbol table and CFG analysis first
        let symbol_table = analyze_symbols(&path).map_err(|e| e.to_string())?;
        let cfg_analysis = analyze_control_flow(&path, &symbol_table).map_err(|e| e.to_string())?;

        // Perform code quality analysis
        let quality_result =
            analyze_code_quality(&path, &symbol_table, &cfg_analysis).map_err(|e| e.to_string())?;
        Ok(Json(quality_result))
    }

    #[tool(
        description = "Analyze library dependencies, detect vulnerable libraries, and check license compliance"
    )]
    fn analyze_dependencies(
        &self,
        #[tool(aggr)] request: MetadataRequest,
    ) -> Result<Json<DependencyAnalysisResult>, String> {
        let path = PathBuf::from(&request.file_path);

        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // Get symbol table first
        let symbol_table = analyze_symbols(&path).map_err(|e| e.to_string())?;

        // Extract strings for additional analysis
        let strings = extract_strings(&path, 4).ok();

        // Perform dependency analysis
        let dep_result = analyze_dependencies(&path, &symbol_table, strings.as_ref())
            .map_err(|e| e.to_string())?;
        Ok(Json(dep_result))
    }

    #[tool(
        description = "Analyze entropy patterns to detect packing, encryption, and obfuscation techniques"
    )]
    fn analyze_entropy_patterns(
        &self,
        #[tool(aggr)] request: MetadataRequest,
    ) -> Result<Json<EntropyAnalysis>, String> {
        let path = PathBuf::from(&request.file_path);

        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // Perform entropy analysis
        let entropy_result = analyze_entropy(&path).map_err(|e| e.to_string())?;
        Ok(Json(entropy_result))
    }

    #[tool(
        description = "Disassemble binary code with multi-architecture support and advanced instruction analysis"
    )]
    fn disassemble_code(
        &self,
        #[tool(aggr)] request: MetadataRequest,
    ) -> Result<Json<DisassemblyResult>, String> {
        let path = PathBuf::from(&request.file_path);

        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // Get symbol table first for function boundaries
        let symbol_table = analyze_symbols(&path).map_err(|e| e.to_string())?;

        // Perform disassembly
        let disassembly_result =
            disassemble_binary(&path, &symbol_table).map_err(|e| e.to_string())?;
        Ok(Json(disassembly_result))
    }

    #[tool(
        description = "Detect threats and malware using YARA-X rules with comprehensive pattern matching"
    )]
    fn detect_threats(
        &self,
        #[tool(aggr)] request: MetadataRequest,
    ) -> Result<Json<ThreatAnalysis>, String> {
        let path = PathBuf::from(&request.file_path);

        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // Perform threat analysis
        let threat_result = analyze_threats(&path).map_err(|e| e.to_string())?;
        Ok(Json(threat_result))
    }

    #[tool(
        description = "Analyze behavioral patterns including anti-analysis, persistence, and evasion techniques"
    )]
    fn analyze_behavioral_patterns(
        &self,
        #[tool(aggr)] request: MetadataRequest,
    ) -> Result<Json<BehavioralAnalysis>, String> {
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
        let behavioral_result = analyze_behavior(
            &path,
            strings.as_ref(),
            symbols.as_ref(),
            disassembly.as_ref(),
        )
        .map_err(|e| e.to_string())?;
        Ok(Json(behavioral_result))
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
            instructions: Some("A comprehensive file scanner that provides detailed metadata, hash calculations, string extraction, binary analysis, YARA indicator extraction, digital signature verification, and advanced threat detection for files.".into()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
        }
    }
}
