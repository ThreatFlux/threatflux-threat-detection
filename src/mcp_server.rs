use anyhow::Result;
use rmcp::{
    handler::server::wrapper::Json,
    model::{Implementation, ProtocolVersion, ServerCapabilities, ServerInfo},
    schemars, tool, ServerHandler,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

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
    #[schemars(skip)]
    pub metadata: Option<FileMetadata>,
    #[schemars(skip)]
    pub hashes: Option<Hashes>,
    pub strings: Option<Vec<String>>,
    pub hex_dump: Option<String>,
    #[schemars(skip)]
    pub binary_info: Option<BinaryInfo>,
    pub signatures: Option<serde_json::Value>,
    #[schemars(skip)]
    pub symbols: Option<SymbolTable>,
    #[schemars(skip)]
    pub control_flow: Option<ControlFlowAnalysis>,
    #[schemars(skip)]
    pub vulnerabilities: Option<VulnerabilityDetectionResult>,
    #[schemars(skip)]
    pub code_quality: Option<CodeQualityAnalysis>,
    #[schemars(skip)]
    pub dependencies: Option<DependencyAnalysisResult>,
    #[schemars(skip)]
    pub entropy: Option<EntropyAnalysis>,
    #[schemars(skip)]
    pub disassembly: Option<DisassemblyResult>,
    #[schemars(skip)]
    pub threats: Option<ThreatAnalysis>,
    #[schemars(skip)]
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LlmFileAnalysisRequest {
    #[schemars(description = "Path to the file to analyze")]
    pub file_path: String,

    #[schemars(description = "Token limit for the response (default: 25000)")]
    pub token_limit: Option<usize>,

    #[schemars(description = "Minimum string length to extract (default: 6)")]
    pub min_string_length: Option<usize>,

    #[schemars(description = "Maximum number of strings to return (default: 50)")]
    pub max_strings: Option<usize>,

    #[schemars(description = "Maximum number of imports to return (default: 30)")]
    pub max_imports: Option<usize>,

    #[schemars(description = "Maximum number of opcodes to return (default: 10)")]
    pub max_opcodes: Option<usize>,

    #[schemars(description = "Size of hex patterns to extract (default: 32)")]
    pub hex_pattern_size: Option<usize>,

    #[schemars(description = "Generate YARA rule suggestion (default: true)")]
    pub suggest_yara_rule: Option<bool>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct LlmFileAnalysisResult {
    pub md5: String,
    pub file_size: u64,
    pub key_strings: Vec<String>,
    pub hex_patterns: Vec<String>,
    pub imports: Vec<String>,
    pub opcodes: Vec<String>,
    pub entropy: Option<f64>,
    pub yara_rule_suggestion: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FileScannerMcp;

#[tool(tool_box)]
impl FileScannerMcp {
    #[tool(
        description = "Comprehensive file analysis tool - use flags to control which analyses to perform (metadata, hashes, strings, hex_dump, binary_info, signatures, symbols, control_flow, vulnerabilities, code_quality, dependencies, entropy, disassembly, threats, behavioral, yara_indicators)"
    )]
    pub async fn analyze_file(
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
            metadata
                .calculate_hashes()
                .await
                .map_err(|e| e.to_string())?;
            result.metadata = Some(metadata);
        }

        // Hashes
        if request.hashes.unwrap_or(false) {
            let hashes = calculate_all_hashes(&path)
                .await
                .map_err(|e| e.to_string())?;
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
            // Convert the result to a JSON-serializable format
            let sig_json = match sig_result {
                Ok(info) => serde_json::json!({
                    "status": "success",
                    "is_signed": info.is_signed,
                    "signature_type": info.signature_type,
                    "signer": info.signer,
                    "timestamp": info.timestamp,
                    "verification_status": info.verification_status,
                    "certificate_chain": info.certificate_chain,
                }),
                Err(e) => serde_json::json!({
                    "status": "error",
                    "error": e.to_string()
                }),
            };
            result.signatures = Some(sig_json);
        }

        // Symbols
        if request.symbols.unwrap_or(false) {
            if let Ok(symbols) = analyze_symbols(&path) {
                result.symbols = Some(symbols);
            }
        }

        // Control flow
        if request.control_flow.unwrap_or(false) {
            if let Ok(symbols) = analyze_symbols(&path) {
                if let Ok(control_flow) = analyze_control_flow(&path, &symbols) {
                    result.control_flow = Some(control_flow);
                }
            }
        }

        // Vulnerabilities
        if request.vulnerabilities.unwrap_or(false) {
            if let Ok(symbols) = analyze_symbols(&path) {
                if let Ok(control_flow) = analyze_control_flow(&path, &symbols) {
                    if let Ok(vulns) = analyze_vulnerabilities(&path, &symbols, &control_flow) {
                        result.vulnerabilities = Some(vulns);
                    }
                }
            }
        }

        // Code quality
        if request.code_quality.unwrap_or(false) {
            if let Ok(symbols) = analyze_symbols(&path) {
                if let Ok(control_flow) = analyze_control_flow(&path, &symbols) {
                    if let Ok(quality) = analyze_code_quality(&path, &symbols, &control_flow) {
                        result.code_quality = Some(quality);
                    }
                }
            }
        }

        // Dependencies
        if request.dependencies.unwrap_or(false) {
            if let Ok(symbols) = analyze_symbols(&path) {
                let strings = extract_strings(&path, 4).ok();
                if let Ok(deps) = analyze_dependencies(&path, &symbols, strings.as_ref()) {
                    result.dependencies = Some(deps);
                }
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

            if let Ok(behavioral) = analyze_behavior(
                &path,
                strings.as_ref(),
                symbols.as_ref(),
                disassembly.as_ref(),
            ) {
                result.behavioral = Some(behavioral);
            }
        }

        // YARA indicators
        if request.yara_indicators.unwrap_or(false) {
            let file_metadata = std::fs::metadata(&path).map_err(|e| e.to_string())?;
            let file_size = file_metadata.len();

            // Get hashes if not already calculated
            let hashes = match &result.hashes {
                Some(_) => result.hashes.take().unwrap(),
                None => calculate_all_hashes(&path)
                    .await
                    .map_err(|e| e.to_string())?,
            };

            // Get magic bytes
            let hex_options = HexDumpOptions {
                offset: 0,
                length: Some(8),
                bytes_per_line: 8,
                max_lines: Some(1),
            };
            let hex_dump = generate_hex_dump(&path, hex_options).map_err(|e| e.to_string())?;
            let magic_bytes = hex_dump
                .lines
                .first()
                .map(|line| {
                    line.raw_bytes
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default();

            // Get entropy if not already calculated
            let entropy_analysis = if let Some(e) = result.entropy.clone() {
                e
            } else {
                analyze_entropy(&path).map_err(|e| e.to_string())?
            };

            // Extract unique strings
            let strings = extract_strings(&path, 8).map_err(|e| e.to_string())?;
            let mut unique_strings: Vec<String> = strings
                .interesting_strings
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
                (
                    bi.imports.clone(),
                    bi.sections.iter().map(|s| s.name.clone()).collect(),
                )
            } else if let Ok(bi) = parse_binary(&path) {
                (
                    bi.imports.clone(),
                    bi.sections.iter().map(|s| s.name.clone()).collect(),
                )
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
                is_packed: entropy_analysis.packed_indicators.likely_packed
                    || entropy_analysis.overall_entropy > 7.0,
            });
        }

        Ok(Json(result))
    }

    #[tool(
        description = "LLM-optimized file analysis for YARA rule generation - returns focused, token-limited output with key indicators"
    )]
    pub async fn llm_analyze_file(
        &self,
        #[tool(aggr)] request: LlmFileAnalysisRequest,
    ) -> Result<Json<LlmFileAnalysisResult>, String> {
        use crate::{
            binary_parser::parse_binary, entropy_analysis::analyze_entropy,
            strings::extract_strings,
        };

        let path = PathBuf::from(&request.file_path);
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // Get file metadata for MD5 hash
        let metadata = std::fs::metadata(&path).map_err(|e| e.to_string())?;
        let file_size = metadata.len();

        // Calculate MD5 hash only
        let md5_hash = crate::hash::calculate_md5(&path)
            .await
            .map_err(|e| e.to_string())?;

        // Extract strings with focus on interesting patterns
        let min_string_len = request.min_string_length.unwrap_or(6);
        let strings = extract_strings(&path, min_string_len).map_err(|e| e.to_string())?;

        // Filter and prioritize strings for YARA rules
        let key_strings = self.extract_key_strings(&strings, request.max_strings.unwrap_or(50));

        // Get hex patterns from file header/footer
        let hex_patterns =
            self.extract_hex_patterns(&path, request.hex_pattern_size.unwrap_or(32))?;

        // Parse binary for imports
        let imports = if let Ok(binary_info) = parse_binary(&path) {
            binary_info
                .imports
                .into_iter()
                .take(request.max_imports.unwrap_or(30))
                .collect()
        } else {
            vec![]
        };

        // Get interesting opcodes/byte sequences
        let opcodes = self.extract_key_opcodes(&path, request.max_opcodes.unwrap_or(10))?;

        // Calculate entropy for packing detection
        let entropy = analyze_entropy(&path).ok().map(|e| e.overall_entropy);

        // Build focused result
        let mut result = LlmFileAnalysisResult {
            md5: md5_hash,
            file_size,
            key_strings,
            hex_patterns,
            imports,
            opcodes,
            entropy,
            yara_rule_suggestion: None,
        };

        // Generate YARA rule suggestion if requested
        if request.suggest_yara_rule.unwrap_or(true) {
            result.yara_rule_suggestion =
                Some(self.generate_yara_rule_suggestion(&result, &request.file_path));
        }

        // Ensure we're within token limit
        let serialized = serde_json::to_string(&result).unwrap_or_default();
        let token_limit = request.token_limit.unwrap_or(25000);

        if serialized.len() > token_limit {
            // Trim results to fit token limit
            result = self.trim_results_to_token_limit(result, token_limit);
        }

        Ok(Json(result))
    }

    fn extract_key_strings(
        &self,
        strings: &crate::strings::ExtractedStrings,
        max_count: usize,
    ) -> Vec<String> {
        let mut key_strings = Vec::new();

        // Prioritize interesting strings
        for s in &strings.interesting_strings {
            if key_strings.len() >= max_count {
                break;
            }
            if s.value.len() >= 8 && s.value.len() <= 100 {
                key_strings.push(s.value.clone());
            }
        }

        // Add unique ASCII strings
        let mut seen = std::collections::HashSet::new();
        for s in &strings.ascii_strings {
            if key_strings.len() >= max_count {
                break;
            }
            if s.len() >= 8 && s.len() <= 100 && seen.insert(s) {
                key_strings.push(s.clone());
            }
        }

        key_strings
    }

    fn extract_hex_patterns(
        &self,
        path: &PathBuf,
        pattern_size: usize,
    ) -> Result<Vec<String>, String> {
        use crate::hexdump::{generate_hex_dump, HexDumpOptions};

        let mut patterns = Vec::new();

        // Get file header pattern
        let header_options = HexDumpOptions {
            offset: 0,
            length: Some(pattern_size),
            bytes_per_line: pattern_size,
            max_lines: Some(1),
        };

        if let Ok(header_dump) = generate_hex_dump(path, header_options) {
            if let Some(line) = header_dump.lines.first() {
                let hex_pattern = line
                    .raw_bytes
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                patterns.push(hex_pattern);
            }
        }

        // Get file footer pattern if file is large enough
        if let Ok(metadata) = std::fs::metadata(path) {
            if metadata.len() > pattern_size as u64 {
                let footer_options = HexDumpOptions {
                    offset: metadata.len() - pattern_size as u64,
                    length: Some(pattern_size),
                    bytes_per_line: pattern_size,
                    max_lines: Some(1),
                };

                if let Ok(footer_dump) = generate_hex_dump(path, footer_options) {
                    if let Some(line) = footer_dump.lines.first() {
                        let hex_pattern = line
                            .raw_bytes
                            .iter()
                            .map(|b| format!("{:02X}", b))
                            .collect::<Vec<_>>()
                            .join(" ");
                        patterns.push(hex_pattern);
                    }
                }
            }
        }

        Ok(patterns)
    }

    fn extract_key_opcodes(&self, path: &Path, max_count: usize) -> Result<Vec<String>, String> {
        use crate::hexdump::{generate_hex_dump, HexDumpOptions};

        let mut opcodes = Vec::new();

        // Look for common opcode patterns in code sections
        let options = HexDumpOptions {
            offset: 0x1000, // Common code section offset
            length: Some(256),
            bytes_per_line: 16,
            max_lines: Some(16),
        };

        if let Ok(dump) = generate_hex_dump(path, options) {
            for line in dump.lines.iter().take(max_count) {
                // Look for interesting opcode sequences
                let bytes = &line.raw_bytes;
                for window in bytes.windows(4) {
                    // Common interesting patterns
                    if (window[0] == 0xE8 || window[0] == 0xE9) || // CALL/JMP
                       (window[0] == 0xFF && (window[1] & 0xF0) == 0x10) || // Indirect calls
                       (window[0] == 0x48 && window[1] == 0x8B) || // MOV patterns
                       (window[0] == 0x55 && window[1] == 0x48)
                    {
                        // Function prologue
                        let pattern = window
                            .iter()
                            .map(|b| format!("{:02X}", b))
                            .collect::<Vec<_>>()
                            .join(" ");
                        if !opcodes.contains(&pattern) {
                            opcodes.push(pattern);
                        }
                    }
                }
            }
        }

        Ok(opcodes.into_iter().take(max_count).collect())
    }

    fn generate_yara_rule_suggestion(
        &self,
        analysis: &LlmFileAnalysisResult,
        file_name: &str,
    ) -> String {
        let rule_name = file_name
            .replace("/", "_")
            .replace(".", "_")
            .replace("-", "_");
        let mut conditions = Vec::new();

        // Add file size condition
        conditions.push(format!("filesize == {}", analysis.file_size));

        // Add entropy condition if packed
        if let Some(entropy) = analysis.entropy {
            if entropy > 7.0 {
                conditions.push(format!("math.entropy(0, filesize) > {:.1}", entropy - 0.5));
            }
        }

        // Build string conditions
        let string_count = analysis.key_strings.len().min(5);
        if string_count > 0 {
            conditions.push(format!("{} of ($s*)", string_count.div_ceil(2)));
        }

        // Add hex pattern conditions
        if !analysis.hex_patterns.is_empty() {
            conditions.push("$header at 0".to_string());
        }

        // Build the rule
        let mut rule = format!("rule {} {{\n", rule_name);
        rule.push_str("    meta:\n");
        rule.push_str(&format!("        md5 = \"{}\"\n", analysis.md5));
        rule.push_str(&format!("        filesize = {}\n", analysis.file_size));

        rule.push_str("    strings:\n");

        // Add hex patterns
        if let Some(header) = analysis.hex_patterns.first() {
            rule.push_str(&format!("        $header = {{ {} }}\n", header));
        }

        // Add key strings
        for (i, s) in analysis.key_strings.iter().take(10).enumerate() {
            let escaped = s.replace("\\", "\\\\").replace("\"", "\\\"");
            rule.push_str(&format!("        $s{} = \"{}\"\n", i + 1, escaped));
        }

        // Add condition
        rule.push_str("    condition:\n");
        rule.push_str(&format!("        {}\n", conditions.join(" and ")));
        rule.push_str("}\n");

        rule
    }

    fn trim_results_to_token_limit(
        &self,
        mut result: LlmFileAnalysisResult,
        token_limit: usize,
    ) -> LlmFileAnalysisResult {
        // Progressively trim results until we fit within token limit
        loop {
            let serialized = serde_json::to_string(&result).unwrap_or_default();
            if serialized.len() <= token_limit {
                break;
            }

            // Trim strategies in order of preference
            if result.key_strings.len() > 20 {
                result.key_strings.truncate(result.key_strings.len() - 5);
            } else if result.imports.len() > 10 {
                result.imports.truncate(result.imports.len() - 5);
            } else if result.opcodes.len() > 5 {
                result.opcodes.truncate(result.opcodes.len() - 2);
            } else if result.key_strings.len() > 5 {
                result.key_strings.truncate(result.key_strings.len() - 1);
            } else {
                // Last resort: remove YARA suggestion
                result.yara_rule_suggestion = None;
                break;
            }
        }

        result
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
            instructions: Some("A comprehensive file scanner with a single analyze_file tool that supports multiple analysis types via flags: metadata, hashes, strings, hex_dump, binary_info, signatures, symbols, control_flow, vulnerabilities, code_quality, dependencies, entropy, disassembly, threats, behavioral, and yara_indicators.".into()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
        }
    }
}
