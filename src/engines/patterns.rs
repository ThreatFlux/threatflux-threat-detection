//! Pattern matching detection engine implementation

use crate::error::{Result, ThreatError};
use crate::types::{
    DetectionEngine, IndicatorType, ScanTarget, Severity, StringMatch, ThreatAnalysis,
    ThreatClassification, ThreatIndicator, ThreatLevel, YaraMatch,
};
use async_trait::async_trait;
use std::collections::HashMap;

#[cfg(feature = "pattern-matching")]
use aho_corasick::AhoCorasick;
#[cfg(feature = "pattern-matching")]
use regex::RegexSet;

/// Pattern matching based detection engine
pub struct PatternEngine {
    #[cfg(feature = "pattern-matching")]
    string_patterns: Option<AhoCorasick>,
    #[cfg(feature = "pattern-matching")]
    string_pattern_list: Vec<String>,
    #[cfg(feature = "pattern-matching")]
    regex_patterns: Option<RegexSet>,
    #[cfg(feature = "pattern-matching")]
    regex_pattern_list: Vec<String>,
    #[cfg(not(feature = "pattern-matching"))]
    _placeholder: (),
}

impl PatternEngine {
    /// Create new pattern engine
    pub async fn new() -> Result<Self> {
        #[cfg(feature = "pattern-matching")]
        {
            let (string_patterns, string_list, regex_patterns, regex_list) =
                Self::build_default_patterns().await?;
            Ok(Self {
                string_patterns: Some(string_patterns),
                string_pattern_list: string_list,
                regex_patterns: Some(regex_patterns),
                regex_pattern_list: regex_list,
            })
        }
        #[cfg(not(feature = "pattern-matching"))]
        {
            Ok(Self { _placeholder: () })
        }
    }

    /// Create pattern engine with custom patterns
    pub async fn with_patterns(
        string_patterns: Vec<String>,
        regex_patterns: Vec<String>,
    ) -> Result<Self> {
        #[cfg(feature = "pattern-matching")]
        {
            let string_matcher = if !string_patterns.is_empty() {
                Some(AhoCorasick::new(&string_patterns).map_err(|e| {
                    ThreatError::pattern(format!("Failed to build string matcher: {}", e))
                })?)
            } else {
                None
            };

            let regex_matcher = if !regex_patterns.is_empty() {
                Some(RegexSet::new(&regex_patterns).map_err(|e| {
                    ThreatError::pattern(format!("Failed to build regex matcher: {}", e))
                })?)
            } else {
                None
            };

            Ok(Self {
                string_patterns: string_matcher,
                string_pattern_list: string_patterns,
                regex_patterns: regex_matcher,
                regex_pattern_list: regex_patterns,
            })
        }
        #[cfg(not(feature = "pattern-matching"))]
        {
            // Validate that patterns aren't empty for error checking
            if string_patterns.is_empty() && regex_patterns.is_empty() {
                return Err(ThreatError::pattern("No patterns provided"));
            }
            Ok(Self { _placeholder: () })
        }
    }

    #[cfg(feature = "pattern-matching")]
    async fn build_default_patterns() -> Result<(AhoCorasick, Vec<String>, RegexSet, Vec<String>)> {
        // Default malicious string patterns
        let default_strings = vec![
            // Process injection APIs
            "VirtualAlloc".to_string(),
            "WriteProcessMemory".to_string(),
            "CreateRemoteThread".to_string(),
            "SetWindowsHookEx".to_string(),
            "GetProcAddress".to_string(),
            "LoadLibrary".to_string(),
            // Crypto/mining indicators
            "stratum+tcp".to_string(),
            "xmrig".to_string(),
            "ccminer".to_string(),
            // Command execution
            "cmd.exe".to_string(),
            "powershell.exe".to_string(),
            "rundll32.exe".to_string(),
            // Persistence mechanisms
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            "HKEY_LOCAL_MACHINE".to_string(),
            // Anti-debugging
            "IsDebuggerPresent".to_string(),
            "CheckRemoteDebuggerPresent".to_string(),
            // Ransom indicators
            "ransom".to_string(),
            "decrypt".to_string(),
            "bitcoin".to_string(),
            "READ_ME.txt".to_string(),
        ];

        // Default regex patterns
        let default_regexes = vec![
            // Bitcoin addresses
            r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}".to_string(),
            // Monero addresses
            r"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}".to_string(),
            // IP addresses in suspicious contexts
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:\d+\b".to_string(),
            // Base64 encoded data (potential obfuscation)
            r"[A-Za-z0-9+/]{50,}={0,2}".to_string(),
            // URLs with suspicious TLDs
            r"https?://[^\s]+\.(?:tk|ml|ga|cf)\b".to_string(),
        ];

        let string_matcher = AhoCorasick::new(&default_strings).map_err(|e| {
            ThreatError::pattern(format!("Failed to build default string matcher: {}", e))
        })?;

        let regex_matcher = RegexSet::new(&default_regexes).map_err(|e| {
            ThreatError::pattern(format!("Failed to build default regex matcher: {}", e))
        })?;

        Ok((
            string_matcher,
            default_strings,
            regex_matcher,
            default_regexes,
        ))
    }
}

#[async_trait]
impl DetectionEngine for PatternEngine {
    fn engine_type(&self) -> &'static str {
        "PatternMatching"
    }

    fn version(&self) -> &'static str {
        "0.1.0-placeholder"
    }

    async fn scan(&self, target: ScanTarget) -> Result<ThreatAnalysis> {
        let start_time = std::time::Instant::now();

        #[cfg(feature = "pattern-matching")]
        {
            let (matches, patterns_matched) = self.scan_with_patterns(&target).await?;
            let scan_duration = start_time.elapsed();
            let file_size = self.get_target_size(&target).await?;

            // Convert pattern matches to threat analysis
            let threat_level = self.calculate_threat_level(&matches);
            let classifications = self.extract_classifications(&matches);
            let indicators = self.extract_indicators(&matches);

            Ok(ThreatAnalysis {
                matches,
                threat_level,
                classifications,
                indicators,
                scan_stats: crate::types::ScanStatistics {
                    scan_duration,
                    rules_evaluated: 1, // Pattern engine treated as single "rule"
                    patterns_matched,
                    file_size_scanned: file_size,
                },
                recommendations: Vec::new(),
            })
        }
        #[cfg(not(feature = "pattern-matching"))]
        {
            let scan_duration = start_time.elapsed();
            let file_size = self.get_target_size(&target).await?;

            Ok(ThreatAnalysis {
                matches: Vec::new(),
                threat_level: ThreatLevel::None,
                classifications: Vec::new(),
                indicators: vec![ThreatIndicator {
                    indicator_type: IndicatorType::SystemModification,
                    description: "Pattern matching engine not available".to_string(),
                    severity: Severity::Low,
                    confidence: 1.0,
                    mitre_technique: None,
                    context: HashMap::new(),
                }],
                scan_stats: crate::types::ScanStatistics {
                    scan_duration,
                    rules_evaluated: 0,
                    patterns_matched: 0,
                    file_size_scanned: file_size,
                },
                recommendations: vec![
                    "Enable pattern-matching feature for basic pattern detection".to_string(),
                ],
            })
        }
    }

    async fn scan_with_custom_rule(
        &self,
        target: ScanTarget,
        _rule: &str,
    ) -> Result<ThreatAnalysis> {
        // Pattern engine doesn't support YARA-style rules
        self.scan(target).await
    }

    async fn update_rules(&mut self) -> Result<()> {
        // Placeholder - would update pattern database
        Ok(())
    }

    fn is_available(&self) -> bool {
        #[cfg(feature = "pattern-matching")]
        {
            self.string_patterns.is_some() || self.regex_patterns.is_some()
        }
        #[cfg(not(feature = "pattern-matching"))]
        {
            false
        }
    }
}

impl PatternEngine {
    /// Get the size of a scan target
    async fn get_target_size(&self, target: &ScanTarget) -> Result<u64> {
        match target {
            ScanTarget::File(path) => tokio::fs::metadata(path)
                .await
                .map(|m| m.len())
                .map_err(|e| ThreatError::file(format!("Failed to read file metadata: {}", e))),
            ScanTarget::Memory { data, .. } => Ok(data.len() as u64),
            ScanTarget::Directory(_) => Ok(0), // Directory size not meaningful for patterns
        }
    }

    #[cfg(feature = "pattern-matching")]
    async fn scan_with_patterns(&self, target: &ScanTarget) -> Result<(Vec<YaraMatch>, usize)> {
        let data = match target {
            ScanTarget::File(path) => tokio::fs::read(path)
                .await
                .map_err(|e| ThreatError::file(format!("Failed to read file: {}", e)))?,
            ScanTarget::Memory { data, .. } => data.clone(),
            ScanTarget::Directory(_) => {
                return Err(ThreatError::pattern(
                    "Directory scanning not supported by pattern engine",
                ));
            }
        };

        // Convert to string for pattern matching (lossy conversion for binary data)
        let content = String::from_utf8_lossy(&data);
        let mut matches = Vec::new();
        let mut patterns_matched = 0;

        // String pattern matching
        if let Some(ref string_matcher) = self.string_patterns {
            for mat in string_matcher.find_iter(content.as_ref()) {
                let pattern_id = mat.pattern().as_u32() as usize;
                // We need to track the patterns ourselves since AhoCorasick doesn't expose them
                let pattern_text = self.get_pattern_text(pattern_id);
                let yara_match = YaraMatch {
                    rule_identifier: format!("string_pattern_{}", pattern_id),
                    tags: self.get_tags_for_pattern(&pattern_text),
                    metadata: self.get_metadata_for_pattern(&pattern_text),
                    strings: vec![StringMatch {
                        identifier: format!("${}", pattern_id),
                        offset: mat.start() as u64,
                        length: mat.len(),
                        value: Some(pattern_text),
                    }],
                };
                matches.push(yara_match);
                patterns_matched += 1;
            }
        }

        // Regex pattern matching
        if let Some(ref regex_matcher) = self.regex_patterns {
            let matches_set = regex_matcher.matches(&content);
            for (pattern_idx, _) in matches_set.iter().enumerate() {
                if matches_set.matched(pattern_idx) {
                    let pattern_name = format!("regex_pattern_{}", pattern_idx);
                    let yara_match = YaraMatch {
                        rule_identifier: pattern_name.clone(),
                        tags: vec!["pattern".to_string(), "regex".to_string()],
                        metadata: HashMap::from([
                            ("type".to_string(), "regex".to_string()),
                            ("pattern_id".to_string(), pattern_idx.to_string()),
                        ]),
                        strings: vec![StringMatch {
                            identifier: format!("${}", pattern_idx),
                            offset: 0, // Regex doesn't provide exact offset easily
                            length: 0,
                            value: Some(pattern_name),
                        }],
                    };
                    matches.push(yara_match);
                    patterns_matched += 1;
                }
            }
        }

        Ok((matches, patterns_matched))
    }

    #[cfg(feature = "pattern-matching")]
    fn get_tags_for_pattern(&self, pattern: &str) -> Vec<String> {
        let mut tags = vec!["pattern".to_string(), "string".to_string()];

        // Add specific tags based on pattern content
        let pattern_lower = pattern.to_lowercase();
        if pattern_lower.contains("virtualalloc") || pattern_lower.contains("writeprocessmemory") {
            tags.push("injection".to_string());
            tags.push("malware".to_string());
        } else if pattern_lower.contains("cmd.exe") || pattern_lower.contains("powershell") {
            tags.push("execution".to_string());
            tags.push("suspicious".to_string());
        } else if pattern_lower.contains("bitcoin") || pattern_lower.contains("stratum") {
            tags.push("cryptominer".to_string());
            tags.push("suspicious".to_string());
        } else if pattern_lower.contains("ransom") || pattern_lower.contains("decrypt") {
            tags.push("ransomware".to_string());
            tags.push("malware".to_string());
        } else if pattern_lower.contains("registry") || pattern_lower.contains("hkey") {
            tags.push("persistence".to_string());
            tags.push("suspicious".to_string());
        } else if pattern_lower.contains("debugger") {
            tags.push("anti_debug".to_string());
            tags.push("evasion".to_string());
        }

        tags
    }

    #[cfg(feature = "pattern-matching")]
    fn get_metadata_for_pattern(&self, pattern: &str) -> HashMap<String, String> {
        let mut metadata = HashMap::new();
        metadata.insert("type".to_string(), "string_pattern".to_string());
        metadata.insert("pattern".to_string(), pattern.to_string());

        // Add specific metadata based on pattern
        let pattern_lower = pattern.to_lowercase();
        if pattern_lower.contains("virtualalloc") || pattern_lower.contains("writeprocessmemory") {
            metadata.insert("category".to_string(), "process_injection".to_string());
            metadata.insert("severity".to_string(), "high".to_string());
        } else if pattern_lower.contains("bitcoin") || pattern_lower.contains("stratum") {
            metadata.insert("category".to_string(), "cryptocurrency".to_string());
            metadata.insert("severity".to_string(), "medium".to_string());
        } else if pattern_lower.contains("ransom") {
            metadata.insert("category".to_string(), "ransomware".to_string());
            metadata.insert("severity".to_string(), "critical".to_string());
        }

        metadata
    }

    fn calculate_threat_level(&self, matches: &[YaraMatch]) -> ThreatLevel {
        if matches.is_empty() {
            return ThreatLevel::Clean;
        }

        let mut max_severity = ThreatLevel::Clean;

        for yara_match in matches {
            let severity = if yara_match
                .tags
                .iter()
                .any(|t| t == "malware" || t == "ransomware")
            {
                ThreatLevel::Critical
            } else if yara_match
                .tags
                .iter()
                .any(|t| t == "injection" || t == "cryptominer")
            {
                ThreatLevel::Malicious
            } else if yara_match
                .tags
                .iter()
                .any(|t| t == "suspicious" || t == "execution")
            {
                ThreatLevel::Suspicious
            } else {
                ThreatLevel::Clean
            };

            if severity > max_severity {
                max_severity = severity;
            }
        }

        max_severity
    }

    fn extract_classifications(&self, matches: &[YaraMatch]) -> Vec<ThreatClassification> {
        let mut classifications = Vec::new();

        for yara_match in matches {
            if yara_match.tags.iter().any(|t| t == "ransomware") {
                if !classifications.contains(&ThreatClassification::Ransomware) {
                    classifications.push(ThreatClassification::Ransomware);
                }
            }
            if yara_match.tags.iter().any(|t| t == "cryptominer") {
                if !classifications.contains(&ThreatClassification::Cryptominer) {
                    classifications.push(ThreatClassification::Cryptominer);
                }
            }
            if yara_match.tags.iter().any(|t| t == "injection") {
                if !classifications.contains(&ThreatClassification::Trojan) {
                    classifications.push(ThreatClassification::Trojan);
                }
            }
        }

        classifications
    }

    fn extract_indicators(&self, matches: &[YaraMatch]) -> Vec<ThreatIndicator> {
        let mut indicators = Vec::new();

        for yara_match in matches {
            let (indicator_type, severity) = if yara_match.tags.iter().any(|t| t == "injection") {
                (IndicatorType::ProcessInjection, Severity::Critical)
            } else if yara_match.tags.iter().any(|t| t == "persistence") {
                (IndicatorType::PersistenceMechanism, Severity::High)
            } else if yara_match.tags.iter().any(|t| t == "execution") {
                (IndicatorType::SuspiciousBehavior, Severity::Medium)
            } else if yara_match.tags.iter().any(|t| t == "anti_debug") {
                (IndicatorType::AntiAnalysis, Severity::Medium)
            } else {
                (IndicatorType::SuspiciousBehavior, Severity::Low)
            };

            let indicator = ThreatIndicator {
                indicator_type,
                description: format!("Pattern match: {}", yara_match.rule_identifier),
                severity,
                confidence: 0.6, // Medium confidence for pattern matches
                mitre_technique: None,
                context: yara_match.metadata.clone(),
            };

            indicators.push(indicator);
        }

        indicators
    }

    #[cfg(feature = "pattern-matching")]
    fn get_pattern_text(&self, pattern_id: usize) -> String {
        self.string_pattern_list
            .get(pattern_id)
            .cloned()
            .unwrap_or_else(|| format!("unknown_pattern_{}", pattern_id))
    }
}
