//! YARA detection engine implementation

use crate::error::{Result, ThreatError};
use crate::types::{
    DetectionEngine, IndicatorType, ScanTarget, Severity, StringMatch, ThreatAnalysis,
    ThreatClassification, ThreatIndicator, ThreatLevel, YaraMatch,
};
use async_trait::async_trait;
use std::collections::HashMap;

#[cfg(feature = "yara-engine")]
use yara_x::{CompileContext, Rules, Scanner};

/// YARA-X based detection engine
pub struct YaraEngine {
    #[cfg(feature = "yara-engine")]
    rules: Option<Rules>,
    #[cfg(not(feature = "yara-engine"))]
    _placeholder: (),
}

impl YaraEngine {
    /// Create new YARA engine
    pub async fn new() -> Result<Self> {
        #[cfg(feature = "yara-engine")]
        {
            // Load built-in rules if available
            let rules = Self::load_builtin_rules().await?;
            Ok(Self { rules: Some(rules) })
        }
        #[cfg(not(feature = "yara-engine"))]
        {
            Ok(Self { _placeholder: () })
        }
    }

    /// Create YARA engine with custom rules
    pub async fn with_rules(rule_content: &str) -> Result<Self> {
        #[cfg(feature = "yara-engine")]
        {
            let rules = Self::compile_rules_from_string(rule_content).await?;
            Ok(Self { rules: Some(rules) })
        }
        #[cfg(not(feature = "yara-engine"))]
        {
            if rule_content.is_empty() {
                return Err(ThreatError::invalid_rule("Rule content cannot be empty"));
            }
            Ok(Self { _placeholder: () })
        }
    }

    /// Compile YARA rule from string
    pub async fn compile_rule(&self, rule_content: &str) -> Result<()> {
        if rule_content.is_empty() {
            return Err(ThreatError::invalid_rule("Rule content cannot be empty"));
        }

        #[cfg(feature = "yara-engine")]
        {
            Self::compile_rules_from_string(rule_content).await?;
        }

        Ok(())
    }

    #[cfg(feature = "yara-engine")]
    async fn load_builtin_rules() -> Result<Rules> {
        #[cfg(feature = "builtin-rules")]
        {
            let builtin_rules = crate::rules::builtin::get_builtin_rules();
            let combined_rules = builtin_rules.join("\n");
            Self::compile_rules_from_string(&combined_rules).await
        }
        #[cfg(not(feature = "builtin-rules"))]
        {
            // Create empty rules set
            let context = CompileContext::new();
            context
                .build()
                .map_err(|e| ThreatError::yara(format!("Failed to build empty rules: {}", e)))
        }
    }

    #[cfg(feature = "yara-engine")]
    async fn compile_rules_from_string(rule_content: &str) -> Result<Rules> {
        tokio::task::spawn_blocking(move || {
            let mut context = CompileContext::new();
            context.add_source(rule_content.to_string()).map_err(|e| {
                ThreatError::rule_compilation(format!("Failed to add rule source: {}", e))
            })?;
            context.build().map_err(|e| {
                ThreatError::rule_compilation(format!("Failed to compile rules: {}", e))
            })
        })
        .await
        .map_err(|e| ThreatError::internal(format!("Task join error: {}", e)))?
    }
}

#[async_trait]
impl DetectionEngine for YaraEngine {
    fn engine_type(&self) -> &'static str {
        "YARA"
    }

    fn version(&self) -> &'static str {
        "0.1.0-placeholder"
    }

    async fn scan(&self, target: ScanTarget) -> Result<ThreatAnalysis> {
        let start_time = std::time::Instant::now();

        #[cfg(feature = "yara-engine")]
        {
            let matches = self.scan_with_yara(&target).await?;
            let scan_duration = start_time.elapsed();
            let file_size = self.get_target_size(&target).await?;

            // Convert YARA matches to threat analysis
            let threat_level = crate::analysis::calculate_threat_level(&matches, &[]);
            let classifications = self.extract_classifications(&matches);
            let indicators = self.extract_indicators(&matches);

            Ok(ThreatAnalysis {
                matches,
                threat_level,
                classifications,
                indicators,
                scan_stats: crate::types::ScanStatistics {
                    scan_duration,
                    rules_evaluated: self.rules.as_ref().map(|_| 1).unwrap_or(0),
                    patterns_matched: 0,
                    file_size_scanned: file_size,
                },
                recommendations: Vec::new(),
            })
        }
        #[cfg(not(feature = "yara-engine"))]
        {
            let scan_duration = start_time.elapsed();
            let file_size = self.get_target_size(&target).await?;

            Ok(ThreatAnalysis {
                matches: Vec::new(),
                threat_level: ThreatLevel::None,
                classifications: Vec::new(),
                indicators: vec![ThreatIndicator {
                    indicator_type: IndicatorType::SystemModification,
                    description: "YARA engine not available".to_string(),
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
                    "Enable YARA engine feature for comprehensive scanning".to_string()
                ],
            })
        }
    }

    async fn scan_with_custom_rule(
        &self,
        target: ScanTarget,
        rule: &str,
    ) -> Result<ThreatAnalysis> {
        // Compile the custom rule first
        self.compile_rule(rule).await?;

        // Then scan with it
        self.scan(target).await
    }

    async fn update_rules(&mut self) -> Result<()> {
        // Placeholder - would update YARA rule database
        Ok(())
    }

    fn is_available(&self) -> bool {
        #[cfg(feature = "yara-engine")]
        {
            self.rules.is_some()
        }
        #[cfg(not(feature = "yara-engine"))]
        {
            false
        }
    }
}

impl YaraEngine {
    /// Get the size of a scan target
    async fn get_target_size(&self, target: &ScanTarget) -> Result<u64> {
        match target {
            ScanTarget::File(path) => tokio::fs::metadata(path)
                .await
                .map(|m| m.len())
                .map_err(|e| ThreatError::file(format!("Failed to read file metadata: {}", e))),
            ScanTarget::Memory { data, .. } => Ok(data.len() as u64),
            ScanTarget::Directory(_) => Ok(0), // Directory size not meaningful for YARA
        }
    }

    #[cfg(feature = "yara-engine")]
    async fn scan_with_yara(&self, target: &ScanTarget) -> Result<Vec<YaraMatch>> {
        let rules = self
            .rules
            .as_ref()
            .ok_or_else(|| ThreatError::yara("No YARA rules loaded"))?;

        match target {
            ScanTarget::File(path) => {
                let path_clone = path.clone();
                let rules_clone = rules.clone();

                tokio::task::spawn_blocking(move || {
                    let scanner = Scanner::new(&rules_clone);
                    let scan_results = scanner
                        .scan_file(&path_clone)
                        .map_err(|e| ThreatError::yara(format!("YARA scan failed: {}", e)))?;

                    let mut matches = Vec::new();
                    for rule in scan_results.matching_rules() {
                        let yara_match = YaraMatch {
                            rule_identifier: rule.identifier().to_string(),
                            tags: rule.tags().map(|t| t.to_string()).collect(),
                            metadata: rule
                                .metadata()
                                .map(|m| (m.identifier().to_string(), m.value().to_string()))
                                .collect(),
                            strings: rule
                                .patterns()
                                .flat_map(|p| p.matches())
                                .map(|m| StringMatch {
                                    identifier: "unknown".to_string(),
                                    offset: m.offset(),
                                    length: m.length(),
                                    value: None, // Raw bytes not always printable
                                })
                                .collect(),
                        };
                        matches.push(yara_match);
                    }

                    Ok(matches)
                })
                .await
                .map_err(|e| ThreatError::internal(format!("Task join error: {}", e)))?
            }
            ScanTarget::Memory { data, .. } => {
                let data_clone = data.clone();
                let rules_clone = rules.clone();

                tokio::task::spawn_blocking(move || {
                    let scanner = Scanner::new(&rules_clone);
                    let scan_results = scanner
                        .scan_mem(&data_clone)
                        .map_err(|e| ThreatError::yara(format!("YARA scan failed: {}", e)))?;

                    let mut matches = Vec::new();
                    for rule in scan_results.matching_rules() {
                        let yara_match = YaraMatch {
                            rule_identifier: rule.identifier().to_string(),
                            tags: rule.tags().map(|t| t.to_string()).collect(),
                            metadata: rule
                                .metadata()
                                .map(|m| (m.identifier().to_string(), m.value().to_string()))
                                .collect(),
                            strings: rule
                                .patterns()
                                .flat_map(|p| p.matches())
                                .map(|m| StringMatch {
                                    identifier: "unknown".to_string(),
                                    offset: m.offset(),
                                    length: m.length(),
                                    value: None,
                                })
                                .collect(),
                        };
                        matches.push(yara_match);
                    }

                    Ok(matches)
                })
                .await
                .map_err(|e| ThreatError::internal(format!("Task join error: {}", e)))?
            }
            ScanTarget::Directory(_) => Err(ThreatError::yara(
                "Directory scanning not supported by YARA engine",
            )),
        }
    }

    fn extract_classifications(&self, matches: &[YaraMatch]) -> Vec<ThreatClassification> {
        let mut classifications = Vec::new();
        for yara_match in matches {
            let rule_classifications =
                crate::analysis::extract_classifications_from_tags(&yara_match.tags);
            for classification in rule_classifications {
                if !classifications.contains(&classification) {
                    classifications.push(classification);
                }
            }
        }
        classifications
    }

    fn extract_indicators(&self, matches: &[YaraMatch]) -> Vec<ThreatIndicator> {
        let mut indicators = Vec::new();

        for yara_match in matches {
            // Create indicator based on rule match
            let severity =
                if yara_match.tags.iter().any(|t| {
                    t.contains("critical") || t.contains("malware") || t.contains("trojan")
                }) {
                    Severity::Critical
                } else if yara_match
                    .tags
                    .iter()
                    .any(|t| t.contains("suspicious") || t.contains("apt"))
                {
                    Severity::High
                } else {
                    Severity::Medium
                };

            let indicator_type = if yara_match.tags.iter().any(|t| t.contains("malware")) {
                IndicatorType::KnownMalwareFamily
            } else if yara_match.tags.iter().any(|t| t.contains("exploit")) {
                IndicatorType::ExploitTechnique
            } else {
                IndicatorType::SuspiciousBehavior
            };

            let indicator = ThreatIndicator {
                indicator_type,
                description: format!("YARA rule match: {}", yara_match.rule_identifier),
                severity,
                confidence: 0.8, // High confidence for YARA matches
                mitre_technique: yara_match.metadata.get("mitre_technique").cloned(),
                context: yara_match.metadata.clone(),
            };

            indicators.push(indicator);
        }

        indicators
    }
}
