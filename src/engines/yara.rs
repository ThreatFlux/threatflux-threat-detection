//! YARA detection engine implementation

use crate::error::{Result, ThreatError};
#[cfg(not(feature = "yara-engine"))]
use crate::types::ThreatLevel;
use crate::types::{
    DetectionEngine, IndicatorType, ScanTarget, Severity, StringMatch, ThreatAnalysis,
    ThreatClassification, ThreatIndicator, YaraMatch,
};
use async_trait::async_trait;
#[cfg(not(feature = "yara-engine"))]
use std::collections::HashMap;
#[cfg(feature = "yara-engine")]
use std::sync::Arc;

#[cfg(feature = "yara-engine")]
use yara_x::{Compiler, MetaValue, Rules, Scanner};

/// YARA-X based detection engine
pub struct YaraEngine {
    #[cfg(feature = "yara-engine")]
    rules: Option<Arc<Rules>>,
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
    async fn load_builtin_rules() -> Result<Arc<Rules>> {
        #[cfg(feature = "builtin-rules")]
        {
            let builtin_rules = crate::rules::builtin::get_builtin_rules();
            let combined_rules = builtin_rules.join("\n");
            Self::compile_rules_from_string(&combined_rules).await
        }
        #[cfg(not(feature = "builtin-rules"))]
        {
            // Create empty rules set
            Ok(Arc::new(Compiler::new().build()))
        }
    }

    #[cfg(feature = "yara-engine")]
    async fn compile_rules_from_string(rule_content: &str) -> Result<Arc<Rules>> {
        let rule_content = rule_content.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut compiler = Compiler::new();
            compiler.add_source(rule_content.as_str()).map_err(|e| {
                ThreatError::rule_compilation(format!("Failed to add rule source: {}", e))
            })?;
            Ok(Arc::new(compiler.build()))
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
                    "Enable YARA engine feature for comprehensive scanning".to_string(),
                ],
            })
        }
    }

    async fn scan_with_custom_rule(
        &self,
        target: ScanTarget,
        rule: &str,
    ) -> Result<ThreatAnalysis> {
        #[cfg(feature = "yara-engine")]
        {
            let custom_engine = Self::with_rules(rule).await?;
            return custom_engine.scan(target).await;
        }

        #[cfg(not(feature = "yara-engine"))]
        {
            self.compile_rule(rule).await?;
            self.scan(target).await
        }
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
                    let mut scanner = Scanner::new(&rules_clone);
                    let scan_results = scanner
                        .scan_file(&path_clone)
                        .map_err(|e| ThreatError::yara(format!("YARA scan failed: {}", e)))?;

                    let mut matches = Vec::new();
                    for rule in scan_results.matching_rules() {
                        let yara_match = YaraMatch {
                            rule_identifier: rule.identifier().to_string(),
                            tags: rule
                                .tags()
                                .map(|tag| tag.identifier().to_string())
                                .collect(),
                            metadata: rule
                                .metadata()
                                .map(|(identifier, value)| {
                                    (identifier.to_string(), meta_value_to_string(value))
                                })
                                .collect(),
                            strings: rule
                                .patterns()
                                .flat_map(|p| p.matches())
                                .map(|m| {
                                    let range = m.range();
                                    StringMatch {
                                        identifier: "unknown".to_string(),
                                        offset: u64::try_from(range.start).unwrap_or(u64::MAX),
                                        length: range.len(),
                                        value: None, // Raw bytes not always printable
                                    }
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
                    let mut scanner = Scanner::new(&rules_clone);
                    let scan_results = scanner
                        .scan(&data_clone)
                        .map_err(|e| ThreatError::yara(format!("YARA scan failed: {}", e)))?;

                    let mut matches = Vec::new();
                    for rule in scan_results.matching_rules() {
                        let yara_match = YaraMatch {
                            rule_identifier: rule.identifier().to_string(),
                            tags: rule
                                .tags()
                                .map(|tag| tag.identifier().to_string())
                                .collect(),
                            metadata: rule
                                .metadata()
                                .map(|(identifier, value)| {
                                    (identifier.to_string(), meta_value_to_string(value))
                                })
                                .collect(),
                            strings: rule
                                .patterns()
                                .flat_map(|p| p.matches())
                                .map(|m| {
                                    let range = m.range();
                                    StringMatch {
                                        identifier: "unknown".to_string(),
                                        offset: u64::try_from(range.start).unwrap_or(u64::MAX),
                                        length: range.len(),
                                        value: None,
                                    }
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

#[cfg(feature = "yara-engine")]
fn meta_value_to_string(value: MetaValue<'_>) -> String {
    match value {
        MetaValue::Integer(value) => value.to_string(),
        MetaValue::Float(value) => value.to_string(),
        MetaValue::Bool(value) => value.to_string(),
        MetaValue::String(value) => value.to_string(),
        MetaValue::Bytes(value) => String::from_utf8_lossy(value.as_ref()).into_owned(),
    }
}

#[cfg(all(test, feature = "yara-engine"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn custom_rule_is_used_for_scanning() {
        let engine = YaraEngine::new()
            .await
            .expect("built-in rules should compile");
        let rule = r#"
rule custom_rule : custom suspicious {
    meta:
        family = "test-family"
        score = 7
        enabled = true
    strings:
        $needle = "custom needle"
    condition:
        $needle
}
"#;

        let analysis = engine
            .scan_with_custom_rule(
                ScanTarget::Memory {
                    data: b"prefix custom needle suffix".to_vec(),
                    name: Some("sample.bin".to_string()),
                },
                rule,
            )
            .await
            .expect("custom scan should succeed");

        assert_eq!(analysis.matches.len(), 1);
        let matched_rule = &analysis.matches[0];
        assert_eq!(matched_rule.rule_identifier, "custom_rule");
        assert_eq!(matched_rule.tags, ["custom", "suspicious"]);
        assert_eq!(
            matched_rule.metadata.get("family").map(String::as_str),
            Some("test-family")
        );
        assert_eq!(
            matched_rule.metadata.get("score").map(String::as_str),
            Some("7")
        );
        assert_eq!(
            matched_rule.metadata.get("enabled").map(String::as_str),
            Some("true")
        );
        assert_eq!(matched_rule.strings.len(), 1);
        assert_eq!(matched_rule.strings[0].offset, 7);
        assert_eq!(matched_rule.strings[0].length, 13);
    }
}
