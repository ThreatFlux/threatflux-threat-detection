//! ClamAV detection engine implementation

use crate::error::{Result, ThreatError};
use crate::types::{
    DetectionEngine, IndicatorType, ScanTarget, Severity, ThreatAnalysis, ThreatClassification,
    ThreatIndicator, ThreatLevel, YaraMatch,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::Duration;

#[cfg(feature = "clamav-engine")]
use clamav_client::tokio::{self as clamd, Tcp};

const DEFAULT_CLAMD_ADDRESS: &str = "127.0.0.1:3310";

/// ClamAV based detection engine
pub struct ClamAVEngine {
    #[cfg(feature = "clamav-engine")]
    clamd_address: Option<String>,
    #[cfg(not(feature = "clamav-engine"))]
    _placeholder: (),
}

impl ClamAVEngine {
    /// Create new ClamAV engine
    pub async fn new() -> Result<Self> {
        #[cfg(feature = "clamav-engine")]
        {
            // Initialize ClamAV engine
            match Self::initialize_clamav().await {
                Ok(address) => Ok(Self {
                    clamd_address: Some(address),
                }),
                Err(e) => {
                    log::warn!("Failed to initialize ClamAV engine: {}", e);
                    Ok(Self {
                        clamd_address: None,
                    })
                }
            }
        }
        #[cfg(not(feature = "clamav-engine"))]
        {
            Ok(Self { _placeholder: () })
        }
    }

    #[cfg(feature = "clamav-engine")]
    async fn initialize_clamav() -> Result<String> {
        let address =
            std::env::var("CLAMD_ADDRESS").unwrap_or_else(|_| DEFAULT_CLAMD_ADDRESS.to_string());
        let connection = Tcp {
            host_address: address.as_str(),
        };
        let response = tokio::time::timeout(Duration::from_secs(2), clamd::ping(connection))
            .await
            .map_err(|_| {
                ThreatError::clamav(format!("Timed out connecting to clamd at {address}"))
            })?
            .map_err(|error| {
                ThreatError::clamav(format!("Failed to connect to clamd at {address}: {error}"))
            })?;

        if response == clamav_client::PONG {
            Ok(address)
        } else {
            Err(ThreatError::clamav(format!(
                "Unexpected clamd ping response from {address}"
            )))
        }
    }

    /// Check if ClamAV is properly installed and databases are available
    #[cfg(feature = "clamav-engine")]
    pub async fn check_installation() -> bool {
        Self::initialize_clamav().await.is_ok()
    }
}

#[async_trait]
impl DetectionEngine for ClamAVEngine {
    fn engine_type(&self) -> &'static str {
        "ClamAV"
    }

    fn version(&self) -> &'static str {
        "0.1.0-placeholder"
    }

    async fn scan(&self, target: ScanTarget) -> Result<ThreatAnalysis> {
        let start_time = std::time::Instant::now();

        #[cfg(feature = "clamav-engine")]
        {
            let scan_result = match &self.clamd_address {
                Some(address) => self.scan_with_clamav(address, &target).await?,
                None => self.create_unavailable_result(&target).await?,
            };

            let scan_duration = start_time.elapsed();
            let file_size = self.get_target_size(&target).await?;

            // Update scan statistics
            let mut result = scan_result;
            result.scan_stats.scan_duration = scan_duration;
            result.scan_stats.file_size_scanned = file_size;

            Ok(result)
        }
        #[cfg(not(feature = "clamav-engine"))]
        {
            let scan_duration = start_time.elapsed();
            let file_size = self.get_target_size(&target).await?;

            Ok(ThreatAnalysis {
                matches: Vec::new(),
                threat_level: ThreatLevel::None,
                classifications: Vec::new(),
                indicators: vec![ThreatIndicator {
                    indicator_type: IndicatorType::SystemModification,
                    description: "ClamAV engine not available".to_string(),
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
                    "Enable clamav-engine feature for antivirus scanning".to_string(),
                ],
            })
        }
    }

    async fn scan_with_custom_rule(
        &self,
        target: ScanTarget,
        _rule: &str,
    ) -> Result<ThreatAnalysis> {
        // ClamAV doesn't support custom rules in the same way as YARA
        self.scan(target).await
    }

    async fn update_rules(&mut self) -> Result<()> {
        // Placeholder - would update ClamAV signatures
        Ok(())
    }

    fn is_available(&self) -> bool {
        #[cfg(feature = "clamav-engine")]
        {
            self.clamd_address.is_some()
        }
        #[cfg(not(feature = "clamav-engine"))]
        {
            false
        }
    }
}

impl ClamAVEngine {
    /// Get the size of a scan target
    async fn get_target_size(&self, target: &ScanTarget) -> Result<u64> {
        match target {
            ScanTarget::File(path) => tokio::fs::metadata(path)
                .await
                .map(|m| m.len())
                .map_err(|e| ThreatError::file(format!("Failed to read file metadata: {}", e))),
            ScanTarget::Memory { data, .. } => Ok(data.len() as u64),
            ScanTarget::Directory(_) => Ok(0), // Directory size not meaningful for ClamAV
        }
    }

    #[cfg(feature = "clamav-engine")]
    async fn scan_with_clamav(&self, address: &str, target: &ScanTarget) -> Result<ThreatAnalysis> {
        let connection = Tcp {
            host_address: address,
        };
        let response = match target {
            ScanTarget::File(path) => clamd::scan_file(path, connection, None).await,
            ScanTarget::Memory { data, .. } => clamd::scan_buffer(data, connection, None).await,
            ScanTarget::Directory(_) => Err(ThreatError::clamav(
                "Directory scanning not supported by this ClamAV engine",
            ))?,
        }
        .map_err(|error| ThreatError::clamav(format!("Clamd scan failed: {error}")))?;

        Self::analysis_from_response(&response)
    }

    #[cfg(feature = "clamav-engine")]
    fn analysis_from_response(response: &[u8]) -> Result<ThreatAnalysis> {
        let response = std::str::from_utf8(response)
            .map_err(|error| ThreatError::clamav(format!("Invalid clamd response: {error}")))?
            .trim_end_matches('\0')
            .trim();

        let signature = response
            .strip_suffix(" FOUND")
            .and_then(|result| result.rsplit_once(": ").map(|(_, name)| name));

        if let Some(signature) = signature {
            return Ok(ThreatAnalysis {
                matches: vec![YaraMatch {
                    rule_identifier: signature.to_string(),
                    tags: vec!["clamav".to_string(), "malware".to_string()],
                    metadata: HashMap::from([("engine".to_string(), "ClamAV".to_string())]),
                    strings: Vec::new(),
                }],
                threat_level: ThreatLevel::Malicious,
                classifications: vec![ThreatClassification::Virus],
                indicators: vec![ThreatIndicator {
                    indicator_type: IndicatorType::KnownMalwareFamily,
                    description: format!("ClamAV detected {signature}"),
                    severity: Severity::Critical,
                    confidence: 1.0,
                    mitre_technique: None,
                    context: HashMap::from([("signature".to_string(), signature.to_string())]),
                }],
                scan_stats: crate::types::ScanStatistics {
                    scan_duration: Duration::default(),
                    rules_evaluated: 1,
                    patterns_matched: 1,
                    file_size_scanned: 0,
                },
                recommendations: vec![
                    "Quarantine the detected file and investigate its origin".to_string(),
                ],
            });
        }

        if response.ends_with(" OK") {
            return Ok(ThreatAnalysis {
                matches: Vec::new(),
                threat_level: ThreatLevel::Clean,
                classifications: Vec::new(),
                indicators: Vec::new(),
                scan_stats: crate::types::ScanStatistics {
                    scan_duration: Duration::default(),
                    rules_evaluated: 1,
                    patterns_matched: 0,
                    file_size_scanned: 0,
                },
                recommendations: Vec::new(),
            });
        }

        Err(ThreatError::clamav(format!(
            "Unexpected clamd scan response: {response}"
        )))
    }

    #[cfg(feature = "clamav-engine")]
    async fn create_unavailable_result(&self, target: &ScanTarget) -> Result<ThreatAnalysis> {
        let file_size = self.get_target_size(target).await?;

        Ok(ThreatAnalysis {
            matches: Vec::new(),
            threat_level: ThreatLevel::None,
            classifications: Vec::new(),
            indicators: vec![ThreatIndicator {
                indicator_type: IndicatorType::SystemModification,
                description: "ClamAV daemon is unavailable".to_string(),
                severity: Severity::Low,
                confidence: 1.0,
                mitre_technique: None,
                context: HashMap::from([(
                    "reason".to_string(),
                    format!(
                        "No clamd service responded at {}",
                        std::env::var("CLAMD_ADDRESS")
                            .unwrap_or_else(|_| DEFAULT_CLAMD_ADDRESS.to_string())
                    ),
                )]),
            }],
            scan_stats: crate::types::ScanStatistics {
                scan_duration: std::time::Duration::default(),
                rules_evaluated: 0,
                patterns_matched: 0,
                file_size_scanned: file_size,
            },
            recommendations: vec![
                "Start clamd and ensure its virus definitions are current".to_string(),
                "Set CLAMD_ADDRESS when clamd is not listening on 127.0.0.1:3310".to_string(),
            ],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clean_response() {
        let analysis = ClamAVEngine::analysis_from_response(b"stream: OK\0")
            .expect("clean response should parse");
        assert_eq!(analysis.threat_level, ThreatLevel::Clean);
        assert!(analysis.matches.is_empty());
    }

    #[test]
    fn parses_malware_response() {
        let analysis =
            ClamAVEngine::analysis_from_response(b"stream: Win.Test.EICAR_HDB-1 FOUND\0")
                .expect("malware response should parse");
        assert_eq!(analysis.threat_level, ThreatLevel::Malicious);
        assert_eq!(analysis.matches.len(), 1);
        assert_eq!(analysis.matches[0].rule_identifier, "Win.Test.EICAR_HDB-1");
        assert_eq!(analysis.classifications, [ThreatClassification::Virus]);
    }

    #[test]
    fn rejects_error_response() {
        let error = ClamAVEngine::analysis_from_response(b"stream: size limit exceeded ERROR\0")
            .expect_err("error response should be rejected");
        assert!(error.to_string().contains("Unexpected clamd scan response"));
    }
}
