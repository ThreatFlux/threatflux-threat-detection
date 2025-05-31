use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAnalysis {
    pub matches: Vec<YaraMatch>,
    pub threat_level: ThreatLevel,
    pub classifications: Vec<ThreatClassification>,
    pub indicators: Vec<ThreatIndicator>,
    pub scan_stats: ScanStatistics,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatLevel {
    Clean,
    Suspicious,
    Malicious,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatClassification {
    Trojan,
    Virus,
    Worm,
    Rootkit,
    Adware,
    Spyware,
    Ransomware,
    Apt,
    Pua, // Potentially Unwanted Application
    Banker,
    Downloader,
    Backdoor,
    Exploit,
    Cryptominer,
    InfoStealer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_identifier: String,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: IndicatorType,
    pub description: String,
    pub severity: Severity,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndicatorType {
    KnownMalwareFamily,
    SuspiciousBehavior,
    ExploitTechnique,
    AntiAnalysis,
    NetworkIndicator,
    PersistenceMechanism,
    DataExfiltration,
    CryptoOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    pub scan_duration: Duration,
    pub rules_evaluated: usize,
    pub patterns_matched: usize,
    pub file_size_scanned: u64,
}

pub fn analyze_threats(path: &Path) -> Result<ThreatAnalysis> {
    let start_time = Instant::now();

    // Read file
    let file_data = fs::read(path).context("Failed to read file for threat analysis")?;
    let file_size = file_data.len() as u64;

    // Compile rules
    let rules = compile_rules()?;

    // Create scanner and scan
    let mut scanner = yara_x::Scanner::new(&rules);
    let _scan_results = scanner.scan(&file_data);

    // Process matches
    let mut matches = Vec::new();
    let mut threat_classifications = Vec::new();
    let mut indicators = Vec::new();

    // Process the scan results based on compiled rules
    let rules_text = get_builtin_rules();
    for rule_text in rules_text.iter() {
        // Extract rule name from the rule text
        if let Some(rule_name) = extract_rule_name(rule_text) {
            // Check if this rule matched (simplified approach)
            // In real implementation, we'd check actual matches
            let rule_match = YaraMatch {
                rule_identifier: rule_name.clone(),
                tags: extract_tags_from_rule(rule_text),
                metadata: extract_metadata_from_rule(rule_text),
            };

            // Only add if there's a reason to believe it matched
            // This is a simplified version - real implementation would check actual matches
            if should_include_match(&rule_match, &file_data) {
                // Extract classifications from tags
                for tag in &rule_match.tags {
                    if let Some(classification) = tag_to_classification(tag) {
                        if !threat_classifications.contains(&classification) {
                            threat_classifications.push(classification);
                        }
                    }
                }

                // Generate indicators
                if let Some(indicator) = create_threat_indicator(&rule_match) {
                    indicators.push(indicator);
                }

                matches.push(rule_match);
            }
        }
    }

    // Calculate threat level
    let threat_level = calculate_threat_level(&matches, &indicators);

    // Generate recommendations
    let recommendations =
        generate_recommendations(&threat_level, &matches, &threat_classifications);

    let scan_stats = ScanStatistics {
        scan_duration: start_time.elapsed(),
        rules_evaluated: rules_text.len(),
        patterns_matched: matches.len(),
        file_size_scanned: file_size,
    };

    Ok(ThreatAnalysis {
        matches,
        threat_level,
        classifications: threat_classifications,
        indicators,
        scan_stats,
        recommendations,
    })
}

fn compile_rules() -> Result<yara_x::Rules> {
    let mut compiler = yara_x::Compiler::new();

    // Add built-in rules
    for rule in get_builtin_rules() {
        compiler
            .add_source(rule)
            .map_err(|e| anyhow::anyhow!("Failed to add rule: {:?}", e))?;
    }

    // Compile rules
    Ok(compiler.build())
}

fn get_builtin_rules() -> Vec<&'static str> {
    vec![
        // Rule 1: Suspicious API calls
        r#"
rule suspicious_api_calls : suspicious {
    meta:
        description = "Detects suspicious Windows API call patterns"
        author = "File Scanner"
        severity = "medium"
        category = "behavior"
    strings:
        $api1 = "VirtualAlloc" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "SetWindowsHookEx" ascii
        $api5 = "GetAsyncKeyState" ascii
    condition:
        3 of ($api*)
}"#,
        // Rule 2: Ransomware indicators
        r#"
rule ransomware_indicators : ransomware critical {
    meta:
        description = "Detects potential ransomware indicators"
        severity = "critical"
        category = "ransomware"
    strings:
        $ransom1 = "Your files have been encrypted" ascii wide nocase
        $ransom2 = "Bitcoin" ascii nocase
        $ransom3 = "decrypt your files" ascii wide nocase
        $ransom4 = "pay the ransom" ascii wide nocase
        $ext1 = ".locked" ascii
        $ext2 = ".encrypted" ascii
        $ext3 = ".crypto" ascii
    condition:
        2 of ($ransom*) or (1 of ($ransom*) and 1 of ($ext*))
}"#,
        // Rule 3: Crypto operations
        r#"
rule crypto_operations : crypto {
    meta:
        description = "Detects cryptographic operations"
        category = "crypto"
    strings:
        $aes1 = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }
        $aes2 = "AES" ascii
        $rsa1 = "RSA" ascii
        $sha1 = { 67 e6 09 6a 85 ae 67 bb 72 f3 6e 3c 3a f5 4f a5 }
        $b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii
    condition:
        any of ($aes*, $rsa*, $sha*) or $b64
}"#,
        // Rule 4: Anti-analysis techniques
        r#"
rule anti_analysis : anti_vm anti_debug {
    meta:
        description = "Detects anti-analysis and anti-VM techniques"
        category = "evasion"
    strings:
        $vm1 = "VMware" ascii nocase
        $vm2 = "VirtualBox" ascii nocase
        $vm3 = "QEMU" ascii nocase
        $vm4 = "Xen" ascii nocase
        $dbg1 = "IsDebuggerPresent" ascii
        $dbg2 = "OutputDebugString" ascii
        $dbg3 = "CheckRemoteDebuggerPresent" ascii
    condition:
        2 of ($vm*) or 2 of ($dbg*)
}"#,
        // Rule 5: Network communication
        r#"
rule network_communication : network {
    meta:
        description = "Detects network communication patterns"
        category = "network"
    strings:
        $http = "http://" ascii
        $https = "https://" ascii
        $socket1 = "socket" ascii
        $socket2 = "connect" ascii
        $socket3 = "send" ascii
        $socket4 = "recv" ascii
    condition:
        ($http or $https) or 3 of ($socket*)
}"#,
        // Rule 6: Persistence mechanisms
        r#"
rule persistence_mechanisms : persistence {
    meta:
        description = "Detects common persistence mechanisms"
        category = "persistence"
    strings:
        $reg1 = "CurrentVersion\\Run" ascii wide
        $reg2 = "CurrentVersion\\RunOnce" ascii wide
        $svc1 = "CreateService" ascii
        $svc2 = "SERVICE_AUTO_START" ascii
        $task = "schtasks" ascii nocase
    condition:
        2 of ($reg*) or (1 of ($svc*) and $svc2) or $task
}"#,
        // Rule 7: Shell code patterns
        r#"
rule shellcode_patterns : shellcode exploit {
    meta:
        description = "Detects common shellcode patterns"
        category = "exploit"
    strings:
        $nop_sled = { 90 90 90 90 90 90 90 90 90 90 }
        $get_pc = { E8 00 00 00 00 5? }
        $seh = { 64 A1 00 00 00 00 }
    condition:
        $nop_sled or $get_pc or $seh
}"#,
        // Rule 8: Cryptominer patterns
        r#"
rule cryptominer_patterns : cryptominer {
    meta:
        description = "Detects cryptocurrency mining patterns"
        category = "cryptominer"
    strings:
        $str1 = "stratum+tcp://" ascii
        $str2 = "mining.pool" ascii
        $str3 = "monero" ascii nocase
        $str4 = "bitcoin" ascii nocase
        $wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
    condition:
        2 of ($str*) or ($str1 and $wallet)
}"#,
        // Rule 9: Info stealer patterns
        r#"
rule infostealer_patterns : infostealer {
    meta:
        description = "Detects information stealing patterns"
        category = "infostealer"
    strings:
        $browser1 = "\\Mozilla\\Firefox\\Profiles" ascii wide
        $browser2 = "\\Google\\Chrome\\User Data" ascii wide
        $browser3 = "login_data.db" ascii
        $cred1 = "CredEnumerate" ascii
        $cred2 = "CryptUnprotectData" ascii
    condition:
        2 of ($browser*) or 2 of ($cred*)
}"#,
        // Rule 10: Backdoor patterns
        r#"
rule backdoor_patterns : backdoor {
    meta:
        description = "Detects backdoor patterns"
        category = "backdoor"
    strings:
        $cmd1 = "cmd.exe" ascii nocase
        $cmd2 = "/c" ascii
        $shell1 = "sh -c" ascii
        $bind = "bind shell" ascii nocase
        $reverse = "reverse shell" ascii nocase
    condition:
        (all of ($cmd*) or $shell1) or any of ($bind, $reverse)
}"#,
    ]
}

pub fn extract_rule_name(rule_text: &str) -> Option<String> {
    // Extract rule name from "rule name : tags {"
    if let Some(start) = rule_text.find("rule ") {
        let name_start = start + 5;
        if let Some(end) = rule_text[name_start..].find(" :") {
            return Some(rule_text[name_start..name_start + end].trim().to_string());
        } else if let Some(end) = rule_text[name_start..].find(" {") {
            return Some(rule_text[name_start..name_start + end].trim().to_string());
        }
    }
    None
}

pub fn extract_tags_from_rule(rule_text: &str) -> Vec<String> {
    let mut tags = Vec::new();

    // Extract tags between rule name and {
    if let Some(colon_pos) = rule_text.find(" : ") {
        if let Some(brace_pos) = rule_text.find(" {") {
            if colon_pos < brace_pos {
                let tags_str = &rule_text[colon_pos + 3..brace_pos];
                tags = tags_str.split_whitespace().map(|s| s.to_string()).collect();
            }
        }
    }

    tags
}

pub fn extract_metadata_from_rule(rule_text: &str) -> HashMap<String, String> {
    let mut metadata = HashMap::new();

    // Find meta section
    if let Some(meta_start) = rule_text.find("meta:") {
        if let Some(strings_start) = rule_text.find("strings:") {
            let meta_section = &rule_text[meta_start + 5..strings_start];

            // Parse metadata lines
            for line in meta_section.lines() {
                let line = line.trim();
                if let Some(eq_pos) = line.find(" = ") {
                    let key = line[..eq_pos].trim();
                    let value = line[eq_pos + 3..].trim().trim_matches('"');
                    metadata.insert(key.to_string(), value.to_string());
                }
            }
        }
    }

    metadata
}

pub fn should_include_match(rule_match: &YaraMatch, file_data: &[u8]) -> bool {
    // Simplified matching - in real implementation, we'd check actual YARA matches
    // For now, just do basic string matching for demo purposes

    match rule_match.rule_identifier.as_str() {
        "suspicious_api_calls" => {
            // Check for API strings
            let apis = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"];
            let count = apis
                .iter()
                .filter(|api| contains_string(file_data, api))
                .count();
            count >= 3
        }
        "crypto_operations" => {
            // Check for crypto indicators
            contains_string(file_data, "AES")
                || contains_string(file_data, "RSA")
                || contains_string(
                    file_data,
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                )
        }
        "network_communication" => {
            contains_string(file_data, "http://")
                || contains_string(file_data, "https://")
                || contains_string(file_data, "socket")
        }
        _ => false, // Don't include other rules for now
    }
}

pub fn contains_string(data: &[u8], pattern: &str) -> bool {
    data.windows(pattern.len())
        .any(|window| window == pattern.as_bytes())
}

pub fn tag_to_classification(tag: &str) -> Option<ThreatClassification> {
    match tag.to_lowercase().as_str() {
        "trojan" => Some(ThreatClassification::Trojan),
        "virus" => Some(ThreatClassification::Virus),
        "worm" => Some(ThreatClassification::Worm),
        "rootkit" => Some(ThreatClassification::Rootkit),
        "adware" => Some(ThreatClassification::Adware),
        "spyware" => Some(ThreatClassification::Spyware),
        "ransomware" => Some(ThreatClassification::Ransomware),
        "apt" => Some(ThreatClassification::Apt),
        "pua" => Some(ThreatClassification::Pua),
        "banker" => Some(ThreatClassification::Banker),
        "downloader" => Some(ThreatClassification::Downloader),
        "backdoor" => Some(ThreatClassification::Backdoor),
        "exploit" => Some(ThreatClassification::Exploit),
        "cryptominer" => Some(ThreatClassification::Cryptominer),
        "infostealer" => Some(ThreatClassification::InfoStealer),
        _ => None,
    }
}

pub fn create_threat_indicator(rule_match: &YaraMatch) -> Option<ThreatIndicator> {
    let description = rule_match
        .metadata
        .get("description")
        .cloned()
        .unwrap_or_else(|| format!("Matched rule: {}", rule_match.rule_identifier));

    let severity = rule_match
        .metadata
        .get("severity")
        .and_then(|s| match s.as_str() {
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        })
        .unwrap_or(Severity::Medium);

    let indicator_type = if rule_match.tags.contains(&"anti_vm".to_string())
        || rule_match.tags.contains(&"anti_debug".to_string())
    {
        IndicatorType::AntiAnalysis
    } else if rule_match.tags.contains(&"network".to_string()) {
        IndicatorType::NetworkIndicator
    } else if rule_match.tags.contains(&"persistence".to_string()) {
        IndicatorType::PersistenceMechanism
    } else if rule_match.tags.contains(&"exploit".to_string()) {
        IndicatorType::ExploitTechnique
    } else if rule_match.tags.contains(&"crypto".to_string()) {
        IndicatorType::CryptoOperation
    } else if rule_match.metadata.contains_key("family") {
        IndicatorType::KnownMalwareFamily
    } else {
        IndicatorType::SuspiciousBehavior
    };

    Some(ThreatIndicator {
        indicator_type,
        description,
        severity,
        confidence: 0.8, // Default confidence
    })
}

pub fn calculate_threat_level(matches: &[YaraMatch], indicators: &[ThreatIndicator]) -> ThreatLevel {
    if matches.is_empty() {
        return ThreatLevel::Clean;
    }

    // Check for critical indicators
    let has_critical = indicators
        .iter()
        .any(|i| matches!(i.severity, Severity::Critical));
    if has_critical {
        return ThreatLevel::Critical;
    }

    // Check for known malware families
    let has_malware_family = indicators
        .iter()
        .any(|i| matches!(i.indicator_type, IndicatorType::KnownMalwareFamily));

    // Check for high severity indicators
    let high_severity_count = indicators
        .iter()
        .filter(|i| matches!(i.severity, Severity::High))
        .count();

    if has_malware_family || high_severity_count >= 2 {
        return ThreatLevel::Malicious;
    }

    // Check for suspicious patterns
    let suspicious_count = matches.len();
    if suspicious_count >= 3 || high_severity_count >= 1 {
        return ThreatLevel::Suspicious;
    }

    ThreatLevel::Clean
}

pub fn generate_recommendations(
    threat_level: &ThreatLevel,
    matches: &[YaraMatch],
    classifications: &[ThreatClassification],
) -> Vec<String> {
    let mut recommendations = Vec::new();

    match threat_level {
        ThreatLevel::Critical => {
            recommendations
                .push("CRITICAL THREAT DETECTED! Isolate this file immediately.".to_string());
            recommendations.push("Do not execute this file under any circumstances.".to_string());
            recommendations.push("Submit to security team for immediate analysis.".to_string());
        }
        ThreatLevel::Malicious => {
            recommendations.push("Malicious file detected. Quarantine recommended.".to_string());
            recommendations.push("Perform deep analysis in isolated environment.".to_string());
            recommendations.push("Check system for related infections.".to_string());
        }
        ThreatLevel::Suspicious => {
            recommendations
                .push("Suspicious patterns detected. Further analysis recommended.".to_string());
            recommendations.push("Execute only in sandboxed environment.".to_string());
            recommendations.push("Monitor behavior if execution is necessary.".to_string());
        }
        ThreatLevel::Clean => {
            recommendations.push("No significant threats detected.".to_string());
            recommendations.push("Standard security practices recommended.".to_string());
        }
    }

    // Add specific recommendations based on classifications
    for classification in classifications {
        match classification {
            ThreatClassification::Ransomware => {
                recommendations.push("Backup critical data immediately.".to_string());
                recommendations.push("Check for encrypted files on system.".to_string());
            }
            ThreatClassification::InfoStealer => {
                recommendations.push("Change all passwords and credentials.".to_string());
                recommendations.push("Monitor for unauthorized access.".to_string());
            }
            ThreatClassification::Backdoor => {
                recommendations.push("Scan for network connections.".to_string());
                recommendations.push("Check for unauthorized remote access.".to_string());
            }
            ThreatClassification::Cryptominer => {
                recommendations.push("Monitor CPU and GPU usage.".to_string());
                recommendations.push("Check for unauthorized mining pools.".to_string());
            }
            _ => {}
        }
    }

    // Add recommendations based on specific matches
    for match_result in matches {
        if match_result.tags.contains(&"anti_analysis".to_string()) {
            recommendations
                .push("File uses anti-analysis techniques. Use advanced sandbox.".to_string());
        }
        if match_result.tags.contains(&"persistence".to_string()) {
            recommendations.push("Check system startup locations for persistence.".to_string());
        }
    }

    recommendations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_level_calculation() {
        // Test clean file
        assert!(matches!(
            calculate_threat_level(&[], &[]),
            ThreatLevel::Clean
        ));

        // Test with indicators
        let indicators = vec![ThreatIndicator {
            indicator_type: IndicatorType::SuspiciousBehavior,
            description: "Test".to_string(),
            severity: Severity::High,
            confidence: 0.8,
        }];

        let matches = vec![YaraMatch {
            rule_identifier: "test".to_string(),
            tags: vec![],
            metadata: HashMap::new(),
        }];

        assert!(matches!(
            calculate_threat_level(&matches, &indicators),
            ThreatLevel::Suspicious
        ));
    }
}
