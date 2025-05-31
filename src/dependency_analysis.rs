use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::function_analysis::SymbolTable;
use crate::strings::ExtractedStrings;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DependencyAnalysisResult {
    pub dependencies: Vec<DependencyInfo>,
    pub dependency_graph: DependencyGraph,
    pub security_assessment: SecurityAssessment,
    pub license_summary: LicenseSummary,
    pub analysis_stats: DependencyAnalysisStats,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DependencyInfo {
    pub name: String,
    pub version: Option<String>,
    pub library_type: LibraryType,
    pub path: Option<String>,
    pub hash: Option<String>,
    pub vulnerabilities: Vec<KnownVulnerability>,
    pub license: Option<LicenseInfo>,
    pub source: DependencySource,
    pub is_system_library: bool,
    pub imported_functions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum LibraryType {
    StaticLibrary,
    DynamicLibrary,
    SystemLibrary,
    RuntimeLibrary,
    Framework,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum DependencySource {
    Import,          // From import table
    DynamicLink,     // From dynamic section
    StaticLink,      // Linked statically
    StringReference, // Found in strings
    RuntimeLoad,     // dlopen/LoadLibrary
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KnownVulnerability {
    pub cve_id: String,
    pub severity: VulnerabilitySeverity,
    pub description: String,
    pub affected_versions: Vec<String>,
    pub fixed_in: Option<String>,
    pub cvss_score: Option<f32>,
    pub published_date: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum VulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
    None,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LicenseInfo {
    pub license_type: String,
    pub license_family: LicenseFamily,
    pub is_oss: bool,
    pub is_copyleft: bool,
    pub is_commercial_friendly: bool,
    pub attribution_required: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum LicenseFamily {
    MIT,
    Apache,
    GPL,
    LGPL,
    BSD,
    Proprietary,
    PublicDomain,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DependencyGraph {
    pub direct_dependencies: Vec<String>,
    pub transitive_dependencies: HashMap<String, Vec<String>>,
    pub dependency_tree: HashMap<String, Vec<String>>,
    pub dependency_depth: usize,
    pub total_dependencies: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityAssessment {
    pub vulnerable_dependencies: Vec<VulnerableDependency>,
    pub total_vulnerabilities: usize,
    pub critical_vulnerabilities: usize,
    pub high_vulnerabilities: usize,
    pub outdated_dependencies: Vec<OutdatedDependency>,
    pub security_score: f32, // 0-100
    pub risk_level: SecurityRiskLevel,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VulnerableDependency {
    pub dependency_name: String,
    pub current_version: Option<String>,
    pub vulnerabilities: Vec<String>, // CVE IDs
    pub highest_severity: VulnerabilitySeverity,
    pub recommended_action: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OutdatedDependency {
    pub dependency_name: String,
    pub current_version: Option<String>,
    pub latest_version: Option<String>,
    pub versions_behind: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SecurityRiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Minimal,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LicenseSummary {
    pub licenses_found: Vec<String>,
    pub license_conflicts: Vec<LicenseConflict>,
    pub copyleft_dependencies: Vec<String>,
    pub proprietary_dependencies: Vec<String>,
    pub compliance_issues: Vec<ComplianceIssue>,
    pub is_commercial_use_safe: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LicenseConflict {
    pub dependency1: String,
    pub license1: String,
    pub dependency2: String,
    pub license2: String,
    pub conflict_reason: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ComplianceIssue {
    pub dependency: String,
    pub issue_type: ComplianceIssueType,
    pub description: String,
    pub severity: ComplianceSeverity,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ComplianceIssueType {
    MissingLicense,
    IncompatibleLicense,
    AttributionRequired,
    SourceCodeRequired,
    PatentConcern,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ComplianceSeverity {
    Blocking,
    High,
    Medium,
    Low,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DependencyAnalysisStats {
    pub analysis_duration_ms: u64,
    pub total_dependencies_found: usize,
    pub libraries_analyzed: usize,
    pub vulnerabilities_checked: usize,
    pub licenses_identified: usize,
}

pub struct DependencyAnalyzer {
    vulnerability_db: VulnerabilityDatabase,
    license_detector: LicenseDetector,
}

struct VulnerabilityDatabase {
    known_vulnerabilities: HashMap<String, Vec<KnownVulnerability>>,
}

struct LicenseDetector {
    license_patterns: HashMap<String, Regex>,
}

impl DependencyAnalyzer {
    pub fn new() -> Self {
        let mut analyzer = Self {
            vulnerability_db: VulnerabilityDatabase::new(),
            license_detector: LicenseDetector::new(),
        };

        analyzer.load_vulnerability_database();
        analyzer
    }

    fn load_vulnerability_database(&mut self) {
        // Load known vulnerabilities for common libraries
        // In a real implementation, this would connect to NVD or other CVE databases

        // Example: OpenSSL vulnerabilities
        self.vulnerability_db.add_vulnerability(
            "openssl",
            KnownVulnerability {
                cve_id: "CVE-2014-0160".to_string(), // Heartbleed
                severity: VulnerabilitySeverity::Critical,
                description: "Heartbleed - allows remote attackers to obtain sensitive information"
                    .to_string(),
                affected_versions: vec![
                    "1.0.1".to_string(),
                    "1.0.1a".to_string(),
                    "1.0.1b".to_string(),
                    "1.0.1c".to_string(),
                    "1.0.1d".to_string(),
                    "1.0.1e".to_string(),
                    "1.0.1f".to_string(),
                ],
                fixed_in: Some("1.0.1g".to_string()),
                cvss_score: Some(7.5),
                published_date: Some("2014-04-07".to_string()),
            },
        );

        // Log4j vulnerability
        self.vulnerability_db.add_vulnerability(
            "log4j",
            KnownVulnerability {
                cve_id: "CVE-2021-44228".to_string(), // Log4Shell
                severity: VulnerabilitySeverity::Critical,
                description: "Log4Shell - Remote code execution vulnerability".to_string(),
                affected_versions: vec![
                    "2.0".to_string(),
                    "2.1".to_string(),
                    "2.2".to_string(),
                    "2.3".to_string(),
                    "2.4".to_string(),
                    "2.5".to_string(),
                    "2.6".to_string(),
                    "2.7".to_string(),
                    "2.8".to_string(),
                    "2.9".to_string(),
                    "2.10".to_string(),
                    "2.11".to_string(),
                    "2.12".to_string(),
                    "2.13".to_string(),
                    "2.14".to_string(),
                ],
                fixed_in: Some("2.15.0".to_string()),
                cvss_score: Some(10.0),
                published_date: Some("2021-12-10".to_string()),
            },
        );

        // zlib vulnerability
        self.vulnerability_db.add_vulnerability(
            "zlib",
            KnownVulnerability {
                cve_id: "CVE-2018-25032".to_string(),
                severity: VulnerabilitySeverity::High,
                description: "Memory corruption vulnerability".to_string(),
                affected_versions: vec!["1.2.11".to_string()],
                fixed_in: Some("1.2.12".to_string()),
                cvss_score: Some(7.5),
                published_date: Some("2022-03-25".to_string()),
            },
        );
    }

    pub fn analyze(
        &self,
        _path: &Path,
        symbol_table: &SymbolTable,
        extracted_strings: Option<&ExtractedStrings>,
    ) -> Result<DependencyAnalysisResult> {
        let start_time = std::time::Instant::now();
        let mut dependencies = Vec::new();
        let mut dependency_names = HashSet::new();

        // Analyze imports from symbol table
        for import in &symbol_table.imports {
            let dep_name = self.extract_library_name(&import.name);
            dependency_names.insert(dep_name.clone());

            let version = self.extract_version(&import.name, extracted_strings);
            let vulnerabilities = self
                .vulnerability_db
                .check_vulnerabilities(&dep_name, version.as_deref());
            let license = self.detect_license(&dep_name, extracted_strings);

            dependencies.push(DependencyInfo {
                name: dep_name,
                version,
                library_type: LibraryType::DynamicLibrary,
                path: None,
                hash: None,
                vulnerabilities,
                license,
                source: DependencySource::Import,
                is_system_library: self.is_system_library(&import.name),
                imported_functions: vec![import.name.clone()],
            });
        }

        // Check for additional dependencies in strings
        if let Some(strings) = extracted_strings {
            self.analyze_string_dependencies(&mut dependencies, &mut dependency_names, strings)?;
        }

        // Build dependency graph
        let dependency_graph = self.build_dependency_graph(&dependencies);

        // Perform security assessment
        let security_assessment = self.assess_security(&dependencies);

        // Generate license summary
        let license_summary = self.summarize_licenses(&dependencies);

        let duration = start_time.elapsed().as_millis() as u64;
        let total_vulnerabilities = security_assessment.total_vulnerabilities;
        let licenses_count = license_summary.licenses_found.len();

        Ok(DependencyAnalysisResult {
            dependencies,
            dependency_graph,
            security_assessment,
            license_summary,
            analysis_stats: DependencyAnalysisStats {
                analysis_duration_ms: duration,
                total_dependencies_found: dependency_names.len(),
                libraries_analyzed: dependency_names.len(),
                vulnerabilities_checked: total_vulnerabilities,
                licenses_identified: licenses_count,
            },
        })
    }

    fn extract_library_name(&self, import_name: &str) -> String {
        // Extract library name from function import
        // e.g., "printf@GLIBC_2.2.5" -> "glibc"
        if let Some(at_pos) = import_name.find('@') {
            let lib_part = &import_name[at_pos + 1..];
            if let Some(underscore_pos) = lib_part.find('_') {
                return lib_part[..underscore_pos].to_lowercase();
            }
            return lib_part.to_lowercase();
        }

        // Handle Windows-style imports (e.g., "kernel32.dll")
        if import_name.ends_with(".dll") {
            return import_name[..import_name.len() - 4].to_lowercase();
        }

        // Handle lib prefix (e.g., "libssl.so.1.1" -> "ssl")
        if import_name.starts_with("lib") && import_name.contains(".so") {
            if let Some(dot_pos) = import_name[3..].find('.') {
                return import_name[3..3 + dot_pos].to_string();
            }
        }

        import_name.to_lowercase()
    }

    fn extract_version(
        &self,
        import_name: &str,
        strings: Option<&ExtractedStrings>,
    ) -> Option<String> {
        // Try to extract version from import name
        let version_regex = Regex::new(r"(\d+\.\d+(?:\.\d+)?)").ok()?;

        if let Some(captures) = version_regex.captures(import_name) {
            return captures.get(1).map(|m| m.as_str().to_string());
        }

        // Search in strings for version information
        if let Some(strings) = strings {
            for string in &strings.ascii_strings {
                if string.contains("version") || string.contains("Version") {
                    if let Some(captures) = version_regex.captures(string) {
                        return captures.get(1).map(|m| m.as_str().to_string());
                    }
                }
            }
        }

        None
    }

    fn analyze_string_dependencies(
        &self,
        dependencies: &mut Vec<DependencyInfo>,
        dependency_names: &mut HashSet<String>,
        strings: &ExtractedStrings,
    ) -> Result<()> {
        // Look for library references in strings
        let lib_patterns = vec![
            r"lib(\w+)\.so(?:\.\d+)*",
            r"(\w+)\.dll",
            r"(\w+)\.dylib",
            r"lib(\w+)\.a",
        ];

        for pattern in lib_patterns {
            let regex = Regex::new(pattern)?;

            for string in &strings.ascii_strings {
                if let Some(captures) = regex.captures(string) {
                    if let Some(lib_name) = captures.get(1) {
                        let name = lib_name.as_str().to_lowercase();

                        if !dependency_names.contains(&name) && !self.is_common_file(&name) {
                            dependency_names.insert(name.clone());

                            let version = self.extract_version(string, Some(strings));
                            let vulnerabilities = self
                                .vulnerability_db
                                .check_vulnerabilities(&name, version.as_deref());
                            let license = self.detect_license(&name, Some(strings));

                            dependencies.push(DependencyInfo {
                                name,
                                version,
                                library_type: LibraryType::DynamicLibrary,
                                path: Some(string.clone()),
                                hash: None,
                                vulnerabilities,
                                license,
                                source: DependencySource::StringReference,
                                is_system_library: false,
                                imported_functions: Vec::new(),
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn is_system_library(&self, name: &str) -> bool {
        let system_libs = vec![
            "kernel32",
            "user32",
            "advapi32",
            "ntdll",
            "msvcrt", // Windows
            "libc",
            "libm",
            "libpthread",
            "libdl",
            "ld-linux", // Linux
            "libSystem",
            "libobjc",
            "CoreFoundation", // macOS
        ];

        let lower_name = name.to_lowercase();
        system_libs.iter().any(|&lib| lower_name.contains(lib))
    }

    fn is_common_file(&self, name: &str) -> bool {
        // Filter out common non-library files
        let common_files = ["config", "data", "cache", "tmp", "log", "pid"];
        common_files.iter().any(|&file| name.contains(file))
    }

    fn detect_license(
        &self,
        lib_name: &str,
        strings: Option<&ExtractedStrings>,
    ) -> Option<LicenseInfo> {
        // Simple license detection based on library name and strings
        let license = match lib_name {
            "openssl" => Some(("Apache-2.0", LicenseFamily::Apache)),
            "zlib" => Some(("Zlib", LicenseFamily::BSD)),
            "sqlite" => Some(("Public Domain", LicenseFamily::PublicDomain)),
            "boost" => Some(("BSL-1.0", LicenseFamily::BSD)),
            _ => None,
        };

        if let Some((license_type, family)) = license {
            return Some(LicenseInfo {
                license_type: license_type.to_string(),
                license_family: family.clone(),
                is_oss: true,
                is_copyleft: matches!(family, LicenseFamily::GPL | LicenseFamily::LGPL),
                is_commercial_friendly: !matches!(family, LicenseFamily::GPL),
                attribution_required: matches!(
                    family,
                    LicenseFamily::MIT | LicenseFamily::BSD | LicenseFamily::Apache
                ),
            });
        }

        // Try to detect license from strings
        if let Some(strings) = strings {
            self.license_detector.detect_from_strings(strings)
        } else {
            None
        }
    }

    fn build_dependency_graph(&self, dependencies: &[DependencyInfo]) -> DependencyGraph {
        let mut direct_deps = Vec::new();
        let mut dependency_tree = HashMap::new();

        for dep in dependencies {
            if dep.source == DependencySource::Import {
                direct_deps.push(dep.name.clone());
            }

            // Simple tree - in reality would need to analyze actual dependencies
            dependency_tree.insert(dep.name.clone(), Vec::new());
        }

        DependencyGraph {
            direct_dependencies: direct_deps,
            transitive_dependencies: HashMap::new(),
            dependency_tree,
            dependency_depth: 1,
            total_dependencies: dependencies.len(),
        }
    }

    fn assess_security(&self, dependencies: &[DependencyInfo]) -> SecurityAssessment {
        let mut vulnerable_deps = Vec::new();
        let mut total_vulns = 0;
        let mut critical_vulns = 0;
        let mut high_vulns = 0;

        for dep in dependencies {
            if !dep.vulnerabilities.is_empty() {
                let highest_severity = dep
                    .vulnerabilities
                    .iter()
                    .map(|v| &v.severity)
                    .max_by_key(|s| match s {
                        VulnerabilitySeverity::Critical => 4,
                        VulnerabilitySeverity::High => 3,
                        VulnerabilitySeverity::Medium => 2,
                        VulnerabilitySeverity::Low => 1,
                        VulnerabilitySeverity::None => 0,
                    })
                    .cloned()
                    .unwrap_or(VulnerabilitySeverity::None);

                vulnerable_deps.push(VulnerableDependency {
                    dependency_name: dep.name.clone(),
                    current_version: dep.version.clone(),
                    vulnerabilities: dep
                        .vulnerabilities
                        .iter()
                        .map(|v| v.cve_id.clone())
                        .collect(),
                    highest_severity: highest_severity.clone(),
                    recommended_action: self.get_recommended_action(&dep.name, &highest_severity),
                });

                total_vulns += dep.vulnerabilities.len();
                for vuln in &dep.vulnerabilities {
                    match vuln.severity {
                        VulnerabilitySeverity::Critical => critical_vulns += 1,
                        VulnerabilitySeverity::High => high_vulns += 1,
                        _ => {}
                    }
                }
            }
        }

        let security_score =
            self.calculate_security_score(dependencies, critical_vulns, high_vulns);
        let risk_level = self.determine_risk_level(security_score, critical_vulns);

        let mut recommendations = Vec::new();
        if critical_vulns > 0 {
            recommendations.push(
                "URGENT: Critical vulnerabilities found. Update affected dependencies immediately."
                    .to_string(),
            );
        }
        if high_vulns > 0 {
            recommendations.push(
                "High severity vulnerabilities detected. Plan updates within 24 hours.".to_string(),
            );
        }
        if vulnerable_deps.is_empty() {
            recommendations.push("No known vulnerabilities detected in dependencies.".to_string());
        }

        SecurityAssessment {
            vulnerable_dependencies: vulnerable_deps,
            total_vulnerabilities: total_vulns,
            critical_vulnerabilities: critical_vulns,
            high_vulnerabilities: high_vulns,
            outdated_dependencies: Vec::new(), // Would need version database
            security_score,
            risk_level,
            recommendations,
        }
    }

    fn get_recommended_action(&self, lib_name: &str, severity: &VulnerabilitySeverity) -> String {
        match severity {
            VulnerabilitySeverity::Critical => {
                format!(
                    "Immediately update {} to the latest patched version",
                    lib_name
                )
            }
            VulnerabilitySeverity::High => {
                format!("Update {} as soon as possible", lib_name)
            }
            VulnerabilitySeverity::Medium => {
                format!("Plan to update {} in your next release", lib_name)
            }
            _ => format!("Monitor {} for updates", lib_name),
        }
    }

    fn calculate_security_score(
        &self,
        dependencies: &[DependencyInfo],
        critical: usize,
        high: usize,
    ) -> f32 {
        if dependencies.is_empty() {
            return 100.0;
        }

        let vuln_deps = dependencies
            .iter()
            .filter(|d| !d.vulnerabilities.is_empty())
            .count();
        let vuln_ratio = vuln_deps as f32 / dependencies.len() as f32;

        let mut score = 100.0;
        score -= critical as f32 * 20.0;
        score -= high as f32 * 10.0;
        score -= vuln_ratio * 30.0;

        score.max(0.0)
    }

    fn determine_risk_level(&self, score: f32, critical_vulns: usize) -> SecurityRiskLevel {
        if critical_vulns > 0 || score < 30.0 {
            SecurityRiskLevel::Critical
        } else if score < 50.0 {
            SecurityRiskLevel::High
        } else if score < 70.0 {
            SecurityRiskLevel::Medium
        } else if score < 90.0 {
            SecurityRiskLevel::Low
        } else {
            SecurityRiskLevel::Minimal
        }
    }

    fn summarize_licenses(&self, dependencies: &[DependencyInfo]) -> LicenseSummary {
        let mut licenses_found = HashSet::new();
        let mut copyleft_deps = Vec::new();
        let mut proprietary_deps = Vec::new();
        let mut compliance_issues = Vec::new();

        for dep in dependencies {
            if let Some(license) = &dep.license {
                licenses_found.insert(license.license_type.clone());

                if license.is_copyleft {
                    copyleft_deps.push(dep.name.clone());
                }

                if matches!(license.license_family, LicenseFamily::Proprietary) {
                    proprietary_deps.push(dep.name.clone());
                }

                // Check for missing attribution
                if license.attribution_required && dep.is_system_library {
                    compliance_issues.push(ComplianceIssue {
                        dependency: dep.name.clone(),
                        issue_type: ComplianceIssueType::AttributionRequired,
                        description: "Attribution required for this dependency".to_string(),
                        severity: ComplianceSeverity::Medium,
                    });
                }
            } else if !dep.is_system_library {
                compliance_issues.push(ComplianceIssue {
                    dependency: dep.name.clone(),
                    issue_type: ComplianceIssueType::MissingLicense,
                    description: "No license information found".to_string(),
                    severity: ComplianceSeverity::High,
                });
            }
        }

        let is_commercial_safe = copyleft_deps.is_empty() && proprietary_deps.is_empty();

        LicenseSummary {
            licenses_found: licenses_found.into_iter().collect(),
            license_conflicts: Vec::new(), // Would need more sophisticated analysis
            copyleft_dependencies: copyleft_deps,
            proprietary_dependencies: proprietary_deps,
            compliance_issues,
            is_commercial_use_safe: is_commercial_safe,
        }
    }
}

impl VulnerabilityDatabase {
    fn new() -> Self {
        Self {
            known_vulnerabilities: HashMap::new(),
        }
    }

    fn add_vulnerability(&mut self, library: &str, vulnerability: KnownVulnerability) {
        self.known_vulnerabilities
            .entry(library.to_string())
            .or_insert_with(Vec::new)
            .push(vulnerability);
    }

    fn check_vulnerabilities(
        &self,
        library: &str,
        version: Option<&str>,
    ) -> Vec<KnownVulnerability> {
        if let Some(vulns) = self.known_vulnerabilities.get(library) {
            if let Some(ver) = version {
                vulns
                    .iter()
                    .filter(|v| v.affected_versions.contains(&ver.to_string()))
                    .cloned()
                    .collect()
            } else {
                // If no version info, return all vulnerabilities for awareness
                vulns.clone()
            }
        } else {
            Vec::new()
        }
    }
}

impl LicenseDetector {
    fn new() -> Self {
        let mut patterns = HashMap::new();

        // Common license patterns
        patterns.insert("MIT".to_string(), Regex::new(r"(?i)mit\s+license").unwrap());
        patterns.insert(
            "Apache-2.0".to_string(),
            Regex::new(r"(?i)apache\s+license.*2\.0").unwrap(),
        );
        patterns.insert(
            "GPL-3.0".to_string(),
            Regex::new(r"(?i)gnu\s+general\s+public\s+license.*3").unwrap(),
        );
        patterns.insert(
            "BSD-3-Clause".to_string(),
            Regex::new(r"(?i)bsd\s+3-clause").unwrap(),
        );

        Self {
            license_patterns: patterns,
        }
    }

    fn detect_from_strings(&self, strings: &ExtractedStrings) -> Option<LicenseInfo> {
        for string in &strings.ascii_strings {
            for (license_type, pattern) in &self.license_patterns {
                if pattern.is_match(string) {
                    let family = match license_type.as_str() {
                        "MIT" => LicenseFamily::MIT,
                        "Apache-2.0" => LicenseFamily::Apache,
                        "GPL-3.0" => LicenseFamily::GPL,
                        "BSD-3-Clause" => LicenseFamily::BSD,
                        _ => LicenseFamily::Unknown,
                    };

                    return Some(LicenseInfo {
                        license_type: license_type.clone(),
                        license_family: family.clone(),
                        is_oss: true,
                        is_copyleft: matches!(family, LicenseFamily::GPL | LicenseFamily::LGPL),
                        is_commercial_friendly: !matches!(family, LicenseFamily::GPL),
                        attribution_required: true,
                    });
                }
            }
        }

        None
    }
}

pub fn analyze_dependencies(
    path: &Path,
    symbol_table: &SymbolTable,
    extracted_strings: Option<&ExtractedStrings>,
) -> Result<DependencyAnalysisResult> {
    let analyzer = DependencyAnalyzer::new();
    analyzer.analyze(path, symbol_table, extracted_strings)
}
