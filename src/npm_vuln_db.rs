use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::dependency_analysis::{KnownVulnerability, VulnerabilitySeverity};

/// NPM vulnerability database
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NpmVulnerabilityDatabase {
    pub vulnerabilities: HashMap<String, Vec<PackageVulnerability>>,
    pub last_updated: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PackageVulnerability {
    pub package_name: String,
    pub vulnerability: KnownVulnerability,
    pub affected_version_ranges: Vec<VersionRange>,
    pub patched_versions: Vec<String>,
    pub references: Vec<String>,
    pub disclosure_date: Option<String>,
    pub exploit_available: bool,
    pub malware_indicators: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VersionRange {
    pub min_version: Option<String>,
    pub max_version: Option<String>,
    pub includes_min: bool,
    pub includes_max: bool,
}

/// Create a hardcoded vulnerability database for common npm vulnerabilities
pub fn create_npm_vulnerability_database() -> NpmVulnerabilityDatabase {
    let mut vulnerabilities = HashMap::new();

    // Event-stream malware incident
    vulnerabilities.insert(
        "event-stream".to_string(),
        vec![PackageVulnerability {
            package_name: "event-stream".to_string(),
            vulnerability: KnownVulnerability {
                cve_id: "NPM-MALWARE-2018-001".to_string(),
                severity: VulnerabilitySeverity::Critical,
                description: "Malicious code injection that steals cryptocurrency wallets"
                    .to_string(),
                affected_versions: vec!["3.3.6".to_string()],
                fixed_in: Some("4.0.0".to_string()),
                cvss_score: Some(9.8),
                published_date: Some("2018-11-26".to_string()),
            },
            affected_version_ranges: vec![VersionRange {
                min_version: Some("3.3.6".to_string()),
                max_version: Some("3.3.6".to_string()),
                includes_min: true,
                includes_max: true,
            }],
            patched_versions: vec!["4.0.0".to_string()],
            references: vec![
                "https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident"
                    .to_string(),
            ],
            disclosure_date: Some("2018-11-26".to_string()),
            exploit_available: true,
            malware_indicators: vec![
                "flatmap-stream".to_string(),
                "cryptocurrency wallet theft".to_string(),
            ],
        }],
    );

    // ua-parser-js crypto mining malware
    vulnerabilities.insert(
        "ua-parser-js".to_string(),
        vec![PackageVulnerability {
            package_name: "ua-parser-js".to_string(),
            vulnerability: KnownVulnerability {
                cve_id: "CVE-2021-41265".to_string(),
                severity: VulnerabilitySeverity::Critical,
                description:
                    "Compromised versions contain crypto mining and password stealing malware"
                        .to_string(),
                affected_versions: vec![
                    "0.7.29".to_string(),
                    "0.8.0".to_string(),
                    "1.0.0".to_string(),
                ],
                fixed_in: Some("0.7.30".to_string()),
                cvss_score: Some(9.8),
                published_date: Some("2021-10-22".to_string()),
            },
            affected_version_ranges: vec![
                VersionRange {
                    min_version: Some("0.7.29".to_string()),
                    max_version: Some("0.7.29".to_string()),
                    includes_min: true,
                    includes_max: true,
                },
                VersionRange {
                    min_version: Some("0.8.0".to_string()),
                    max_version: Some("0.8.0".to_string()),
                    includes_min: true,
                    includes_max: true,
                },
                VersionRange {
                    min_version: Some("1.0.0".to_string()),
                    max_version: Some("1.0.0".to_string()),
                    includes_min: true,
                    includes_max: true,
                },
            ],
            patched_versions: vec![
                "0.7.30".to_string(),
                "0.8.1".to_string(),
                "1.0.1".to_string(),
            ],
            references: vec!["https://github.com/faisalman/ua-parser-js/issues/536".to_string()],
            disclosure_date: Some("2021-10-22".to_string()),
            exploit_available: true,
            malware_indicators: vec![
                "crypto mining".to_string(),
                "password stealer".to_string(),
                "jsextension".to_string(),
            ],
        }],
    );

    // node-ipc malware protest-ware
    vulnerabilities.insert(
        "node-ipc".to_string(),
        vec![PackageVulnerability {
            package_name: "node-ipc".to_string(),
            vulnerability: KnownVulnerability {
                cve_id: "CVE-2022-23812".to_string(),
                severity: VulnerabilitySeverity::Critical,
                description:
                    "Malicious code that overwrites files with specific geographic IP addresses"
                        .to_string(),
                affected_versions: vec!["10.1.1".to_string(), "10.1.2".to_string()],
                fixed_in: Some("10.1.3".to_string()),
                cvss_score: Some(9.8),
                published_date: Some("2022-03-16".to_string()),
            },
            affected_version_ranges: vec![VersionRange {
                min_version: Some("10.1.1".to_string()),
                max_version: Some("10.1.2".to_string()),
                includes_min: true,
                includes_max: true,
            }],
            patched_versions: vec!["10.1.3".to_string()],
            references: vec!["https://snyk.io/vuln/SNYK-JS-NODEIPC-2426370".to_string()],
            disclosure_date: Some("2022-03-16".to_string()),
            exploit_available: true,
            malware_indicators: vec![
                "protestware".to_string(),
                "file overwrite".to_string(),
                "geo-targeted".to_string(),
            ],
        }],
    );

    // colors and faker protest-ware
    vulnerabilities.insert(
        "colors".to_string(),
        vec![PackageVulnerability {
            package_name: "colors".to_string(),
            vulnerability: KnownVulnerability {
                cve_id: "GHSA-2pr3-vjfc-gx2g".to_string(),
                severity: VulnerabilitySeverity::High,
                description: "Infinite loop causing Denial of Service".to_string(),
                affected_versions: vec!["1.4.1".to_string(), "1.4.44-liberty".to_string()],
                fixed_in: Some("1.4.0".to_string()),
                cvss_score: Some(7.5),
                published_date: Some("2022-01-08".to_string()),
            },
            affected_version_ranges: vec![VersionRange {
                min_version: Some("1.4.1".to_string()),
                max_version: Some("1.4.44-liberty".to_string()),
                includes_min: true,
                includes_max: true,
            }],
            patched_versions: vec!["1.4.0".to_string()],
            references: vec!["https://github.com/advisories/GHSA-2pr3-vjfc-gx2g".to_string()],
            disclosure_date: Some("2022-01-08".to_string()),
            exploit_available: true,
            malware_indicators: vec!["infinite loop".to_string(), "protestware".to_string()],
        }],
    );

    // Common vulnerability patterns (not specific packages but patterns to detect)
    vulnerabilities.insert(
        "PATTERN-TYPOSQUATTING".to_string(),
        vec![PackageVulnerability {
            package_name: "PATTERN-TYPOSQUATTING".to_string(),
            vulnerability: KnownVulnerability {
                cve_id: "PATTERN-001".to_string(),
                severity: VulnerabilitySeverity::High,
                description:
                    "Typosquatting attack pattern - packages with names similar to popular packages"
                        .to_string(),
                affected_versions: vec!["*".to_string()],
                fixed_in: None,
                cvss_score: Some(8.0),
                published_date: None,
            },
            affected_version_ranges: vec![],
            patched_versions: vec![],
            references: vec![],
            disclosure_date: None,
            exploit_available: true,
            malware_indicators: vec!["typosquatting".to_string(), "similar name".to_string()],
        }],
    );

    // lodash vulnerability
    vulnerabilities.insert(
        "lodash".to_string(),
        vec![PackageVulnerability {
            package_name: "lodash".to_string(),
            vulnerability: KnownVulnerability {
                cve_id: "CVE-2019-10744".to_string(),
                severity: VulnerabilitySeverity::High,
                description: "Prototype pollution vulnerability in defaultsDeep function"
                    .to_string(),
                affected_versions: vec!["< 4.17.12".to_string()],
                fixed_in: Some("4.17.12".to_string()),
                cvss_score: Some(7.5),
                published_date: Some("2019-07-26".to_string()),
            },
            affected_version_ranges: vec![VersionRange {
                min_version: None,
                max_version: Some("4.17.11".to_string()),
                includes_min: true,
                includes_max: true,
            }],
            patched_versions: vec!["4.17.12".to_string()],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2019-10744".to_string()],
            disclosure_date: Some("2019-07-26".to_string()),
            exploit_available: true,
            malware_indicators: vec![],
        }],
    );

    // minimist vulnerability
    vulnerabilities.insert(
        "minimist".to_string(),
        vec![PackageVulnerability {
            package_name: "minimist".to_string(),
            vulnerability: KnownVulnerability {
                cve_id: "CVE-2020-7598".to_string(),
                severity: VulnerabilitySeverity::Medium,
                description:
                    "Prototype pollution vulnerability allowing modification of Object prototype"
                        .to_string(),
                affected_versions: vec!["< 1.2.2".to_string()],
                fixed_in: Some("1.2.2".to_string()),
                cvss_score: Some(5.3),
                published_date: Some("2020-03-11".to_string()),
            },
            affected_version_ranges: vec![VersionRange {
                min_version: None,
                max_version: Some("1.2.1".to_string()),
                includes_min: true,
                includes_max: true,
            }],
            patched_versions: vec!["1.2.2".to_string()],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-7598".to_string()],
            disclosure_date: Some("2020-03-11".to_string()),
            exploit_available: false,
            malware_indicators: vec![],
        }],
    );

    NpmVulnerabilityDatabase {
        vulnerabilities,
        last_updated: "2025-01-06".to_string(),
        version: "1.0.0".to_string(),
    }
}

/// Check if a package has known vulnerabilities
pub fn check_package_vulnerabilities(package_name: &str, version: &str) -> Vec<KnownVulnerability> {
    let db = create_npm_vulnerability_database();
    let mut found_vulnerabilities = vec![];

    if let Some(package_vulns) = db.vulnerabilities.get(package_name) {
        for vuln in package_vulns {
            if is_version_affected(version, &vuln.affected_version_ranges) {
                found_vulnerabilities.push(vuln.vulnerability.clone());
            }
        }
    }

    found_vulnerabilities
}

/// Check if a version is within the affected ranges
fn is_version_affected(version: &str, ranges: &[VersionRange]) -> bool {
    // Simple version check - in production, use a proper semver library
    for range in ranges {
        // If specific versions are listed in affected_versions, check exact match
        if let (Some(min), Some(max)) = (&range.min_version, &range.max_version) {
            if min == max && version == min {
                return true;
            }
        }

        // TODO: Implement proper semver range checking
        // For now, do simple string comparison
        if version.contains('-') || version.contains('+') {
            // Pre-release or build metadata versions need special handling
            return true; // Conservative approach
        }
    }

    false
}

/// Get a list of known malicious package patterns
pub fn get_malicious_patterns() -> Vec<MaliciousPackagePattern> {
    vec![
        MaliciousPackagePattern {
            pattern_name: "Install script with external download".to_string(),
            description: "Package downloads and executes external code during installation"
                .to_string(),
            indicators: vec![
                "curl|wget.*http".to_string(),
                "exec.*http".to_string(),
                "eval.*fetch".to_string(),
            ],
            severity: "Critical".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Obfuscated code execution".to_string(),
            description: "Package contains heavily obfuscated code that executes dynamically"
                .to_string(),
            indicators: vec![
                r"eval\s*\(".to_string(),
                r"Function\s*\(".to_string(),
                r"atob\s*\(".to_string(),
                r#"Buffer\.from\([^,]+,\s*['"]base64"#.to_string(),
            ],
            severity: "High".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Environment variable exfiltration".to_string(),
            description: "Package attempts to read and send environment variables".to_string(),
            indicators: vec![
                "process\\.env.*http".to_string(),
                "process\\.env.*fetch".to_string(),
                "process\\.env.*request".to_string(),
            ],
            severity: "Critical".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Cryptocurrency theft".to_string(),
            description: "Package contains patterns associated with cryptocurrency wallet theft"
                .to_string(),
            indicators: vec![
                "wallet".to_string(),
                "bitcoin".to_string(),
                "ethereum".to_string(),
                "private.*key".to_string(),
                "seed.*phrase".to_string(),
            ],
            severity: "Critical".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Reverse shell".to_string(),
            description: "Package attempts to establish reverse shell connection".to_string(),
            indicators: vec![
                "nc.*-e".to_string(),
                "bash.*-i".to_string(),
                "/dev/tcp".to_string(),
                "socket.*connect".to_string(),
            ],
            severity: "Critical".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Suspicious network activity".to_string(),
            description: "Package makes unexpected network connections".to_string(),
            indicators: vec![
                r"https?://\d+\.\d+\.\d+\.\d+".to_string(), // IP addresses
                "pastebin\\.com".to_string(),
                "ngrok\\.io".to_string(),
                "webhook".to_string(),
            ],
            severity: "High".to_string(),
        },
    ]
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MaliciousPackagePattern {
    pub pattern_name: String,
    pub description: String,
    pub indicators: Vec<String>,
    pub severity: String,
}

/// Known malicious npm packages list (for quick lookup)
pub fn get_known_malicious_packages() -> Vec<&'static str> {
    vec![
        // Known malicious packages
        "flatmap-stream",
        "event-stream@3.3.6",
        "eslint-scope@3.7.2",
        "bootstrap-sass@3.3.7",
        "crossenv",
        "cross-env.js",
        "d3.js",
        "fabric-js",
        "ffmpeg.js",
        "gruntcli",
        "http-proxy.js",
        "jquery.js",
        "mariadb",
        "mongose",
        "mssql.js",
        "mssql-node",
        "node-fabric",
        "node-opencv",
        "node-opensl",
        "node-openssl",
        "node-sqlite",
        "node-tkinter",
        "nodecaffe",
        "nodefabric",
        "nodeffmpeg",
        "nodemailer-js",
        "noderequest",
        "nodesass",
        "nodesqlite",
        "opencv.js",
        "openssl.js",
        "proxy.js",
        "shadowsock",
        "smb",
        "sqlite.js",
        "sqliter",
        "sqlserver",
        "tkinter",
        // Typosquatting attempts
        "babelcli",
        "babel-preset-es2015",
        "babel-preset-es2016",
        "babel-preset-es2017",
        "babel-preset-react",
        "babel-preset-stage-0",
        "font-awesome",
        "react-dev-utils",
        "react-scripts",
        "vue-cli",
        "webpack-dev-server",
    ]
}

/// Check if a package name is suspiciously similar to a popular package
pub fn check_typosquatting_similarity(package_name: &str) -> Option<Vec<String>> {
    let popular_packages = vec![
        "react",
        "express",
        "lodash",
        "axios",
        "moment",
        "webpack",
        "babel",
        "typescript",
        "jest",
        "eslint",
        "prettier",
        "redux",
        "next",
        "vue",
        "angular",
        "jquery",
        "bootstrap",
        "material-ui",
        "styled-components",
        "react-router",
        "react-redux",
        "react-dom",
        "prop-types",
        "classnames",
        "commander",
        "chalk",
        "debug",
        "request",
        "async",
        "underscore",
        "body-parser",
        "cookie-parser",
        "cors",
        "dotenv",
        "jsonwebtoken",
        "mongoose",
        "mysql",
        "passport",
        "socket.io",
        "validator",
    ];

    let mut similar_packages = vec![];

    for popular in &popular_packages {
        let distance = levenshtein_distance(package_name, popular);
        if distance > 0 && distance <= 2 {
            similar_packages.push(popular.to_string());
        }

        // Check for common typosquatting patterns
        if package_name.starts_with(popular) && package_name.len() > popular.len() {
            let suffix = &package_name[popular.len()..];
            if matches!(
                suffix,
                "-dev" | "-test" | "js" | ".js" | "-js" | "2" | "-cli"
            ) {
                similar_packages.push(format!("{} (suspicious suffix: {})", popular, suffix));
            }
        }
    }

    if similar_packages.is_empty() {
        None
    } else {
        Some(similar_packages)
    }
}

fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let len1 = s1.chars().count();
    let len2 = s2.chars().count();
    let mut matrix = vec![vec![0; len2 + 1]; len1 + 1];

    for i in 0..=len1 {
        matrix[i][0] = i;
    }
    for j in 0..=len2 {
        matrix[0][j] = j;
    }

    for (i, c1) in s1.chars().enumerate() {
        for (j, c2) in s2.chars().enumerate() {
            let cost = if c1 == c2 { 0 } else { 1 };
            matrix[i + 1][j + 1] = std::cmp::min(
                std::cmp::min(matrix[i][j + 1] + 1, matrix[i + 1][j] + 1),
                matrix[i][j] + cost,
            );
        }
    }

    matrix[len1][len2]
}
