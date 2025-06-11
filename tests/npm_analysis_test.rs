use file_scanner::npm_analysis::analyze_npm_package;
use std::path::Path;

#[test]
fn test_npm_package_analysis() {
    let path = Path::new("test_npm_package");

    let analysis = analyze_npm_package(path).expect("Failed to analyze npm package");

    // Basic package info
    assert_eq!(analysis.package_info.name, "test-package");
    assert_eq!(analysis.package_info.version, "1.0.0");
    assert_eq!(analysis.package_info.license, Some("MIT".to_string()));

    // Check dependencies
    assert_eq!(analysis.dependencies.dependency_count, 4);

    // Check for vulnerabilities
    assert!(analysis.dependencies.vulnerability_summary.total_count > 0);
    assert!(analysis
        .dependencies
        .vulnerability_summary
        .vulnerable_packages
        .contains(&"event-stream".to_string()));
    assert!(analysis
        .dependencies
        .vulnerability_summary
        .vulnerable_packages
        .contains(&"lodash".to_string()));

    // Security analysis
    assert!(analysis.security_analysis.has_preinstall_script);
    assert!(analysis.security_analysis.has_postinstall_script);
    assert!(analysis.security_analysis.supply_chain_risk_score > 0.0);

    // Malicious indicators
    assert!(analysis.malicious_indicators.overall_risk_score > 50.0);

    // Should detect suspicious scripts
    assert!(!analysis.security_analysis.suspicious_scripts.is_empty());

    // Should detect network patterns
    assert!(!analysis
        .security_analysis
        .network_access_patterns
        .is_empty());
    let suspicious_urls: Vec<&str> = analysis
        .security_analysis
        .network_access_patterns
        .iter()
        .filter(|p| p.is_suspicious)
        .map(|p| p.url.as_str())
        .collect();
    assert!(suspicious_urls
        .iter()
        .any(|url| url.contains("suspicious-site.com")));

    println!("NPM Analysis Test Results:");
    println!(
        "Package: {} v{}",
        analysis.package_info.name, analysis.package_info.version
    );
    println!(
        "Vulnerabilities found: {}",
        analysis.dependencies.vulnerability_summary.total_count
    );
    println!(
        "Risk score: {:.1}/100",
        analysis.malicious_indicators.overall_risk_score
    );
    println!("Risk level: {:?}", analysis.malicious_indicators.risk_level);
}
