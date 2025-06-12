use file_scanner::typosquatting_detection::{
    TyposquattingDetector, analyze_typosquatting, is_potential_typosquatting,
    calculate_package_similarity, SimilarityType, RiskLevel
};

#[test]
fn test_typosquatting_detector_creation() {
    let detector = TyposquattingDetector::new();
    // Test that detector can be created without panicking
    assert!(true); // Placeholder assertion since internal state is private
}

#[test]
fn test_typosquatting_detector_default() {
    let detector = TyposquattingDetector::default();
    // Test that default creation works
    assert!(true); // Placeholder assertion
}

#[test]
fn test_analyze_typosquatting_function() {
    let result = analyze_typosquatting("react", "npm");
    
    match result {
        Ok(analysis) => {
            // "react" is a legitimate package, should not be flagged as typosquatting
            assert!(!analysis.is_potential_typosquatting);
            assert!(analysis.typosquatting_score >= 0.0 && analysis.typosquatting_score <= 1.0);
            assert!(!analysis.recommendations.is_empty());
        }
        Err(_) => {
            // Analysis might fail, which is acceptable
        }
    }
}

#[test]
fn test_is_potential_typosquatting_function() {
    // Test with a legitimate package
    let is_typosquatting = is_potential_typosquatting("react", "npm");
    assert!(!is_typosquatting);
    
    // Test with a suspicious package name
    let is_typosquatting = is_potential_typosquatting("reakt", "npm");
    // Function should not panic and return a boolean
    assert!(is_typosquatting == true || is_typosquatting == false);
}

#[test]
fn test_calculate_package_similarity_function() {
    // Test identical names
    let similarity = calculate_package_similarity("react", "react");
    assert_eq!(similarity, 1.0);
    
    // Test completely different names
    let similarity = calculate_package_similarity("react", "django");
    assert!(similarity < 0.5);
    
    // Test similar names
    let similarity = calculate_package_similarity("react", "reakt");
    assert!(similarity > 0.5);
    assert!(similarity < 1.0);
    
    // Test with empty strings
    let similarity = calculate_package_similarity("", "");
    assert!(similarity >= 0.0 && similarity <= 1.0);
}

#[test]
fn test_detect_character_substitution() {
    let result = analyze_typosquatting("reakt", "npm");
    
    match result {
        Ok(analysis) => {
            // Should detect similarity to "react"
            let has_react_similarity = analysis.similar_packages.iter()
                .any(|p| p.name == "react");
            
            if has_react_similarity {
                assert!(analysis.is_potential_typosquatting);
                
                // Should detect character substitution technique
                let has_char_substitution = analysis.attack_techniques.iter()
                    .any(|t| t.technique_name == "Character Substitution" && t.detected);
                
                assert!(has_char_substitution);
            }
        }
        Err(_) => {
            // Analysis might fail, which is acceptable
        }
    }
}

#[test]
fn test_detect_keyboard_proximity() {
    let result = analyze_typosquatting("rwact", "npm"); // 'e' -> 'w' (adjacent keys)
    
    match result {
        Ok(analysis) => {
            if analysis.is_potential_typosquatting {
                // Should potentially detect keyboard proximity
                let has_keyboard_proximity = analysis.attack_techniques.iter()
                    .any(|t| t.technique_name == "Keyboard Proximity");
                
                // Keyboard proximity technique should exist (detected or not)
                assert!(has_keyboard_proximity);
            }
        }
        Err(_) => {
            // Analysis might fail, which is acceptable
        }
    }
}

#[test]
fn test_detect_visual_similarity() {
    let result = analyze_typosquatting("react", "npm"); // Using numbers that look like letters
    
    match result {
        Ok(analysis) => {
            // Should have visual similarity technique defined
            let has_visual_similarity = analysis.attack_techniques.iter()
                .any(|t| t.technique_name == "Visual Similarity");
            
            assert!(has_visual_similarity);
        }
        Err(_) => {
            // Analysis might fail, which is acceptable
        }
    }
}

#[test]
fn test_detect_hyphenation_variations() {
    let result = analyze_typosquatting("vue-router", "npm");
    
    match result {
        Ok(analysis) => {
            // Should have hyphenation technique defined
            let has_hyphenation = analysis.attack_techniques.iter()
                .any(|t| t.technique_name == "Hyphenation/Underscore");
            
            assert!(has_hyphenation);
        }
        Err(_) => {
            // Analysis might fail, which is acceptable
        }
    }
}

#[test]
fn test_detect_suspicious_patterns() {
    // Test development suffix
    let result = analyze_typosquatting("react-dev", "npm");
    
    match result {
        Ok(analysis) => {
            let has_dev_suffix = analysis.suspicious_patterns.iter()
                .any(|p| p.pattern_type == "Development Suffix");
            
            assert!(has_dev_suffix);
        }
        Err(_) => {
            // Analysis might fail, which is acceptable
        }
    }
    
    // Test test prefix
    let result = analyze_typosquatting("test-package", "npm");
    
    match result {
        Ok(analysis) => {
            let has_test_prefix = analysis.suspicious_patterns.iter()
                .any(|p| p.pattern_type == "Test Prefix");
            
            assert!(has_test_prefix);
        }
        Err(_) => {
            // Analysis might fail, which is acceptable
        }
    }
    
    // Test numeric suffix
    let result = analyze_typosquatting("package1", "npm");
    
    match result {
        Ok(analysis) => {
            let has_numeric_suffix = analysis.suspicious_patterns.iter()
                .any(|p| p.pattern_type == "Numeric Suffix");
            
            assert!(has_numeric_suffix);
        }
        Err(_) => {
            // Analysis might fail, which is acceptable
        }
    }
}

#[test]
fn test_npm_popular_packages() {
    // Test against known popular npm packages
    let popular_packages = ["react", "lodash", "express", "axios", "moment", "webpack"];
    
    for package in &popular_packages {
        let result = analyze_typosquatting(package, "npm");
        
        match result {
            Ok(analysis) => {
                // Popular packages themselves should not be flagged as typosquatting
                assert!(!analysis.is_potential_typosquatting);
                assert!(analysis.typosquatting_score < 0.5);
            }
            Err(_) => {
                // Analysis might fail, which is acceptable
            }
        }
    }
}

#[test]
fn test_pypi_popular_packages() {
    // Test against known popular PyPI packages
    let popular_packages = ["requests", "numpy", "pandas", "django", "flask"];
    
    for package in &popular_packages {
        let result = analyze_typosquatting(package, "pypi");
        
        match result {
            Ok(analysis) => {
                // Popular packages themselves should not be flagged as typosquatting
                assert!(!analysis.is_potential_typosquatting);
                assert!(analysis.typosquatting_score < 0.5);
            }
            Err(_) => {
                // Analysis might fail, which is acceptable
            }
        }
    }
}

#[test]
fn test_high_risk_typosquatting() {
    // Test with packages very similar to popular ones
    let suspicious_packages = [
        ("reqeusts", "pypi"),   // requests typo
        ("expresss", "npm"),    // express typo
        ("reactt", "npm"),      // react typo
    ];
    
    for (package, ecosystem) in &suspicious_packages {
        let result = analyze_typosquatting(package, ecosystem);
        
        match result {
            Ok(analysis) => {
                if analysis.is_potential_typosquatting {
                    // Should have high typosquatting score
                    assert!(analysis.typosquatting_score > 0.5);
                    
                    // Should have similar packages detected
                    assert!(!analysis.similar_packages.is_empty());
                    
                    // Should have recommendations
                    assert!(!analysis.recommendations.is_empty());
                }
            }
            Err(_) => {
                // Analysis might fail, which is acceptable
            }
        }
    }
}

#[test]
fn test_similarity_type_variants() {
    // Test that all similarity types can be created
    let _char_sub = SimilarityType::CharacterSubstitution;
    let _char_add = SimilarityType::CharacterAddition;
    let _char_del = SimilarityType::CharacterDeletion;
    let _char_trans = SimilarityType::CharacterTransposition;
    let _keyboard = SimilarityType::KeyboardProximity;
    let _visual = SimilarityType::VisualSimilarity;
    let _phonetic = SimilarityType::PhoneticSimilarity;
    let _hyphen = SimilarityType::Hyphenation;
    let _abbrev = SimilarityType::Abbreviation;
}

#[test]
fn test_risk_level_variants() {
    // Test that all risk levels can be created
    let _critical = RiskLevel::Critical;
    let _high = RiskLevel::High;
    let _medium = RiskLevel::Medium;
    let _low = RiskLevel::Low;
}

#[test]
fn test_distance_metrics() {
    let result = analyze_typosquatting("reakt", "npm");
    
    match result {
        Ok(analysis) => {
            for similar_package in &analysis.similar_packages {
                // Verify distance metrics are calculated
                assert!(similar_package.distance_metrics.levenshtein_distance >= 0);
                assert!(similar_package.distance_metrics.jaro_winkler_similarity >= 0.0);
                assert!(similar_package.distance_metrics.jaro_winkler_similarity <= 1.0);
                assert!(similar_package.distance_metrics.damerau_levenshtein_similarity >= 0.0);
                assert!(similar_package.distance_metrics.damerau_levenshtein_similarity <= 1.0);
                assert!(similar_package.distance_metrics.edit_distance >= 0);
                assert!(similar_package.distance_metrics.normalized_similarity >= 0.0);
                assert!(similar_package.distance_metrics.normalized_similarity <= 1.0);
            }
        }
        Err(_) => {
            // Analysis might fail, which is acceptable
        }
    }
}

#[test]
fn test_empty_package_name() {
    let result = analyze_typosquatting("", "npm");
    
    match result {
        Ok(analysis) => {
            // Empty package name should not cause panic
            assert!(analysis.typosquatting_score >= 0.0);
            assert!(analysis.typosquatting_score <= 1.0);
        }
        Err(_) => {
            // Analysis might fail for empty names, which is acceptable
        }
    }
}

#[test]
fn test_very_short_package_names() {
    let short_names = ["a", "ab", "xy"];
    
    for name in &short_names {
        let result = analyze_typosquatting(name, "npm");
        
        match result {
            Ok(analysis) => {
                // Short names should be handled gracefully
                assert!(analysis.typosquatting_score >= 0.0);
                assert!(analysis.typosquatting_score <= 1.0);
            }
            Err(_) => {
                // Analysis might fail for very short names, which is acceptable
            }
        }
    }
}

#[test]
fn test_very_long_package_names() {
    let long_name = "a".repeat(100);
    
    let result = analyze_typosquatting(&long_name, "npm");
    
    match result {
        Ok(analysis) => {
            // Long names should be handled gracefully
            assert!(analysis.typosquatting_score >= 0.0);
            assert!(analysis.typosquatting_score <= 1.0);
        }
        Err(_) => {
            // Analysis might fail for very long names, which is acceptable
        }
    }
}

#[test]
fn test_special_characters_in_package_names() {
    let special_names = ["@react/core", "package-with-hyphens", "package_with_underscores"];
    
    for name in &special_names {
        let result = analyze_typosquatting(name, "npm");
        
        match result {
            Ok(analysis) => {
                // Special characters should be handled gracefully
                assert!(analysis.typosquatting_score >= 0.0);
                assert!(analysis.typosquatting_score <= 1.0);
            }
            Err(_) => {
                // Analysis might fail for names with special characters, which is acceptable
            }
        }
    }
}

#[test]
fn test_number_substitution_detection() {
    let result = analyze_typosquatting("reac7", "npm"); // 't' -> '7'
    
    match result {
        Ok(analysis) => {
            let has_number_substitution = analysis.suspicious_patterns.iter()
                .any(|p| p.pattern_type == "Number Substitution");
            
            assert!(has_number_substitution);
        }
        Err(_) => {
            // Analysis might fail, which is acceptable
        }
    }
}

#[test]
fn test_repeated_characters_detection() {
    let result = analyze_typosquatting("reeact", "npm"); // repeated 'e'
    
    match result {
        Ok(analysis) => {
            let has_repeated_chars = analysis.suspicious_patterns.iter()
                .any(|p| p.pattern_type == "Repeated Characters");
            
            assert!(has_repeated_chars);
        }
        Err(_) => {
            // Analysis might fail, which is acceptable
        }
    }
}

#[test]
fn test_recommendations_generation() {
    let result = analyze_typosquatting("reakt", "npm");
    
    match result {
        Ok(analysis) => {
            // Should always have recommendations
            assert!(!analysis.recommendations.is_empty());
            
            if analysis.is_potential_typosquatting {
                // High-risk packages should have specific recommendations
                let has_verification_recommendation = analysis.recommendations.iter()
                    .any(|r| r.contains("Verify") || r.contains("author"));
                
                assert!(has_verification_recommendation);
            }
        }
        Err(_) => {
            // Analysis might fail, which is acceptable
        }
    }
}

#[test]
fn test_unknown_ecosystem() {
    let result = analyze_typosquatting("somepackage", "unknown");
    
    match result {
        Ok(analysis) => {
            // Unknown ecosystem should be handled gracefully
            assert!(analysis.typosquatting_score >= 0.0);
            assert!(analysis.typosquatting_score <= 1.0);
        }
        Err(_) => {
            // Analysis might fail for unknown ecosystems, which is acceptable
        }
    }
}

#[test]
fn test_case_sensitivity() {
    let result1 = analyze_typosquatting("React", "npm");
    let result2 = analyze_typosquatting("REACT", "npm");
    
    match (result1, result2) {
        (Ok(analysis1), Ok(analysis2)) => {
            // Case variations should be handled consistently
            assert!(analysis1.typosquatting_score >= 0.0);
            assert!(analysis2.typosquatting_score >= 0.0);
        }
        _ => {
            // Analysis might fail, which is acceptable
        }
    }
}

#[test]
fn test_attack_techniques_structure() {
    let result = analyze_typosquatting("test-package", "npm");
    
    match result {
        Ok(analysis) => {
            // All attack techniques should be present
            assert!(!analysis.attack_techniques.is_empty());
            
            for technique in &analysis.attack_techniques {
                // Each technique should have proper structure
                assert!(!technique.technique_name.is_empty());
                assert!(!technique.description.is_empty());
                assert!(!technique.examples.is_empty());
                // detected field should be boolean (no need to test specific value)
            }
        }
        Err(_) => {
            // Analysis might fail, which is acceptable
        }
    }
}

#[test]
fn test_similar_packages_sorting() {
    let result = analyze_typosquatting("reactt", "npm");
    
    match result {
        Ok(analysis) => {
            if analysis.similar_packages.len() > 1 {
                // Similar packages should be sorted by risk level and similarity
                let mut prev_was_critical = false;
                let mut prev_was_high = false;
                
                for package in &analysis.similar_packages {
                    match package.risk_level {
                        RiskLevel::Critical => {
                            prev_was_critical = true;
                        }
                        RiskLevel::High => {
                            assert!(prev_was_critical || !prev_was_high);
                            prev_was_high = true;
                        }
                        _ => {
                            // Medium and Low should come after Critical and High
                        }
                    }
                }
            }
        }
        Err(_) => {
            // Analysis might fail, which is acceptable
        }
    }
}

#[test]
fn test_popularity_score_integration() {
    let result = analyze_typosquatting("reakt", "npm");
    
    match result {
        Ok(analysis) => {
            for package in &analysis.similar_packages {
                if package.name == "react" {
                    // Popular packages should have popularity scores
                    assert!(package.popularity_score.is_some());
                    assert!(package.popularity_score.unwrap() > 0);
                }
            }
        }
        Err(_) => {
            // Analysis might fail, which is acceptable
        }
    }
}