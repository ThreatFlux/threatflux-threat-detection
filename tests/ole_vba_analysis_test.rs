use file_scanner::ole_vba_analysis::*;
use serde_json;
use serde_yaml;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

#[test]
fn test_ole_file_type_variants() {
    // Test all OleFileType variants for serialization
    let file_types = vec![
        OleFileType::Ole2Document,
        OleFileType::OfficeDocument,
        OleFileType::OfficeOpenXml,
        OleFileType::OutlookMessage,
        OleFileType::VisioDocument,
        OleFileType::OneNoteDocument,
        OleFileType::Other("CustomFormat".to_string()),
        OleFileType::NotOleFile,
    ];

    for file_type in file_types {
        let json = serde_json::to_string(&file_type).unwrap();
        let deserialized: OleFileType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{:?}", file_type), format!("{:?}", deserialized));
    }
}

#[test]
fn test_entry_type_variants() {
    let entry_types = vec![EntryType::Storage, EntryType::Stream, EntryType::Root];

    for entry_type in entry_types {
        let json = serde_json::to_string(&entry_type).unwrap();
        let deserialized: EntryType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{:?}", entry_type), format!("{:?}", deserialized));
    }
}

#[test]
fn test_node_color_variants() {
    let colors = vec![NodeColor::Red, NodeColor::Black];

    for color in colors {
        let json = serde_json::to_string(&color).unwrap();
        let deserialized: NodeColor = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{:?}", color), format!("{:?}", deserialized));
    }
}

#[test]
fn test_vba_module_type_variants() {
    let module_types = vec![
        VbaModuleType::Standard,
        VbaModuleType::ClassModule,
        VbaModuleType::UserForm,
        VbaModuleType::Document,
        VbaModuleType::Unknown,
    ];

    for module_type in module_types {
        let json = serde_json::to_string(&module_type).unwrap();
        let deserialized: VbaModuleType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{:?}", module_type), format!("{:?}", deserialized));
    }
}

#[test]
fn test_vba_procedure_type_variants() {
    let procedure_types = vec![
        VbaProcedureType::Sub,
        VbaProcedureType::Function,
        VbaProcedureType::Property,
        VbaProcedureType::Event,
    ];

    for proc_type in procedure_types {
        let json = serde_json::to_string(&proc_type).unwrap();
        let deserialized: VbaProcedureType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{:?}", proc_type), format!("{:?}", deserialized));
    }
}

#[test]
fn test_vba_reference_type_variants() {
    let reference_types = vec![
        VbaReferenceType::TypeLib,
        VbaReferenceType::Project,
        VbaReferenceType::Control,
        VbaReferenceType::Unknown,
    ];

    for ref_type in reference_types {
        let json = serde_json::to_string(&ref_type).unwrap();
        let deserialized: VbaReferenceType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{:?}", ref_type), format!("{:?}", deserialized));
    }
}

#[test]
fn test_stream_type_variants() {
    let stream_types = vec![
        StreamType::VbaProject,
        StreamType::VbaModule,
        StreamType::VbaCompiled,
        StreamType::WordDocument,
        StreamType::ExcelWorkbook,
        StreamType::PowerPointDocument,
        StreamType::OleObject,
        StreamType::Metadata,
        StreamType::CustomData,
        StreamType::Unknown,
    ];

    for stream_type in stream_types {
        let json = serde_json::to_string(&stream_type).unwrap();
        let deserialized: StreamType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{:?}", stream_type), format!("{:?}", deserialized));
    }
}

#[test]
fn test_obfuscation_type_variants() {
    let obfuscation_types = vec![
        ObfuscationType::StringConcatenation,
        ObfuscationType::CharCodeObfuscation,
        ObfuscationType::Base64Encoding,
        ObfuscationType::HexEncoding,
        ObfuscationType::VariableNameObfuscation,
        ObfuscationType::ControlFlowObfuscation,
        ObfuscationType::CommentObfuscation,
        ObfuscationType::Unknown,
    ];

    for obf_type in obfuscation_types {
        let json = serde_json::to_string(&obf_type).unwrap();
        let deserialized: ObfuscationType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{:?}", obf_type), format!("{:?}", deserialized));
    }
}

#[test]
fn test_connection_type_variants() {
    let connection_types = vec![
        ConnectionType::HttpRequest,
        ConnectionType::FtpConnection,
        ConnectionType::EmailSending,
        ConnectionType::DnsLookup,
        ConnectionType::SocketConnection,
        ConnectionType::Unknown,
    ];

    for conn_type in connection_types {
        let json = serde_json::to_string(&conn_type).unwrap();
        let deserialized: ConnectionType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{:?}", conn_type), format!("{:?}", deserialized));
    }
}

#[test]
fn test_risk_level_variants() {
    let risk_levels = vec![
        RiskLevel::Low,
        RiskLevel::Medium,
        RiskLevel::High,
        RiskLevel::Critical,
    ];

    for risk_level in risk_levels {
        let json = serde_json::to_string(&risk_level).unwrap();
        let deserialized: RiskLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{:?}", risk_level), format!("{:?}", deserialized));
    }
}

#[test]
fn test_comprehensive_ole_vba_analysis() {
    // Create a comprehensive OleVbaAnalysis structure for testing
    let analysis = OleVbaAnalysis {
        file_type: OleFileType::OfficeDocument,
        ole_structure: Some(OleStructure {
            sector_size: 512,
            mini_sector_size: 64,
            total_sectors: 100,
            fat_sectors: 10,
            directory_sectors: 5,
            mini_fat_sectors: 2,
            root_entry: DirectoryEntry {
                name: "Root Entry".to_string(),
                entry_type: EntryType::Root,
                color: NodeColor::Black,
                size: 0,
                start_sector: 0,
                children: vec!["VBA".to_string(), "WordDocument".to_string()],
            },
            entries: vec![
                DirectoryEntry {
                    name: "VBA".to_string(),
                    entry_type: EntryType::Storage,
                    color: NodeColor::Red,
                    size: 1024,
                    start_sector: 10,
                    children: vec!["Module1".to_string()],
                },
                DirectoryEntry {
                    name: "Module1".to_string(),
                    entry_type: EntryType::Stream,
                    color: NodeColor::Black,
                    size: 512,
                    start_sector: 15,
                    children: vec![],
                },
            ],
        }),
        vba_project: Some(VbaProject {
            project_name: "TestProject".to_string(),
            modules: vec![VbaModule {
                name: "Module1".to_string(),
                module_type: VbaModuleType::Standard,
                source_code: Some("Sub Auto_Open()\n    Shell \"cmd.exe\"\nEnd Sub".to_string()),
                compiled_code: None,
                line_count: 3,
                procedure_count: 1,
                procedures: vec![VbaProcedure {
                    name: "Auto_Open".to_string(),
                    procedure_type: VbaProcedureType::Sub,
                    start_line: 0,
                    end_line: 2,
                    parameters: vec![],
                    local_variables: vec![],
                    external_calls: vec!["Shell".to_string()],
                    risk_score: 85,
                }],
                suspicious_patterns: vec!["Suspicious keyword: shell".to_string()],
            }],
            references: vec![VbaReference {
                name: "stdole".to_string(),
                guid: Some("{00020430-0000-0000-C000-000000000046}".to_string()),
                version: Some("2.0".to_string()),
                path: Some("C:\\Windows\\System32\\stdole2.tlb".to_string()),
                reference_type: VbaReferenceType::TypeLib,
            }],
            properties: std::collections::HashMap::new(),
            protection: VbaProtection {
                is_locked: false,
                is_password_protected: false,
                lock_bytes: None,
                password_hash: None,
            },
            version_info: VbaVersionInfo {
                major: 5,
                minor: 0,
                language_id: 1033,
                performance_cache: false,
            },
        }),
        macros: vec![VbaModule {
            name: "Module1".to_string(),
            module_type: VbaModuleType::Standard,
            source_code: Some("Sub Auto_Open()\n    Shell \"cmd.exe\"\nEnd Sub".to_string()),
            compiled_code: None,
            line_count: 3,
            procedure_count: 1,
            procedures: vec![VbaProcedure {
                name: "Auto_Open".to_string(),
                procedure_type: VbaProcedureType::Sub,
                start_line: 0,
                end_line: 2,
                parameters: vec![],
                local_variables: vec![],
                external_calls: vec!["Shell".to_string()],
                risk_score: 85,
            }],
            suspicious_patterns: vec!["Suspicious keyword: shell".to_string()],
        }],
        streams: vec![
            StreamInfo {
                name: "WordDocument".to_string(),
                size: 4096,
                stream_type: StreamType::WordDocument,
                content_preview: Some("Document content preview...".to_string()),
                entropy: 4.5,
                compression_ratio: Some(0.3),
            },
            StreamInfo {
                name: "VBA/Module1".to_string(),
                size: 512,
                stream_type: StreamType::VbaModule,
                content_preview: Some("Sub Auto_Open()...".to_string()),
                entropy: 6.2,
                compression_ratio: None,
            },
        ],
        suspicious_indicators: SuspiciousIndicators {
            has_macros: true,
            auto_exec_macros: vec!["Module1:Auto_Open".to_string()],
            suspicious_api_calls: vec![SuspiciousApiCall {
                api_name: "shell".to_string(),
                module_name: "Module1".to_string(),
                call_count: 1,
                context: "Found in module Module1".to_string(),
                risk_level: RiskLevel::Critical,
                description: "Command execution".to_string(),
            }],
            obfuscated_code: vec![],
            external_connections: vec![],
            file_operations: vec![],
            registry_operations: vec![],
            process_operations: vec![ProcessOperation {
                operation_type: ProcessOperationType::Create,
                target_process: "Process execution detected".to_string(),
                parameters: vec!["Various parameters".to_string()],
                location: "Module1".to_string(),
                risk_level: RiskLevel::Critical,
            }],
            cryptographic_operations: vec![],
            risk_score: 75,
        },
        metadata: OleMetadata {
            title: Some("Test Document".to_string()),
            subject: Some("VBA Test".to_string()),
            author: Some("Test Author".to_string()),
            keywords: Some("macro, vba, test".to_string()),
            comments: Some("Test document with VBA macros".to_string()),
            last_author: Some("Test User".to_string()),
            revision_number: Some("1".to_string()),
            application_name: Some("Microsoft Word".to_string()),
            creation_time: Some("2024-01-01T00:00:00Z".to_string()),
            last_saved_time: Some("2024-01-02T00:00:00Z".to_string()),
            total_edit_time: Some("PT1H".to_string()),
            security: Some(0),
            custom_properties: std::collections::HashMap::new(),
        },
        security_assessment: SecurityAssessment {
            overall_risk: RiskLevel::Critical,
            risk_factors: vec![
                RiskFactor {
                    factor_type: RiskFactorType::MacroPresence,
                    description: "Document contains VBA macros".to_string(),
                    severity: RiskLevel::Medium,
                    confidence: 1.0,
                },
                RiskFactor {
                    factor_type: RiskFactorType::AutoExecution,
                    description: "Auto-executing macros found: Module1:Auto_Open".to_string(),
                    severity: RiskLevel::High,
                    confidence: 0.9,
                },
                RiskFactor {
                    factor_type: RiskFactorType::SuspiciousApiCalls,
                    description: "Found 1 high-risk API calls".to_string(),
                    severity: RiskLevel::High,
                    confidence: 0.8,
                },
            ],
            recommendations: vec![
                "Disable macros unless absolutely necessary".to_string(),
                "Auto-executing macros detected. Exercise extreme caution".to_string(),
            ],
            ioc_indicators: vec![],
            yara_matches: vec![],
        },
    };

    // Test JSON serialization
    let json = serde_json::to_string(&analysis).unwrap();
    let deserialized: OleVbaAnalysis = serde_json::from_str(&json).unwrap();

    assert_eq!(
        format!("{:?}", analysis.file_type),
        format!("{:?}", deserialized.file_type)
    );
    assert_eq!(analysis.macros.len(), deserialized.macros.len());
    assert_eq!(analysis.streams.len(), deserialized.streams.len());
    assert_eq!(
        analysis.suspicious_indicators.has_macros,
        deserialized.suspicious_indicators.has_macros
    );
    assert_eq!(
        analysis.suspicious_indicators.auto_exec_macros,
        deserialized.suspicious_indicators.auto_exec_macros
    );
    assert_eq!(
        analysis.suspicious_indicators.risk_score,
        deserialized.suspicious_indicators.risk_score
    );
    assert_eq!(
        format!("{:?}", analysis.security_assessment.overall_risk),
        format!("{:?}", deserialized.security_assessment.overall_risk)
    );
}

#[test]
fn test_vba_module_comprehensive() {
    let module = VbaModule {
        name: "TestModule".to_string(),
        module_type: VbaModuleType::ClassModule,
        source_code: Some("Private Sub Class_Initialize()\n    Debug.Print \"Initialized\"\nEnd Sub\n\nPublic Function GetValue() As String\n    GetValue = \"Test\"\nEnd Function".to_string()),
        compiled_code: Some(vec![0x01, 0x02, 0x03, 0x04]),
        line_count: 6,
        procedure_count: 2,
        procedures: vec![
            VbaProcedure {
                name: "Class_Initialize".to_string(),
                procedure_type: VbaProcedureType::Sub,
                start_line: 0,
                end_line: 2,
                parameters: vec![],
                local_variables: vec![],
                external_calls: vec!["Debug.Print".to_string()],
                risk_score: 10,
            },
            VbaProcedure {
                name: "GetValue".to_string(),
                procedure_type: VbaProcedureType::Function,
                start_line: 4,
                end_line: 6,
                parameters: vec![],
                local_variables: vec!["GetValue".to_string()],
                external_calls: vec![],
                risk_score: 5,
            },
        ],
        suspicious_patterns: vec![],
    };

    let json = serde_json::to_string(&module).unwrap();
    let deserialized: VbaModule = serde_json::from_str(&json).unwrap();

    assert_eq!(module.name, deserialized.name);
    assert_eq!(
        format!("{:?}", module.module_type),
        format!("{:?}", deserialized.module_type)
    );
    assert_eq!(module.source_code, deserialized.source_code);
    assert_eq!(module.compiled_code, deserialized.compiled_code);
    assert_eq!(module.line_count, deserialized.line_count);
    assert_eq!(module.procedure_count, deserialized.procedure_count);
    assert_eq!(module.procedures.len(), deserialized.procedures.len());
    assert_eq!(module.suspicious_patterns, deserialized.suspicious_patterns);
}

#[test]
fn test_suspicious_indicators_comprehensive() {
    let indicators = SuspiciousIndicators {
        has_macros: true,
        auto_exec_macros: vec![
            "Module1:Auto_Open".to_string(),
            "Module2:Document_Open".to_string(),
        ],
        suspicious_api_calls: vec![
            SuspiciousApiCall {
                api_name: "CreateObject".to_string(),
                module_name: "Module1".to_string(),
                call_count: 2,
                context: "Object creation in macro".to_string(),
                risk_level: RiskLevel::High,
                description: "Dynamic object creation".to_string(),
            },
            SuspiciousApiCall {
                api_name: "URLDownloadToFile".to_string(),
                module_name: "Module2".to_string(),
                call_count: 1,
                context: "Network download".to_string(),
                risk_level: RiskLevel::Critical,
                description: "Downloads files from internet".to_string(),
            },
        ],
        obfuscated_code: vec![
            ObfuscationIndicator {
                technique: ObfuscationType::StringConcatenation,
                description: "Excessive string concatenation".to_string(),
                location: "Module1".to_string(),
                confidence: 0.8,
            },
            ObfuscationIndicator {
                technique: ObfuscationType::CharCodeObfuscation,
                description: "Character code obfuscation".to_string(),
                location: "Module2".to_string(),
                confidence: 0.9,
            },
        ],
        external_connections: vec![ExternalConnection {
            connection_type: ConnectionType::HttpRequest,
            target: "https://example.com/payload.exe".to_string(),
            method: "GET".to_string(),
            location: "Module1".to_string(),
        }],
        file_operations: vec![FileOperation {
            operation_type: FileOperationType::Write,
            target_path: "C:\\temp\\output.txt".to_string(),
            location: "Module2".to_string(),
            risk_level: RiskLevel::Medium,
        }],
        registry_operations: vec![RegistryOperation {
            operation_type: RegistryOperationType::Write,
            key_path: "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                .to_string(),
            value_name: Some("MyApp".to_string()),
            location: "Module1".to_string(),
            risk_level: RiskLevel::High,
        }],
        process_operations: vec![ProcessOperation {
            operation_type: ProcessOperationType::Create,
            target_process: "cmd.exe".to_string(),
            parameters: vec!["/c", "dir"].iter().map(|s| s.to_string()).collect(),
            location: "Module2".to_string(),
            risk_level: RiskLevel::Critical,
        }],
        cryptographic_operations: vec![CryptoOperation {
            operation_type: CryptoOperationType::Encryption,
            algorithm: "AES".to_string(),
            location: "Module1".to_string(),
            risk_level: RiskLevel::Medium,
        }],
        risk_score: 85,
    };

    let json = serde_json::to_string(&indicators).unwrap();
    let deserialized: SuspiciousIndicators = serde_json::from_str(&json).unwrap();

    assert_eq!(indicators.has_macros, deserialized.has_macros);
    assert_eq!(indicators.auto_exec_macros, deserialized.auto_exec_macros);
    assert_eq!(
        indicators.suspicious_api_calls.len(),
        deserialized.suspicious_api_calls.len()
    );
    assert_eq!(
        indicators.obfuscated_code.len(),
        deserialized.obfuscated_code.len()
    );
    assert_eq!(
        indicators.external_connections.len(),
        deserialized.external_connections.len()
    );
    assert_eq!(
        indicators.file_operations.len(),
        deserialized.file_operations.len()
    );
    assert_eq!(
        indicators.registry_operations.len(),
        deserialized.registry_operations.len()
    );
    assert_eq!(
        indicators.process_operations.len(),
        deserialized.process_operations.len()
    );
    assert_eq!(
        indicators.cryptographic_operations.len(),
        deserialized.cryptographic_operations.len()
    );
    assert_eq!(indicators.risk_score, deserialized.risk_score);
}

#[test]
fn test_security_assessment_comprehensive() {
    let assessment = SecurityAssessment {
        overall_risk: RiskLevel::Critical,
        risk_factors: vec![
            RiskFactor {
                factor_type: RiskFactorType::MacroPresence,
                description: "VBA macros detected".to_string(),
                severity: RiskLevel::Medium,
                confidence: 1.0,
            },
            RiskFactor {
                factor_type: RiskFactorType::AutoExecution,
                description: "Auto-executing macros found".to_string(),
                severity: RiskLevel::High,
                confidence: 0.95,
            },
            RiskFactor {
                factor_type: RiskFactorType::NetworkConnections,
                description: "External network connections detected".to_string(),
                severity: RiskLevel::Critical,
                confidence: 0.9,
            },
        ],
        recommendations: vec![
            "Quarantine this document immediately".to_string(),
            "Do not enable macros".to_string(),
            "Scan with updated antivirus".to_string(),
            "Report to security team".to_string(),
        ],
        ioc_indicators: vec![
            IocIndicator {
                indicator_type: IocType::Domain,
                value: "malicious.example.com".to_string(),
                confidence: 0.8,
                context: "Found in VBA code".to_string(),
            },
            IocIndicator {
                indicator_type: IocType::FileName,
                value: "payload.exe".to_string(),
                confidence: 0.9,
                context: "Downloaded file reference".to_string(),
            },
        ],
        yara_matches: vec![
            "VBA_AutoExec_Macro".to_string(),
            "Suspicious_Shell_Commands".to_string(),
        ],
    };

    let json = serde_json::to_string(&assessment).unwrap();
    let deserialized: SecurityAssessment = serde_json::from_str(&json).unwrap();

    assert_eq!(
        format!("{:?}", assessment.overall_risk),
        format!("{:?}", deserialized.overall_risk)
    );
    assert_eq!(
        assessment.risk_factors.len(),
        deserialized.risk_factors.len()
    );
    assert_eq!(assessment.recommendations, deserialized.recommendations);
    assert_eq!(
        assessment.ioc_indicators.len(),
        deserialized.ioc_indicators.len()
    );
    assert_eq!(assessment.yara_matches, deserialized.yara_matches);
}

#[test]
fn test_analyze_ole_vba_non_ole_file() {
    // Test with a non-OLE file
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"This is not an OLE file").unwrap();
    temp_file.flush().unwrap();

    let result = analyze_ole_vba(temp_file.path());

    // This may fail due to insufficient header size, which is expected
    match result {
        Ok(analysis) => {
            assert!(matches!(analysis.file_type, OleFileType::NotOleFile));
            assert!(analysis.ole_structure.is_none());
            assert!(analysis.vba_project.is_none());
            assert!(analysis.macros.is_empty());
            assert!(analysis.streams.is_empty());
            assert!(!analysis.suspicious_indicators.has_macros);
            assert_eq!(analysis.suspicious_indicators.risk_score, 0);
        }
        Err(_) => {
            // Expected for non-OLE files with insufficient header size
        }
    }
}

#[test]
fn test_analyze_ole_vba_text_file() {
    // Test with a plain text file
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file
        .write_all(b"Plain text file content\nwith multiple lines\nfor testing")
        .unwrap();
    temp_file.flush().unwrap();

    let result = analyze_ole_vba(temp_file.path());

    // This may fail due to insufficient header size, which is expected
    match result {
        Ok(analysis) => {
            assert!(matches!(analysis.file_type, OleFileType::NotOleFile));
            assert!(analysis.ole_structure.is_none());
            assert!(analysis.vba_project.is_none());
            assert!(analysis.macros.is_empty());
            assert!(!analysis.suspicious_indicators.has_macros);
        }
        Err(_) => {
            // Expected for non-OLE files with insufficient header size
        }
    }
}

#[test]
fn test_analyze_ole_vba_empty_file() {
    // Test with an empty file
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.flush().unwrap();

    let result = analyze_ole_vba(temp_file.path());

    // This will fail due to insufficient header size, which is expected
    match result {
        Ok(analysis) => {
            assert!(matches!(analysis.file_type, OleFileType::NotOleFile));
            assert!(analysis.ole_structure.is_none());
            assert!(analysis.vba_project.is_none());
            assert!(analysis.macros.is_empty());
            assert!(!analysis.suspicious_indicators.has_macros);
        }
        Err(_) => {
            // Expected for empty files with no header
        }
    }
}

#[test]
fn test_analyze_ole_vba_error_cases() {
    // Test with nonexistent file
    let result = analyze_ole_vba(Path::new("/nonexistent/file/path"));
    assert!(result.is_err());

    // Test with directory
    let result = analyze_ole_vba(Path::new("/tmp"));
    assert!(result.is_err());
}

#[test]
fn test_default_implementations() {
    // Test default implementations
    let suspicious_indicators = SuspiciousIndicators::default();
    assert!(!suspicious_indicators.has_macros);
    assert!(suspicious_indicators.auto_exec_macros.is_empty());
    assert!(suspicious_indicators.suspicious_api_calls.is_empty());
    assert_eq!(suspicious_indicators.risk_score, 0);

    let ole_metadata = OleMetadata::default();
    assert!(ole_metadata.title.is_none());
    assert!(ole_metadata.author.is_none());
    assert!(ole_metadata.custom_properties.is_empty());

    let security_assessment = SecurityAssessment::default();
    assert!(matches!(security_assessment.overall_risk, RiskLevel::Low));
    assert!(security_assessment.risk_factors.is_empty());
    assert!(security_assessment.recommendations.is_empty());
    assert!(security_assessment.ioc_indicators.is_empty());
    assert!(security_assessment.yara_matches.is_empty());
}

#[test]
fn test_yaml_serialization() {
    // Test YAML serialization with a simple structure
    let analysis = OleVbaAnalysis {
        file_type: OleFileType::OfficeDocument,
        ole_structure: None,
        vba_project: None,
        macros: vec![],
        streams: vec![],
        suspicious_indicators: SuspiciousIndicators::default(),
        metadata: OleMetadata::default(),
        security_assessment: SecurityAssessment::default(),
    };

    let yaml = serde_yaml::to_string(&analysis).unwrap();
    assert!(yaml.contains("file_type"));
    assert!(yaml.contains("OfficeDocument"));

    let deserialized: OleVbaAnalysis = serde_yaml::from_str(&yaml).unwrap();
    assert!(matches!(
        deserialized.file_type,
        OleFileType::OfficeDocument
    ));
    assert!(deserialized.ole_structure.is_none());
    assert!(deserialized.vba_project.is_none());
}

#[test]
fn test_edge_cases_and_boundaries() {
    // Test with maximum values
    let procedure = VbaProcedure {
        name: "MaxValueTest".to_string(),
        procedure_type: VbaProcedureType::Function,
        start_line: usize::MAX,
        end_line: usize::MAX,
        parameters: vec!["param1".to_string(); 100], // Large parameter list
        local_variables: vec!["var1".to_string(); 50],
        external_calls: vec!["call1".to_string(); 25],
        risk_score: 100, // Maximum risk score
    };

    let json = serde_json::to_string(&procedure).unwrap();
    let deserialized: VbaProcedure = serde_json::from_str(&json).unwrap();

    assert_eq!(procedure.name, deserialized.name);
    assert_eq!(procedure.start_line, deserialized.start_line);
    assert_eq!(procedure.end_line, deserialized.end_line);
    assert_eq!(procedure.parameters.len(), deserialized.parameters.len());
    assert_eq!(procedure.risk_score, deserialized.risk_score);

    // Test with minimum values
    let minimal_procedure = VbaProcedure {
        name: "".to_string(), // Empty name
        procedure_type: VbaProcedureType::Sub,
        start_line: 0,
        end_line: 0,
        parameters: vec![], // Empty parameters
        local_variables: vec![],
        external_calls: vec![],
        risk_score: 0, // Minimum risk score
    };

    let json = serde_json::to_string(&minimal_procedure).unwrap();
    let deserialized: VbaProcedure = serde_json::from_str(&json).unwrap();

    assert_eq!(minimal_procedure.name, deserialized.name);
    assert_eq!(
        minimal_procedure.parameters.len(),
        deserialized.parameters.len()
    );
    assert_eq!(minimal_procedure.risk_score, deserialized.risk_score);
}

#[test]
fn test_operation_type_variants() {
    // Test FileOperationType variants
    let file_ops = vec![
        FileOperationType::Read,
        FileOperationType::Write,
        FileOperationType::Delete,
        FileOperationType::Execute,
        FileOperationType::Copy,
        FileOperationType::Move,
        FileOperationType::CreateDirectory,
        FileOperationType::Unknown,
    ];

    for op in file_ops {
        let json = serde_json::to_string(&op).unwrap();
        let deserialized: FileOperationType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{:?}", op), format!("{:?}", deserialized));
    }

    // Test RegistryOperationType variants
    let reg_ops = vec![
        RegistryOperationType::Read,
        RegistryOperationType::Write,
        RegistryOperationType::Delete,
        RegistryOperationType::CreateKey,
        RegistryOperationType::Unknown,
    ];

    for op in reg_ops {
        let json = serde_json::to_string(&op).unwrap();
        let deserialized: RegistryOperationType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{:?}", op), format!("{:?}", deserialized));
    }

    // Test ProcessOperationType variants
    let proc_ops = vec![
        ProcessOperationType::Create,
        ProcessOperationType::Execute,
        ProcessOperationType::Inject,
        ProcessOperationType::Terminate,
        ProcessOperationType::Unknown,
    ];

    for op in proc_ops {
        let json = serde_json::to_string(&op).unwrap();
        let deserialized: ProcessOperationType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{:?}", op), format!("{:?}", deserialized));
    }

    // Test CryptoOperationType variants
    let crypto_ops = vec![
        CryptoOperationType::Encryption,
        CryptoOperationType::Decryption,
        CryptoOperationType::Hashing,
        CryptoOperationType::KeyGeneration,
        CryptoOperationType::Unknown,
    ];

    for op in crypto_ops {
        let json = serde_json::to_string(&op).unwrap();
        let deserialized: CryptoOperationType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{:?}", op), format!("{:?}", deserialized));
    }
}

#[test]
fn test_risk_factor_type_variants() {
    let risk_factor_types = vec![
        RiskFactorType::MacroPresence,
        RiskFactorType::AutoExecution,
        RiskFactorType::SuspiciousApiCalls,
        RiskFactorType::NetworkConnections,
        RiskFactorType::FileSystemAccess,
        RiskFactorType::RegistryAccess,
        RiskFactorType::ProcessManipulation,
        RiskFactorType::Obfuscation,
        RiskFactorType::Encryption,
        RiskFactorType::EmbeddedObjects,
        RiskFactorType::Unknown,
    ];

    for factor_type in risk_factor_types {
        let json = serde_json::to_string(&factor_type).unwrap();
        let deserialized: RiskFactorType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{:?}", factor_type), format!("{:?}", deserialized));
    }
}

#[test]
fn test_ioc_type_variants() {
    let ioc_types = vec![
        IocType::Domain,
        IocType::IpAddress,
        IocType::Url,
        IocType::EmailAddress,
        IocType::FileName,
        IocType::FilePath,
        IocType::RegistryKey,
        IocType::Mutex,
        IocType::ProcessName,
        IocType::Unknown,
    ];

    for ioc_type in ioc_types {
        let json = serde_json::to_string(&ioc_type).unwrap();
        let deserialized: IocType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{:?}", ioc_type), format!("{:?}", deserialized));
    }
}

#[test]
fn test_complex_vba_project() {
    let project = VbaProject {
        project_name: "ComplexProject".to_string(),
        modules: vec![
            VbaModule {
                name: "StandardModule".to_string(),
                module_type: VbaModuleType::Standard,
                source_code: Some("Sub TestSub()\nEnd Sub".to_string()),
                compiled_code: None,
                line_count: 2,
                procedure_count: 1,
                procedures: vec![],
                suspicious_patterns: vec![],
            },
            VbaModule {
                name: "ClassModule1".to_string(),
                module_type: VbaModuleType::ClassModule,
                source_code: None,
                compiled_code: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
                line_count: 0,
                procedure_count: 0,
                procedures: vec![],
                suspicious_patterns: vec![],
            },
        ],
        references: vec![
            VbaReference {
                name: "stdole".to_string(),
                guid: Some("{00020430-0000-0000-C000-000000000046}".to_string()),
                version: Some("2.0".to_string()),
                path: Some("C:\\Windows\\System32\\stdole2.tlb".to_string()),
                reference_type: VbaReferenceType::TypeLib,
            },
            VbaReference {
                name: "MSForms".to_string(),
                guid: Some("{0D452EE1-E08F-101A-852E-02608C4D0BB4}".to_string()),
                version: Some("2.0".to_string()),
                path: None,
                reference_type: VbaReferenceType::Control,
            },
        ],
        properties: {
            let mut props = std::collections::HashMap::new();
            props.insert("Name".to_string(), "ComplexProject".to_string());
            props.insert("HelpContextID".to_string(), "0".to_string());
            props.insert("VersionCompatible32".to_string(), "393222000".to_string());
            props
        },
        protection: VbaProtection {
            is_locked: true,
            is_password_protected: true,
            lock_bytes: Some(vec![0x12, 0x34, 0x56, 0x78]),
            password_hash: Some("abc123def456".to_string()),
        },
        version_info: VbaVersionInfo {
            major: 6,
            minor: 1,
            language_id: 1033,
            performance_cache: true,
        },
    };

    let json = serde_json::to_string(&project).unwrap();
    let deserialized: VbaProject = serde_json::from_str(&json).unwrap();

    assert_eq!(project.project_name, deserialized.project_name);
    assert_eq!(project.modules.len(), deserialized.modules.len());
    assert_eq!(project.references.len(), deserialized.references.len());
    assert_eq!(project.properties.len(), deserialized.properties.len());
    assert_eq!(
        project.protection.is_locked,
        deserialized.protection.is_locked
    );
    assert_eq!(
        project.protection.is_password_protected,
        deserialized.protection.is_password_protected
    );
    assert_eq!(project.version_info.major, deserialized.version_info.major);
    assert_eq!(
        project.version_info.performance_cache,
        deserialized.version_info.performance_cache
    );
}
