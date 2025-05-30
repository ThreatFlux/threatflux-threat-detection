use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::disassembly::DisassemblyResult;
use crate::function_analysis::SymbolTable;
use crate::strings::ExtractedStrings;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAnalysis {
    pub anti_analysis: Vec<AntiAnalysisTechnique>,
    pub persistence: Vec<PersistenceMechanism>,
    pub network_behavior: Vec<NetworkPattern>,
    pub file_operations: Vec<FileOperation>,
    pub registry_operations: Vec<RegistryOperation>,
    pub process_operations: Vec<ProcessOperation>,
    pub evasion_score: f32,
    pub suspicious_behaviors: Vec<SuspiciousBehavior>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiAnalysisTechnique {
    pub technique_type: AntiAnalysisType,
    pub indicators: Vec<String>,
    pub confidence: f32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AntiAnalysisType {
    AntiDebug,
    AntiVM,
    AntiSandbox,
    AntiDisassembly,
    Obfuscation,
    TimeDelays,
    EnvironmentChecks,
    ProcessHollowing,
    CodeInjection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceMechanism {
    pub mechanism_type: PersistenceType,
    pub target_locations: Vec<String>,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PersistenceType {
    RegistryKeys,
    ServiceInstallation,
    ScheduledTasks,
    StartupFolders,
    DLLHijacking,
    ProcessInjection,
    BootkitRootkit,
    WMIEventSubscription,
    BrowserExtension,
    OfficeAddins,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPattern {
    pub pattern_type: NetworkPatternType,
    pub indicators: Vec<String>,
    pub protocols: Vec<String>,
    pub ports: Vec<u16>,
    pub suspicious_level: SuspicionLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkPatternType {
    CommandAndControl,
    DataExfiltration,
    DomainGeneration,
    TorUsage,
    P2PCommunication,
    HTTPSBypass,
    DNSTunneling,
    IRCCommunication,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SuspicionLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperation {
    pub operation_type: FileOpType,
    pub targets: Vec<String>,
    pub suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum FileOpType {
    FileCreation,
    FileDeletion,
    FileModification,
    FileEncryption,
    FileCopying,
    FileHiding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryOperation {
    pub operation_type: RegistryOpType,
    pub keys: Vec<String>,
    pub purpose: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegistryOpType {
    KeyCreation,
    KeyDeletion,
    ValueModification,
    PermissionChange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessOperation {
    pub operation_type: ProcessOpType,
    pub targets: Vec<String>,
    pub techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProcessOpType {
    ProcessCreation,
    ProcessTermination,
    ProcessInjection,
    ProcessHollowing,
    ThreadCreation,
    PrivilegeEscalation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousBehavior {
    pub behavior_type: String,
    pub description: String,
    pub severity: Severity,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

pub fn analyze_behavior(
    _path: &Path,
    strings: Option<&ExtractedStrings>,
    symbols: Option<&SymbolTable>,
    disassembly: Option<&DisassemblyResult>,
) -> Result<BehavioralAnalysis> {
    let anti_analysis = detect_anti_analysis(strings, symbols, disassembly);
    let persistence = detect_persistence_mechanisms(strings, symbols);
    let network_behavior = detect_network_patterns(strings, symbols);
    let file_operations = detect_file_operations(strings, symbols);
    let registry_operations = detect_registry_operations(strings);
    let process_operations = detect_process_operations(strings, symbols);

    let suspicious_behaviors = identify_suspicious_behaviors(
        &anti_analysis,
        &persistence,
        &network_behavior,
        &file_operations,
        &process_operations,
    );

    let evasion_score = calculate_evasion_score(&anti_analysis, &suspicious_behaviors);
    let recommendations = generate_behavioral_recommendations(
        &anti_analysis,
        &persistence,
        &network_behavior,
        &suspicious_behaviors,
        evasion_score,
    );

    Ok(BehavioralAnalysis {
        anti_analysis,
        persistence,
        network_behavior,
        file_operations,
        registry_operations,
        process_operations,
        evasion_score,
        suspicious_behaviors,
        recommendations,
    })
}

fn detect_anti_analysis(
    strings: Option<&ExtractedStrings>,
    symbols: Option<&SymbolTable>,
    disassembly: Option<&DisassemblyResult>,
) -> Vec<AntiAnalysisTechnique> {
    let mut techniques = Vec::new();

    // Anti-debugging detection
    let debug_indicators = vec![
        ("IsDebuggerPresent", "Windows API for debugger detection"),
        ("CheckRemoteDebuggerPresent", "Remote debugger detection"),
        ("NtQueryInformationProcess", "Process information query"),
        ("OutputDebugString", "Debug output detection"),
        ("NtSetInformationThread", "Thread hiding from debugger"),
        ("ZwSetInformationThread", "Thread hiding alternate"),
        ("PEB", "Process Environment Block access"),
        ("BeingDebugged", "Direct PEB flag check"),
        ("NtGlobalFlag", "Global flag debugging check"),
        ("RDTSC", "Timing-based anti-debug"),
        ("GetTickCount", "Timing checks"),
        ("QueryPerformanceCounter", "High-precision timing"),
    ];

    let mut found_indicators = Vec::new();

    // Check strings
    if let Some(strings) = strings {
        for (indicator, desc) in &debug_indicators {
            if strings.ascii_strings.iter().any(|s| s.contains(indicator))
                || strings
                    .unicode_strings
                    .iter()
                    .any(|s| s.contains(indicator))
            {
                found_indicators.push(indicator.to_string());
            }
        }
    }

    // Check symbols
    if let Some(symbols) = symbols {
        for (indicator, _) in &debug_indicators {
            if symbols.functions.iter().any(|f| f.name.contains(indicator)) {
                if !found_indicators.contains(&indicator.to_string()) {
                    found_indicators.push(indicator.to_string());
                }
            }
        }
    }

    if !found_indicators.is_empty() {
        techniques.push(AntiAnalysisTechnique {
            technique_type: AntiAnalysisType::AntiDebug,
            indicators: found_indicators,
            confidence: 0.85,
            description: "Debugger detection techniques found".to_string(),
        });
    }

    // Anti-VM detection
    let vm_indicators = vec![
        ("VMware", "VMware detection"),
        ("VirtualBox", "VirtualBox detection"),
        ("QEMU", "QEMU detection"),
        ("Xen", "Xen hypervisor detection"),
        ("Hyper-V", "Hyper-V detection"),
        ("vmci", "VMware driver"),
        ("vboxdrv", "VirtualBox driver"),
        ("vpc.exe", "Virtual PC detection"),
        ("VMToolsd", "VMware tools"),
        ("VBoxService", "VirtualBox service"),
        ("HARDWARE\\ACPI\\DSDT\\VBOX", "VirtualBox registry key"),
        ("HARDWARE\\ACPI\\DSDT\\VMW", "VMware registry key"),
        ("SystemBiosVersion", "BIOS version check"),
        ("VideoBiosVersion", "Video BIOS check"),
        ("CPUID", "CPU feature detection"),
        ("hypervisor", "Hypervisor bit check"),
    ];

    let mut vm_found = Vec::new();

    if let Some(strings) = strings {
        for (indicator, _) in &vm_indicators {
            if strings.ascii_strings.iter().any(|s| s.contains(indicator))
                || strings
                    .unicode_strings
                    .iter()
                    .any(|s| s.contains(indicator))
            {
                vm_found.push(indicator.to_string());
            }
        }
    }

    if !vm_found.is_empty() {
        techniques.push(AntiAnalysisTechnique {
            technique_type: AntiAnalysisType::AntiVM,
            indicators: vm_found,
            confidence: 0.80,
            description: "Virtual machine detection attempts".to_string(),
        });
    }

    // Anti-sandbox detection
    let sandbox_indicators = vec![
        ("SbieDll", "Sandboxie detection"),
        ("SxIn", "360 Sandbox detection"),
        ("Sf2", "Avast Sandbox"),
        ("cmdvrt", "COMODO Sandbox"),
        ("sample", "Common sandbox filename"),
        ("malware", "Common sandbox filename"),
        ("virus", "Common sandbox filename"),
        ("sandbox", "Sandbox environment string"),
        ("GetUserName", "Username checking"),
        ("GetComputerName", "Computer name checking"),
        ("Sleep", "Delay execution"),
        ("NtDelayExecution", "Kernel delay execution"),
        ("GetCursorPos", "User activity check"),
        ("GetLastInputInfo", "User input timing"),
        ("mouse_event", "Simulated mouse check"),
        ("CreateToolhelp32Snapshot", "Process enumeration"),
    ];

    let mut sandbox_found = Vec::new();

    if let Some(strings) = strings {
        for (indicator, _) in &sandbox_indicators {
            if strings.ascii_strings.iter().any(|s| s.contains(indicator)) {
                sandbox_found.push(indicator.to_string());
            }
        }
    }

    if sandbox_found.len() >= 3 {
        techniques.push(AntiAnalysisTechnique {
            technique_type: AntiAnalysisType::AntiSandbox,
            indicators: sandbox_found,
            confidence: 0.75,
            description: "Sandbox evasion techniques detected".to_string(),
        });
    }

    // Code obfuscation detection
    if let Some(disassembly) = disassembly {
        let suspicious_patterns = &disassembly.analysis.suspicious_patterns;
        let obfuscation_indicators = [
            ("NopSled", "NOP sled obfuscation"),
            ("IndirectJumps", "Control flow obfuscation"),
            ("SelfModifying", "Self-modifying code"),
            ("ReturnOriented", "ROP chain obfuscation"),
        ];

        for pattern in suspicious_patterns {
            if let Some(desc) = obfuscation_indicators
                .iter()
                .find(|(name, _)| format!("{:?}", pattern.pattern_type).contains(name))
                .map(|(_, desc)| desc)
            {
                techniques.push(AntiAnalysisTechnique {
                    technique_type: AntiAnalysisType::Obfuscation,
                    indicators: vec![format!("{:?}", pattern.pattern_type)],
                    confidence: 0.70,
                    description: desc.to_string(),
                });
            }
        }
    }

    techniques
}

fn detect_persistence_mechanisms(
    strings: Option<&ExtractedStrings>,
    symbols: Option<&SymbolTable>,
) -> Vec<PersistenceMechanism> {
    let mut mechanisms = Vec::new();

    // Registry persistence
    let registry_persistence = vec![
        (
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            PersistenceType::RegistryKeys,
            "Startup registry key",
        ),
        (
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            PersistenceType::RegistryKeys,
            "Run once registry key",
        ),
        (
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
            PersistenceType::RegistryKeys,
            "Run services key",
        ),
        (
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
            PersistenceType::RegistryKeys,
            "Shell folders manipulation",
        ),
        (
            "SOFTWARE\\Classes\\",
            PersistenceType::RegistryKeys,
            "File association hijacking",
        ),
        (
            "SYSTEM\\CurrentControlSet\\Services",
            PersistenceType::ServiceInstallation,
            "Service installation",
        ),
        (
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            PersistenceType::RegistryKeys,
            "Winlogon manipulation",
        ),
        (
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
            PersistenceType::RegistryKeys,
            "Policy modification",
        ),
    ];

    if let Some(strings) = strings {
        for (key, pers_type, desc) in registry_persistence {
            if strings.ascii_strings.iter().any(|s| s.contains(key))
                || strings.unicode_strings.iter().any(|s| s.contains(key))
            {
                mechanisms.push(PersistenceMechanism {
                    mechanism_type: pers_type,
                    target_locations: vec![key.to_string()],
                    severity: Severity::High,
                    description: desc.to_string(),
                });
            }
        }
    }

    // Service creation APIs
    let service_apis = vec![
        ("CreateService", "Service creation API"),
        ("OpenSCManager", "Service manager access"),
        ("StartService", "Service startup"),
        ("ChangeServiceConfig", "Service configuration change"),
        ("RegisterServiceCtrlHandler", "Service control handler"),
    ];

    let mut service_indicators = Vec::new();

    if let Some(symbols) = symbols {
        for (api, _) in &service_apis {
            if symbols.functions.iter().any(|f| f.name.contains(api)) {
                service_indicators.push(api.to_string());
            }
        }
    }

    if service_indicators.len() >= 2 {
        mechanisms.push(PersistenceMechanism {
            mechanism_type: PersistenceType::ServiceInstallation,
            target_locations: service_indicators,
            severity: Severity::High,
            description: "Windows service installation capability".to_string(),
        });
    }

    // Scheduled task indicators
    let task_indicators = vec![
        ("schtasks", "Scheduled task command"),
        ("Task Scheduler", "Task scheduler reference"),
        ("ITaskScheduler", "Task scheduler interface"),
        ("\\Tasks\\", "Tasks folder path"),
        ("at.exe", "AT command scheduler"),
    ];

    if let Some(strings) = strings {
        let mut found_tasks = Vec::new();
        for (indicator, _) in &task_indicators {
            if strings.ascii_strings.iter().any(|s| s.contains(indicator)) {
                found_tasks.push(indicator.to_string());
            }
        }

        if !found_tasks.is_empty() {
            mechanisms.push(PersistenceMechanism {
                mechanism_type: PersistenceType::ScheduledTasks,
                target_locations: found_tasks,
                severity: Severity::Medium,
                description: "Scheduled task persistence".to_string(),
            });
        }
    }

    // DLL hijacking indicators
    let dll_hijack_indicators = vec![
        ("LoadLibrary", "Dynamic library loading"),
        ("SetDllDirectory", "DLL directory manipulation"),
        ("AddDllDirectory", "DLL directory addition"),
        (".dll", "DLL file references"),
        ("System32", "System directory access"),
        ("SysWOW64", "32-bit system directory"),
    ];

    let mut dll_indicators = Vec::new();

    if let Some(strings) = strings {
        for (indicator, _) in &dll_hijack_indicators {
            if strings.ascii_strings.iter().any(|s| s.contains(indicator)) {
                dll_indicators.push(indicator.to_string());
            }
        }
    }

    if dll_indicators.len() >= 3 {
        mechanisms.push(PersistenceMechanism {
            mechanism_type: PersistenceType::DLLHijacking,
            target_locations: dll_indicators,
            severity: Severity::High,
            description: "DLL hijacking capability".to_string(),
        });
    }

    mechanisms
}

fn detect_network_patterns(
    strings: Option<&ExtractedStrings>,
    symbols: Option<&SymbolTable>,
) -> Vec<NetworkPattern> {
    let mut patterns = Vec::new();

    // C&C indicators
    let cc_indicators = vec![
        ("http://", "HTTP communication"),
        ("https://", "HTTPS communication"),
        ("ftp://", "FTP protocol"),
        ("tcp://", "TCP protocol"),
        ("ws://", "WebSocket protocol"),
        ("wss://", "Secure WebSocket"),
        (".onion", "Tor hidden service"),
        ("tor2web", "Tor gateway"),
        ("user-agent", "HTTP user agent"),
        ("POST", "HTTP POST method"),
        ("GET", "HTTP GET method"),
        ("Content-Type", "HTTP content type"),
        ("application/json", "JSON data format"),
        ("base64", "Base64 encoding"),
    ];

    let mut found_cc = Vec::new();
    let mut protocols = HashSet::new();

    if let Some(strings) = strings {
        for (indicator, _) in &cc_indicators {
            if strings.ascii_strings.iter().any(|s| s.contains(indicator)) {
                found_cc.push(indicator.to_string());

                // Extract protocol
                if indicator.ends_with("://") {
                    protocols.insert(indicator.trim_end_matches("://").to_string());
                }
            }
        }

        // Look for IP addresses
        let ip_pattern = regex::Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap();
        for s in &strings.ascii_strings {
            if ip_pattern.is_match(s) {
                found_cc.push("IP address found".to_string());
                break;
            }
        }

        // Look for domains
        let domain_pattern = regex::Regex::new(r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b").unwrap();
        let mut domain_count = 0;
        for s in &strings.ascii_strings {
            if domain_pattern.is_match(s)
                && s.contains('.')
                && !s.ends_with(".dll")
                && !s.ends_with(".exe")
            {
                domain_count += 1;
                if domain_count >= 3 {
                    found_cc.push("Multiple domains found".to_string());
                    break;
                }
            }
        }
    }

    if !found_cc.is_empty() {
        patterns.push(NetworkPattern {
            pattern_type: NetworkPatternType::CommandAndControl,
            indicators: found_cc,
            protocols: protocols.clone().into_iter().collect(),
            ports: vec![],
            suspicious_level: if protocols.contains("https") || protocols.contains("wss") {
                SuspicionLevel::High
            } else {
                SuspicionLevel::Medium
            },
        });
    }

    // Network APIs
    let network_apis = vec![
        ("socket", "Socket creation"),
        ("connect", "Network connection"),
        ("send", "Data sending"),
        ("recv", "Data receiving"),
        ("WSAStartup", "Winsock initialization"),
        ("InternetOpen", "WinINet initialization"),
        ("InternetConnect", "Internet connection"),
        ("HttpSendRequest", "HTTP request"),
        ("URLDownloadToFile", "File download"),
        ("WinHttpOpen", "WinHTTP initialization"),
        ("getaddrinfo", "DNS resolution"),
        ("gethostbyname", "DNS lookup"),
    ];

    let mut found_apis = Vec::new();

    if let Some(symbols) = symbols {
        for (api, _) in &network_apis {
            if symbols.functions.iter().any(|f| f.name.contains(api)) {
                found_apis.push(api.to_string());
            }
        }
    }

    // Common ports
    let port_indicators = vec![
        (":80", 80, "HTTP"),
        (":443", 443, "HTTPS"),
        (":8080", 8080, "HTTP alternate"),
        (":8443", 8443, "HTTPS alternate"),
        (":21", 21, "FTP"),
        (":22", 22, "SSH"),
        (":23", 23, "Telnet"),
        (":25", 25, "SMTP"),
        (":3389", 3389, "RDP"),
        (":445", 445, "SMB"),
        (":1433", 1433, "MSSQL"),
        (":3306", 3306, "MySQL"),
        (":6667", 6667, "IRC"),
        (":9001", 9001, "Tor"),
    ];

    let mut found_ports = Vec::new();
    let mut port_numbers = Vec::new();

    if let Some(strings) = strings {
        for (indicator, port, desc) in &port_indicators {
            if strings.ascii_strings.iter().any(|s| s.contains(indicator)) {
                found_ports.push(format!("{} ({})", port, desc));
                port_numbers.push(*port);
            }
        }
    }

    if !found_apis.is_empty() {
        let suspicious_level = if found_apis.len() >= 4 {
            SuspicionLevel::High
        } else {
            SuspicionLevel::Medium
        };

        patterns.push(NetworkPattern {
            pattern_type: NetworkPatternType::DataExfiltration,
            indicators: found_apis,
            protocols: vec!["TCP".to_string()],
            ports: port_numbers,
            suspicious_level,
        });
    }

    // Tor indicators
    let tor_indicators = vec![
        (".onion", "Tor hidden service"),
        ("tor.exe", "Tor executable"),
        ("Tor Browser", "Tor browser"),
        ("9050", "Tor SOCKS port"),
        ("9051", "Tor control port"),
        ("torrc", "Tor configuration"),
    ];

    let mut tor_found = Vec::new();

    if let Some(strings) = strings {
        for (indicator, _) in &tor_indicators {
            if strings.ascii_strings.iter().any(|s| s.contains(indicator)) {
                tor_found.push(indicator.to_string());
            }
        }
    }

    if !tor_found.is_empty() {
        patterns.push(NetworkPattern {
            pattern_type: NetworkPatternType::TorUsage,
            indicators: tor_found,
            protocols: vec!["Tor".to_string()],
            ports: vec![9050, 9051],
            suspicious_level: SuspicionLevel::High,
        });
    }

    patterns
}

fn detect_file_operations(
    strings: Option<&ExtractedStrings>,
    symbols: Option<&SymbolTable>,
) -> Vec<FileOperation> {
    let mut operations = Vec::new();

    // File manipulation APIs
    let file_apis = vec![
        ("CreateFile", FileOpType::FileCreation),
        ("DeleteFile", FileOpType::FileDeletion),
        ("MoveFile", FileOpType::FileModification),
        ("CopyFile", FileOpType::FileCopying),
        ("WriteFile", FileOpType::FileModification),
        ("SetFileAttributes", FileOpType::FileHiding),
        ("FindFirstFile", FileOpType::FileModification),
        ("GetTempPath", FileOpType::FileCreation),
    ];

    let mut found_ops = HashMap::new();

    if let Some(symbols) = symbols {
        for (api, op_type) in &file_apis {
            if symbols.functions.iter().any(|f| f.name.contains(api)) {
                found_ops
                    .entry(op_type.clone())
                    .or_insert_with(Vec::new)
                    .push(api.to_string());
            }
        }
    }

    // File extensions of interest
    let suspicious_extensions = vec![
        (".exe", "Executable files"),
        (".dll", "Library files"),
        (".sys", "System drivers"),
        (".bat", "Batch scripts"),
        (".cmd", "Command scripts"),
        (".ps1", "PowerShell scripts"),
        (".vbs", "VBScript files"),
        (".js", "JavaScript files"),
        (".tmp", "Temporary files"),
        (".log", "Log files"),
        (".dat", "Data files"),
        (".ini", "Configuration files"),
        (".cfg", "Configuration files"),
        (".encrypted", "Encrypted files"),
        (".locked", "Locked files"),
    ];

    let mut target_extensions = Vec::new();

    if let Some(strings) = strings {
        for (ext, _) in &suspicious_extensions {
            if strings.ascii_strings.iter().any(|s| s.ends_with(ext)) {
                target_extensions.push(ext.to_string());
            }
        }
    }

    // Convert found operations to FileOperation structs
    for (op_type, apis) in found_ops {
        let suspicious = matches!(
            op_type,
            FileOpType::FileDeletion | FileOpType::FileEncryption | FileOpType::FileHiding
        );

        operations.push(FileOperation {
            operation_type: op_type,
            targets: apis,
            suspicious,
        });
    }

    // Check for encryption patterns
    let crypto_file_patterns = vec![
        "CryptEncrypt",
        "CryptDecrypt",
        "AES",
        "RSA",
        ".encrypted",
        ".locked",
        "ransom",
    ];

    let mut crypto_indicators = Vec::new();

    if let Some(strings) = strings {
        for pattern in &crypto_file_patterns {
            if strings.ascii_strings.iter().any(|s| s.contains(pattern)) {
                crypto_indicators.push(pattern.to_string());
            }
        }
    }

    if crypto_indicators.len() >= 2 {
        operations.push(FileOperation {
            operation_type: FileOpType::FileEncryption,
            targets: crypto_indicators,
            suspicious: true,
        });
    }

    operations
}

fn detect_registry_operations(strings: Option<&ExtractedStrings>) -> Vec<RegistryOperation> {
    let mut operations = Vec::new();

    if let Some(strings) = strings {
        // Registry APIs
        let registry_apis = vec![
            (
                "RegCreateKey",
                RegistryOpType::KeyCreation,
                "Registry key creation",
            ),
            (
                "RegOpenKey",
                RegistryOpType::ValueModification,
                "Registry key access",
            ),
            (
                "RegSetValue",
                RegistryOpType::ValueModification,
                "Registry value setting",
            ),
            (
                "RegDeleteKey",
                RegistryOpType::KeyDeletion,
                "Registry key deletion",
            ),
            (
                "RegDeleteValue",
                RegistryOpType::KeyDeletion,
                "Registry value deletion",
            ),
            (
                "RegQueryValue",
                RegistryOpType::ValueModification,
                "Registry value query",
            ),
        ];

        for (api, op_type, purpose) in registry_apis {
            if strings.ascii_strings.iter().any(|s| s.contains(api)) {
                operations.push(RegistryOperation {
                    operation_type: op_type,
                    keys: vec![api.to_string()],
                    purpose: purpose.to_string(),
                });
            }
        }

        // Common registry paths
        let registry_paths = vec![
            ("HKEY_LOCAL_MACHINE", "System-wide settings"),
            ("HKEY_CURRENT_USER", "User-specific settings"),
            ("SOFTWARE\\Microsoft", "Microsoft software settings"),
            ("SYSTEM\\CurrentControlSet", "System configuration"),
            ("SOFTWARE\\Classes", "File associations"),
        ];

        for (path, purpose) in registry_paths {
            if strings.ascii_strings.iter().any(|s| s.contains(path))
                || strings.unicode_strings.iter().any(|s| s.contains(path))
            {
                operations.push(RegistryOperation {
                    operation_type: RegistryOpType::ValueModification,
                    keys: vec![path.to_string()],
                    purpose: purpose.to_string(),
                });
            }
        }
    }

    operations
}

fn detect_process_operations(
    strings: Option<&ExtractedStrings>,
    symbols: Option<&SymbolTable>,
) -> Vec<ProcessOperation> {
    let mut operations = Vec::new();

    // Process manipulation APIs
    let process_apis = vec![
        (
            "CreateProcess",
            ProcessOpType::ProcessCreation,
            vec!["Process creation"],
        ),
        (
            "CreateThread",
            ProcessOpType::ThreadCreation,
            vec!["Thread creation"],
        ),
        (
            "CreateRemoteThread",
            ProcessOpType::ProcessInjection,
            vec!["Remote thread injection"],
        ),
        (
            "OpenProcess",
            ProcessOpType::ProcessInjection,
            vec!["Process handle acquisition"],
        ),
        (
            "TerminateProcess",
            ProcessOpType::ProcessTermination,
            vec!["Process termination"],
        ),
        (
            "WriteProcessMemory",
            ProcessOpType::ProcessInjection,
            vec!["Memory writing"],
        ),
        (
            "ReadProcessMemory",
            ProcessOpType::ProcessInjection,
            vec!["Memory reading"],
        ),
        (
            "VirtualAllocEx",
            ProcessOpType::ProcessInjection,
            vec!["Remote memory allocation"],
        ),
        (
            "SetThreadContext",
            ProcessOpType::ProcessInjection,
            vec!["Thread context manipulation"],
        ),
        (
            "QueueUserAPC",
            ProcessOpType::ProcessInjection,
            vec!["APC injection"],
        ),
        (
            "NtCreateThreadEx",
            ProcessOpType::ProcessInjection,
            vec!["Native thread creation"],
        ),
        (
            "RtlCreateUserThread",
            ProcessOpType::ProcessInjection,
            vec!["User thread creation"],
        ),
    ];

    let mut found_by_type: HashMap<ProcessOpType, Vec<String>> = HashMap::new();

    if let Some(symbols) = symbols {
        for (api, op_type, techniques) in &process_apis {
            if symbols.functions.iter().any(|f| f.name.contains(api)) {
                found_by_type
                    .entry(op_type.clone())
                    .or_insert_with(Vec::new)
                    .extend(techniques.iter().map(|s| s.to_string()));
            }
        }
    }

    // Process hollowing indicators
    let hollowing_apis = vec![
        "NtUnmapViewOfSection",
        "ZwUnmapViewOfSection",
        "CreateProcess",
        "WriteProcessMemory",
        "SetThreadContext",
        "ResumeThread",
    ];

    let mut hollowing_found = 0;

    if let Some(symbols) = symbols {
        for api in &hollowing_apis {
            if symbols.functions.iter().any(|f| f.name.contains(api)) {
                hollowing_found += 1;
            }
        }
    }

    if hollowing_found >= 4 {
        operations.push(ProcessOperation {
            operation_type: ProcessOpType::ProcessHollowing,
            targets: vec!["Process hollowing capability detected".to_string()],
            techniques: hollowing_apis.iter().map(|s| s.to_string()).collect(),
        });
    }

    // Privilege escalation indicators
    let privilege_apis = vec![
        "AdjustTokenPrivileges",
        "OpenProcessToken",
        "LookupPrivilegeValue",
        "ImpersonateLoggedOnUser",
        "DuplicateTokenEx",
        "SetTokenInformation",
    ];

    let mut priv_indicators = Vec::new();

    if let Some(symbols) = symbols {
        for api in &privilege_apis {
            if symbols.functions.iter().any(|f| f.name.contains(api)) {
                priv_indicators.push(api.to_string());
            }
        }
    }

    if priv_indicators.len() >= 2 {
        operations.push(ProcessOperation {
            operation_type: ProcessOpType::PrivilegeEscalation,
            targets: vec!["Token manipulation detected".to_string()],
            techniques: priv_indicators,
        });
    }

    // Convert found operations
    for (op_type, techniques) in found_by_type {
        operations.push(ProcessOperation {
            operation_type: op_type,
            targets: vec![],
            techniques,
        });
    }

    operations
}

fn identify_suspicious_behaviors(
    anti_analysis: &[AntiAnalysisTechnique],
    persistence: &[PersistenceMechanism],
    network: &[NetworkPattern],
    file_ops: &[FileOperation],
    process_ops: &[ProcessOperation],
) -> Vec<SuspiciousBehavior> {
    let mut behaviors = Vec::new();

    // Check for ransomware behavior
    let has_encryption = file_ops
        .iter()
        .any(|op| matches!(op.operation_type, FileOpType::FileEncryption));
    let has_file_enum = file_ops
        .iter()
        .any(|op| op.targets.iter().any(|t| t.contains("FindFirstFile")));
    let has_deletion = file_ops
        .iter()
        .any(|op| matches!(op.operation_type, FileOpType::FileDeletion));

    if has_encryption && (has_file_enum || has_deletion) {
        behaviors.push(SuspiciousBehavior {
            behavior_type: "Ransomware".to_string(),
            description: "File encryption with enumeration/deletion patterns".to_string(),
            severity: Severity::Critical,
            evidence: vec![
                "File encryption capability".to_string(),
                "File enumeration/deletion".to_string(),
            ],
        });
    }

    // Check for rootkit behavior
    let has_kernel_apis = process_ops.iter().any(|op| {
        op.techniques
            .iter()
            .any(|t| t.contains("Nt") || t.contains("Zw"))
    });
    let has_process_hiding = process_ops
        .iter()
        .any(|op| matches!(op.operation_type, ProcessOpType::ProcessInjection));
    let has_service_install = persistence
        .iter()
        .any(|p| matches!(p.mechanism_type, PersistenceType::ServiceInstallation));

    if has_kernel_apis && (has_process_hiding || has_service_install) {
        behaviors.push(SuspiciousBehavior {
            behavior_type: "Rootkit".to_string(),
            description: "Kernel API usage with hiding/persistence".to_string(),
            severity: Severity::Critical,
            evidence: vec![
                "Native API usage".to_string(),
                "Process manipulation".to_string(),
            ],
        });
    }

    // Check for data theft
    let has_network = !network.is_empty();
    let has_file_access = file_ops
        .iter()
        .any(|op| matches!(op.operation_type, FileOpType::FileCopying));
    let has_credential_apis = process_ops.iter().any(|op| {
        op.techniques
            .iter()
            .any(|t| t.contains("Cred") || t.contains("Token") || t.contains("Password"))
    });

    if has_network && (has_file_access || has_credential_apis) {
        behaviors.push(SuspiciousBehavior {
            behavior_type: "DataTheft".to_string(),
            description: "Network capability with file/credential access".to_string(),
            severity: Severity::High,
            evidence: vec![
                "Network communication".to_string(),
                "File/credential access".to_string(),
            ],
        });
    }

    // Check for backdoor
    let has_cc = network
        .iter()
        .any(|n| matches!(n.pattern_type, NetworkPatternType::CommandAndControl));
    let has_persistence_mech = !persistence.is_empty();
    let has_remote_exec = process_ops
        .iter()
        .any(|op| matches!(op.operation_type, ProcessOpType::ProcessCreation));

    if has_cc && has_persistence_mech && has_remote_exec {
        behaviors.push(SuspiciousBehavior {
            behavior_type: "Backdoor".to_string(),
            description: "C&C communication with persistence and execution".to_string(),
            severity: Severity::Critical,
            evidence: vec![
                "Command and control".to_string(),
                "Persistence mechanism".to_string(),
                "Remote execution".to_string(),
            ],
        });
    }

    // Check for dropper/downloader
    let has_download = network.iter().any(|n| {
        n.indicators
            .iter()
            .any(|i| i.contains("URLDownloadToFile") || i.contains("InternetReadFile"))
    });
    let has_file_write = file_ops
        .iter()
        .any(|op| matches!(op.operation_type, FileOpType::FileCreation));
    let has_exec = process_ops
        .iter()
        .any(|op| matches!(op.operation_type, ProcessOpType::ProcessCreation));

    if has_download && has_file_write && has_exec {
        behaviors.push(SuspiciousBehavior {
            behavior_type: "Dropper".to_string(),
            description: "Downloads and executes additional payloads".to_string(),
            severity: Severity::High,
            evidence: vec![
                "Download capability".to_string(),
                "File writing".to_string(),
                "Process execution".to_string(),
            ],
        });
    }

    behaviors
}

fn calculate_evasion_score(
    anti_analysis: &[AntiAnalysisTechnique],
    suspicious_behaviors: &[SuspiciousBehavior],
) -> f32 {
    let mut score = 0.0;

    // Anti-analysis techniques contribute to evasion score
    for technique in anti_analysis {
        score += match technique.technique_type {
            AntiAnalysisType::AntiDebug => 15.0,
            AntiAnalysisType::AntiVM => 15.0,
            AntiAnalysisType::AntiSandbox => 20.0,
            AntiAnalysisType::AntiDisassembly => 10.0,
            AntiAnalysisType::Obfuscation => 20.0,
            AntiAnalysisType::ProcessHollowing => 25.0,
            AntiAnalysisType::CodeInjection => 20.0,
            _ => 10.0,
        };

        // Adjust by confidence
        score *= technique.confidence;
    }

    // Critical behaviors increase evasion score
    for behavior in suspicious_behaviors {
        if matches!(behavior.severity, Severity::Critical) {
            score += 10.0;
        }
    }

    // Cap at 100
    score.min(100.0)
}

fn generate_behavioral_recommendations(
    anti_analysis: &[AntiAnalysisTechnique],
    persistence: &[PersistenceMechanism],
    network: &[NetworkPattern],
    suspicious_behaviors: &[SuspiciousBehavior],
    evasion_score: f32,
) -> Vec<String> {
    let mut recommendations = Vec::new();

    // Evasion score recommendations
    if evasion_score > 70.0 {
        recommendations.push(
            "CRITICAL: Very high evasion score. Use advanced sandbox with anti-evasion bypasses."
                .to_string(),
        );
        recommendations
            .push("Consider manual reverse engineering in isolated environment.".to_string());
    } else if evasion_score > 40.0 {
        recommendations.push(
            "High evasion techniques detected. Extended sandbox analysis recommended.".to_string(),
        );
        recommendations.push("Monitor for delayed execution and environment checks.".to_string());
    }

    // Anti-analysis recommendations
    for technique in anti_analysis {
        match technique.technique_type {
            AntiAnalysisType::AntiDebug => {
                recommendations.push(
                    "Anti-debugging detected. Use kernel-mode debugger or bypass techniques."
                        .to_string(),
                );
            }
            AntiAnalysisType::AntiVM => {
                recommendations.push(
                    "VM detection present. Use bare-metal analysis or VM hiding techniques."
                        .to_string(),
                );
            }
            AntiAnalysisType::AntiSandbox => {
                recommendations.push(
                    "Sandbox evasion detected. Extend analysis time and simulate user activity."
                        .to_string(),
                );
            }
            AntiAnalysisType::ProcessHollowing => {
                recommendations.push(
                    "Process hollowing capability. Monitor child process creation closely."
                        .to_string(),
                );
            }
            _ => {}
        }
    }

    // Persistence recommendations
    if !persistence.is_empty() {
        recommendations
            .push("Persistence mechanisms detected. Check system after reboot.".to_string());

        for mechanism in persistence {
            match mechanism.mechanism_type {
                PersistenceType::RegistryKeys => {
                    recommendations
                        .push("Registry persistence found. Monitor registry changes.".to_string());
                }
                PersistenceType::ServiceInstallation => {
                    recommendations.push(
                        "Service installation capability. Check installed services.".to_string(),
                    );
                }
                PersistenceType::ScheduledTasks => {
                    recommendations
                        .push("Scheduled task persistence. Review task scheduler.".to_string());
                }
                _ => {}
            }
        }
    }

    // Network recommendations
    for pattern in network {
        match pattern.pattern_type {
            NetworkPatternType::CommandAndControl => {
                recommendations.push(
                    "C&C communication detected. Monitor network traffic closely.".to_string(),
                );
                recommendations.push("Block identified C&C servers at firewall.".to_string());
            }
            NetworkPatternType::TorUsage => {
                recommendations
                    .push("Tor usage detected. Sample may use hidden services.".to_string());
            }
            NetworkPatternType::DataExfiltration => {
                recommendations.push(
                    "Data exfiltration capability. Monitor outbound connections.".to_string(),
                );
            }
            _ => {}
        }
    }

    // Behavior-specific recommendations
    for behavior in suspicious_behaviors {
        match behavior.behavior_type.as_str() {
            "Ransomware" => {
                recommendations
                    .push("RANSOMWARE BEHAVIOR DETECTED! Isolate immediately.".to_string());
                recommendations.push("Backup critical files before any execution.".to_string());
                recommendations.push("Monitor file system for encryption activity.".to_string());
            }
            "Rootkit" => {
                recommendations
                    .push("Rootkit behavior detected. Use rootkit detection tools.".to_string());
                recommendations.push("Check for hidden processes and files.".to_string());
            }
            "Backdoor" => {
                recommendations.push(
                    "Backdoor functionality detected. Scan for network listeners.".to_string(),
                );
                recommendations.push("Check all persistence locations.".to_string());
            }
            "DataTheft" => {
                recommendations
                    .push("Data theft capability. Monitor sensitive file access.".to_string());
                recommendations.push("Check for credential dumping attempts.".to_string());
            }
            _ => {}
        }
    }

    if recommendations.is_empty() {
        recommendations.push("No significant behavioral anomalies detected.".to_string());
        recommendations.push("Standard security monitoring recommended.".to_string());
    }

    recommendations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evasion_score_calculation() {
        let anti_analysis = vec![AntiAnalysisTechnique {
            technique_type: AntiAnalysisType::AntiDebug,
            indicators: vec!["IsDebuggerPresent".to_string()],
            confidence: 0.9,
            description: "Test".to_string(),
        }];

        let behaviors = vec![];

        let score = calculate_evasion_score(&anti_analysis, &behaviors);
        assert!(score > 0.0 && score <= 100.0);
    }
}
