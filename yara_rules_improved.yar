// Improved YARA rules without hash dependencies
// Focus on behavioral patterns and structural analysis
// Generated on 2025-06-02

rule AMD_PPM_Service_Behavioral {
    meta:
        description = "AMD PPM Provisioning File Service - Behavioral Detection"
        author = "file-scanner LLM API"
        date = "2025-06-02"
        
    strings:
        // AMD-specific debug paths
        $debug_path = /E:\\Drivers.{1,100}AMD.{1,50}PPM.{1,50}Release.{1,50}\.pdb/
        
        // PPM service specific strings
        $ppm1 = "PPM Provisioning"
        $ppm2 = "AmdPpkgSvc"
        
        // Windows service patterns
        $service1 = "InitializeCriticalSectionEx"
        $service2 = "GetLogicalProcessorInformationEx"
        
        // Error handling patterns common in AMD drivers
        $error1 = "executable format error"
        $error2 = "iostream stream error"
        
    condition:
        uint16(0) == 0x5A4D and  // PE header
        filesize > 100KB and filesize < 2MB and
        (
            ($debug_path and 1 of ($ppm*)) or
            (2 of ($ppm*) and 1 of ($service*))
        ) and
        1 of ($error*)
}

rule AMD_TEE_API_Behavioral {
    meta:
        description = "AMD Trusted Execution Environment API - Behavioral Detection"
        author = "file-scanner LLM API"
        date = "2025-06-02"
        
    strings:
        // TEE-specific function exports
        $tee_func1 = "AMDTEE_FetchDebugStrings"
        $tee_func2 = "AMDTEE_GetDebugToken"
        $tee_func3 = "AMDTEE_StartTADebug"
        $tee_func4 = "AMDTEE_StopTADebug"
        $tee_func5 = "AMDTEE_VersionInfo"
        
        // TEE API identifier
        $tee_api = "amdtee_api"
        
        // Certificate authority patterns in AMD signed drivers
        $cert1 = "http://crl.sectigo.com/"
        $cert2 = "http://ocsp.sectigo.com"
        $cert3 = "DigiCert"
        
        // Debug capabilities
        $debug1 = "IsDebuggerPresent"
        $debug2 = "OutputDebugStringW"
        
    condition:
        uint16(0) == 0x5A4D and  // PE header
        filesize > 100KB and filesize < 2MB and
        (
            (3 of ($tee_func*)) or
            ($tee_api and 2 of ($tee_func*))
        ) and
        1 of ($cert*) and
        1 of ($debug*)
}

rule AMD_Installer_Qt_Behavioral {
    meta:
        description = "AMD Qt-based Installer - Behavioral Detection"
        author = "file-scanner LLM API"
        date = "2025-06-02"
        
    strings:
        // AMD installation paths
        $install_path1 = "/AMD/RyzenMasterExtract/"
        $install_path2 = "/AMD/RyzenMasterMonitorSDKExtract/"
        $install_path3 = "AMD Ryzen Master"
        
        // Installation parameters
        $install_param1 = "DESKTOP_SHORTCUT="
        $install_param2 = "INSTALL_ATHENA="
        $install_param3 = "LAUNCHED_FROM_CLIENT=RM"
        
        // Registry modification patterns
        $registry1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\ATI Technologies"
        
        // Qt framework indicators
        $qt1 = "QApplication"
        $qt2 = "QMessageBox"
        $qt3 = "QQmlApplicationEngine"
        
        // AMD copyright
        $copyright = "Advanced Micro Devices, Inc.  All rights reserved."
        
    condition:
        uint16(0) == 0x5A4D and  // PE header
        filesize > 200KB and filesize < 5MB and
        (
            (2 of ($install_path*) and 1 of ($install_param*)) or
            (1 of ($install_path*) and $registry1 and $copyright)
        ) and
        2 of ($qt*)
}

rule AMD_Driver_Family_Generic {
    meta:
        description = "Generic AMD Driver/Software Family Detection"
        author = "file-scanner LLM API"
        date = "2025-06-02"
        
    strings:
        // Company identifiers
        $company1 = "Advanced Micro Devices"
        $company2 = "ATI Technologies"
        $company3 = "AMD" nocase
        
        // Driver patterns
        $driver1 = "InitializeCriticalSectionEx"
        $driver2 = "IsDebuggerPresent"
        $driver3 = "GetLastError"
        
        // Certificate patterns in signed AMD software
        $cert_sectigo = /http:\/\/[a-z.]{1,50}sectigo\.com/
        $cert_digicert = "DigiCert"
        
        // AMD-specific strings
        $amd_specific1 = "Ryzen"
        $amd_specific2 = "Radeon"
        $amd_specific3 = "AMDTEE"
        $amd_specific4 = "AmdPpm"
        
    condition:
        uint16(0) == 0x5A4D and  // PE header
        filesize > 50KB and filesize < 20MB and
        (
            (1 of ($company*) and 2 of ($driver*) and 1 of ($cert*)) or
            (1 of ($company*) and 1 of ($amd_specific*) and 1 of ($driver*))
        )
}

rule AMD_Suspicious_Debug_Capabilities {
    meta:
        description = "AMD Software with Extensive Debug Capabilities"
        author = "file-scanner LLM API"
        date = "2025-06-02"
        threat_level = "medium"
        
    strings:
        // AMD identifier
        $amd = "AMD" nocase
        
        // Debug functions that could be abused
        $debug1 = "AMDTEE_StartTADebug"
        $debug2 = "AMDTEE_FetchDebugStrings"
        $debug3 = "IsDebuggerPresent"
        $debug4 = "OutputDebugStringW"
        
        // Process/system interaction
        $system1 = "GetLogicalProcessorInformationEx"
        $system2 = "CreateFileW"
        $system3 = "DeviceIoControl"
        
        // Potential persistence indicators
        $persist1 = "HKEY_LOCAL_MACHINE\\SOFTWARE"
        $persist2 = "\\CurrentVersion\\Run"
        
    condition:
        uint16(0) == 0x5A4D and  // PE header
        $amd and
        3 of ($debug*) and
        2 of ($system*) and
        any of ($persist*) and
        filesize > 100KB
}

rule Suspicious_AMD_Like_Impersonation {
    meta:
        description = "Potential AMD Software Impersonation"
        author = "file-scanner LLM API"
        date = "2025-06-02"
        threat_level = "high"
        
    strings:
        // AMD-like names but suspicious characteristics
        $fake_amd1 = "AMD" nocase
        $fake_amd2 = "Ryzen" nocase
        $fake_amd3 = "Radeon" nocase
        
        // Suspicious API combinations
        $susp1 = "VirtualAlloc"
        $susp2 = "WriteProcessMemory"
        $susp3 = "CreateRemoteThread"
        $susp4 = "NtWriteVirtualMemory"
        
        // Network capabilities (unusual for drivers)
        $net1 = "InternetOpenA"
        $net2 = "HttpOpenRequestA"
        $net3 = "WinHttpConnect"
        
        // Anti-analysis
        $anti1 = "IsDebuggerPresent"
        $anti2 = "CheckRemoteDebuggerPresent"
        $anti3 = "GetTickCount"
        
    condition:
        uint16(0) == 0x5A4D and  // PE header
        1 of ($fake_amd*) and
        (
            (2 of ($susp*)) or
            (1 of ($net*) and 1 of ($susp*)) or
            (2 of ($anti*) and 1 of ($susp*))
        ) and
        filesize > 50KB
}