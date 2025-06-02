// Auto-generated YARA rules from file-scanner LLM API
// Generated on 2025-06-02

rule AMD_PPM_Service_AmdPpkgSvc_exe {
    meta:
        description = "AMD PPM Provisioning File Service"
        md5 = "9dac56ab6992051b823305e0ae26ce5a"
        file_size = 518944
        author = "file-scanner LLM API"
        date = "2025-06-02"
        
    strings:
        $header = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 }
        $s1 = "executable format error"
        $s2 = "io error"
        $s3 = "protocol error"
        $s4 = "unknown error"
        $s5 = "InitializeCriticalSectionEx"
        $s6 = "GetLocaleInfoEx"
        $s7 = "iostream stream error"
        $s8 = "E:\\Drivers_-_FCH_-_IO\\AMD_PPM_Provisioning_File\\Dbuild48\\CloneRepo\\Source\\x64\\Release\\AmdPpkgSvc.pdb"
        $s9 = "GetLastError"
        $s10 = "GetLogicalProcessorInformationEx"
        
    condition:
        filesize == 518944 and 3 of ($s*) and $header at 0
}

rule AMD_TEE_API_amdtee_api64_dll {
    meta:
        description = "AMD Trusted Execution Environment API"
        md5 = "8432c412ce436272db2004da696e155f"
        file_size = 526160
        author = "file-scanner LLM API"
        date = "2025-06-02"
        
    strings:
        $header = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 }
        $s1 = "InitializeCriticalSectionEx"
        $s2 = "GetLocaleInfoEx"
        $s3 = "GetUserObjectInformationW"
        $s4 = "AMDTEE_FetchDebugStrings"
        $s5 = "AMDTEE_GetDebugToken"
        $s6 = "AMDTEE_StartTADebug"
        $s7 = "AMDTEE_StopTADebug"
        $s8 = "AMDTEE_VersionInfo"
        $s9 = "GetLastError"
        $s10 = "IsDebuggerPresent"
        
    condition:
        filesize == 526160 and 3 of ($s*) and $header at 0
}

rule AMD_RyzenMaster_Qt_Setup_exe {
    meta:
        description = "AMD Ryzen Master Qt Dependencies Setup"
        md5 = "d488a9acd29af8dbb9d99c847f250352"
        file_size = 689360
        author = "file-scanner LLM API"
        date = "2025-06-02"
        
    strings:
        $header = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 }
        $s1 = "/AMD/RyzenMasterExtract/MSIFiles/Packages/AMD Ryzen Master UI.exe"
        $s2 = "\\AMD_RMMONITORSDK.log"
        $s3 = "\\AMD_RMMONITORSDK_Uninstall.log"
        $s4 = "/AMD/RyzenMasterMonitorSDKExtract/MSIFiles/Packages/AMDRyzenMasterMonitoringSDK.exe"
        $s5 = " DESKTOP_SHORTCUT="
        $s6 = " INSTALL_ATHENA="
        $s7 = "LAUNCHED_FROM_CLIENT=RM"
        $s8 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\ATI Technologies\\Install\\PPC"
        $s9 = "//=== Copyright (c) 2024 Advanced Micro Devices, Inc.  All rights reserved."
        $s10 = "        id: recForWarning"
        
    condition:
        filesize == 689360 and 3 of ($s*) and $header at 0
}

// Generic AMD Driver Detection Rule
rule AMD_Driver_Generic {
    meta:
        description = "Generic AMD driver components detection"
        author = "file-scanner LLM API"
        date = "2025-06-02"
        
    strings:
        $amd1 = "Advanced Micro Devices"
        $amd2 = "AMD"
        $amd3 = "ATI Technologies"
        $driver1 = "GetLastError"
        $driver2 = "InitializeCriticalSectionEx" 
        $driver3 = "IsDebuggerPresent"
        $cert1 = "http://crl.sectigo.com/"
        $cert2 = "http://ocsp.sectigo.com"
        $cert3 = "DigiCert"
        
    condition:
        (uint16(0) == 0x5A4D) and  // PE header
        (1 of ($amd*)) and
        (2 of ($driver*)) and
        (any of ($cert*)) and
        filesize > 100KB and filesize < 10MB
}