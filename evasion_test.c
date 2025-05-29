#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Test file with anti-analysis and evasion techniques

int main() {
    // Anti-debugging strings
    const char* debug1 = "IsDebuggerPresent";
    const char* debug2 = "CheckRemoteDebuggerPresent";
    const char* debug3 = "OutputDebugString";
    
    // Anti-VM strings
    const char* vm1 = "VMware";
    const char* vm2 = "VirtualBox";
    const char* vm3 = "QEMU";
    const char* vm4 = "HARDWARE\\ACPI\\DSDT\\VBOX";
    
    // Sandbox detection
    const char* sandbox1 = "SbieDll.dll";
    const char* sandbox2 = "sample.exe";
    const char* sandbox3 = "GetCursorPos";
    const char* sandbox4 = "Sleep";
    const char* sandbox5 = "GetUserName";
    
    // Persistence mechanisms
    const char* reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    const char* reg2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
    const char* reg3 = "SYSTEM\\CurrentControlSet\\Services";
    const char* svc1 = "CreateService";
    const char* svc2 = "OpenSCManager";
    const char* task = "schtasks /create";
    
    // Network indicators
    const char* url1 = "http://msftupdater.com/beacon";
    const char* url2 = "https://msftupdater.com/exfil";
    const char* tor = ".onion";
    const char* api1 = "WSAStartup";
    const char* api2 = "InternetOpen";
    const char* api3 = "HttpSendRequest";
    
    // Process injection
    const char* inj1 = "CreateRemoteThread";
    const char* inj2 = "WriteProcessMemory";
    const char* inj3 = "VirtualAllocEx";
    const char* inj4 = "OpenProcess";
    const char* inj5 = "SetThreadContext";
    
    // File operations
    const char* file1 = "CreateFile";
    const char* file2 = "DeleteFile";
    const char* file3 = "SetFileAttributes";
    const char* ext1 = ".encrypted";
    const char* ext2 = ".exe";
    const char* ext3 = ".dll";
    
    printf("Evasion test program\n");
    printf("Debug: %s, %s\n", debug1, debug2);
    printf("VM: %s, %s\n", vm1, vm2);
    printf("Persistence: %s\n", reg1);
    printf("Network: %s\n", url1);
    printf("Injection: %s\n", inj1);
    
    return 0;
}