package main

import (
    "fmt"
    "net/http"
    "os"
    "runtime"
)

const C2Server = "msftupdater.com"

func main() {
    fmt.Println("Simple Go Test Binary")
    fmt.Printf("OS: %s, Arch: %s\n", runtime.GOOS, runtime.GOARCH)
    
    // Check environment
    if hostname, err := os.Hostname(); err == nil {
        fmt.Printf("Hostname: %s\n", hostname)
    }
    
    // Try network connection
    resp, err := http.Get("http://" + C2Server)
    if err != nil {
        fmt.Printf("Network error: %v\n", err)
    } else {
        resp.Body.Close()
        fmt.Println("Network connection successful")
    }
}