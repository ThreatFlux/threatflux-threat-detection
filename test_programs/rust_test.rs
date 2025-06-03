// Rust test program with various features for static analysis
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::thread;
use std::time::Duration;

// Suspicious string that might trigger detection
const SUSPICIOUS_URL: &str = "http://msftupdater.com/payload";
const CRYPTO_KEY: &[u8] = b"AES256SecretKey!";

// Function with potential security issues
fn unsafe_file_operation(filename: &str) -> std::io::Result<String> {
    let mut file = File::open(filename)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

// Network communication function
fn phone_home() -> std::io::Result<()> {
    let mut stream = TcpStream::connect("msftupdater.com:443")?;
    stream.write_all(b"GET /beacon HTTP/1.1\r\nHost: msftupdater.com\r\n\r\n")?;
    Ok(())
}

// Function with anti-analysis techniques
fn anti_debug_check() -> bool {
    // Check for debugger (simplified)
    let start = std::time::Instant::now();
    thread::sleep(Duration::from_millis(100));
    let elapsed = start.elapsed();

    // If execution took too long, might be debugging
    elapsed.as_millis() > 500
}

// Recursive function for complexity
fn fibonacci(n: u32) -> u32 {
    match n {
        0 => 0,
        1 => 1,
        _ => fibonacci(n - 1) + fibonacci(n - 2),
    }
}

// Function with high cyclomatic complexity
fn complex_logic(x: i32, y: i32, z: i32) -> i32 {
    let mut result = 0;

    if x > 0 {
        if y > 0 {
            if z > 0 {
                result = x + y + z;
            } else {
                result = x + y - z;
            }
        } else {
            if z > 0 {
                result = x - y + z;
            } else {
                result = x - y - z;
            }
        }
    } else {
        if y > 0 {
            if z > 0 {
                result = -x + y + z;
            } else {
                result = -x + y - z;
            }
        } else {
            if z > 0 {
                result = -x - y + z;
            } else {
                result = -x - y - z;
            }
        }
    }

    result
}

// Crypto-like operation
fn pseudo_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .zip(key.iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect()
}

// System command execution
fn execute_command(cmd: &str) -> std::io::Result<String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// Main function
fn main() {
    println!("Rust Test Binary for Analysis");

    // Anti-debugging check
    if anti_debug_check() {
        println!("Debugger detected!");
        std::process::exit(1);
    }

    // Create some data structures
    let mut data_map: HashMap<String, Vec<u8>> = HashMap::new();
    data_map.insert("key1".to_string(), vec![1, 2, 3, 4, 5]);
    data_map.insert("key2".to_string(), CRYPTO_KEY.to_vec());

    // Complex calculation
    let result = complex_logic(10, -5, 3);
    println!("Complex logic result: {}", result);

    // Fibonacci calculation
    let fib_result = fibonacci(10);
    println!("Fibonacci(10) = {}", fib_result);

    // Crypto operation
    let encrypted = pseudo_encrypt(b"secret data", CRYPTO_KEY);
    println!("Encrypted data: {:?}", encrypted);

    // Try network operation (will likely fail)
    match phone_home() {
        Ok(_) => println!("Phone home successful"),
        Err(e) => println!("Phone home failed: {}", e),
    }

    // Environment check
    if let Ok(user) = std::env::var("USER") {
        if user == "sandbox" || user == "malware" {
            println!("Sandbox detected!");
            return;
        }
    }

    println!("Program completed successfully");
}
