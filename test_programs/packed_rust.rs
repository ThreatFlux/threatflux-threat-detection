// Rust program that will be packed with UPX
use std::ptr;
use std::mem;

// XOR encryption key
const XOR_KEY: &[u8] = b"ThisIsASecretXORKey123456789012";

// Anti-debugging using inline assembly (x86_64 only)
#[cfg(target_arch = "x86_64")]
fn anti_debug_asm() -> bool {
    unsafe {
        let mut rax: u64;
        std::arch::asm!(
            "mov rax, 0",
            "int 3",  // Breakpoint interrupt
            out("rax") rax,
        );
        false
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn anti_debug_asm() -> bool {
    false
}

// Self-modifying code simulation
fn self_modify() {
    let code = vec![0x90; 100]; // NOP sled
    let code_ptr = code.as_ptr() as *mut u8;

    unsafe {
        // Would normally modify code here
        ptr::write_volatile(code_ptr, 0xC3); // RET instruction
    }
}

// Obfuscated string decryption
fn decrypt_string(encrypted: &[u8]) -> String {
    encrypted.iter()
        .zip(XOR_KEY.iter().cycle())
        .map(|(a, b)| a ^ b)
        .map(|c| c as char)
        .collect()
}

// Memory manipulation
fn memory_tricks() {
    // Allocate and immediately deallocate
    let mut data = vec![0u8; 1024 * 1024]; // 1MB
    data[0] = 0xFF;
    mem::forget(data); // Leak memory intentionally

    // Stack manipulation
    let mut stack_data = [0x41u8; 8192]; // Large stack allocation
    unsafe {
        ptr::write_volatile(&mut stack_data[0] as *mut u8, 0x42);
    }
}

// Hidden functionality
fn hidden_payload() {
    let encrypted_cmd = [0x7b, 0x36, 0x3d, 0x24, 0x36, 0x78, 0x54, 0x4b, 0x5e];
    let cmd = decrypt_string(&encrypted_cmd);
    println!("Hidden: {}", cmd);
}

fn main() {
    println!("Packed Rust Binary Test");

    // Anti-debugging check
    #[cfg(target_arch = "x86_64")]
    {
        if anti_debug_asm() {
            std::process::exit(1);
        }
    }

    // Self-modification attempt
    self_modify();

    // Memory manipulation
    memory_tricks();

    // Obfuscated operations
    let encrypted_msg = [0x52, 0x3c, 0x3e, 0x38, 0x25, 0x61, 0x55, 0x5e, 0x4f, 0x49, 0x4b, 0x43];
    let msg = decrypt_string(&encrypted_msg);
    println!("Decrypted: {}", msg);

    // Hidden functionality
    hidden_payload();

    println!("Execution complete");
}
