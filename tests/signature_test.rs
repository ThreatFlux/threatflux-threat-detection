use file_scanner::signature::verify_signature;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_signature_verification_on_non_macho_files() {
    // This test ensures that signature verification doesn't fail on non-Mach-O files
    // even on macOS, which was causing the CI failures

    let temp_dir = TempDir::new().unwrap();

    // Create a minimal ELF file
    let elf_path = temp_dir.path().join("test.elf");
    let elf_header = vec![
        0x7f, 0x45, 0x4c, 0x46, // Magic number
        0x02, // 64-bit
        0x01, // Little endian
        0x01, // ELF version
        0x00, // System V ABI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
        0x02, 0x00, // Executable file
        0x3e, 0x00, // x86-64
        0x01, 0x00, 0x00, 0x00, // Version 1
    ];
    fs::write(&elf_path, &elf_header).unwrap();

    // Verify signature should not panic or fail catastrophically
    let result = verify_signature(&elf_path);
    assert!(result.is_ok());

    let sig_info = result.unwrap();
    assert!(!sig_info.is_signed);

    // Create a minimal PE file
    let pe_path = temp_dir.path().join("test.exe");
    let mut pe_data = vec![
        0x4d, 0x5a, // MZ signature
    ];
    pe_data.extend_from_slice(&[0x90; 58]); // Padding
    pe_data.extend_from_slice(&[0x3c, 0x00, 0x00, 0x00]); // PE header offset
    fs::write(&pe_path, &pe_data).unwrap();

    // Verify signature should not panic or fail catastrophically
    let result = verify_signature(&pe_path);
    assert!(result.is_ok());

    let sig_info = result.unwrap();
    assert!(!sig_info.is_signed);

    // Test with a regular text file
    let text_path = temp_dir.path().join("test.txt");
    fs::write(&text_path, b"Hello, World!").unwrap();

    let result = verify_signature(&text_path);
    assert!(result.is_ok());

    let sig_info = result.unwrap();
    assert!(!sig_info.is_signed);
}

#[test]
fn test_signature_verification_empty_file() {
    let temp_dir = TempDir::new().unwrap();
    let empty_path = temp_dir.path().join("empty.bin");
    fs::write(&empty_path, b"").unwrap();

    let result = verify_signature(&empty_path);
    assert!(result.is_ok());

    let sig_info = result.unwrap();
    assert!(!sig_info.is_signed);
}
