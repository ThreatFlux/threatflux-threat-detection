use anyhow::Result;
use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn test_cli_help() {
    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("file-scanner"))
        .stdout(predicate::str::contains("--npm-analysis"))
        .stdout(predicate::str::contains("--python-analysis"));
}

#[test]
fn test_cli_version() {
    // The CLI doesn't have a --version flag, skip this test
    // or test with --help which shows the binary name
    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("file-scanner"));
}

#[test]
fn test_cli_basic_file_scan() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, "Hello, World!")?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(test_file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("file_name"))
        .stdout(predicate::str::contains("test.txt"))
        .stdout(predicate::str::contains("file_size"));

    Ok(())
}

#[test]
fn test_cli_json_format() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, "test content")?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(test_file.to_str().unwrap())
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("{"))
        .stdout(predicate::str::contains("\"file_name\":\"test.txt\""));

    Ok(())
}

#[test]
fn test_cli_yaml_format() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, "test content")?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(test_file.to_str().unwrap())
        .arg("--format")
        .arg("yaml")
        .assert()
        .success()
        .stdout(predicate::str::contains("file_name: test.txt"));

    Ok(())
}

#[test]
fn test_cli_with_strings() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    fs::write(
        &test_file,
        "Hello World\nThis is a test string\nAnother line here",
    )?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(test_file.to_str().unwrap())
        .arg("--strings")
        .assert()
        .success()
        .stdout(predicate::str::contains("extracted_strings"));

    Ok(())
}

#[test]
fn test_cli_with_hex_dump() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.bin");
    fs::write(&test_file, b"ABCDEFGHIJKLMNOP")?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(test_file.to_str().unwrap())
        .arg("--hex-dump")
        .assert()
        .success()
        .stdout(predicate::str::contains("hex_dump"))
        .stdout(predicate::str::contains("41 42 43 44")); // ABCD in hex

    Ok(())
}

#[test]
fn test_cli_npm_analysis_with_package_json() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let package_json = temp_dir.path().join("package.json");
    fs::write(
        &package_json,
        r#"{
        "name": "test-package",
        "version": "1.0.0",
        "description": "Test package for CLI testing",
        "dependencies": {
            "express": "^4.18.0"
        }
    }"#,
    )?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(package_json.to_str().unwrap())
        .arg("--npm-analysis")
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .stdout(predicate::str::contains("npm_analysis"))
        .stdout(predicate::str::contains("test-package"));

    Ok(())
}

#[test]
fn test_cli_npm_analysis_with_directory() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let package_json = temp_dir.path().join("package.json");
    fs::write(
        &package_json,
        r#"{
        "name": "dir-package",
        "version": "2.0.0",
        "license": "MIT"
    }"#,
    )?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(temp_dir.path().to_str().unwrap())
        .arg("--npm-analysis")
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .stdout(predicate::str::contains("npm_analysis"))
        .stdout(predicate::str::contains("dir-package"));

    Ok(())
}

#[test]
fn test_cli_python_analysis_with_setup_py() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let setup_py = temp_dir.path().join("setup.py");
    fs::write(
        &setup_py,
        r#"
from setuptools import setup

setup(
    name="test-python-package",
    version="1.0.0",
    author="Test Author",
    install_requires=["requests>=2.25.0"],
)
"#,
    )?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(temp_dir.path().to_str().unwrap())
        .arg("--python-analysis")
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .stdout(predicate::str::contains("python_analysis"))
        .stdout(predicate::str::contains("test-python-package"));

    Ok(())
}

#[test]
fn test_cli_combined_options() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, "Test content with strings")?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(test_file.to_str().unwrap())
        .arg("--strings")
        .arg("--hex-dump")
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .stdout(predicate::str::contains("extracted_strings"))
        .stdout(predicate::str::contains("hex_dump"));

    Ok(())
}

#[test]
fn test_cli_nonexistent_file() {
    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg("/nonexistent/file.txt")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_cli_no_arguments() {
    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
#[ignore = "MCP server runs indefinitely, manual testing required"]
fn test_cli_mcp_stdio_command() {
    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg("mcp-stdio")
        .timeout(std::time::Duration::from_secs(1))
        .assert()
        .interrupted(); // MCP server runs indefinitely, so we interrupt it
}

#[test]
fn test_cli_mcp_http_command() {
    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg("mcp-http")
        .arg("--port")
        .arg("0") // Use port 0 to let OS assign
        .timeout(std::time::Duration::from_secs(1))
        .assert()
        .interrupted();
}

#[test]
fn test_cli_custom_string_length() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, "ab\nabcde\nabcdefgh\nabcdefghijk")?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(test_file.to_str().unwrap())
        .arg("--strings")
        .arg("--min-string-len")
        .arg("8")
        .arg("--format")
        .arg("json")
        .assert()
        .success();

    Ok(())
}

#[test]
fn test_cli_hex_dump_with_size() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.bin");
    fs::write(&test_file, vec![0u8; 1024])?; // 1KB of zeros

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(test_file.to_str().unwrap())
        .arg("--hex-dump")
        .arg("--hex-dump-size")
        .arg("64")
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"total_bytes\":1024"));

    Ok(())
}

#[test]
fn test_cli_hex_dump_with_offset() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.bin");
    fs::write(&test_file, b"HEADER_DATA_MIDDLE_DATA_FOOTER")?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(test_file.to_str().unwrap())
        .arg("--hex-dump")
        .arg("--hex-dump-offset")
        .arg("-6") // Last 6 bytes (FOOTER)
        .arg("--hex-dump-size")
        .arg("6")
        .arg("--format")
        .arg("json")
        .assert()
        .success();

    Ok(())
}
