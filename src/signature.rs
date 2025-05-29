use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureInfo {
    pub is_signed: bool,
    pub signature_type: Option<String>,
    pub signer: Option<String>,
    pub timestamp: Option<String>,
    pub certificate_chain: Vec<CertificateInfo>,
    pub verification_status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
}

pub fn verify_signature(path: &Path) -> Result<SignatureInfo> {
    // Try different signature verification methods based on the platform and file type
    
    // First, check if it's a PE file with Authenticode signature
    if let Ok(authenticode_info) = check_authenticode_signature(path) {
        return Ok(authenticode_info);
    }
    
    // Check for GPG signatures
    if let Ok(gpg_info) = check_gpg_signature(path) {
        return Ok(gpg_info);
    }
    
    // Check for macOS code signatures
    if cfg!(target_os = "macos") {
        if let Ok(codesign_info) = check_macos_codesign(path) {
            return Ok(codesign_info);
        }
    }
    
    // No signature found
    Ok(SignatureInfo {
        is_signed: false,
        signature_type: None,
        signer: None,
        timestamp: None,
        certificate_chain: Vec::new(),
        verification_status: "No signature found".to_string(),
    })
}

fn check_authenticode_signature(path: &Path) -> Result<SignatureInfo> {
    // This is a simplified version. In production, you'd use Windows APIs
    // or a library like authenticode-parser
    
    let buffer = std::fs::read(path)?;
    
    // Check for PE signature
    if buffer.len() < 64 || &buffer[0..2] != b"MZ" {
        anyhow::bail!("Not a PE file");
    }
    
    // In a real implementation, you would:
    // 1. Parse the PE headers
    // 2. Find the security directory
    // 3. Parse the PKCS#7 signature
    // 4. Verify the certificate chain
    
    // For now, we'll use osslsigncode if available
    if let Ok(output) = Command::new("osslsigncode")
        .arg("verify")
        .arg(path)
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let _stderr = String::from_utf8_lossy(&output.stderr);
        
        if output.status.success() && stdout.contains("Signature verification: ok") {
            return Ok(SignatureInfo {
                is_signed: true,
                signature_type: Some("Authenticode".to_string()),
                signer: extract_signer_from_output(&stdout),
                timestamp: extract_timestamp_from_output(&stdout),
                certificate_chain: Vec::new(), // Would parse from output
                verification_status: "Valid".to_string(),
            });
        }
    }
    
    anyhow::bail!("No Authenticode signature found")
}

fn check_gpg_signature(path: &Path) -> Result<SignatureInfo> {
    // Check for detached GPG signature
    let sig_path = path.with_extension(format!("{}.sig", path.extension().unwrap_or_default().to_str().unwrap_or("")));
    let asc_path = path.with_extension(format!("{}.asc", path.extension().unwrap_or_default().to_str().unwrap_or("")));
    
    let sig_file = if sig_path.exists() {
        Some(sig_path)
    } else if asc_path.exists() {
        Some(asc_path)
    } else {
        None
    };
    
    if let Some(sig_file) = sig_file {
        if let Ok(output) = Command::new("gpg")
            .arg("--verify")
            .arg(sig_file)
            .arg(path)
            .output()
        {
            let stderr = String::from_utf8_lossy(&output.stderr);
            
            if stderr.contains("Good signature") {
                return Ok(SignatureInfo {
                    is_signed: true,
                    signature_type: Some("GPG".to_string()),
                    signer: extract_gpg_signer(&stderr),
                    timestamp: extract_gpg_timestamp(&stderr),
                    certificate_chain: Vec::new(),
                    verification_status: "Valid".to_string(),
                });
            }
        }
    }
    
    anyhow::bail!("No GPG signature found")
}

fn check_macos_codesign(path: &Path) -> Result<SignatureInfo> {
    if let Ok(output) = Command::new("codesign")
        .arg("-dv")
        .arg("--verbose=4")
        .arg(path)
        .output()
    {
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        if output.status.success() {
            let mut info = SignatureInfo {
                is_signed: true,
                signature_type: Some("Apple Code Signature".to_string()),
                signer: None,
                timestamp: None,
                certificate_chain: Vec::new(),
                verification_status: "Unknown".to_string(),
            };
            
            // Parse authority
            if let Some(auth_line) = stderr.lines().find(|l| l.starts_with("Authority=")) {
                info.signer = Some(auth_line.replace("Authority=", "").to_string());
            }
            
            // Parse timestamp
            if let Some(ts_line) = stderr.lines().find(|l| l.starts_with("Timestamp=")) {
                info.timestamp = Some(ts_line.replace("Timestamp=", "").to_string());
            }
            
            // Verify signature
            if let Ok(verify_output) = Command::new("codesign")
                .arg("--verify")
                .arg("--deep")
                .arg("--strict")
                .arg(path)
                .output()
            {
                info.verification_status = if verify_output.status.success() {
                    "Valid".to_string()
                } else {
                    "Invalid".to_string()
                };
            }
            
            return Ok(info);
        }
    }
    
    anyhow::bail!("No macOS code signature found")
}

fn extract_signer_from_output(output: &str) -> Option<String> {
    output.lines()
        .find(|l| l.contains("Subject:"))
        .map(|l| l.split("Subject:").nth(1).unwrap_or("").trim().to_string())
}

fn extract_timestamp_from_output(output: &str) -> Option<String> {
    output.lines()
        .find(|l| l.contains("Timestamp:"))
        .map(|l| l.split("Timestamp:").nth(1).unwrap_or("").trim().to_string())
}

fn extract_gpg_signer(output: &str) -> Option<String> {
    output.lines()
        .find(|l| l.contains("Good signature from"))
        .map(|l| {
            l.split("Good signature from")
                .nth(1)
                .unwrap_or("")
                .trim()
                .trim_matches('"')
                .to_string()
        })
}

fn extract_gpg_timestamp(output: &str) -> Option<String> {
    output.lines()
        .find(|l| l.contains("Signature made"))
        .map(|l| {
            l.split("Signature made")
                .nth(1)
                .unwrap_or("")
                .trim()
                .to_string()
        })
}