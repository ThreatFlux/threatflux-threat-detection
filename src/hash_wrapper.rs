// Compatibility wrapper for threatflux-hashing library
// This file can replace the current hash.rs to use the external library

// Re-export all public types and functions from the library
pub use threatflux_hashing::{calculate_all_hashes, calculate_md5, Hashes};

// For backward compatibility with anyhow::Result
use anyhow::Result;
use std::path::Path;

// Wrapper functions that convert library errors to anyhow errors
pub async fn calculate_all_hashes_compat(path: &Path) -> Result<Hashes> {
    threatflux_hashing::calculate_all_hashes(path)
        .await
        .map_err(|e| anyhow::anyhow!("Hash calculation error: {}", e))
}

pub async fn calculate_md5_compat(path: &Path) -> Result<String> {
    threatflux_hashing::calculate_md5(path)
        .await
        .map_err(|e| anyhow::anyhow!("MD5 calculation error: {}", e))
}

// Additional compatibility layer to handle the change from non-optional to optional fields
pub async fn calculate_all_hashes_legacy(path: &Path) -> Result<LegacyHashes> {
    let hashes = calculate_all_hashes(path)
        .await
        .map_err(|e| anyhow::anyhow!("Hash calculation error: {}", e))?;

    Ok(LegacyHashes {
        md5: hashes.md5.unwrap_or_else(|| "error".to_string()),
        sha256: hashes.sha256.unwrap_or_else(|| "error".to_string()),
        sha512: hashes.sha512.unwrap_or_else(|| "error".to_string()),
        blake3: hashes.blake3.unwrap_or_else(|| "error".to_string()),
    })
}

// Legacy struct with non-optional fields for full backward compatibility
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct LegacyHashes {
    pub md5: String,
    pub sha256: String,
    pub sha512: String,
    pub blake3: String,
}

// Conversion from new to legacy format
impl From<Hashes> for LegacyHashes {
    fn from(hashes: Hashes) -> Self {
        LegacyHashes {
            md5: hashes.md5.unwrap_or_else(|| "error".to_string()),
            sha256: hashes.sha256.unwrap_or_else(|| "error".to_string()),
            sha512: hashes.sha512.unwrap_or_else(|| "error".to_string()),
            blake3: hashes.blake3.unwrap_or_else(|| "error".to_string()),
        }
    }
}
