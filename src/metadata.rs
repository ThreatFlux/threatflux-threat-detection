use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::os::unix::fs::MetadataExt;

use crate::binary_parser::BinaryInfo;
use crate::hash::Hashes;
use crate::hexdump::HexDump;
use crate::signature::SignatureInfo;
use crate::strings::ExtractedStrings;

#[derive(Debug, Serialize, Deserialize)]
pub struct FileMetadata {
    pub file_path: PathBuf,
    pub file_name: String,
    pub file_size: u64,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    pub permissions: String,
    pub is_executable: bool,
    pub mime_type: Option<String>,
    pub hashes: Option<Hashes>,
    pub binary_info: Option<BinaryInfo>,
    pub extracted_strings: Option<ExtractedStrings>,
    pub signature_info: Option<SignatureInfo>,
    pub hex_dump: Option<HexDump>,
    pub owner_uid: u32,
    pub group_gid: u32,
}

impl FileMetadata {
    pub fn new(path: &Path) -> Result<Self> {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        Ok(Self {
            file_path: path.to_path_buf(),
            file_name,
            file_size: 0,
            created: None,
            modified: None,
            accessed: None,
            permissions: String::new(),
            is_executable: false,
            mime_type: None,
            hashes: None,
            binary_info: None,
            extracted_strings: None,
            signature_info: None,
            hex_dump: None,
            owner_uid: 0,
            group_gid: 0,
        })
    }

    pub fn extract_basic_info(&mut self) -> Result<()> {
        let metadata = fs::metadata(&self.file_path)?;
        
        self.file_size = metadata.len();
        self.owner_uid = metadata.uid();
        self.group_gid = metadata.gid();
        
        let mode = metadata.mode();
        self.permissions = format!("{:o}", mode & 0o777);
        self.is_executable = mode & 0o111 != 0;

        if let Ok(modified) = metadata.modified() {
            self.modified = Some(DateTime::from(modified));
        }

        if let Ok(accessed) = metadata.accessed() {
            self.accessed = Some(DateTime::from(accessed));
        }

        if let Ok(created) = metadata.created() {
            self.created = Some(DateTime::from(created));
        }

        self.detect_mime_type()?;

        Ok(())
    }

    fn detect_mime_type(&mut self) -> Result<()> {
        let mut buffer = vec![0u8; 512];
        if let Ok(mut file) = fs::File::open(&self.file_path) {
            use std::io::Read;
            let _ = file.read(&mut buffer)?;
            
            self.mime_type = Some(match &buffer[..] {
                b if b.starts_with(b"\x7FELF") => "application/x-elf",
                b if b.starts_with(b"MZ") => "application/x-dosexec",
                b if b.starts_with(b"\xCA\xFE\xBA\xBE") => "application/x-mach-binary",
                b if b.starts_with(b"\xFE\xED\xFA") => "application/x-mach-binary",
                b if b.starts_with(b"#!/") => "text/x-shellscript",
                b if b.starts_with(b"\x89PNG") => "image/png",
                b if b.starts_with(b"\xFF\xD8\xFF") => "image/jpeg",
                b if b.starts_with(b"GIF8") => "image/gif",
                b if b.starts_with(b"PK\x03\x04") => "application/zip",
                b if b.starts_with(b"\x1F\x8B") => "application/gzip",
                b if b.starts_with(b"BZh") => "application/x-bzip2",
                b if b.starts_with(b"%PDF") => "application/pdf",
                _ => "application/octet-stream",
            }.to_string());
        }
        
        Ok(())
    }

    pub async fn calculate_hashes(&mut self) -> Result<()> {
        self.hashes = Some(crate::hash::calculate_all_hashes(&self.file_path).await?);
        Ok(())
    }
}