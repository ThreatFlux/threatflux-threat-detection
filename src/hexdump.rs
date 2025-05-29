use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct HexDump {
    pub offset: u64,
    pub length: usize,
    pub bytes_per_line: usize,
    pub total_bytes: u64,
    pub lines: Vec<HexLine>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HexLine {
    pub offset: u64,
    pub hex_bytes: String,
    pub ascii_repr: String,
    pub raw_bytes: Vec<u8>,
}

pub struct HexDumpOptions {
    pub offset: u64,
    pub length: Option<usize>,
    pub bytes_per_line: usize,
    pub max_lines: Option<usize>,
}

impl Default for HexDumpOptions {
    fn default() -> Self {
        Self {
            offset: 0,
            length: None,
            bytes_per_line: 16,
            max_lines: Some(32), // Default to first 512 bytes
        }
    }
}

pub fn generate_hex_dump(path: &Path, options: HexDumpOptions) -> Result<HexDump> {
    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();
    
    file.seek(SeekFrom::Start(options.offset))?;
    
    let max_bytes = match (options.length, options.max_lines) {
        (Some(len), _) => len,
        (None, Some(max_lines)) => max_lines * options.bytes_per_line,
        (None, None) => file_size as usize,
    };
    
    let bytes_to_read = std::cmp::min(max_bytes, (file_size - options.offset) as usize);
    
    let mut buffer = vec![0u8; bytes_to_read];
    let mut reader = BufReader::new(file);
    let actual_read = reader.read(&mut buffer)?;
    buffer.truncate(actual_read);
    
    let mut lines = Vec::new();
    let mut current_offset = options.offset;
    
    for chunk in buffer.chunks(options.bytes_per_line) {
        let hex_bytes = chunk
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        
        // Pad hex representation to align ASCII
        let padded_hex = if chunk.len() < options.bytes_per_line {
            let padding_needed = (options.bytes_per_line - chunk.len()) * 3;
            format!("{}{}", hex_bytes, " ".repeat(padding_needed))
        } else {
            hex_bytes
        };
        
        let ascii_repr = chunk
            .iter()
            .map(|&b| {
                if b >= 32 && b <= 126 {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        
        lines.push(HexLine {
            offset: current_offset,
            hex_bytes: padded_hex,
            ascii_repr,
            raw_bytes: chunk.to_vec(),
        });
        
        current_offset += chunk.len() as u64;
    }
    
    Ok(HexDump {
        offset: options.offset,
        length: actual_read,
        bytes_per_line: options.bytes_per_line,
        total_bytes: file_size,
        lines,
    })
}

pub fn format_hex_dump_text(hex_dump: &HexDump) -> String {
    let mut output = String::new();
    
    output.push_str(&format!(
        "Hex dump (offset: 0x{:08x}, length: {} bytes, total file size: {} bytes)\n",
        hex_dump.offset, hex_dump.length, hex_dump.total_bytes
    ));
    output.push_str(&format!("{:-<80}\n", ""));
    
    for line in &hex_dump.lines {
        output.push_str(&format!(
            "{:08x}  {}  |{}|\n",
            line.offset,
            line.hex_bytes,
            line.ascii_repr
        ));
    }
    
    if hex_dump.lines.len() * hex_dump.bytes_per_line < hex_dump.total_bytes as usize {
        output.push_str("... (truncated)\n");
    }
    
    output
}

pub fn extract_header_hex(path: &Path, header_size: usize) -> Result<HexDump> {
    let options = HexDumpOptions {
        offset: 0,
        length: Some(header_size),
        bytes_per_line: 16,
        max_lines: None,
    };
    generate_hex_dump(path, options)
}

pub fn extract_footer_hex(path: &Path, footer_size: usize) -> Result<HexDump> {
    let file = File::open(path)?;
    let file_size = file.metadata()?.len();
    
    let offset = if file_size > footer_size as u64 {
        file_size - footer_size as u64
    } else {
        0
    };
    
    let options = HexDumpOptions {
        offset,
        length: Some(footer_size),
        bytes_per_line: 16,
        max_lines: None,
    };
    generate_hex_dump(path, options)
}