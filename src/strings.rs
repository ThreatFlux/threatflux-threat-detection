use anyhow::Result;
use encoding_rs::{UTF_16BE, UTF_16LE};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtractedStrings {
    pub total_count: usize,
    pub unique_count: usize,
    pub ascii_strings: Vec<String>,
    pub unicode_strings: Vec<String>,
    pub interesting_strings: Vec<InterestingString>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InterestingString {
    pub category: String,
    pub value: String,
    pub offset: usize,
}

pub fn extract_strings(path: &Path, min_length: usize) -> Result<ExtractedStrings> {
    let file = File::open(path)?;
    let file_size = file.metadata()?.len() as usize;
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::with_capacity(file_size.min(100_000_000)); // Cap at 100MB
    reader.read_to_end(&mut buffer)?;

    let ascii_pattern = format!(r"[\x20-\x7E]{{{},}}", min_length);
    let ascii_regex = Regex::new(&ascii_pattern)?;
    
    let mut ascii_strings = Vec::new();
    let mut unicode_strings = Vec::new();
    let mut interesting_strings = Vec::new();
    let mut unique_strings = HashSet::new();

    for mat in ascii_regex.find_iter(&buffer) {
        if let Ok(s) = std::str::from_utf8(mat.as_bytes()) {
            let string = s.to_string();
            unique_strings.insert(string.clone());
            ascii_strings.push(string.clone());
            
            if let Some(interesting) = categorize_string(&string, mat.start()) {
                interesting_strings.push(interesting);
            }
        }
    }

    let utf16_le_pattern = format!(r"(?:[\x00-\x7F]\x00){{{},}}", min_length);
    let utf16_le_regex = Regex::new(&utf16_le_pattern)?;
    
    for mat in utf16_le_regex.find_iter(&buffer) {
        let (decoded, _, _) = UTF_16LE.decode(mat.as_bytes());
        let string = decoded.into_owned();
        if string.len() >= min_length {
            unique_strings.insert(string.clone());
            unicode_strings.push(string.clone());
            
            if let Some(interesting) = categorize_string(&string, mat.start()) {
                interesting_strings.push(interesting);
            }
        }
    }

    let utf16_be_pattern = format!(r"(?:\x00[\x00-\x7F]){{{},}}", min_length);
    let utf16_be_regex = Regex::new(&utf16_be_pattern)?;
    
    for mat in utf16_be_regex.find_iter(&buffer) {
        let (decoded, _, _) = UTF_16BE.decode(mat.as_bytes());
        let string = decoded.into_owned();
        if string.len() >= min_length {
            unique_strings.insert(string.clone());
            unicode_strings.push(string.clone());
            
            if let Some(interesting) = categorize_string(&string, mat.start()) {
                interesting_strings.push(interesting);
            }
        }
    }

    Ok(ExtractedStrings {
        total_count: ascii_strings.len() + unicode_strings.len(),
        unique_count: unique_strings.len(),
        ascii_strings: ascii_strings.into_iter().take(1000).collect(), // Limit output
        unicode_strings: unicode_strings.into_iter().take(1000).collect(),
        interesting_strings,
    })
}

fn categorize_string(s: &str, offset: usize) -> Option<InterestingString> {
    let patterns = [
        (r"(?i)https?://[^\s]+", "URL"),
        (r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", "Email"),
        (r"(?i)(?:password|passwd|pwd)\s*[:=]\s*\S+", "Password"),
        (r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*\S+", "API Key"),
        (r"(?i)(?:secret|token)\s*[:=]\s*\S+", "Secret/Token"),
        (r"[A-Z]{3,}_[A-Z_]{3,}", "Environment Variable"),
        (r"(?i)copyright\s+.*\d{4}", "Copyright"),
        (r"(?i)version\s*[:=]?\s*\d+\.\d+", "Version"),
        (r"(?:/[a-zA-Z0-9._-]+){3,}", "File Path"),
        (r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", "IP Address"),
        (r"(?i)(?:error|warning|fatal|critical).*", "Error/Warning"),
        (r"(?i)(?:debug|trace|info).*", "Debug Info"),
    ];

    for (pattern, category) in patterns.iter() {
        if let Ok(regex) = Regex::new(pattern) {
            if regex.is_match(s.as_bytes()) {
                return Some(InterestingString {
                    category: category.to_string(),
                    value: s.to_string(),
                    offset,
                });
            }
        }
    }

    None
}