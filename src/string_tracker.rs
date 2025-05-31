use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringOccurrence {
    pub file_path: String,
    pub file_hash: String,
    pub tool_name: String,
    pub timestamp: DateTime<Utc>,
    pub context: StringContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StringContext {
    FileString { offset: Option<usize> },
    Import { library: String },
    Export { symbol: String },
    Resource { resource_type: String },
    Section { section_name: String },
    Metadata { field: String },
    Path { path_type: String },
    Url { protocol: Option<String> },
    Registry { hive: Option<String> },
    Command { command_type: String },
    Other { category: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringEntry {
    pub value: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub total_occurrences: usize,
    pub unique_files: HashSet<String>,
    pub occurrences: Vec<StringOccurrence>,
    pub categories: HashSet<String>,
    pub is_suspicious: bool,
    pub entropy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringStatistics {
    pub total_unique_strings: usize,
    pub total_occurrences: usize,
    pub total_files_analyzed: usize,
    pub most_common: Vec<(String, usize)>,
    pub suspicious_strings: Vec<String>,
    pub high_entropy_strings: Vec<(String, f64)>,
    pub category_distribution: HashMap<String, usize>,
    pub length_distribution: HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringFilter {
    pub min_occurrences: Option<usize>,
    pub max_occurrences: Option<usize>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub categories: Option<Vec<String>>,
    pub file_paths: Option<Vec<String>>,
    pub file_hashes: Option<Vec<String>>,
    pub suspicious_only: Option<bool>,
    pub regex_pattern: Option<String>,
    pub min_entropy: Option<f64>,
    pub max_entropy: Option<f64>,
    pub date_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
}

#[derive(Clone)]
pub struct StringTracker {
    entries: Arc<Mutex<HashMap<String, StringEntry>>>,
    suspicious_patterns: Vec<regex::Regex>,
}

impl StringTracker {
    pub fn new() -> Self {
        let suspicious_patterns = vec![
            // Network indicators
            regex::Regex::new(r"(?i)(https?|ftp|ssh|telnet|rdp)://").unwrap(),
            regex::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap(),
            regex::Regex::new(r"(?i)(cmd\.exe|powershell|bash|sh)").unwrap(),
            regex::Regex::new(r"(?i)(eval|exec|system|shell)").unwrap(),
            // Crypto/encoding
            regex::Regex::new(r"(?i)(base64|rot13|xor|aes|des|rsa)").unwrap(),
            regex::Regex::new(r"^[A-Za-z0-9+/]{20,}={0,2}$").unwrap(), // Base64
            // Suspicious paths
            regex::Regex::new(r"(?i)(\\temp\\|\/tmp\/|\\windows\\system32)").unwrap(),
            regex::Regex::new(r"(?i)(passwords?|credential|secret|token|api[_-]?key)").unwrap(),
            // Registry keys
            regex::Regex::new(r"(?i)(HKEY_|SOFTWARE\\Microsoft\\Windows)").unwrap(),
            // Common malware strings
            regex::Regex::new(r"(?i)(dropper|payload|inject|hook|rootkit)").unwrap(),
            regex::Regex::new(r"(?i)(keylog|screenshot|webcam|microphone)").unwrap(),
        ];

        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            suspicious_patterns,
        }
    }

    pub fn track_string(
        &self,
        value: &str,
        file_path: &str,
        file_hash: &str,
        tool_name: &str,
        context: StringContext,
    ) -> Result<()> {
        let mut entries = self.entries.lock().unwrap();

        let occurrence = StringOccurrence {
            file_path: file_path.to_string(),
            file_hash: file_hash.to_string(),
            tool_name: tool_name.to_string(),
            timestamp: Utc::now(),
            context: context.clone(),
        };

        let category = match &context {
            StringContext::FileString { .. } => "file_string",
            StringContext::Import { .. } => "import",
            StringContext::Export { .. } => "export",
            StringContext::Resource { .. } => "resource",
            StringContext::Section { .. } => "section",
            StringContext::Metadata { .. } => "metadata",
            StringContext::Path { .. } => "path",
            StringContext::Url { .. } => "url",
            StringContext::Registry { .. } => "registry",
            StringContext::Command { .. } => "command",
            StringContext::Other { category } => category,
        };

        let entry = entries.entry(value.to_string()).or_insert_with(|| {
            let entropy = self.calculate_entropy(value);
            let is_suspicious = self.is_suspicious(value);

            StringEntry {
                value: value.to_string(),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                total_occurrences: 0,
                unique_files: HashSet::new(),
                occurrences: Vec::new(),
                categories: HashSet::new(),
                is_suspicious,
                entropy,
            }
        });

        entry.last_seen = Utc::now();
        entry.total_occurrences += 1;
        entry.unique_files.insert(file_hash.to_string());
        entry.occurrences.push(occurrence);
        entry.categories.insert(category.to_string());

        // Limit occurrences per string to prevent memory explosion
        if entry.occurrences.len() > 1000 {
            entry.occurrences.remove(0);
        }

        Ok(())
    }

    pub fn track_strings_from_results(
        &self,
        strings: &[String],
        file_path: &str,
        file_hash: &str,
        tool_name: &str,
    ) -> Result<()> {
        for string in strings {
            // Categorize the string
            let context = self.categorize_string(string);
            self.track_string(string, file_path, file_hash, tool_name, context)?;
        }
        Ok(())
    }

    fn categorize_string(&self, s: &str) -> StringContext {
        // URL detection
        if s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://") {
            let protocol = s.split("://").next().map(|p| p.to_string());
            return StringContext::Url { protocol };
        }

        // Path detection
        if (s.contains('/') || s.contains('\\'))
            && (s.starts_with("/") || s.starts_with("\\") || s.contains(":\\"))
        {
            let path_type = if s.contains("\\Windows") || s.contains("/usr") {
                "system"
            } else if s.contains("\\Temp") || s.contains("/tmp") {
                "temp"
            } else {
                "general"
            };
            return StringContext::Path {
                path_type: path_type.to_string(),
            };
        }

        // Registry key detection
        if s.starts_with("HKEY_") || s.contains("\\SOFTWARE\\") {
            let hive = s.split('\\').next().map(|h| h.to_string());
            return StringContext::Registry { hive };
        }

        // Import/Export detection (simplified)
        if s.ends_with(".dll") || s.ends_with(".so") || s.ends_with(".dylib") {
            return StringContext::Import {
                library: s.to_string(),
            };
        }

        // Command detection
        if s.contains("cmd") || s.contains("powershell") || s.contains("bash") {
            return StringContext::Command {
                command_type: "shell".to_string(),
            };
        }

        // Default to file string
        StringContext::FileString { offset: None }
    }

    fn calculate_entropy(&self, s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut char_counts = HashMap::new();
        for ch in s.chars() {
            *char_counts.entry(ch).or_insert(0) += 1;
        }

        let len = s.len() as f64;
        let mut entropy = 0.0;

        for count in char_counts.values() {
            let probability = *count as f64 / len;
            entropy -= probability * probability.log2();
        }

        entropy
    }

    fn is_suspicious(&self, s: &str) -> bool {
        // Check against suspicious patterns
        for pattern in &self.suspicious_patterns {
            if pattern.is_match(s) {
                return true;
            }
        }

        // Check entropy (high entropy might indicate encoding/encryption)
        let entropy = self.calculate_entropy(s);
        if entropy > 4.5 && s.len() > 10 {
            return true;
        }

        // Check for non-printable characters
        if s.chars()
            .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
        {
            return true;
        }

        false
    }

    pub fn get_statistics(&self, filter: Option<&StringFilter>) -> StringStatistics {
        let entries = self.entries.lock().unwrap();

        let filtered_entries: Vec<_> = entries
            .values()
            .filter(|entry| self.matches_filter(entry, filter))
            .collect();

        let total_unique_strings = filtered_entries.len();
        let total_occurrences: usize = filtered_entries.iter().map(|e| e.total_occurrences).sum();

        let total_files_analyzed: HashSet<_> = filtered_entries
            .iter()
            .flat_map(|e| e.unique_files.iter())
            .collect();

        // Most common strings
        let mut most_common: Vec<_> = filtered_entries
            .iter()
            .map(|e| (e.value.clone(), e.total_occurrences))
            .collect();
        most_common.sort_by(|a, b| b.1.cmp(&a.1));
        most_common.truncate(100);

        // Suspicious strings
        let suspicious_strings: Vec<_> = filtered_entries
            .iter()
            .filter(|e| e.is_suspicious)
            .map(|e| e.value.clone())
            .take(50)
            .collect();

        // High entropy strings
        let mut high_entropy_strings: Vec<_> = filtered_entries
            .iter()
            .filter(|e| e.entropy > 4.0)
            .map(|e| (e.value.clone(), e.entropy))
            .collect();
        high_entropy_strings.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        high_entropy_strings.truncate(50);

        // Category distribution
        let mut category_distribution = HashMap::new();
        for entry in &filtered_entries {
            for category in &entry.categories {
                *category_distribution.entry(category.clone()).or_insert(0) += 1;
            }
        }

        // Length distribution
        let mut length_distribution = HashMap::new();
        for entry in &filtered_entries {
            let len_bucket = match entry.value.len() {
                0..=10 => "0-10",
                11..=20 => "11-20",
                21..=50 => "21-50",
                51..=100 => "51-100",
                101..=200 => "101-200",
                _ => "200+",
            };
            *length_distribution
                .entry(len_bucket.to_string())
                .or_insert(0) += 1;
        }

        StringStatistics {
            total_unique_strings,
            total_occurrences,
            total_files_analyzed: total_files_analyzed.len(),
            most_common,
            suspicious_strings,
            high_entropy_strings,
            category_distribution,
            length_distribution,
        }
    }

    fn matches_filter(&self, entry: &StringEntry, filter: Option<&StringFilter>) -> bool {
        let Some(f) = filter else {
            return true;
        };

        if let Some(min) = f.min_occurrences {
            if entry.total_occurrences < min {
                return false;
            }
        }

        if let Some(max) = f.max_occurrences {
            if entry.total_occurrences > max {
                return false;
            }
        }

        if let Some(min) = f.min_length {
            if entry.value.len() < min {
                return false;
            }
        }

        if let Some(max) = f.max_length {
            if entry.value.len() > max {
                return false;
            }
        }

        if let Some(ref categories) = f.categories {
            if !categories.iter().any(|c| entry.categories.contains(c)) {
                return false;
            }
        }

        if let Some(ref file_hashes) = f.file_hashes {
            if !file_hashes.iter().any(|h| entry.unique_files.contains(h)) {
                return false;
            }
        }

        if let Some(suspicious_only) = f.suspicious_only {
            if suspicious_only && !entry.is_suspicious {
                return false;
            }
        }

        if let Some(ref pattern) = f.regex_pattern {
            if let Ok(re) = regex::Regex::new(pattern) {
                if !re.is_match(&entry.value) {
                    return false;
                }
            }
        }

        if let Some(min_entropy) = f.min_entropy {
            if entry.entropy < min_entropy {
                return false;
            }
        }

        if let Some(max_entropy) = f.max_entropy {
            if entry.entropy > max_entropy {
                return false;
            }
        }

        true
    }

    pub fn get_string_details(&self, value: &str) -> Option<StringEntry> {
        let entries = self.entries.lock().unwrap();
        entries.get(value).cloned()
    }

    pub fn search_strings(&self, query: &str, limit: usize) -> Vec<StringEntry> {
        let entries = self.entries.lock().unwrap();
        let query_lower = query.to_lowercase();

        let mut results: Vec<_> = entries
            .values()
            .filter(|e| e.value.to_lowercase().contains(&query_lower))
            .cloned()
            .collect();

        results.sort_by(|a, b| b.total_occurrences.cmp(&a.total_occurrences));
        results.truncate(limit);
        results
    }

    pub fn get_related_strings(&self, value: &str, limit: usize) -> Vec<(String, f64)> {
        let entries = self.entries.lock().unwrap();

        let Some(target_entry) = entries.get(value) else {
            return vec![];
        };

        let mut similarities: Vec<_> = entries
            .iter()
            .filter(|(k, _)| *k != value)
            .map(|(k, v)| {
                let similarity = self.calculate_similarity(target_entry, v);
                (k.clone(), similarity)
            })
            .filter(|(_, sim)| *sim > 0.3)
            .collect();

        similarities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        similarities.truncate(limit);
        similarities
    }

    fn calculate_similarity(&self, a: &StringEntry, b: &StringEntry) -> f64 {
        let mut score = 0.0;
        let mut factors = 0.0;

        // Shared files
        let shared_files: HashSet<_> = a.unique_files.intersection(&b.unique_files).collect();
        if !shared_files.is_empty() {
            score +=
                shared_files.len() as f64 / a.unique_files.len().min(b.unique_files.len()) as f64;
            factors += 1.0;
        }

        // Shared categories
        let shared_categories: HashSet<_> = a.categories.intersection(&b.categories).collect();
        if !shared_categories.is_empty() {
            score +=
                shared_categories.len() as f64 / a.categories.len().min(b.categories.len()) as f64;
            factors += 1.0;
        }

        // Similar entropy
        let entropy_diff = (a.entropy - b.entropy).abs();
        if entropy_diff < 0.5 {
            score += 1.0 - (entropy_diff / 0.5);
            factors += 1.0;
        }

        // Similar length
        let len_a = a.value.len() as f64;
        let len_b = b.value.len() as f64;
        let len_ratio = len_a.min(len_b) / len_a.max(len_b);
        score += len_ratio;
        factors += 1.0;

        if factors > 0.0 {
            score / factors
        } else {
            0.0
        }
    }

    #[allow(dead_code)]
    pub fn clear(&self) {
        let mut entries = self.entries.lock().unwrap();
        entries.clear();
    }
}
