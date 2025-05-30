use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub file_path: String,
    pub file_hash: String,
    pub tool_name: String,
    pub tool_args: HashMap<String, serde_json::Value>,
    pub result: serde_json::Value,
    pub timestamp: DateTime<Utc>,
    pub file_size: u64,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMetadata {
    pub total_entries: usize,
    pub total_unique_files: usize,
    pub cache_size_bytes: u64,
    pub last_updated: DateTime<Utc>,
}

#[derive(Clone)]
pub struct AnalysisCache {
    entries: Arc<Mutex<HashMap<String, Vec<CacheEntry>>>>,
    cache_dir: PathBuf,
    max_entries_per_file: usize,
}

impl AnalysisCache {
    pub fn new<P: AsRef<Path>>(cache_dir: P) -> Result<Self> {
        let cache_dir = cache_dir.as_ref().to_path_buf();
        
        // Create cache directory if it doesn't exist
        fs::create_dir_all(&cache_dir)?;
        
        let cache = Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            cache_dir,
            max_entries_per_file: 100,
        };
        
        // Load existing cache
        cache.load_from_disk()?;
        
        Ok(cache)
    }
    
    pub fn add_entry(&self, entry: CacheEntry) -> Result<()> {
        let mut entries = self.entries.lock().unwrap();
        
        // Use file hash as key for better cache hits
        let key = entry.file_hash.clone();
        
        let file_entries = entries.entry(key).or_insert_with(Vec::new);
        file_entries.push(entry);
        
        // Limit entries per file
        if file_entries.len() > self.max_entries_per_file {
            file_entries.remove(0);
        }
        
        drop(entries);
        
        // Save to disk asynchronously
        let cache_clone = self.clone();
        tokio::spawn(async move {
            let _ = cache_clone.save_to_disk().await;
        });
        
        Ok(())
    }
    
    pub fn get_entries(&self, file_hash: &str) -> Option<Vec<CacheEntry>> {
        let entries = self.entries.lock().unwrap();
        entries.get(file_hash).cloned()
    }
    
    pub fn get_latest_analysis(&self, file_hash: &str, tool_name: &str) -> Option<CacheEntry> {
        let entries = self.entries.lock().unwrap();
        entries.get(file_hash)?
            .iter()
            .filter(|e| e.tool_name == tool_name)
            .max_by_key(|e| e.timestamp)
            .cloned()
    }
    
    pub fn get_all_entries(&self) -> Vec<CacheEntry> {
        let entries = self.entries.lock().unwrap();
        entries.values()
            .flat_map(|v| v.iter().cloned())
            .collect()
    }
    
    pub fn get_metadata(&self) -> CacheMetadata {
        let entries = self.entries.lock().unwrap();
        
        let total_entries: usize = entries.values().map(|v| v.len()).sum();
        let total_unique_files = entries.len();
        
        // Calculate approximate cache size
        let cache_size_bytes: u64 = entries.values()
            .flat_map(|v| v.iter())
            .map(|e| {
                // Rough estimate of memory usage
                serde_json::to_string(e).unwrap_or_default().len() as u64
            })
            .sum();
        
        CacheMetadata {
            total_entries,
            total_unique_files,
            cache_size_bytes,
            last_updated: Utc::now(),
        }
    }
    
    pub fn clear(&self) -> Result<()> {
        let mut entries = self.entries.lock().unwrap();
        entries.clear();
        
        // Remove cache files
        if self.cache_dir.exists() {
            for entry in fs::read_dir(&self.cache_dir)? {
                let entry = entry?;
                if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
                    fs::remove_file(entry.path())?;
                }
            }
        }
        
        Ok(())
    }
    
    pub fn search_entries(&self, query: &CacheSearchQuery) -> Vec<CacheEntry> {
        let entries = self.entries.lock().unwrap();
        
        entries.values()
            .flat_map(|v| v.iter())
            .filter(|e| {
                let mut matches = true;
                
                if let Some(ref tool) = query.tool_name {
                    matches &= e.tool_name == *tool;
                }
                
                if let Some(ref path_pattern) = query.file_path_pattern {
                    matches &= e.file_path.contains(path_pattern);
                }
                
                if let Some(ref start) = query.start_time {
                    matches &= e.timestamp >= *start;
                }
                
                if let Some(ref end) = query.end_time {
                    matches &= e.timestamp <= *end;
                }
                
                if let Some(min_size) = query.min_file_size {
                    matches &= e.file_size >= min_size;
                }
                
                if let Some(max_size) = query.max_file_size {
                    matches &= e.file_size <= max_size;
                }
                
                matches
            })
            .cloned()
            .collect()
    }
    
    async fn save_to_disk(&self) -> Result<()> {
        let entries = self.entries.lock().unwrap().clone();
        
        for (hash, file_entries) in entries.iter() {
            let cache_file = self.cache_dir.join(format!("{}.json", hash));
            let json = serde_json::to_string_pretty(file_entries)?;
            
            let mut file = File::create(&cache_file).await?;
            file.write_all(json.as_bytes()).await?;
        }
        
        // Save metadata
        let metadata = self.get_metadata();
        let metadata_file = self.cache_dir.join("metadata.json");
        let json = serde_json::to_string_pretty(&metadata)?;
        
        let mut file = File::create(&metadata_file).await?;
        file.write_all(json.as_bytes()).await?;
        
        Ok(())
    }
    
    fn load_from_disk(&self) -> Result<()> {
        if !self.cache_dir.exists() {
            return Ok(());
        }
        
        let mut entries = self.entries.lock().unwrap();
        
        for entry in fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("json") 
                && path.file_stem().and_then(|s| s.to_str()) != Some("metadata") {
                
                let json = fs::read_to_string(&path)?;
                if let Ok(file_entries) = serde_json::from_str::<Vec<CacheEntry>>(&json) {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        entries.insert(stem.to_string(), file_entries);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    pub fn get_statistics(&self) -> CacheStatistics {
        let entries = self.entries.lock().unwrap();
        
        let mut tool_counts: HashMap<String, usize> = HashMap::new();
        let mut total_execution_time = 0u64;
        let mut file_type_counts: HashMap<String, usize> = HashMap::new();
        
        for file_entries in entries.values() {
            for entry in file_entries {
                *tool_counts.entry(entry.tool_name.clone()).or_insert(0) += 1;
                total_execution_time += entry.execution_time_ms;
                
                // Extract file extension
                if let Some(ext) = Path::new(&entry.file_path).extension().and_then(|s| s.to_str()) {
                    *file_type_counts.entry(ext.to_string()).or_insert(0) += 1;
                }
            }
        }
        
        let total_entries: usize = entries.values().map(|v| v.len()).sum();
        let avg_execution_time = if total_entries > 0 {
            total_execution_time / total_entries as u64
        } else {
            0
        };
        
        CacheStatistics {
            tool_counts,
            file_type_counts,
            total_analyses: total_entries,
            unique_files: entries.len(),
            avg_execution_time_ms: avg_execution_time,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheSearchQuery {
    pub tool_name: Option<String>,
    pub file_path_pattern: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub min_file_size: Option<u64>,
    pub max_file_size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStatistics {
    pub tool_counts: HashMap<String, usize>,
    pub file_type_counts: HashMap<String, usize>,
    pub total_analyses: usize,
    pub unique_files: usize,
    pub avg_execution_time_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_cache_operations() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();
        
        // Add entry
        let entry = CacheEntry {
            file_path: "/test/file.bin".to_string(),
            file_hash: "abc123".to_string(),
            tool_name: "calculate_file_hashes".to_string(),
            tool_args: HashMap::new(),
            result: serde_json::json!({"md5": "test"}),
            timestamp: Utc::now(),
            file_size: 1024,
            execution_time_ms: 100,
        };
        
        cache.add_entry(entry.clone()).unwrap();
        
        // Get entry
        let entries = cache.get_entries("abc123").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tool_name, "calculate_file_hashes");
        
        // Search
        let query = CacheSearchQuery {
            tool_name: Some("calculate_file_hashes".to_string()),
            file_path_pattern: None,
            start_time: None,
            end_time: None,
            min_file_size: None,
            max_file_size: None,
        };
        
        let results = cache.search_entries(&query);
        assert_eq!(results.len(), 1);
    }
}