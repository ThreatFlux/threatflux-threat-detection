//! Tests for filesystem backend implementation

#[cfg(feature = "filesystem-backend")]
use threatflux_cache::backends::filesystem::FilesystemBackend;
use threatflux_cache::{StorageBackend, CacheEntry, EntryMetadata};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use tempfile::TempDir;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TestData {
    id: u32,
    name: String,
    value: i32,
}

impl TestData {
    fn new(id: u32, name: &str, value: i32) -> Self {
        Self {
            id,
            name: name.to_string(),
            value,
        }
    }
}

fn create_test_entry(key: &str, data: TestData) -> CacheEntry<TestData> {
    CacheEntry {
        key: key.to_string(),
        value: data,
        metadata: EntryMetadata {
            created_at: SystemTime::now(),
            last_accessed: SystemTime::now(),
            access_count: 1,
            size_bytes: 64, // Approximate size
            ttl: None,
        },
    }
}

#[cfg(feature = "filesystem-backend")]
#[tokio::test]
async fn test_filesystem_backend_basic_operations() {
    let temp_dir = TempDir::new().unwrap();
    let cache_dir = temp_dir.path().to_path_buf();
    
    let backend = FilesystemBackend::<String, TestData>::new(cache_dir.clone()).await.unwrap();
    
    let test_data = TestData::new(1, "test", 42);
    let entry = create_test_entry("test_key", test_data.clone());
    
    // Test store
    backend.store("test_key".to_string(), entry.clone()).await.unwrap();
    
    // Verify file was created
    let file_path = cache_dir.join("test_key.cache");
    assert!(file_path.exists());
    
    // Test exists
    assert!(backend.exists(&"test_key".to_string()).await.unwrap());
    assert!(!backend.exists(&"nonexistent".to_string()).await.unwrap());
    
    // Test load
    let loaded = backend.load(&"test_key".to_string()).await.unwrap();
    assert!(loaded.is_some());
    let loaded_entry = loaded.unwrap();
    assert_eq!(loaded_entry.key, "test_key");
    assert_eq!(loaded_entry.value, test_data);
    
    // Test remove
    let removed = backend.remove(&"test_key".to_string()).await.unwrap();
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().value, test_data);
    
    // Verify file was deleted
    assert!(!file_path.exists());
    
    // Verify removed from backend
    assert!(!backend.exists(&"test_key".to_string()).await.unwrap());
    assert!(backend.load(&"test_key".to_string()).await.unwrap().is_none());
}

#[cfg(feature = "filesystem-backend")]
#[tokio::test]
async fn test_filesystem_backend_multiple_entries() {
    let temp_dir = TempDir::new().unwrap();
    let cache_dir = temp_dir.path().to_path_buf();
    
    let backend = FilesystemBackend::<String, TestData>::new(cache_dir.clone()).await.unwrap();
    
    // Store multiple entries
    for i in 1..=10 {
        let data = TestData::new(i, &format!("test_{}", i), i as i32 * 10);
        let entry = create_test_entry(&format!("key_{}", i), data);
        backend.store(format!("key_{}", i), entry).await.unwrap();
    }
    
    // Verify all files were created
    for i in 1..=10 {
        let file_path = cache_dir.join(format!("key_{}.cache", i));
        assert!(file_path.exists());
    }
    
    // Verify all entries exist
    for i in 1..=10 {
        assert!(backend.exists(&format!("key_{}", i)).await.unwrap());
        
        let loaded = backend.load(&format!("key_{}", i)).await.unwrap();
        assert!(loaded.is_some());
        
        let entry = loaded.unwrap();
        assert_eq!(entry.value.id, i);
        assert_eq!(entry.value.name, format!("test_{}", i));
        assert_eq!(entry.value.value, i as i32 * 10);
    }
    
    // Test list_keys
    let keys = backend.list_keys().await.unwrap();
    assert_eq!(keys.len(), 10);
    
    for i in 1..=10 {
        assert!(keys.contains(&format!("key_{}", i)));
    }
}

#[cfg(feature = "filesystem-backend")]
#[tokio::test]
async fn test_filesystem_backend_persistence() {
    let temp_dir = TempDir::new().unwrap();
    let cache_dir = temp_dir.path().to_path_buf();
    
    let test_data = TestData::new(1, "persistence_test", 42);
    let entry = create_test_entry("persist_key", test_data.clone());
    
    // Create backend and store data
    {
        let backend = FilesystemBackend::<String, TestData>::new(cache_dir.clone()).await.unwrap();
        backend.store("persist_key".to_string(), entry).await.unwrap();
    } // Backend goes out of scope
    
    // Create new backend instance
    let new_backend = FilesystemBackend::<String, TestData>::new(cache_dir).await.unwrap();
    
    // Data should still be accessible
    assert!(new_backend.exists(&"persist_key".to_string()).await.unwrap());
    let loaded = new_backend.load(&"persist_key".to_string()).await.unwrap();
    assert!(loaded.is_some());
    assert_eq!(loaded.unwrap().value, test_data);
}

#[cfg(feature = "filesystem-backend")]
#[tokio::test]
async fn test_filesystem_backend_overwrite() {
    let temp_dir = TempDir::new().unwrap();
    let cache_dir = temp_dir.path().to_path_buf();
    
    let backend = FilesystemBackend::<String, TestData>::new(cache_dir.clone()).await.unwrap();
    
    let original_data = TestData::new(1, "original", 100);
    let original_entry = create_test_entry("overwrite_key", original_data.clone());
    
    // Store original
    backend.store("overwrite_key".to_string(), original_entry).await.unwrap();
    
    // Verify original
    let loaded = backend.load(&"overwrite_key".to_string()).await.unwrap().unwrap();
    assert_eq!(loaded.value, original_data);
    
    // Overwrite with new data
    let new_data = TestData::new(2, "updated", 200);
    let new_entry = create_test_entry("overwrite_key", new_data.clone());
    backend.store("overwrite_key".to_string(), new_entry).await.unwrap();
    
    // Verify new data
    let loaded = backend.load(&"overwrite_key".to_string()).await.unwrap().unwrap();
    assert_eq!(loaded.value, new_data);
    assert_ne!(loaded.value, original_data);
}

#[cfg(feature = "filesystem-backend")]
#[tokio::test]
async fn test_filesystem_backend_clear() {
    let temp_dir = TempDir::new().unwrap();
    let cache_dir = temp_dir.path().to_path_buf();
    
    let backend = FilesystemBackend::<String, TestData>::new(cache_dir.clone()).await.unwrap();
    
    // Add some entries
    for i in 1..=5 {
        let data = TestData::new(i, &format!("clear_test_{}", i), i as i32);
        let entry = create_test_entry(&format!("clear_key_{}", i), data);
        backend.store(format!("clear_key_{}", i), entry).await.unwrap();
    }
    
    // Verify entries exist
    assert_eq!(backend.list_keys().await.unwrap().len(), 5);
    
    // Verify files exist
    for i in 1..=5 {
        let file_path = cache_dir.join(format!("clear_key_{}.cache", i));
        assert!(file_path.exists());
    }
    
    // Clear all
    backend.clear().await.unwrap();
    
    // Verify empty
    assert_eq!(backend.list_keys().await.unwrap().len(), 0);
    
    // Verify files are deleted
    for i in 1..=5 {
        let file_path = cache_dir.join(format!("clear_key_{}.cache", i));
        assert!(!file_path.exists());
        assert!(!backend.exists(&format!("clear_key_{}", i)).await.unwrap());
    }
}

#[cfg(feature = "filesystem-backend")]
#[tokio::test]
async fn test_filesystem_backend_special_characters() {
    let temp_dir = TempDir::new().unwrap();
    let cache_dir = temp_dir.path().to_path_buf();
    
    let backend = FilesystemBackend::<String, TestData>::new(cache_dir).await.unwrap();
    
    // Test keys with special characters (implementation should handle them)
    let special_keys = vec![
        "key with spaces",
        "key/with/slashes",
        "key-with-dashes",
        "key_with_underscores",
        "key.with.dots",
        "key:with:colons",
    ];
    
    for (i, key) in special_keys.iter().enumerate() {
        let data = TestData::new(i as u32, &format!("special_{}", i), i as i32);
        let entry = create_test_entry(key, data.clone());
        
        // Store should handle special characters
        let result = backend.store(key.to_string(), entry).await;
        if result.is_ok() {
            // If storage succeeds, retrieval should also work
            let loaded = backend.load(&key.to_string()).await.unwrap();
            assert!(loaded.is_some());
            assert_eq!(loaded.unwrap().value, data);
        }
        // Some special characters might be rejected - that's acceptable
    }
}

#[cfg(feature = "filesystem-backend")]
#[tokio::test]
async fn test_filesystem_backend_large_data() {
    let temp_dir = TempDir::new().unwrap();
    let cache_dir = temp_dir.path().to_path_buf();
    
    let backend = FilesystemBackend::<String, String>::new(cache_dir.clone()).await.unwrap();
    
    // Test with large data
    let large_string = "x".repeat(1024 * 1024); // 1MB string
    let large_entry = CacheEntry {
        key: "large_key".to_string(),
        value: large_string.clone(),
        metadata: EntryMetadata {
            created_at: SystemTime::now(),
            last_accessed: SystemTime::now(),
            access_count: 1,
            size_bytes: large_string.len(),
            ttl: None,
        },
    };
    
    // Store large data
    backend.store("large_key".to_string(), large_entry).await.unwrap();
    
    // Verify file was created
    let file_path = cache_dir.join("large_key.cache");
    assert!(file_path.exists());
    
    // Load large data
    let loaded = backend.load(&"large_key".to_string()).await.unwrap().unwrap();
    assert_eq!(loaded.value.len(), 1024 * 1024);
    assert_eq!(loaded.value, large_string);
}

#[cfg(feature = "filesystem-backend")]
#[tokio::test]
async fn test_filesystem_backend_corruption_recovery() {
    let temp_dir = TempDir::new().unwrap();
    let cache_dir = temp_dir.path().to_path_buf();
    
    let backend = FilesystemBackend::<String, TestData>::new(cache_dir.clone()).await.unwrap();
    
    let test_data = TestData::new(1, "corruption_test", 42);
    let entry = create_test_entry("corrupt_key", test_data);
    
    // Store valid data
    backend.store("corrupt_key".to_string(), entry).await.unwrap();
    
    // Corrupt the file
    let file_path = cache_dir.join("corrupt_key.cache");
    std::fs::write(&file_path, b"corrupted data").unwrap();
    
    // Loading corrupted data should handle gracefully
    let result = backend.load(&"corrupt_key".to_string()).await;
    match result {
        Ok(None) => {
            // Acceptable - corrupted data treated as missing
        }
        Err(_) => {
            // Acceptable - error due to corruption
        }
        Ok(Some(_)) => {
            // Should not happen with corrupted data
            panic!("Should not successfully load corrupted data");
        }
    }
}

#[cfg(feature = "filesystem-backend")]
#[tokio::test]
async fn test_filesystem_backend_concurrent_access() {
    use std::sync::Arc;
    use tokio::task;
    
    let temp_dir = TempDir::new().unwrap();
    let cache_dir = temp_dir.path().to_path_buf();
    
    let backend = Arc::new(FilesystemBackend::<String, TestData>::new(cache_dir).await.unwrap());
    let num_tasks = 5;
    let entries_per_task = 20;
    
    let mut handles = vec![];
    
    // Spawn concurrent write tasks
    for task_id in 0..num_tasks {
        let backend_clone = Arc::clone(&backend);
        let handle = task::spawn(async move {
            for i in 0..entries_per_task {
                let key = format!("concurrent_{}_{}", task_id, i);
                let data = TestData::new(task_id * 1000 + i, &key, i as i32);
                let entry = create_test_entry(&key, data);
                
                backend_clone.store(key, entry).await.unwrap();
            }
        });
        handles.push(handle);
    }
    
    // Wait for all writes to complete
    for handle in handles {
        handle.await.unwrap();
    }
    
    // Verify all entries were stored
    let keys = backend.list_keys().await.unwrap();
    assert_eq!(keys.len(), num_tasks * entries_per_task);
    
    // Spawn concurrent read tasks
    let mut read_handles = vec![];
    for task_id in 0..num_tasks {
        let backend_clone = Arc::clone(&backend);
        let handle = task::spawn(async move {
            for i in 0..entries_per_task {
                let key = format!("concurrent_{}_{}", task_id, i);
                let loaded = backend_clone.load(&key).await.unwrap();
                assert!(loaded.is_some());
                
                let entry = loaded.unwrap();
                assert_eq!(entry.value.id, task_id * 1000 + i);
                assert_eq!(entry.value.name, key);
                assert_eq!(entry.value.value, i as i32);
            }
        });
        read_handles.push(handle);
    }
    
    // Wait for all reads to complete
    for handle in read_handles {
        handle.await.unwrap();
    }
}

#[cfg(feature = "filesystem-backend")]
#[tokio::test]
async fn test_filesystem_backend_directory_creation() {
    let temp_dir = TempDir::new().unwrap();
    let nested_cache_dir = temp_dir.path().join("nested").join("cache").join("dir");
    
    // Directory doesn't exist yet
    assert!(!nested_cache_dir.exists());
    
    // Creating backend should create the directory
    let backend = FilesystemBackend::<String, TestData>::new(nested_cache_dir.clone()).await.unwrap();
    
    // Directory should now exist
    assert!(nested_cache_dir.exists());
    assert!(nested_cache_dir.is_dir());
    
    // Should be able to store data
    let data = TestData::new(1, "directory_test", 42);
    let entry = create_test_entry("dir_key", data.clone());
    backend.store("dir_key".to_string(), entry).await.unwrap();
    
    let loaded = backend.load(&"dir_key".to_string()).await.unwrap().unwrap();
    assert_eq!(loaded.value, data);
}

#[cfg(feature = "filesystem-backend")]
#[tokio::test]
async fn test_filesystem_backend_error_handling() {
    let temp_dir = TempDir::new().unwrap();
    let cache_dir = temp_dir.path().to_path_buf();
    
    let backend = FilesystemBackend::<String, TestData>::new(cache_dir).await.unwrap();
    
    // Test operations on nonexistent entries
    let result = backend.load(&"nonexistent".to_string()).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
    
    let result = backend.remove(&"nonexistent".to_string()).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
    
    let result = backend.exists(&"nonexistent".to_string()).await;
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[cfg(not(feature = "filesystem-backend"))]
#[tokio::test]
async fn test_filesystem_backend_feature_disabled() {
    // When filesystem-backend feature is disabled, ensure the module compiles
    // but the functionality is not available
    println!("Filesystem backend feature is disabled");
}