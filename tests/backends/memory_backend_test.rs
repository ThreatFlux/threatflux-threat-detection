//! Tests for memory backend implementation

use threatflux_cache::backends::memory::MemoryBackend;
use threatflux_cache::{StorageBackend, CacheEntry, EntryMetadata};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

#[tokio::test]
async fn test_memory_backend_basic_operations() {
    let backend = MemoryBackend::<String, TestData>::new();
    
    let test_data = TestData::new(1, "test", 42);
    let entry = create_test_entry("test_key", test_data.clone());
    
    // Test store
    backend.store("test_key".to_string(), entry.clone()).await.unwrap();
    
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
    
    // Verify removed
    assert!(!backend.exists(&"test_key".to_string()).await.unwrap());
    assert!(backend.load(&"test_key".to_string()).await.unwrap().is_none());
}

#[tokio::test]
async fn test_memory_backend_multiple_entries() {
    let backend = MemoryBackend::<String, TestData>::new();
    
    // Store multiple entries
    for i in 1..=10 {
        let data = TestData::new(i, &format!("test_{}", i), i as i32 * 10);
        let entry = create_test_entry(&format!("key_{}", i), data);
        backend.store(format!("key_{}", i), entry).await.unwrap();
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

#[tokio::test]
async fn test_memory_backend_overwrite() {
    let backend = MemoryBackend::<String, TestData>::new();
    
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

#[tokio::test]
async fn test_memory_backend_clear() {
    let backend = MemoryBackend::<String, TestData>::new();
    
    // Add some entries
    for i in 1..=5 {
        let data = TestData::new(i, &format!("clear_test_{}", i), i as i32);
        let entry = create_test_entry(&format!("clear_key_{}", i), data);
        backend.store(format!("clear_key_{}", i), entry).await.unwrap();
    }
    
    // Verify entries exist
    assert_eq!(backend.list_keys().await.unwrap().len(), 5);
    
    // Clear all
    backend.clear().await.unwrap();
    
    // Verify empty
    assert_eq!(backend.list_keys().await.unwrap().len(), 0);
    
    for i in 1..=5 {
        assert!(!backend.exists(&format!("clear_key_{}", i)).await.unwrap());
    }
}

#[tokio::test]
async fn test_memory_backend_concurrent_access() {
    use std::sync::Arc;
    use tokio::task;
    
    let backend = Arc::new(MemoryBackend::<String, TestData>::new());
    let num_tasks = 10;
    let entries_per_task = 100;
    
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

#[tokio::test]
async fn test_memory_backend_large_data() {
    let backend = MemoryBackend::<String, String>::new();
    
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
    
    // Load large data
    let loaded = backend.load(&"large_key".to_string()).await.unwrap().unwrap();
    assert_eq!(loaded.value.len(), 1024 * 1024);
    assert_eq!(loaded.value, large_string);
}

#[tokio::test]
async fn test_memory_backend_empty_operations() {
    let backend = MemoryBackend::<String, TestData>::new();
    
    // Test operations on empty backend
    assert!(!backend.exists(&"empty".to_string()).await.unwrap());
    assert!(backend.load(&"empty".to_string()).await.unwrap().is_none());
    assert!(backend.remove(&"empty".to_string()).await.unwrap().is_none());
    assert!(backend.list_keys().await.unwrap().is_empty());
    
    // Clear empty backend (should not fail)
    backend.clear().await.unwrap();
}

#[tokio::test]
async fn test_memory_backend_metadata_preservation() {
    let backend = MemoryBackend::<String, TestData>::new();
    
    let data = TestData::new(1, "metadata_test", 42);
    let created_time = SystemTime::now();
    let access_time = created_time + Duration::from_secs(1);
    
    let entry = CacheEntry {
        key: "metadata_key".to_string(),
        value: data.clone(),
        metadata: EntryMetadata {
            created_at: created_time,
            last_accessed: access_time,
            access_count: 5,
            size_bytes: 128,
            ttl: Some(Duration::from_secs(3600)),
        },
    };
    
    // Store with metadata
    backend.store("metadata_key".to_string(), entry.clone()).await.unwrap();
    
    // Load and verify metadata is preserved
    let loaded = backend.load(&"metadata_key".to_string()).await.unwrap().unwrap();
    
    assert_eq!(loaded.value, data);
    assert_eq!(loaded.metadata.created_at, created_time);
    assert_eq!(loaded.metadata.last_accessed, access_time);
    assert_eq!(loaded.metadata.access_count, 5);
    assert_eq!(loaded.metadata.size_bytes, 128);
    assert_eq!(loaded.metadata.ttl, Some(Duration::from_secs(3600)));
}

#[tokio::test]
async fn test_memory_backend_error_handling() {
    let backend = MemoryBackend::<String, TestData>::new();
    
    // These operations should not fail but might return None/empty results
    let result = backend.load(&"nonexistent".to_string()).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
    
    let result = backend.remove(&"nonexistent".to_string()).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
    
    let result = backend.exists(&"nonexistent".to_string()).await;
    assert!(result.is_ok());
    assert!(!result.unwrap());
    
    let result = backend.list_keys().await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[tokio::test]
async fn test_memory_backend_key_types() {
    // Test with different key types
    let string_backend = MemoryBackend::<String, i32>::new();
    let int_backend = MemoryBackend::<i32, String>::new();
    
    // String keys
    let string_entry = CacheEntry {
        key: "string_key".to_string(),
        value: 42,
        metadata: EntryMetadata {
            created_at: SystemTime::now(),
            last_accessed: SystemTime::now(),
            access_count: 1,
            size_bytes: 4,
            ttl: None,
        },
    };
    
    string_backend.store("string_key".to_string(), string_entry).await.unwrap();
    assert!(string_backend.exists(&"string_key".to_string()).await.unwrap());
    
    // Integer keys
    let int_entry = CacheEntry {
        key: 123,
        value: "integer_value".to_string(),
        metadata: EntryMetadata {
            created_at: SystemTime::now(),
            last_accessed: SystemTime::now(),
            access_count: 1,
            size_bytes: 13,
            ttl: None,
        },
    };
    
    int_backend.store(123, int_entry).await.unwrap();
    assert!(int_backend.exists(&123).await.unwrap());
}

#[tokio::test] 
async fn test_memory_backend_performance() {
    let backend = MemoryBackend::<String, TestData>::new();
    let num_entries = 10000;
    
    // Measure insertion time
    let start_time = std::time::Instant::now();
    
    for i in 0..num_entries {
        let data = TestData::new(i, &format!("perf_test_{}", i), i as i32);
        let entry = create_test_entry(&format!("perf_key_{}", i), data);
        backend.store(format!("perf_key_{}", i), entry).await.unwrap();
    }
    
    let insertion_time = start_time.elapsed();
    println!("Inserted {} entries in {:?}", num_entries, insertion_time);
    
    // Measure retrieval time
    let start_time = std::time::Instant::now();
    
    for i in 0..num_entries {
        let loaded = backend.load(&format!("perf_key_{}", i)).await.unwrap();
        assert!(loaded.is_some());
    }
    
    let retrieval_time = start_time.elapsed();
    println!("Retrieved {} entries in {:?}", num_entries, retrieval_time);
    
    // Performance should be reasonable
    assert!(insertion_time.as_millis() < 10000); // Less than 10 seconds
    assert!(retrieval_time.as_millis() < 5000);  // Less than 5 seconds
}