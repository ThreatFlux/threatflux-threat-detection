//! Integration test for threatflux-cache

use threatflux_cache::{Cache, CacheConfig, AsyncCache};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TestData {
    id: u32,
    name: String,
    value: i32,
}

#[tokio::test]
async fn test_cache_basic_operations() {
    // Create a cache with default configuration
    let config = CacheConfig::default()
        .with_max_entries_per_key(5)
        .with_max_total_entries(100);
    
    let cache: Cache<String, TestData> = Cache::with_config(config).await.unwrap();
    
    // Test data
    let test_data = TestData {
        id: 1,
        name: "Test Item".to_string(),
        value: 42,
    };
    
    // Test basic operations
    
    // Put operation
    cache.put("test_key".to_string(), test_data.clone()).await.unwrap();
    
    // Get operation
    let retrieved = cache.get(&"test_key".to_string()).await.unwrap();
    assert_eq!(retrieved, Some(test_data.clone()));
    
    // Contains operation
    assert!(cache.contains(&"test_key".to_string()).await.unwrap());
    
    // Cache statistics
    let len = cache.len().await.unwrap();
    assert!(len > 0);
    
    // Remove operation
    let removed = cache.remove(&"test_key".to_string()).await.unwrap();
    assert_eq!(removed, Some(test_data));
    
    // Verify empty after removal
    assert!(cache.is_empty().await.unwrap());
    
    // Clear operation
    cache.clear().await.unwrap();
}

#[tokio::test]
async fn test_cache_multiple_entries() {
    let config = CacheConfig::default();
    let cache: Cache<String, String> = Cache::with_config(config).await.unwrap();
    
    // Add multiple entries
    for i in 1..=5 {
        cache.put(format!("key{}", i), format!("value{}", i)).await.unwrap();
    }
    
    // Verify all entries exist
    for i in 1..=5 {
        let value = cache.get(&format!("key{}", i)).await.unwrap();
        assert_eq!(value, Some(format!("value{}", i)));
    }
    
    // Check total length
    let len = cache.len().await.unwrap();
    assert_eq!(len, 5);
}