//! # ThreatFlux Cache
//!
//! A flexible async cache library for Rust with pluggable backends and serialization.
//!
//! ## Features
//!
//! - **Async-first**: Built on tokio for high-performance async operations
//! - **Generic**: Works with any serializable key-value types
//! - **Pluggable backends**: Filesystem, memory, or custom implementations
//! - **Flexible serialization**: JSON, bincode, or custom formats
//! - **Eviction policies**: LRU, LFU, FIFO, TTL-based eviction
//! - **Compression**: Optional compression for stored values
//! - **Search capabilities**: Query cache entries with custom predicates
//! - **Metrics**: Optional Prometheus metrics integration
//!
//! ## Quick Start
//!
//! ```rust
//! use threatflux_cache::{Cache, CacheConfig};
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Serialize, Deserialize, Clone)]
//! struct MyData {
//!     content: String,
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a cache with default configuration
//!     let cache = Cache::<String, MyData>::new(CacheConfig::default())?;
//!     
//!     // Store a value
//!     cache.put("key1".to_string(), MyData { content: "Hello".to_string() }).await?;
//!     
//!     // Retrieve a value
//!     if let Some(data) = cache.get("key1").await? {
//!         println!("Found: {}", data.content);
//!     }
//!     
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

pub mod cache;
pub mod entry;
pub mod error;
pub mod storage;
pub mod backends;
pub mod config;
pub mod eviction;
pub mod search;

#[cfg(feature = "metrics")]
pub mod metrics;

// Re-export main types
pub use cache::{Cache, AsyncCache};
pub use entry::{CacheEntry, EntryMetadata};
pub use error::{CacheError, Result};
pub use config::{CacheConfig, EvictionPolicy, PersistenceConfig};
pub use storage::StorageBackend;
pub use search::{Searchable, SearchQuery};

// Re-export backend implementations
pub use backends::memory::MemoryBackend;
#[cfg(feature = "filesystem-backend")]
pub use backends::filesystem::FilesystemBackend;

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::{
        AsyncCache, Cache, CacheConfig, CacheEntry, CacheError, Result,
        EntryMetadata, StorageBackend, Searchable,
    };
    
    #[cfg(feature = "filesystem-backend")]
    pub use crate::FilesystemBackend;
    pub use crate::MemoryBackend;
}