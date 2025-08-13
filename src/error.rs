//! Error types for the cache library

use std::io;
use thiserror::Error;

/// Main error type for cache operations
#[derive(Error, Debug)]
pub enum CacheError {
    /// I/O error occurred during cache operations
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// Cache capacity exceeded
    #[error("Cache capacity exceeded: {message}")]
    CapacityExceeded {
        /// Error message
        message: String,
    },

    /// Storage backend error
    #[error("Storage backend error: {0}")]
    StorageBackend(String),

    /// Entry not found
    #[error("Entry not found for key")]
    NotFound,

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// Compression error
    #[cfg(feature = "compression")]
    #[error("Compression error: {0}")]
    Compression(String),

    /// Custom error for extensions
    #[error("Custom error: {0}")]
    Custom(String),
}

/// Result type alias for cache operations
pub type Result<T> = std::result::Result<T, CacheError>;

// Implement conversions for common serialization errors
#[cfg(feature = "json-serialization")]
impl From<serde_json::Error> for CacheError {
    fn from(err: serde_json::Error) -> Self {
        if err.is_data() || err.is_eof() {
            CacheError::Deserialization(err.to_string())
        } else {
            CacheError::Serialization(err.to_string())
        }
    }
}

#[cfg(feature = "bincode-serialization")]
impl From<bincode::Error> for CacheError {
    fn from(err: bincode::Error) -> Self {
        CacheError::Serialization(err.to_string())
    }
}
