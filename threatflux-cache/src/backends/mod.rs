//! Storage backend implementations

pub mod memory;

#[cfg(feature = "filesystem-backend")]
pub mod filesystem;