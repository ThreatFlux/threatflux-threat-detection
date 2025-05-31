use file_scanner::metadata::FileMetadata;
use std::path::Path;
use std::time::SystemTime;

/// Common test utilities
pub mod utils {
    use super::*;
    
    /// Compare two FileMetadata structs, ignoring timestamps
    pub fn assert_metadata_equal_ignore_time(actual: &FileMetadata, expected: &FileMetadata) {
        assert_eq!(actual.path, expected.path);
        assert_eq!(actual.size, expected.size);
        assert_eq!(actual.file_type, expected.file_type);
        assert_eq!(actual.permissions, expected.permissions);
        assert_eq!(actual.owner, expected.owner);
        assert_eq!(actual.group, expected.group);
        assert_eq!(actual.is_hidden, expected.is_hidden);
        assert_eq!(actual.is_symlink, expected.is_symlink);
        assert_eq!(actual.symlink_target, expected.symlink_target);
    }
    
    /// Check if a timestamp is recent (within last minute)
    pub fn is_recent_timestamp(time: &Option<SystemTime>) -> bool {
        if let Some(t) = time {
            if let Ok(elapsed) = t.elapsed() {
                return elapsed.as_secs() < 60;
            }
        }
        false
    }
    
    /// Assert that a Result is an error with specific message content
    pub fn assert_error_contains<T, E: std::fmt::Display>(
        result: Result<T, E>,
        expected_msg: &str,
    ) {
        match result {
            Ok(_) => panic!("Expected error containing '{}', but got Ok", expected_msg),
            Err(e) => {
                let error_msg = e.to_string();
                assert!(
                    error_msg.contains(expected_msg),
                    "Error message '{}' does not contain '{}'",
                    error_msg,
                    expected_msg
                );
            }
        }
    }
}

/// Mock implementations for testing
pub mod mocks {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    
    /// Mock file system for testing without actual file I/O
    pub struct MockFileSystem {
        files: HashMap<PathBuf, MockFile>,
    }
    
    pub struct MockFile {
        pub content: Vec<u8>,
        pub metadata: MockMetadata,
    }
    
    pub struct MockMetadata {
        pub size: u64,
        pub is_file: bool,
        pub is_dir: bool,
        pub permissions: u32,
    }
    
    impl MockFileSystem {
        pub fn new() -> Self {
            Self {
                files: HashMap::new(),
            }
        }
        
        pub fn add_file(&mut self, path: impl Into<PathBuf>, content: Vec<u8>) {
            let path = path.into();
            let metadata = MockMetadata {
                size: content.len() as u64,
                is_file: true,
                is_dir: false,
                permissions: 0o644,
            };
            self.files.insert(path, MockFile { content, metadata });
        }
        
        pub fn get_file(&self, path: &Path) -> Option<&MockFile> {
            self.files.get(path)
        }
    }
}

/// Test data generators
pub mod generators {
    use rand::Rng;
    
    /// Generate random bytes of specified length
    pub fn random_bytes(len: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        (0..len).map(|_| rng.gen()).collect()
    }
    
    /// Generate a string with specific pattern
    pub fn generate_string_pattern(base: &str, count: usize) -> String {
        (0..count).map(|i| format!("{}{}", base, i)).collect::<Vec<_>>().join("\n")
    }
    
    /// Generate test binary with embedded strings
    pub fn generate_binary_with_strings(strings: &[&str]) -> Vec<u8> {
        let mut result = Vec::new();
        for s in strings {
            // Add some padding
            result.extend_from_slice(&[0x00; 16]);
            // Add the string
            result.extend_from_slice(s.as_bytes());
            // Add null terminator
            result.push(0x00);
        }
        result
    }
}

/// Assertion helpers
pub mod assertions {
    use pretty_assertions::assert_eq;
    
    /// Assert two vectors are equal, showing differences clearly
    pub fn assert_vec_eq<T: std::fmt::Debug + PartialEq>(actual: &[T], expected: &[T]) {
        assert_eq!(actual, expected);
    }
    
    /// Assert a vector contains specific items
    pub fn assert_vec_contains<T: std::fmt::Debug + PartialEq>(vec: &[T], items: &[T]) {
        for item in items {
            assert!(
                vec.contains(item),
                "Vector {:?} does not contain {:?}",
                vec,
                item
            );
        }
    }
    
    /// Assert a string contains all substrings
    pub fn assert_contains_all(haystack: &str, needles: &[&str]) {
        for needle in needles {
            assert!(
                haystack.contains(needle),
                "String '{}' does not contain '{}'",
                haystack,
                needle
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_random_bytes_generator() {
        let bytes1 = generators::random_bytes(100);
        let bytes2 = generators::random_bytes(100);
        assert_eq!(bytes1.len(), 100);
        assert_eq!(bytes2.len(), 100);
        assert_ne!(bytes1, bytes2); // Should be different (very high probability)
    }
    
    #[test]
    fn test_string_pattern_generator() {
        let pattern = generators::generate_string_pattern("test", 3);
        assert_eq!(pattern, "test0\ntest1\ntest2");
    }
}