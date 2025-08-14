//! Detection engines for threat analysis

#[cfg(feature = "yara-engine")]
pub mod yara;

#[cfg(feature = "clamav-engine")]
pub mod clamav;

#[cfg(feature = "pattern-matching")]
pub mod patterns;
