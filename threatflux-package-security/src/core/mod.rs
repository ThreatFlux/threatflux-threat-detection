//! Core traits and structures for package security analysis

pub mod package;
pub mod dependency;
pub mod vulnerability;
pub mod risk;
pub mod patterns;

pub use package::{PackageInfo, PackageAnalyzer, AnalysisResult, PackageMetadata};
pub use dependency::{Dependency, DependencyType, DependencyAnalysis};
pub use vulnerability::{Vulnerability, VulnerabilitySeverity, VulnerabilityDatabase, UpdateResult, DatabaseStatistics};
pub use risk::{RiskLevel, RiskScore, RiskAssessment, RiskCalculator, SecurityPosture};
pub use patterns::{MaliciousPattern, PatternMatcher, PatternDatabase};