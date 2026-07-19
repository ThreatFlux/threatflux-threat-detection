//! Rule update management for threat detection

use crate::error::{Result, ThreatError};
use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};

/// Rule source configuration
#[derive(Debug, Clone)]
pub struct RuleSource {
    /// Name of the rule source
    pub name: String,
    /// URL or path to rule source
    pub url: String,
    /// Type of source (git, http, file)
    pub source_type: RuleSourceType,
    /// Update frequency in hours
    pub update_frequency_hours: u64,
    /// Last update timestamp
    pub last_updated: Option<DateTime<Utc>>,
}

/// Types of rule sources
#[derive(Debug, Clone)]
pub enum RuleSourceType {
    /// Git repository
    Git,
    /// HTTP endpoint
    Http,
    /// Local file system
    File,
    /// Local file system (compatibility alias)
    Local,
    /// Rules compiled into this crate
    Builtin,
}

/// Rule updater for managing threat detection rules
pub struct RuleUpdater {
    sources: Vec<RuleSource>,
    rules_directory: std::path::PathBuf,
}

impl RuleUpdater {
    /// Create a new rule updater
    pub fn new<P: AsRef<Path>>(rules_directory: P) -> Self {
        Self {
            sources: Vec::new(),
            rules_directory: rules_directory.as_ref().to_path_buf(),
        }
    }

    /// Add a rule source
    pub fn add_source(&mut self, source: RuleSource) {
        self.sources.push(source);
    }

    /// Update rules from all sources
    pub async fn update_all(&mut self) -> Result<()> {
        let rules_directory = self.rules_directory.clone();
        for source in &mut self.sources {
            if let Err(e) = Self::update_source(&rules_directory, source).await {
                log::warn!("Failed to update source {}: {}", source.name, e);
            }
        }
        Ok(())
    }

    /// Update rules from a specific source
    async fn update_source(rules_directory: &Path, source: &mut RuleSource) -> Result<()> {
        match source.source_type {
            RuleSourceType::Git => Self::update_from_git(rules_directory, source).await,
            RuleSourceType::Http => Self::update_from_http(source).await,
            RuleSourceType::File | RuleSourceType::Local => Self::update_from_file(source).await,
            RuleSourceType::Builtin => {
                source.last_updated = Some(Utc::now());
                Ok(())
            }
        }
    }

    /// Update rules from Git repository
    async fn update_from_git(rules_directory: &Path, source: &mut RuleSource) -> Result<()> {
        log::info!("Updating rules from Git source: {}", source.name);
        fetch_git_rules(source, rules_directory).await?;
        source.last_updated = Some(Utc::now());
        Ok(())
    }

    /// Update rules from HTTP endpoint
    async fn update_from_http(source: &mut RuleSource) -> Result<()> {
        log::info!("Updating rules from HTTP source: {}", source.name);
        fetch_http_rules(source).await?;
        source.last_updated = Some(Utc::now());
        Ok(())
    }

    /// Update rules from local file
    async fn update_from_file(source: &mut RuleSource) -> Result<()> {
        log::info!("Updating rules from file source: {}", source.name);

        if !Path::new(&source.url).exists() {
            return Err(ThreatError::rule_not_found(&source.url));
        }

        source.last_updated = Some(Utc::now());
        Ok(())
    }

    /// Check if sources need updating
    pub fn needs_update(&self) -> Vec<&RuleSource> {
        let now = Utc::now();
        self.sources
            .iter()
            .filter(|source| {
                match source.last_updated {
                    Some(last_update) => {
                        let hours_since_update = (now - last_update).num_hours() as u64;
                        hours_since_update >= source.update_frequency_hours
                    }
                    None => true, // Never updated
                }
            })
            .collect()
    }

    /// Get rule sources
    pub fn get_sources(&self) -> &[RuleSource] {
        &self.sources
    }

    /// Get rules directory
    pub fn rules_directory(&self) -> &Path {
        &self.rules_directory
    }
}

/// Validate that a rule source can be refreshed.
pub async fn update_source(source: &RuleSource, rules_directory: &Path) -> Result<()> {
    match source.source_type {
        RuleSourceType::Git => fetch_git_rules(source, rules_directory).await.map(drop),
        RuleSourceType::Http => fetch_http_rules(source).await.map(drop),
        RuleSourceType::File | RuleSourceType::Local => {
            std::fs::metadata(&source.url).map(drop).map_err(|error| {
                ThreatError::rule_update(format!("Local rule source {}: {error}", source.url))
            })
        }
        RuleSourceType::Builtin => Ok(()),
    }
}

/// Fetch YARA source text from an HTTP endpoint.
pub async fn fetch_http_rules(source: &RuleSource) -> Result<String> {
    reqwest::get(&source.url)
        .await?
        .error_for_status()?
        .text()
        .await
        .map_err(Into::into)
}

/// Clone a Git rule source and return all `.yar` and `.yara` files in it.
pub async fn fetch_git_rules(source: &RuleSource, rules_directory: &Path) -> Result<String> {
    let source_url = source.url.clone();
    let rules_directory = rules_directory.to_path_buf();

    tokio::task::spawn_blocking(move || read_git_rules(&source_url, &rules_directory))
        .await
        .map_err(|error| ThreatError::internal(format!("Git rule task failed: {error}")))?
}

fn read_git_rules(source_url: &str, rules_directory: &Path) -> Result<String> {
    std::fs::create_dir_all(rules_directory).map_err(|error| {
        ThreatError::rule_update(format!(
            "Failed to create rule cache {}: {error}",
            rules_directory.display()
        ))
    })?;

    let clone_directory = rules_directory.join(format!("fetch-{}", uuid::Uuid::new_v4()));
    let result = read_cloned_git_rules(source_url, &clone_directory);
    if let Err(error) = std::fs::remove_dir_all(&clone_directory) {
        log::warn!(
            "Failed to remove temporary rule clone {}: {}",
            clone_directory.display(),
            error
        );
    }
    result
}

fn read_cloned_git_rules(source_url: &str, clone_directory: &Path) -> Result<String> {
    let mut builder = git2::build::RepoBuilder::new();
    if !Path::new(source_url).exists() && !source_url.starts_with("file://") {
        let mut fetch_options = git2::FetchOptions::new();
        fetch_options.depth(1);
        builder.fetch_options(fetch_options);
    }
    builder
        .clone(source_url, clone_directory)
        .map_err(|error| {
            ThreatError::rule_update(format!("Failed to clone rule source {source_url}: {error}"))
        })?;

    let mut rule_files: Vec<PathBuf> = walkdir::WalkDir::new(clone_directory)
        .follow_links(false)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| {
            matches!(
                path.extension().and_then(|extension| extension.to_str()),
                Some("yar" | "yara")
            )
        })
        .collect();
    rule_files.sort();

    if rule_files.is_empty() {
        return Err(ThreatError::rule_load(format!(
            "Git rule source {source_url} contains no .yar or .yara files"
        )));
    }

    let mut rules = String::new();
    for path in rule_files {
        let content = std::fs::read_to_string(&path).map_err(|error| {
            ThreatError::rule_load(format!("Failed to read {}: {error}", path.display()))
        })?;
        rules.push_str(&content);
        rules.push('\n');
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_rule_repository(source_directory: &Path) {
        std::fs::create_dir(source_directory).expect("source directory should be created");

        let repository = git2::Repository::init(source_directory)
            .expect("source repository should be initialized");
        std::fs::write(
            source_directory.join("example.yar"),
            "rule example { condition: true }",
        )
        .expect("rule should be written");
        std::fs::write(source_directory.join("README.md"), "ignored")
            .expect("README should be written");

        let mut index = repository.index().expect("index should open");
        index
            .add_path(Path::new("example.yar"))
            .expect("rule should be added");
        index
            .add_path(Path::new("README.md"))
            .expect("README should be added");
        let tree_id = index.write_tree().expect("tree should be written");
        let tree = repository.find_tree(tree_id).expect("tree should be found");
        let signature = git2::Signature::now("ThreatFlux Test", "test@threatflux.local")
            .expect("signature should be created");
        repository
            .commit(
                Some("HEAD"),
                &signature,
                &signature,
                "test rules",
                &tree,
                &[],
            )
            .expect("commit should be created");
        drop(tree);
        drop(repository);
    }

    #[test]
    fn fetches_rules_from_local_git_repository() {
        let temporary = tempfile::tempdir().expect("temporary directory should be created");
        let source_directory = temporary.path().join("source");
        create_rule_repository(&source_directory);

        let cache_directory = temporary.path().join("cache");
        let rules = read_git_rules(
            source_directory
                .to_str()
                .expect("source path should be UTF-8"),
            &cache_directory,
        )
        .expect("rules should be fetched");

        assert_eq!(rules, "rule example { condition: true }\n");
        assert_eq!(
            std::fs::read_dir(cache_directory)
                .expect("cache should exist")
                .count(),
            0
        );
    }
}
