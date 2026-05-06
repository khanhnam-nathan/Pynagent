//! Supply Chain Security Scanner
//!
//! Provides comprehensive supply chain security analysis:
//! - Dependency confusion detection
//! - CVE checking via OSV.dev API
//! - Lock file integrity verification
//! - License compliance scanning

pub mod vuln_db;
pub mod lock_parser;
pub mod license;
pub mod rules;

pub use vuln_db::Ecosystem;
#[allow(unused)]
pub use vuln_db::OsvClient;
#[allow(unused)]
pub use lock_parser::{LockPackage, IntegrityStatus};
#[allow(unused)]
pub use license::detect_from_license_file;

use std::path::Path;
use walkdir::WalkDir;

/// A discovered lock file with its ecosystem type.
#[derive(Debug, Clone)]
pub struct DiscoveredLockFile {
    pub path: std::path::PathBuf,
    pub ecosystem: Ecosystem,
    pub file_name: String,
}

impl DiscoveredLockFile {
    pub fn ecosystem_label(&self) -> &'static str {
        self.ecosystem.as_str()
    }
}

/// Discover all lock files in a project directory.
///
/// Searches for:
/// - `package-lock.json`, `yarn.lock` (npm/Yarn)
/// - `go.sum`, `go.mod` (Go)
/// - `requirements.txt`, `Pipfile.lock`, `poetry.lock` (Python)
/// - `Cargo.lock` (Rust)
/// - `Gemfile.lock` (Ruby)
/// - `*.csproj`, `packages.config` (.NET)
/// - `composer.lock` (PHP)
/// - `pom.xml`, `build.gradle` (Java/Maven/Gradle)
pub fn discover_lock_files(root: &Path) -> Vec<DiscoveredLockFile> {
    let mut results = Vec::new();

    if !root.is_dir() {
        return results;
    }

    for entry in WalkDir::new(root)
        .follow_links(false)
        .max_depth(5)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let file_name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();

        let ecosystem = match file_name {
            "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml" => Some(Ecosystem::Npm),
            "go.sum" | "go.mod" => Some(Ecosystem::Go),
            "requirements.txt" => Some(Ecosystem::PyPI),
            "Pipfile.lock" => Some(Ecosystem::PyPI),
            "poetry.lock" => Some(Ecosystem::PyPI),
            "Cargo.lock" => Some(Ecosystem::CratesIo),
            "Gemfile.lock" => Some(Ecosystem::RubyGems),
            "composer.lock" => Some(Ecosystem::Packagist),
            _ => {
                // Check by extension for .NET and Java
                if file_name.ends_with(".csproj") || file_name == "packages.config" {
                    Some(Ecosystem::NuGet)
                } else if file_name == "pom.xml" || file_name.ends_with(".gradle") {
                    Some(Ecosystem::Maven)
                } else {
                    None
                }
            }
        };

        if let Some(eco) = ecosystem {
            results.push(DiscoveredLockFile {
                path: path.to_path_buf(),
                ecosystem: eco,
                file_name: file_name.to_string(),
            });
        }
    }

    // Sort by ecosystem for consistent output
    results.sort_by_key(|r| r.ecosystem.as_str());
    results
}

/// Parse a lock file by path and return packages.
pub fn parse_lock_file(path: &Path) -> Option<Vec<LockPackage>> {
    let content = std::fs::read_to_string(path).ok()?;
    let file_name = path.file_name()?.to_str()?;

    match file_name {
        "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml" => {
            crate::scanner::supplychain::lock_parser::parse_package_lock(&content).ok()
        }
        "Cargo.lock" => {
            Some(crate::scanner::supplychain::lock_parser::parse_cargo_lock(&content))
        }
        "go.sum" => {
            let results = crate::scanner::supplychain::lock_parser::check_go_sum(&content);
            let packages: Vec<LockPackage> = results
                .into_iter()
                .map(|r| LockPackage {
                    name: r.package,
                    version: String::new(),
                    integrity_hash: None,
                    resolved_url: None,
                    has_git_source: matches!(r.status, IntegrityStatus::GitSource),
                    has_http_source: matches!(r.status, IntegrityStatus::HttpSource),
                })
                .collect();
            Some(packages)
        }
        "requirements.txt" => {
            let results = crate::scanner::supplychain::lock_parser::check_requirements_hash_mode(&content);
            let packages: Vec<LockPackage> = results
                .into_iter()
                .map(|r| LockPackage {
                    name: r.package,
                    version: String::new(),
                    integrity_hash: None,
                    resolved_url: None,
                    has_git_source: matches!(r.status, IntegrityStatus::GitSource),
                    has_http_source: matches!(r.status, IntegrityStatus::HttpSource),
                })
                .collect();
            Some(packages)
        }
        _ => None,
    }
}
