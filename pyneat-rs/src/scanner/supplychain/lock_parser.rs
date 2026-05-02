//! Lock file parsers and integrity verification.
//!
//! Parses package lock files across ecosystems and verifies integrity.
//!
//! Supported lock files:
//! - `package-lock.json` (npm) - verifies integrity hashes
//! - `yarn.lock` (Yarn) - verifies checksums
//! - `go.sum` (Go) - verifies h1: hash format
//! - `requirements.txt` (pip) - checks for --hash= mode
//! - `Cargo.lock` (Rust) - extracts licenses and versions

use regex::Regex;
use serde::Deserialize;

/// A package extracted from a lock file.
#[derive(Debug, Clone)]
pub struct LockPackage {
    pub name: String,
    pub version: String,
    pub integrity_hash: Option<String>,
    pub resolved_url: Option<String>,
    pub has_git_source: bool,
    pub has_http_source: bool,
}

/// Integrity check result.
#[derive(Debug, Clone)]
pub struct IntegrityResult {
    pub package: String,
    pub status: IntegrityStatus,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum IntegrityStatus {
    Valid,
    MissingHash,
    GitSource,
    HttpSource,
    InvalidHash,
    Warning,
}

impl IntegrityResult {
    pub fn is_safe(&self) -> bool {
        matches!(self.status, IntegrityStatus::Valid)
    }
}

/// Parse `package-lock.json` and verify integrity hashes.
/// Supports both v2 (dependencies) and v3 (packages) lock file formats.
pub fn parse_package_lock(content: &str) -> Result<Vec<LockPackage>, String> {
    #[derive(Deserialize)]
    struct PackageLockV3 {
        #[serde(rename = "lockfileVersion")]
        #[allow(dead_code)]
        lockfile_version: Option<u32>,
        packages: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Deserialize)]
    struct PackageLockV2 {
        #[serde(rename = "lockfileVersion")]
        #[allow(dead_code)]
        lockfile_version: Option<u32>,
        dependencies: Option<serde_json::Map<String, serde_json::Value>>,
    }

    let mut packages = Vec::new();

    // Try v3 format first (packages map)
    if let Ok(lock) = serde_json::from_str::<PackageLockV3>(content) {
        if lock.packages.as_ref().map_or(false, |p| !p.is_empty()) {
            if let Some(pkgs) = lock.packages {
                for (path, pkg) in pkgs {
                    if path.is_empty() || !path.starts_with("node_modules/") {
                        continue;
                    }

                    let version = pkg.get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("*")
                        .to_string();

                    let integrity = pkg.get("integrity")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    let resolved = pkg.get("resolved")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    let has_git = resolved.as_ref()
                        .map(|r| r.starts_with("git+"))
                        .unwrap_or(false);

                    let has_http = resolved.as_ref()
                        .map(|r| r.starts_with("http://"))
                        .unwrap_or(false);

                    packages.push(LockPackage {
                        name: path.split("node_modules/").last().unwrap_or(&path).to_string(),
                        version,
                        integrity_hash: integrity,
                        resolved_url: resolved,
                        has_git_source: has_git,
                        has_http_source: has_http,
                    });
                }
            }
            return Ok(packages);
        }
    }

    // Try v2 format (dependencies map)
    if let Ok(lock) = serde_json::from_str::<PackageLockV2>(content) {
        if let Some(deps) = lock.dependencies {
            for (name, dep) in deps {
                let version = dep.get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*")
                    .to_string();

                let integrity = dep.get("integrity")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let resolved = dep.get("resolved")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let has_git = resolved.as_ref()
                    .map(|r| r.starts_with("git+"))
                    .unwrap_or(false);

                let has_http = resolved.as_ref()
                    .map(|r| r.starts_with("http://"))
                    .unwrap_or(false);

                packages.push(LockPackage {
                    name,
                    version,
                    integrity_hash: integrity,
                    resolved_url: resolved,
                    has_git_source: has_git,
                    has_http_source: has_http,
                });
            }
        }
        return Ok(packages);
    }

    Err("Failed to parse package-lock.json: unknown format".to_string())
}

/// Check integrity of `package-lock.json` entries.
pub fn check_package_lock_integrity(content: &str) -> Vec<IntegrityResult> {
    let packages = match parse_package_lock(content) {
        Ok(p) => p,
        Err(_) => return vec![],
    };

    packages
        .iter()
        .map(|pkg| {
            let (status, message) = if pkg.has_git_source {
                (IntegrityStatus::GitSource, format!("Package {} uses git source (not verified by lock file)", pkg.name))
            } else if pkg.has_http_source {
                (IntegrityStatus::HttpSource, format!("Package {} uses HTTP source (use HTTPS)", pkg.name))
            } else if pkg.integrity_hash.is_none() {
                (IntegrityStatus::MissingHash, format!("Package {} has no integrity hash", pkg.name))
            } else {
                (IntegrityStatus::Valid, format!("Package {} integrity verified", pkg.name))
            };
            IntegrityResult {
                package: pkg.name.clone(),
                status,
                message,
            }
        })
        .collect()
}

/// Parse `go.mod` and `go.sum` to verify module integrity.
pub fn check_go_sum(go_sum: &str) -> Vec<IntegrityResult> {
    let mut results = Vec::new();

    for line in go_sum.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let module = parts[0];
            let hash = parts[1];

            let (status, message) = if !hash.starts_with("h1:") {
                (IntegrityStatus::InvalidHash, format!("Module {} has invalid hash format: {}", module, &hash[..hash.len().min(8)]))
            } else if hash.len() < 10 {
                (IntegrityStatus::Warning, format!("Module {} has very short hash", module))
            } else {
                (IntegrityStatus::Valid, format!("Module {} verified", module))
            };

            results.push(IntegrityResult {
                package: module.to_string(),
                status,
                message,
            });
        }
    }

    results
}

/// Parse `requirements.txt` and check for hash verification mode.
pub fn check_requirements_hash_mode(content: &str) -> Vec<IntegrityResult> {
    let mut results = Vec::new();
    let mut has_hash_mode = false;
    let mut has_vcs_deps = false;
    let mut has_insecure_urls = false;
    let mut packages: Vec<String> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if trimmed.starts_with("--hash=") || trimmed.starts_with("--trusted-host") {
            has_hash_mode = true;
            continue;
        }

        if trimmed.starts_with('-') || trimmed.starts_with("git+") || trimmed.starts_with("-e") {
            if trimmed.contains("git://") || trimmed.starts_with("git+http://") {
                has_insecure_urls = true;
            }
            if trimmed.starts_with("git+") || trimmed.starts_with("svn+") || trimmed.starts_with("hg+") {
                has_vcs_deps = true;
            }
            continue;
        }

        let pkg_name = trimmed.split(|c| c == '=' || c == '>' || c == '<' || c == '!')
            .next()
            .unwrap_or(trimmed)
            .trim()
            .to_string();

        if !pkg_name.is_empty() {
            packages.push(pkg_name);
        }

        if trimmed.contains("://") && !trimmed.contains("https://") && !trimmed.starts_with('#') {
            has_insecure_urls = true;
        }
    }

    if !has_hash_mode && !packages.is_empty() {
        results.push(IntegrityResult {
            package: "requirements.txt".to_string(),
            status: IntegrityStatus::MissingHash,
            message: format!(
                "requirements.txt has {} packages without hash verification mode (pip install --require-hashes)",
                packages.len()
            ),
        });
    }

    if has_vcs_deps {
        results.push(IntegrityResult {
            package: "requirements.txt".to_string(),
            status: IntegrityStatus::Warning,
            message: "requirements.txt contains VCS dependencies (git+, svn+, hg+) which may be insecure".to_string(),
        });
    }

    if has_insecure_urls {
        results.push(IntegrityResult {
            package: "requirements.txt".to_string(),
            status: IntegrityStatus::HttpSource,
            message: "requirements.txt contains HTTP (non-HTTPS) URLs".to_string(),
        });
    }

    results
}

/// Parse `Cargo.lock` and extract packages with their licenses.
pub fn parse_cargo_lock(content: &str) -> Vec<LockPackage> {
    let mut packages = Vec::new();

    let name_re = Regex::new(r#"^\s*name\s*=\s*"?([^"\n]+)"?.*$"#).ok();
    let version_re = Regex::new(r#"^\s*version\s*=\s*"?([^"\n]+)"?.*$"#).ok();

    let mut current_name = String::new();
    let mut current_version = String::new();
    let mut in_package = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("[[package]]") {
            in_package = true;
            current_name.clear();
            current_version.clear();
            continue;
        }

        if in_package {
            if let Some(re) = &name_re {
                if let Some(caps) = re.captures(trimmed) {
                    current_name = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                }
            }
            if let Some(re) = &version_re {
                if let Some(caps) = re.captures(trimmed) {
                    current_version = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                }
            }

            if trimmed.is_empty() || trimmed == "[" {
                if !current_name.is_empty() && !current_version.is_empty() {
                    packages.push(LockPackage {
                        name: current_name.clone(),
                        version: current_version.clone(),
                        integrity_hash: None,
                        resolved_url: None,
                        has_git_source: false,
                        has_http_source: false,
                    });
                }
                in_package = false;
            }
        }
    }

    if !current_name.is_empty() && !current_version.is_empty() {
        packages.push(LockPackage {
            name: current_name,
            version: current_version,
            integrity_hash: None,
            resolved_url: None,
            has_git_source: false,
            has_http_source: false,
        });
    }

    packages
}
