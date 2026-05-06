//! OSV.dev vulnerability database client.
//!
//! Queries OSV.dev API to check packages against known vulnerabilities.

#[allow(dead_code)]

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// OSV ecosystem identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    PyPI,
    Npm,
    Maven,
    Go,
    NuGet,
    RubyGems,
    Packagist,
    CratesIo,
    Hex,
    Pub,
    Unknown,
}

impl Ecosystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PyPI => "PyPI",
            Self::Npm => "npm",
            Self::Maven => "Maven",
            Self::Go => "Go",
            Self::NuGet => "NuGet",
            Self::RubyGems => "RubyGems",
            Self::Packagist => "Packagist",
            Self::CratesIo => "crates.io",
            Self::Hex => "Hex",
            Self::Pub => "Pub",
            Self::Unknown => "",
        }
    }

    pub fn from_pkg_manager(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "pip" | "pipenv" | "poetry" | "pypi" | "python" => Self::PyPI,
            "npm" | "yarn" | "pnpm" | "node" => Self::Npm,
            "maven" | "gradle" => Self::Maven,
            "go" | "dep" => Self::Go,
            "nuget" | "dotnet" => Self::NuGet,
            "gem" | "bundler" => Self::RubyGems,
            "composer" => Self::Packagist,
            "cargo" | "crates" => Self::CratesIo,
            "hex" | "mix" => Self::Hex,
            "pub" => Self::Pub,
            _ => Self::Unknown,
        }
    }
}

/// A parsed vulnerability from OSV.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub severity: Option<String>,
    pub cvss_score: Option<f32>,
    pub published: String,
    pub modified: String,
    pub fixed_version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvVuln {
    pub id: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    pub published: String,
    #[serde(default)]
    pub modified: Option<String>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct OsvSeverity {
    #[serde(rename = "type")]
    #[serde(default)]
    pub type_: Option<String>,
    pub score: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct OsvAffected {
    #[serde(rename = "package")]
    #[serde(default)]
    pub package: Option<OsvPackage>,
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
    #[serde(default)]
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct OsvPackage {
    pub name: String,
    pub ecosystem: String,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct OsvRange {
    #[serde(rename = "type")]
    #[serde(default)]
    pub type_: Option<String>,
    #[serde(default)]
    pub events: Vec<OsvEvent>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct OsvEvent {
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
}

impl From<OsvVuln> for Vulnerability {
    fn from(v: OsvVuln) -> Self {
        let cvss_score = v.severity.iter()
            .next()
            .and_then(|s| s.score.as_ref())
            .and_then(|s| s.parse::<f32>().ok());

        let severity = v.severity.iter()
            .next()
            .and_then(|s| s.score.clone());

        let fixed_version = v.affected.iter()
            .flat_map(|a| &a.ranges)
            .flat_map(|r| &r.events)
            .filter_map(|e| e.fixed.clone())
            .next();

        Self {
            id: v.id,
            summary: v.summary,
            details: v.details,
            severity,
            cvss_score,
            published: v.published,
            modified: v.modified.unwrap_or_default(),
            fixed_version,
        }
    }
}

/// OSV.dev API client with in-memory LRU-style bounded caching.
pub struct OsvClient {
    client: reqwest::Client,
    base_url: String,
    cache: HashMap<String, Vec<Vulnerability>>,
    cache_order: Vec<String>,
}

impl Default for OsvClient {
    fn default() -> Self {
        Self::new()
    }
}

impl OsvClient {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            client,
            base_url: "https://api.osv.dev/v1".to_string(),
            cache: HashMap::new(),
            cache_order: Vec::new(),
        }
    }

    const MAX_CACHE_SIZE: usize = 1024;

    pub fn clear_cache(&mut self) {
        self.cache.clear();
        self.cache_order.clear();
    }

    fn cache_key(name: &str, version: &str, eco: &str) -> String {
        format!("{}:{}:{}", name, version, eco)
    }

    fn from_cache(&mut self, key: &str) -> Option<&Vec<Vulnerability>> {
        self.cache.get(key)
    }

    fn to_cache(&mut self, key: String, vulns: Vec<Vulnerability>) {
        if self.cache.len() >= Self::MAX_CACHE_SIZE {
            if let Some(oldest) = self.cache_order.first().cloned() {
                self.cache.remove(&oldest);
                self.cache_order.remove(0);
            }
        }
        self.cache_order.push(key.clone());
        self.cache.insert(key, vulns);
    }

    /// Query a single package + version for vulnerabilities.
    pub async fn query_package(
        &mut self,
        name: &str,
        version: &str,
        ecosystem: Ecosystem,
    ) -> Result<Vec<Vulnerability>, OsvError> {
        let key = Self::cache_key(name, version, ecosystem.as_str());
        if let Some(vulns) = self.from_cache(&key) {
            return Ok(vulns.clone());
        }

        let body = serde_json::json!({
            "package": { "name": name, "ecosystem": ecosystem.as_str() },
            "version": version
        });

        let resp = self.client
            .post(format!("{}/query", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| OsvError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(OsvError::Api(resp.status().as_u16()));
        }

        let osv_resp: OsvResponse = resp
            .json()
            .await
            .map_err(|e| OsvError::Parse(e.to_string()))?;

        let vulns: Vec<Vulnerability> = osv_resp.vulns.into_iter().map(Vulnerability::from).collect();
        self.to_cache(key, vulns.clone());
        Ok(vulns)
    }

    /// Query all known vulnerabilities for a package name (no version).
    pub async fn query_by_name(
        &mut self,
        name: &str,
        ecosystem: Ecosystem,
    ) -> Result<Vec<Vulnerability>, OsvError> {
        let key = format!("{}:*:{}", name, ecosystem.as_str());
        if let Some(vulns) = self.from_cache(&key) {
            return Ok(vulns.clone());
        }

        let body = serde_json::json!({
            "package": { "name": name, "ecosystem": ecosystem.as_str() }
        });

        let resp = self.client
            .post(format!("{}/query", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| OsvError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(OsvError::Api(resp.status().as_u16()));
        }

        let osv_resp: OsvResponse = resp
            .json()
            .await
            .map_err(|e| OsvError::Parse(e.to_string()))?;

        let vulns: Vec<Vulnerability> = osv_resp.vulns.into_iter().map(Vulnerability::from).collect();
        self.to_cache(key, vulns.clone());
        Ok(vulns)
    }

    /// Batch query (up to 1000 packages).
    pub async fn query_batch(
        &mut self,
        packages: Vec<(String, String, Ecosystem)>,
    ) -> Result<Vec<Vec<Vulnerability>>, OsvError> {
        if packages.len() > 1000 {
            return Err(OsvError::BatchSize(packages.len()));
        }

        let queries: Vec<serde_json::Value> = packages
            .iter()
            .map(|(name, version, eco)| {
                serde_json::json!({
                    "package": { "name": name, "ecosystem": eco.as_str() },
                    "version": version
                })
            })
            .collect();

        let body = serde_json::json!({ "queries": queries });

        #[derive(Deserialize)]
        struct BatchResponse {
            results: Vec<OsvResponse>,
        }

        let resp = self.client
            .post(format!("{}/querybatch", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| OsvError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(OsvError::Api(resp.status().as_u16()));
        }

        let batch: BatchResponse = resp
            .json()
            .await
            .map_err(|e| OsvError::Parse(e.to_string()))?;

        let vulns: Vec<Vec<Vulnerability>> = batch.results
            .into_iter()
            .map(|r| r.vulns.into_iter().map(Vulnerability::from).collect())
            .collect();

        Ok(vulns)
    }
}

#[derive(Debug)]
pub enum OsvError {
    Network(String),
    Parse(String),
    Api(u16),
    BatchSize(usize),
}

impl std::fmt::Display for OsvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(s) => write!(f, "Network: {}", s),
            Self::Parse(s) => write!(f, "Parse: {}", s),
            Self::Api(code) => write!(f, "API: HTTP {}", code),
            Self::BatchSize(n) => write!(f, "Batch too large: {} items (max 1000)", n),
        }
    }
}

impl std::error::Error for OsvError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecosystem_from_pkg() {
        assert_eq!(Ecosystem::from_pkg_manager("pip"), Ecosystem::PyPI);
        assert_eq!(Ecosystem::from_pkg_manager("npm"), Ecosystem::Npm);
        assert_eq!(Ecosystem::from_pkg_manager("cargo"), Ecosystem::CratesIo);
        assert_eq!(Ecosystem::from_pkg_manager("unknown"), Ecosystem::Unknown);
    }
}
