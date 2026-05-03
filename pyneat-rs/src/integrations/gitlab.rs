//! GitLab SAST Integration
//!
//! Copyright (C) 2026 PyNEAT Authors
//!
//! Integrates with GitLab SAST (Static Application Security Testing).
//! Provides async API client for uploading reports, creating issues, and checking pipelines.

#[allow(dead_code)]

use serde::{Deserialize, Serialize};

/// GitLab CI configuration for SAST.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabConfig {
    /// GitLab token for API authentication.
    pub token: Option<String>,
    /// GitLab instance URL.
    pub gitlab_url: String,
    /// Project ID or path.
    pub project_id: String,
    /// CI pipeline ID.
    pub pipeline_id: Option<i64>,
    /// CI job ID.
    pub job_id: Option<i64>,
}

impl GitLabConfig {
    pub fn new(project_id: &str) -> Self {
        Self {
            token: std::env::var("GITLAB_TOKEN").ok(),
            gitlab_url: std::env::var("GITLAB_URL")
                .unwrap_or_else(|_| "https://gitlab.com".to_string()),
            project_id: project_id.to_string(),
            pipeline_id: std::env::var("CI_PIPELINE_ID").ok().and_then(|v| v.parse().ok()),
            job_id: std::env::var("CI_JOB_ID").ok().and_then(|v| v.parse().ok()),
        }
    }

    pub fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_string());
        self
    }

    pub fn with_gitlab_url(mut self, url: &str) -> Self {
        self.gitlab_url = url.to_string();
        self
    }
}

// --------------------------------------------------------------------------
// GitLab SAST Format
// --------------------------------------------------------------------------

/// GitLab SAST report entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabSASTReport {
    pub version: String,
    pub vulnerabilities: Vec<GitLabVulnerability>,
    pub scan: GitLabScan,
}

impl GitLabSASTReport {
    pub fn new() -> Self {
        Self {
            version: "14.0.0".to_string(),
            vulnerabilities: Vec::new(),
            scan: GitLabScan::new(),
        }
    }

    pub fn add_vulnerability(&mut self, vuln: GitLabVulnerability) {
        self.vulnerabilities.push(vuln);
    }
}

impl Default for GitLabSASTReport {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabScan {
    pub status: String,
    pub scan_type: String,
    pub start_time: String,
    pub end_time: String,
    pub version: String,
    pub sbom: Option<GitLabSBOM>,
}

impl GitLabScan {
    pub fn new() -> Self {
        Self {
            status: "success".to_string(),
            scan_type: "sast".to_string(),
            start_time: chrono_lite_now(),
            end_time: chrono_lite_now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            sbom: None,
        }
    }
}

impl Default for GitLabScan {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabSBOM {
    pub sbom_format: String,
    pub component: String,
    pub location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabVulnerability {
    pub id: Option<i64>,
    #[serde(rename = "category")]
    pub category: String,
    pub name: String,
    #[serde(rename = "cve")]
    pub cve: Option<String>,
    #[serde(rename = "tracker")]
    pub tracker: Option<String>,
    #[serde(rename = "identifiers")]
    pub identifiers: Vec<GitLabIdentifier>,
    #[serde(rename = "file")]
    pub file: Option<String>,
    #[serde(rename = "start_line")]
    pub start_line: Option<usize>,
    #[serde(rename = "end_line")]
    pub end_line: Option<usize>,
    #[serde(rename = "vulnerable_code")]
    pub vulnerable_code: Option<String>,
    #[serde(rename = "location")]
    pub location: GitLabLocation,
    #[serde(rename = "evidence")]
    pub evidence: Option<GitLabEvidence>,
    #[serde(rename = "solution")]
    pub solution: Option<String>,
    #[serde(rename = "severity")]
    pub severity: String,
    #[serde(rename = "confidence")]
    pub confidence: String,
    #[serde(rename = "scanner")]
    pub scanner: GitLabScanner,
    #[serde(rename = "links")]
    pub links: Vec<GitLabLink>,
    #[serde(rename = "metadata")]
    pub metadata: Option<GitLabMetadata>,
    #[serde(rename = "flags")]
    pub flags: Vec<GitLabFlag>,
    #[serde(rename = "ident")]
    pub ident: Option<String>,
}

impl GitLabVulnerability {
    pub fn new(rule_id: &str, severity: &str, _message: &str) -> Self {
        Self {
            id: None,
            category: "sast".to_string(),
            name: rule_id.to_string(),
            cve: None,
            tracker: None,
            identifiers: vec![],
            file: None,
            start_line: None,
            end_line: None,
            vulnerable_code: None,
            location: GitLabLocation::new(),
            evidence: None,
            solution: None,
            severity: severity.to_string(),
            confidence: "High".to_string(),
            scanner: GitLabScanner::new("PyNEAT", env!("CARGO_PKG_VERSION")),
            links: vec![],
            metadata: None,
            flags: vec![],
            ident: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabIdentifier {
    #[serde(rename = "type")]
    pub identifier_type: String,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabLocation {
    #[serde(rename = "file")]
    pub file: String,
    #[serde(rename = "dependency")]
    pub dependency: Option<GitLabDependency>,
    #[serde(rename = "class")]
    pub class: Option<String>,
    #[serde(rename = "method")]
    pub method: Option<String>,
    #[serde(rename = "start_line")]
    pub start_line: Option<usize>,
    #[serde(rename = "end_line")]
    pub end_line: Option<usize>,
}

impl GitLabLocation {
    pub fn new() -> Self {
        Self {
            file: String::new(),
            dependency: None,
            class: None,
            method: None,
            start_line: None,
            end_line: None,
        }
    }

    pub fn with_file(mut self, file: &str) -> Self {
        self.file = file.to_string();
        self
    }

    pub fn with_lines(mut self, start: usize, end: usize) -> Self {
        self.start_line = Some(start);
        self.end_line = Some(end);
        self
    }
}

impl Default for GitLabLocation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabDependency {
    #[serde(rename = "package")]
    pub package: GitLabPackage,
    #[serde(rename = "version")]
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabPackage {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "ecosystem")]
    pub ecosystem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabEvidence {
    #[serde(rename = "source")]
    pub source: GitLabEvidenceSource,
    #[serde(rename = "state")]
    pub state: Option<String>,
    #[serde(rename = "supporting")]
    pub supporting: Vec<GitLabEvidenceItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabEvidenceSource {
    #[serde(rename = "id")]
    pub id: Option<String>,
    #[serde(rename = "name")]
    pub name: Option<String>,
    #[serde(rename = "value")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabEvidenceItem {
    #[serde(rename = "name")]
    pub name: Option<String>,
    #[serde(rename = "value")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabScanner {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(rename = "external_id")]
    pub external_id: Option<String>,
}

impl GitLabScanner {
    pub fn new(name: &str, version: &str) -> Self {
        Self {
            id: name.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            external_id: Some(format!("pyneat://{}", name.to_lowercase())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabLink {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabMetadata {
    #[serde(rename = "description")]
    pub description: Option<String>,
    #[serde(rename = "license")]
    pub license: Option<String>,
    #[serde(rename = "file_type")]
    pub file_type: Option<String>,
    #[serde(rename = "lang")]
    pub lang: Option<String>,
    #[serde(rename = "cwe")]
    pub cwe: Option<Vec<GitLabCWE>>,
    #[serde(rename = "owasp")]
    pub owasp: Option<Vec<String>>,
    #[serde(rename = "git")]
    pub git: Option<GitLabGit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabCWE {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabGit {
    #[serde(rename = "commit_id")]
    pub commit_id: Option<String>,
    #[serde(rename = "commit_title")]
    pub commit_title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabFlag {
    #[serde(rename = "type")]
    pub flag_type: String,
    #[serde(rename = "origin")]
    pub origin: Option<String>,
    #[serde(rename = "mode")]
    pub mode: Option<String>,
    #[serde(rename = "value")]
    pub value: Option<String>,
}

/// Convert pyneat findings to GitLab SAST format.
pub fn create_gitlab_sast_report(
    _source_file: &str,
    vulnerabilities: Vec<GitLabVulnerability>,
) -> GitLabSASTReport {
    let mut report = GitLabSASTReport::new();
    for vuln in vulnerabilities {
        report.add_vulnerability(vuln);
    }
    report
}

// --------------------------------------------------------------------------
// Helper
// --------------------------------------------------------------------------

fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap();
    let secs = now.as_secs();
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let mins = (remaining % 3600) / 60;
    let seconds = remaining % 60;
    let year = 1970 + days / 365;
    let day_of_year = days % 365;
    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let month_days: [u64; 12] = if is_leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1;
    let mut day_rem = day_of_year;
    for (i, &md) in month_days.iter().enumerate() {
        if day_rem < md {
            month = i + 1;
            break;
        }
        day_rem -= md;
    }
    let day = day_rem + 1;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, hours, mins, seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gitlab_sast_report() {
        let report = GitLabSASTReport::new();
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("version"));
        assert!(json.contains("vulnerabilities"));
    }

    #[test]
    fn test_gitlab_vulnerability() {
        let vuln = GitLabVulnerability::new("SEC-001", "high", "Hardcoded password detected");
        let json = serde_json::to_string(&vuln).unwrap();
        assert!(json.contains("SEC-001"));
        assert!(json.contains("high"));
    }
}

// --------------------------------------------------------------------------
// GitLab API Client (async)
// --------------------------------------------------------------------------

/// Async HTTP client for GitLab API integration.
#[derive(Clone)]
pub struct GitLabClient {
    base_url: String,
    token: Option<String>,
    project_id: String,
    client: reqwest::Client,
}

impl GitLabClient {
    /// Create a new GitLab client from config.
    pub fn from_config(config: &GitLabConfig) -> Self {
        Self {
            base_url: config.gitlab_url.trim_end_matches('/').to_string(),
            token: config.token.clone(),
            project_id: config.project_id.clone(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    /// Create a new GitLab client with a token.
    pub fn new(project_id: &str, token: &str, gitlab_url: Option<&str>) -> Self {
        Self {
            base_url: gitlab_url
                .map(|s| s.trim_end_matches('/').to_string())
                .unwrap_or_else(|| "https://gitlab.com".to_string()),
            token: Some(token.to_string()),
            project_id: project_id.to_string(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    fn auth_headers(&self) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        let empty = String::new();
        let token_str = self.token.as_ref().unwrap_or(&empty);
        if let Ok(val) = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token_str)) {
            headers.insert(reqwest::header::AUTHORIZATION, val);
        }
        if let Ok(val) = reqwest::header::HeaderValue::from_str("application/json") {
            headers.insert(reqwest::header::CONTENT_TYPE, val);
        }
        headers
    }

    /// Upload a SAST report (SARIF or GitLab SAST JSON format).
    pub async fn upload_sast_report(&self, report_content: &str, branch: &str) -> Result<UploadResult, GitLabApiError> {
        let url = format!(
            "{}/api/v4/projects/{}/security/sast_reports",
            self.base_url,
            percent_encode(&self.project_id)
        );

        let part = reqwest::multipart::Part::text(report_content.to_string())
            .file_name("gl-sast-report.json")
            .mime_str("application/json")
            .map_err(|e| GitLabApiError::UploadError(e.to_string()))?;

        let form = reqwest::multipart::Form::new()
            .text("branch", branch.to_string())
            .part("file", part);

        let response = self.client
            .post(&url)
            .headers(self.auth_headers())
            .multipart(form)
            .send()
            .await
            .map_err(|e| GitLabApiError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            let body: serde_json::Value = response.json().await
                .map_err(|e| GitLabApiError::ParseError(e.to_string()))?;
            Ok(UploadResult {
                job_id: body.get("job_id").and_then(|v| v.as_i64()),
                build_id: body.get("build_id").and_then(|v| v.as_i64()),
                report_id: body.get("id").and_then(|v| v.as_i64()),
                status: body.get("status").and_then(|v| v.as_str()).map(String::from),
            })
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(GitLabApiError::HttpError(status.as_u16(), body))
        }
    }

    /// Create a security finding as a GitLab issue.
    pub async fn create_security_issue(
        &self,
        title: &str,
        description: &str,
        severity: &str,
        labels: Option<Vec<&str>>,
    ) -> Result<CreatedIssue, GitLabApiError> {
        #[derive(Serialize)]
        struct CreateIssueRequest<'a> {
            title: &'a str,
            description: &'a str,
            labels: Option<String>,
            #[serde(rename = "severity_id")]
            severity_id: Option<i32>,
        }

        let severity_id = match severity.to_lowercase().as_str() {
            "critical" | "high" => Some(3), // Blocker
            "medium" => Some(2),             // High
            "low" => Some(1),               // Medium
            _ => Some(0),                  // Low
        };

        let labels_str = labels.map(|l| l.join(","));

        let body = CreateIssueRequest {
            title,
            description,
            labels: labels_str,
            severity_id,
        };

        let url = format!(
            "{}/api/v4/projects/{}/issues",
            self.base_url,
            percent_encode(&self.project_id)
        );

        let response = self.client
            .post(&url)
            .headers(self.auth_headers())
            .json(&body)
            .send()
            .await
            .map_err(|e| GitLabApiError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            let body: serde_json::Value = response.json().await
                .map_err(|e| GitLabApiError::ParseError(e.to_string()))?;
            Ok(CreatedIssue {
                iid: body.get("iid").and_then(|v| v.as_i64()).unwrap_or(0),
                id: body.get("id").and_then(|v| v.as_i64()).unwrap_or(0),
                web_url: body.get("web_url").and_then(|v| v.as_str()).map(String::from).unwrap_or_default(),
                title: title.to_string(),
            })
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(GitLabApiError::HttpError(status.as_u16(), body))
        }
    }

    /// Get pipeline status by pipeline ID.
    pub async fn get_pipeline_status(&self, pipeline_id: i64) -> Result<PipelineStatus, GitLabApiError> {
        let url = format!(
            "{}/api/v4/projects/{}/pipelines/{}",
            self.base_url,
            percent_encode(&self.project_id),
            pipeline_id
        );

        let response = self.client
            .get(&url)
            .headers(self.auth_headers())
            .send()
            .await
            .map_err(|e| GitLabApiError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            let body: serde_json::Value = response.json().await
                .map_err(|e| GitLabApiError::ParseError(e.to_string()))?;
            Ok(PipelineStatus {
                id: body.get("id").and_then(|v| v.as_i64()).unwrap_or(0),
                status: body.get("status").and_then(|v| v.as_str()).map(String::from).unwrap_or_default(),
                ref_name: body.get("ref").and_then(|v| v.as_str()).map(String::from).unwrap_or_default(),
                web_url: body.get("web_url").and_then(|v| v.as_str()).map(String::from).unwrap_or_default(),
                created_at: body.get("created_at").and_then(|v| v.as_str()).map(String::from),
                updated_at: body.get("updated_at").and_then(|v| v.as_str()).map(String::from),
            })
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(GitLabApiError::HttpError(status.as_u16(), body))
        }
    }
}

// --------------------------------------------------------------------------
// Response types
// --------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResult {
    pub job_id: Option<i64>,
    pub build_id: Option<i64>,
    pub report_id: Option<i64>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedIssue {
    pub iid: i64,
    pub id: i64,
    pub web_url: String,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStatus {
    pub id: i64,
    pub status: String,
    pub ref_name: String,
    pub web_url: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug)]
pub enum GitLabApiError {
    NetworkError(String),
    HttpError(u16, String),
    ParseError(String),
    UploadError(String),
}

impl std::fmt::Display for GitLabApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitLabApiError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            GitLabApiError::HttpError(code, body) => write!(f, "HTTP {}: {}", code, body),
            GitLabApiError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            GitLabApiError::UploadError(msg) => write!(f, "Upload error: {}", msg),
        }
    }
}

impl std::error::Error for GitLabApiError {}

fn percent_encode(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
            '/' => result.push('/'),
            _ => {
                for byte in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }
    result
}

