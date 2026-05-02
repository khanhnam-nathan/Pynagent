//! Supply Chain Security Rules
//!
//! Detects dependency confusion attacks, typosquatting, lock file integrity issues,
//! and other supply chain risks using the current LangRule API.

use crate::scanner::base::{LangFinding, LangRule};
use crate::scanner::ln_ast::LnAst;
use regex::Regex;

/// Helper: get line text from line number (1-indexed).
#[allow(dead_code)]
fn get_line_text(code: &str, line: usize) -> Option<String> {
    code.lines().nth(line.saturating_sub(1)).map(|l| l.to_string())
}

// ============================================================================
// SC-PY-001: Dependency Confusion in Python requirements.txt
// ============================================================================

pub struct DepConfusionPython;

impl LangRule for DepConfusionPython {
    fn id(&self) -> &str { "SC-PY-001" }
    fn name(&self) -> &str { "Dependency Confusion - Python" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = Vec::new();

        let internal_pkg_pattern = Regex::new(
            r"^([a-z][a-z0-9]*)[-_](internal|private|corp|enterprise|local|company)"
        ).unwrap();

        let permissive_version_pattern = Regex::new(r">=\s*[\d.]+\s*$").unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some(caps) = internal_pkg_pattern.captures(trimmed) {
                let package_name = caps.get(0).map(|m| m.as_str()).unwrap_or("");
                findings.push(LangFinding::new(
                    "SC-PY-001", "high", line_num, package_name,
                    &format!("Potential dependency confusion: package '{}' looks like an internal package. Without proper private index, pip may install a malicious public package.", package_name),
                    "Use a private package index or scope your internal packages."
                ));
            }

            if permissive_version_pattern.is_match(trimmed) && !trimmed.contains("://") {
                findings.push(LangFinding::new(
                    "SC-PY-001", "medium", line_num, trimmed,
                    "Permissive version range without upper bound may fetch untrusted versions.",
                    "Pin to a specific version range."
                ));
            }
        }

        findings
    }
}

// ============================================================================
// SC-JS-001: Dependency Confusion in Node.js package.json
// ============================================================================

pub struct DepConfusionJs;

impl LangRule for DepConfusionJs {
    fn id(&self) -> &str { "SC-JS-001" }
    fn name(&self) -> &str { "Dependency Confusion - JavaScript" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = Vec::new();

        let internal_unscoped_pattern = Regex::new(
            r#""([a-z][a-z0-9]*)[-_](internal|private|corp|enterprise|local|company|utils|lib|component|module)[-_]"#
        ).unwrap();

        let unpinned_version_pattern = Regex::new(r#""\*"|"latest""#).unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();

            if !trimmed.contains(':') || trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }

            if let Some(caps) = internal_unscoped_pattern.captures(trimmed) {
                let package_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                findings.push(LangFinding::new(
                    "SC-JS-001", "high", line_num, trimmed,
                    &format!("Potential dependency confusion: '{}' looks like an internal package but is not scoped.", package_name),
                    "Use a scope like @your-org/package-name."
                ));
            }

            if unpinned_version_pattern.is_match(trimmed) {
                findings.push(LangFinding::new(
                    "SC-JS-001", "high", line_num, trimmed,
                    "Unpinned dependency using wildcard or 'latest'. This can lead to dependency confusion attacks.",
                    "Pin to a specific version."
                ));
            }
        }

        findings
    }
}

// ============================================================================
// SC-GO-001: Dependency Confusion in Go go.mod
// ============================================================================

pub struct DepConfusionGo;

impl LangRule for DepConfusionGo {
    fn id(&self) -> &str { "SC-GO-001" }
    fn name(&self) -> &str { "Dependency Confusion - Go" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = Vec::new();

        let replace_pattern = Regex::new(r"^\s*replace\s+([^\s=>]+)\s*=>\s*(.+)$").unwrap();
        let short_module_pattern = Regex::new(r"^module\s+([a-z]{3,10})$").unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();

            if let Some(caps) = replace_pattern.captures(trimmed) {
                let replacement = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                if replacement.contains("./") || replacement.contains("../") || replacement.starts_with("/") {
                    findings.push(LangFinding::new(
                        "SC-GO-001", "high", line_num, trimmed,
                        "Replace directive overrides public package with local path. This could be exploited in CI/CD.",
                        "Remove replace directives or use version-controlled local modules."
                    ));
                }
            }

            if let Some(caps) = short_module_pattern.captures(trimmed) {
                let module_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                findings.push(LangFinding::new(
                    "SC-GO-001", "medium", line_num, trimmed,
                    &format!("Short module name '{}' is susceptible to typosquatting.", module_name),
                    "Use a full module path like github.com/your-org/module-name."
                ));
            }
        }

        findings
    }
}

// ============================================================================
// SC-JAVA-001: Dependency Confusion in Maven pom.xml
// ============================================================================

pub struct DepConfusionMaven;

impl LangRule for DepConfusionMaven {
    fn id(&self) -> &str { "SC-JAVA-001" }
    fn name(&self) -> &str { "Dependency Confusion - Maven" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = Vec::new();

        let snapshot_pattern = Regex::new(r"<version>[^<]*-SNAPSHOT</version>").unwrap();
        let orphan_artifact_pattern = Regex::new(
            r"<artifactId>([a-z][a-z0-9]*)[-_](internal|private|corp|enterprise|company|lib|utils|common)"
        ).unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();

            if snapshot_pattern.is_match(trimmed) {
                findings.push(LangFinding::new(
                    "SC-JAVA-001", "high", line_num, trimmed,
                    "SNAPSHOT dependency found. External SNAPSHOT versions are vulnerable to time-of-check-time-of-use attacks.",
                    "Avoid external SNAPSHOT dependencies or mirror them internally."
                ));
            }

            if let Some(caps) = orphan_artifact_pattern.captures(trimmed) {
                let artifact_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                findings.push(LangFinding::new(
                    "SC-JAVA-001", "medium", line_num, trimmed,
                    &format!("Internal-looking artifactId '{}' detected.", artifact_name),
                    "Ensure proper groupId and internal repository configuration."
                ));
            }
        }

        findings
    }
}

// ============================================================================
// SC-CS-001: Dependency Confusion in NuGet
// ============================================================================

pub struct DepConfusionNuget;

impl LangRule for DepConfusionNuget {
    fn id(&self) -> &str { "SC-CS-001" }
    fn name(&self) -> &str { "Dependency Confusion - NuGet" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = Vec::new();

        let internal_package_pattern = Regex::new(
            r#"<package\s+id="([a-z][a-z0-9]*)[-_](internal|private|corp|enterprise|company|lib|utils|common|core)[-_]"#
        ).unwrap();

        let unversioned_pattern = Regex::new(
            r#"<package\s+id="[^"]+"\s+version=""\s*/>"#
        ).unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();

            if let Some(caps) = internal_package_pattern.captures(trimmed) {
                let package_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                findings.push(LangFinding::new(
                    "SC-CS-001", "high", line_num, trimmed,
                    &format!("Potential dependency confusion: package '{}' looks internal but may not have proper namespace.", package_name),
                    "Configure NuGet.config with internal feed priority."
                ));
            }

            if unversioned_pattern.is_match(trimmed) {
                findings.push(LangFinding::new(
                    "SC-CS-001", "high", line_num, trimmed,
                    "Unversioned package reference. This can lead to dependency confusion attacks.",
                    "Pin to a specific version."
                ));
            }
        }

        findings
    }
}

// ============================================================================
// Registry
// ============================================================================

pub fn supplychain_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(DepConfusionPython),
        Box::new(DepConfusionJs),
        Box::new(DepConfusionGo),
        Box::new(DepConfusionMaven),
        Box::new(DepConfusionNuget),
    ]
}
