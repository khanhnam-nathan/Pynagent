//! Supply Chain Lock Checksum Rules
//!
//! Detects missing integrity verification for lock files.

use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{LangRule, LangFinding};
use regex::Regex;

fn get_line_text(code: &str, line: usize) -> Option<String> {
    code.lines().nth(line.saturating_sub(1)).map(|l| l.to_string())
}

// ─── LOCK-001: package-lock.json Without Integrity Hash ─────────────────────

pub struct LockMissingIntegrityHash;

impl LangRule for LockMissingIntegrityHash {
    fn id(&self) -> &str { "LOCK-001" }
    fn name(&self) -> &str { "package-lock.json Without Integrity Hash" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Check if this looks like package-lock.json (JSON with "version" and "dependencies")
        let looks_like_package_lock = code.contains("\"version\"")
            && code.contains("\"dependencies\"")
            && (code.contains("\"lockfileVersion\"") || code.contains("\"node_modules\"") || code.contains(": {"))
            && code.contains(": {");

        if !looks_like_package_lock {
            return findings;
        }

        let has_integrity = code.contains("\"integrity\":");
        let has_version = code.contains("\"version\":");

        if has_version && !has_integrity {
            for (line_idx, line) in code.lines().enumerate() {
                if let Ok(re) = Regex::new(r#"\"version":"#) {
                    if re.is_match(line) {
                        let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                        findings.push(LangFinding::new(
                            self.id(), self.severity(), line_idx + 1,
                            &snippet,
                            "package-lock.json entry without SHA512 integrity hash.",
                            "Run `npm install` to regenerate package-lock.json with integrity hashes.",
                        ));
                        break;
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── LOCK-002: go.sum Missing or Incomplete ────────────────────────────────

pub struct LockMissingGoSum;

impl LangRule for LockMissingGoSum {
    fn id(&self) -> &str { "LOCK-002" }
    fn name(&self) -> &str { "go.sum Missing or Incomplete" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Check if this looks like go.sum
        let looks_like_go_sum = code.lines().any(|l| l.contains(" h1:"));

        if looks_like_go_sum {
            let sum_lines: Vec<_> = code.lines().filter(|l| l.contains(" h1:")).collect();
            if sum_lines.is_empty() {
                for (line_idx, line) in code.lines().enumerate() {
                    if !line.trim().is_empty() {
                        findings.push(LangFinding::new(
                            self.id(), self.severity(), line_idx + 1,
                            &line.to_string(),
                            "go.sum appears empty or malformed - no checksum entries found.",
                            "Run `go mod tidy` to regenerate go.sum with proper checksums.",
                        ));
                        break;
                    }
                }
            }
        }

        // Check if this looks like go.mod (has "require" but go.sum is missing)
        let looks_like_go_mod = code.contains("require")
            || (code.contains("go ") && code.contains("module"));

        if looks_like_go_mod && !looks_like_go_sum {
            let has_replace = code.lines().any(|l| {
                l.trim().starts_with("replace") || l.contains("=>")
            });
            if has_replace || (code.lines().any(|l| l.trim().starts_with("require"))) {
                findings.push(LangFinding::new(
                    self.id(), self.severity(), 1,
                    "go.mod",
                    "go.mod contains dependencies but go.sum may be missing or incomplete.",
                    "Run `go mod tidy` to generate or update go.sum with all required checksums.",
                ));
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── LOCK-003: yarn.lock Without Checksum ───────────────────────────────────

pub struct LockMissingYarnChecksum;

impl LangRule for LockMissingYarnChecksum {
    fn id(&self) -> &str { "LOCK-003" }
    fn name(&self) -> &str { "yarn.lock Without Checksum (Integrity)" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Check if this looks like yarn.lock (starts with package name and version)
        let looks_like_yarn_lock = code.lines().any(|l| {
            let trimmed = l.trim();
            trimmed.starts_with('@') || (trimmed.contains("@") && trimmed.contains(":"))
        });

        if !looks_like_yarn_lock {
            return findings;
        }

        let has_checksum = code.contains("integrity=") || code.contains("sha512-");
        if !has_checksum {
            for (line_idx, line) in code.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.contains("@") && trimmed.contains(":") && !trimmed.is_empty() {
                    findings.push(LangFinding::new(
                        self.id(), self.severity(), line_idx + 1,
                        &line.to_string(),
                        "yarn.lock package entry without SHA512 checksum (integrity hash).",
                        "Use Yarn v2+ which enforces integrity hashes. Run `yarn install`.",
                    ));
                    break;
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── LOCK-004: requirements.txt Without Hash Mode ────────────────────────────

pub struct LockMissingPipHash;

impl LangRule for LockMissingPipHash {
    fn id(&self) -> &str { "LOCK-004" }
    fn name(&self) -> &str { "requirements.txt Without Hash Mode" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Check if this looks like requirements.txt (package==version format)
        let looks_like_req = code.lines().any(|l| {
            let trimmed = l.trim();
            !trimmed.is_empty()
                && !trimmed.starts_with('#')
                && !trimmed.starts_with('-')
                && !trimmed.starts_with('[')
                && (trimmed.contains("==") || trimmed.contains(">=") || trimmed.contains("<="))
        });

        if !looks_like_req {
            return findings;
        }

        let has_hash = code.contains("# hash=");
        let has_comment_hash = code.lines().any(|l| l.contains("sha256:"));

        if !has_hash && !has_comment_hash {
            for (line_idx, line) in code.lines().enumerate() {
                let trimmed = line.trim();
                if !trimmed.is_empty()
                    && !trimmed.starts_with('#')
                    && !trimmed.starts_with('-')
                    && !trimmed.starts_with('[')
                    && (trimmed.contains("==") || trimmed.contains(">=") || trimmed.contains("<="))
                {
                    findings.push(LangFinding::new(
                        self.id(), self.severity(), line_idx + 1,
                        &line.to_string(),
                        "requirements.txt without pip hash mode - packages not integrity-verified.",
                        "Use pip hash mode: run `pip hash -r requirements.txt` or use `pip-compile` with hash checking.",
                    ));
                    break;
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

pub fn supply_chain_lock_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(LockMissingIntegrityHash),
        Box::new(LockMissingGoSum),
        Box::new(LockMissingYarnChecksum),
        Box::new(LockMissingPipHash),
    ]
}
