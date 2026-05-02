//! PyNeat Rust Security Scanner
//!
//! Copyright (C) 2026 PyNEAT Authors
//!
//! This program is free software: you can redistribute it and/or modify
//! it under the terms of the GNU Affero General Public License as published
//! by the Free Software Foundation, either version 3 of the License, or
//! (at your option) any later version.
//!
//! This program is distributed in the hope that it will be useful,
//! but WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//! GNU Affero General Public License for more details.
//!
//! You should have received a copy of the GNU Affero General Public License
//! along with this program. If not, see <https://www.gnu.org/licenses/>.


use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{find_calls, LangFix, LangRule, LangFinding};
use regex::Regex;

/// Helper: get line byte offsets (0-indexed lines, 0-indexed bytes).
fn get_line_offsets(code: &str, line: usize) -> (usize, usize) {
    let mut current_line = 1;
    let mut line_start = 0;
    for (i, c) in code.char_indices() {
        if current_line == line {
            line_start = i;
            break;
        }
        if c == '\n' {
            current_line += 1;
        }
    }
    let mut line_end = line_start;
    for (i, c) in code[line_start..].char_indices() {
        if c == '\n' {
            line_end = line_start + i + 1;
            break;
        }
    }
    if line_end == line_start {
        line_end = code.len();
    }
    (line_start, line_end)
}

/// Helper: get the text content of a specific line (1-indexed).
fn get_line_text(code: &str, line: usize) -> Option<String> {
    code.lines().nth(line.saturating_sub(1)).map(|l| l.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-001: SQL Injection
// CWE-89 — CVSS 9.8 — CRITICAL
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpSqlInjection;

impl LangRule for PhpSqlInjection {
    fn id(&self) -> &str { "PHP2-SEC-001" }
    fn name(&self) -> &str { "SQL Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let sql_funcs = ["mysqli_query", "mysql_query", "pg_query", "sqlite_query",
                        "DB::query", "$db->query", "$pdo->query", "select", "insert",
                        "update", "delete"];
        let dangerous_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE"];

        for call in find_calls(tree, &sql_funcs) {
            let args_str = call.arguments.join(" ");
            let has_user_input = dangerous_keywords.iter().any(|p| args_str.contains(p))
                || args_str.contains("$_GET") || args_str.contains("$_POST")
                || args_str.contains("$_REQUEST");
            if has_user_input {
                let (start, end) = get_line_offsets(code, call.start_line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: call.callee.clone(),
                    problem: format!("SQL injection risk: {} with user input", call.callee),
                    fix_hint: "Use prepared statements: $stmt = $pdo->prepare($sql); $stmt->execute($params);".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-002: Cross-Site Scripting (XSS)
// CWE-79 — CVSS 6.1 — MEDIUM
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpXss;

impl LangRule for PhpXss {
    fn id(&self) -> &str { "PHP2-SEC-002" }
    fn name(&self) -> &str { "Cross-Site Scripting (XSS)" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let xss_funcs = ["echo", "print", "printf", "print_r", "var_dump", "var_export"];
        let user_inputs = ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE"];

        for call in find_calls(tree, &xss_funcs) {
            let args_str = call.arguments.join(" ");
            let has_user_input = user_inputs.iter().any(|i| args_str.contains(i));
            if has_user_input && !args_str.contains("htmlspecialchars")
                && !args_str.contains("htmlentities")
                && !args_str.contains("strip_tags") {
                let (start, end) = get_line_offsets(code, call.start_line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: call.callee.clone(),
                    problem: "XSS risk: unescaped user input in output".to_string(),
                    fix_hint: "Escape output: echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-003: Command Injection
// CWE-78 — CVSS 9.8 — CRITICAL
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpCommandInjection;

impl LangRule for PhpCommandInjection {
    fn id(&self) -> &str { "PHP2-SEC-003" }
    fn name(&self) -> &str { "Command Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous_funcs = ["exec", "system", "shell_exec", "passthru", "popen",
                               "proc_open", "pcntl_exec"];

        for call in find_calls(tree, &dangerous_funcs) {
            let args_str = call.arguments.join(" ");
            let _has_user_input = args_str.contains("$_GET") || args_str.contains("$_POST")
                || args_str.contains("$_REQUEST") || args_str.contains("$argv");
            let (start, end) = get_line_offsets(code, call.start_line);
            findings.push(LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line: call.start_line,
                column: 0,
                start_byte: start,
                end_byte: end,
                snippet: call.callee.clone(),
                problem: format!("Command injection risk: {} with user input", call.callee),
                fix_hint: "Use escapeshellarg() or avoid shell commands. Consider PHP native functions.".to_string(),
                auto_fix_available: false,
            });
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-004: Path Traversal / Local File Inclusion
// CWE-22 — CVSS 7.5 — HIGH
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpPathTraversal;

impl LangRule for PhpPathTraversal {
    fn id(&self) -> &str { "PHP2-SEC-004" }
    fn name(&self) -> &str { "Path Traversal / LFI" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous_funcs = ["include", "include_once", "require", "require_once",
                               "file_get_contents", "file_put_contents", "fopen",
                               "readfile", "copy", "unlink"];

        for call in find_calls(tree, &dangerous_funcs) {
            let args_str = call.arguments.join(" ");
            let has_user_input = args_str.contains("$_GET") || args_str.contains("$_POST")
                || args_str.contains("$_REQUEST");
            let has_traversal = args_str.contains("../") || args_str.contains("..\\");
            if has_user_input || has_traversal {
                let (start, end) = get_line_offsets(code, call.start_line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: call.callee.clone(),
                    problem: format!("Path traversal risk: {} with user input or traversal", call.callee),
                    fix_hint: "Validate and sanitize file paths. Use realpath() and whitelist allowed directories.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-005: Insecure Password Hashing
// CWE-328 — CVSS 5.3 — MEDIUM
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpWeakHashing;

impl LangRule for PhpWeakHashing {
    fn id(&self) -> &str { "PHP2-SEC-005" }
    fn name(&self) -> &str { "Weak Password Hashing" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let weak_funcs = ["md5(", "sha1(", "crypt("];
        let weak_algos = ["MD5", "SHA1", "DES", "BLOWFISH"];

        for (i, line) in code.lines().enumerate() {
            for func in &weak_funcs {
                if line.contains(func) {
                    let (start, end) = get_line_offsets(code, i + 1);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: i + 1,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.trim().to_string(),
                        problem: format!("Weak hashing: {} found", func.replace("(", "")),
                        fix_hint: "Use password_hash() with PASSWORD_DEFAULT or password_hash($password, PASSWORD_ARGON2ID).".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
            for algo in &weak_algos {
                if line.contains(algo) && line.contains("hash_") {
                    let (start, end) = get_line_offsets(code, i + 1);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: i + 1,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.trim().to_string(),
                        problem: format!("Weak hashing algorithm: {}", algo),
                        fix_hint: "Use hash_equals() for timing-safe comparison and ARGON2ID for hashing.".to_string(),
                        auto_fix_available: true,
                    });
                }
            }
        }
        findings
    }

    fn fix(&self, finding: &LangFinding, code: &str) -> Option<LangFix> {
        let line_text = code.lines().nth(finding.line - 1)?;
        let mut replacement = line_text.to_string();

        // Replace md5(...) with hash("sha256", ...)
        if line_text.contains("md5(") {
            replacement = replacement.replace("md5(", "hash(\"sha256\", ");
            return Some(LangFix {
                rule_id: self.id().to_string(),
                original: line_text.to_string(),
                replacement,
                start_byte: finding.start_byte,
                end_byte: finding.end_byte,
                description: "Replace md5() with hash(\"sha256\", ...) for secure hashing".to_string(),
            });
        }

        // Replace sha1(...) with hash("sha256", ...)
        if line_text.contains("sha1(") {
            replacement = replacement.replace("sha1(", "hash(\"sha256\", ");
            return Some(LangFix {
                rule_id: self.id().to_string(),
                original: line_text.to_string(),
                replacement,
                start_byte: finding.start_byte,
                end_byte: finding.end_byte,
                description: "Replace sha1() with hash(\"sha256\", ...) for secure hashing".to_string(),
            });
        }

        None
    }

    fn supports_auto_fix(&self) -> bool { true }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-006: Hardcoded Secrets
// CWE-798 — CVSS 7.5 — HIGH
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpHardcodedSecrets;

impl LangRule for PhpHardcodedSecrets {
    fn id(&self) -> &str { "PHP2-SEC-006" }
    fn name(&self) -> &str { "Hardcoded Secrets" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"(?i)password\s*[=:]\s*["'][^"']{4,}["']"#, "Hardcoded password"),
            (r#"(?i)secret\s*[=:]\s*["'][^"']{4,}["']"#, "Hardcoded secret"),
            (r#"(?i)api[_-]?key\s*[=:]\s*["'][^"']{4,}["']"#, "Hardcoded API key"),
            (r#"(?i)token\s*[=:]\s*["'][A-Za-z0-9_\-]{10,}["']"#, "Hardcoded token"),
            (r#"AKIA[A-Z0-9]{16}"#, "AWS Access Key ID"),
            (r#"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"#, "Private key"),
            (r#"(?i)db[_-]?pass(word)?\s*[=:]\s*["'][^"']+["']"#, "Database password"),
            (r#"(?i)aws[_-]?secret\s*[=:]\s*["'][^"']+["']"#, "AWS secret"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Use environment variables: getenv('SECRET') or _ENV['SECRET'].".to_string(),
                        auto_fix_available: true,
                    });
                }
            }
        }
        findings
    }

    fn fix(&self, finding: &LangFinding, code: &str) -> Option<LangFix> {
        let line_text = code.lines().nth(finding.line - 1)?;
        let indented = line_text.trim_start();

        // Extract the key name (e.g., "password", "api_key")
        let key_re = regex::Regex::new(r#"(?i)((?:api[_-]?)?(?:key|secret|password|token|pass(?:word)?))"#).ok()?;
        let key_caps = key_re.captures(&finding.snippet)?;
        let key_name = key_caps.get(1)?.as_str().to_uppercase().replace("-", "_");

        // Create replacement using env var
        let replacement = format!(
            "{} // FIXME: Use getenv('{}') in production",
            indented,
            key_name
        );

        Some(LangFix {
            rule_id: self.id().to_string(),
            original: line_text.to_string(),
            replacement,
            start_byte: finding.start_byte,
            end_byte: finding.end_byte,
            description: format!("Replace hardcoded {} with environment variable", key_name),
        })
    }

    fn supports_auto_fix(&self) -> bool { true }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-007: Eval Usage
// CWE-95 — CVSS 8.1 — HIGH
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpEvalUsage;

impl LangRule for PhpEvalUsage {
    fn id(&self) -> &str { "PHP2-SEC-007" }
    fn name(&self) -> &str { "Dangerous Eval Usage" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous_funcs = ["eval", "assert", "create_function", "preg_replace"];

        for call in find_calls(tree, &dangerous_funcs) {
            let args_str = call.arguments.join(" ");
            let _has_user_input = args_str.contains("$_GET") || args_str.contains("$_POST")
                || args_str.contains("$_REQUEST");
            let (start, end) = get_line_offsets(code, call.start_line);
            findings.push(LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line: call.start_line,
                column: 0,
                start_byte: start,
                end_byte: end,
                snippet: call.callee.clone(),
                problem: format!("Dangerous function: {} with user input risk", call.callee),
                fix_hint: "Avoid eval/assert. Use type checking and whitelist validation instead.".to_string(),
                auto_fix_available: false,
            });
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-008: Session Fixation
// CWE-384 — CVSS 6.0 — MEDIUM
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpSessionFixation;

impl LangRule for PhpSessionFixation {
    fn id(&self) -> &str { "PHP2-SEC-008" }
    fn name(&self) -> &str { "Session Fixation" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let session_funcs = ["session_id", "session_start"];
        let has_regenerate = code.contains("session_regenerate_id");
        let has_destroy = code.contains("session_destroy");

        for call in find_calls(tree, &session_funcs) {
            if !has_regenerate && !has_destroy {
                let (start, end) = get_line_offsets(code, call.start_line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: call.callee.clone(),
                    problem: "Session without regeneration - fixation risk".to_string(),
                    fix_hint: "Add session_regenerate_id(true) after authentication.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-009: Unvalidated Redirect
// CWE-601 — CVSS 6.1 — MEDIUM
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpUnvalidatedRedirect;

impl LangRule for PhpUnvalidatedRedirect {
    fn id(&self) -> &str { "PHP2-SEC-009" }
    fn name(&self) -> &str { "Unvalidated Redirect" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let redirect_funcs = ["header", "Location:", "redirect", "wp_redirect", "http_redirect"];
        let user_inputs = ["$_GET", "$_POST", "$_REQUEST", "$_SERVER"];

        for call in find_calls(tree, &redirect_funcs) {
            let args_str = call.arguments.join(" ");
            let has_user_input = user_inputs.iter().any(|i| args_str.contains(i));
            if has_user_input {
                let (start, end) = get_line_offsets(code, call.start_line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: call.callee.clone(),
                    problem: "Unvalidated redirect with user input".to_string(),
                    fix_hint: "Validate and whitelist redirect URLs. Never allow absolute URLs from user input.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-010: PHP Object Injection
// CWE-502 — CVSS 9.1 — CRITICAL
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpObjectInjection;

impl LangRule for PhpObjectInjection {
    fn id(&self) -> &str { "PHP2-SEC-010" }
    fn name(&self) -> &str { "PHP Object Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous_funcs = ["unserialize"];
        let user_inputs = ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "file_get_contents"];

        for call in find_calls(tree, &dangerous_funcs) {
            let args_str = call.arguments.join(" ");
            let has_user_input = user_inputs.iter().any(|i| args_str.contains(i));
            if has_user_input {
                let (start, end) = get_line_offsets(code, call.start_line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: call.callee.clone(),
                    problem: "Object injection: unserialize with user input".to_string(),
                    fix_hint: "Use json_decode() instead of unserialize(), or implement __wakeup/__destruct validation.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-011: Insecure CORS
// CWE-942 — CVSS 5.3 — MEDIUM
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpInsecureCors;

impl LangRule for PhpInsecureCors {
    fn id(&self) -> &str { "PHP2-SEC-011" }
    fn name(&self) -> &str { "Insecure CORS Configuration" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"header\s*\(\s*["']Access-Control-Allow-Origin:\s*\*["']"#, "CORS allows all origins"),
            (r"Access-Control-Allow-Credentials.*true", "CORS with credentials and wildcard origin"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Specify exact origins: header('Access-Control-Allow-Origin: https://trusted.com');".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-012: Information Disclosure
// CWE-200 — CVSS 5.0 — MEDIUM
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpInfoDisclosure;

impl LangRule for PhpInfoDisclosure {
    fn id(&self) -> &str { "PHP2-SEC-012" }
    fn name(&self) -> &str { "Information Disclosure" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"error_reporting\s*\(\s*E_ALL\s*\)"#, "Error reporting enabled in production"),
            (r#"ini_set\s*\(\s*["']display_errors"#, "Display errors enabled"),
            (r#"phpinfo\s*\(\s*\)"#, "phpinfo() exposes system info"),
            (r#"var_dump\s*\(\s*\$\w+\s*\)"#, "var_dump exposes variable content"),
            (r#"print_r\s*\(\s*\$\w+\s*\)"#, "print_r exposes variable content"),
            (r#"\$_SERVER\s*\[\s*["']PHP_SELF["']"#, "PHP_SELF can cause XSS"),
            (r#"\$_SERVER\s*\[\s*["']REQUEST_URI["']"#, "REQUEST_URI may contain malicious input"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Disable display_errors in production. Use error logging instead.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-013: Weak Random
// CWE-338 — CVSS 6.5 — MEDIUM
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpWeakRandom;

impl LangRule for PhpWeakRandom {
    fn id(&self) -> &str { "PHP2-SEC-013" }
    fn name(&self) -> &str { "Weak Random Number Generation" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r"mt_rand\s*\(", "mt_rand is predictable for security"),
            (r"rand\s*\(", "rand is predictable for security"),
            (r"srand\s*\(", "srand with weak seed"),
            (r"mcrypt_", "mcrypt is deprecated and insecure"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Use random_bytes() for cryptography or Randomizer from randomlib.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-014: Missing HTTPS Enforcement
// CWE-295 — CVSS 5.3 — LOW
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpMissingHttps;

impl LangRule for PhpMissingHttps {
    fn id(&self) -> &str { "PHP2-SEC-014" }
    fn name(&self) -> &str { "Missing HTTPS Enforcement" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let has_https_check = code.contains("HTTPS") && code.contains("on")
            || code.contains("HTTP_X_FORWARDED_PROTO")
            || code.contains("filter_var") && code.contains("FILTER_FLAG_SCHEME_REQUIRED");
        let has_sts = code.contains("Strict-Transport-Security");
        let has_login = find_calls(tree, &["login", "auth", "password", "signin"]).len() > 0;

        if has_login && !has_https_check {
            let (start, end) = get_line_offsets(code, 1);
            findings.push(LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line: 1,
                column: 0,
                start_byte: start,
                end_byte: end,
                snippet: "Login/authentication detected".to_string(),
                problem: "Missing HTTPS enforcement for sensitive operations".to_string(),
                fix_hint: "Add HTTPS check: if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') { die('HTTPS required'); }".to_string(),
                auto_fix_available: false,
            });
        }

        if !has_sts && has_https_check {
            let (start, end) = get_line_offsets(code, 1);
            findings.push(LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line: 1,
                column: 0,
                start_byte: start,
                end_byte: end,
                snippet: "HTTPS detected but no HSTS".to_string(),
                problem: "Missing HTTP Strict Transport Security header".to_string(),
                fix_hint: "Add HSTS header: header('Strict-Transport-Security: max-age=31536000; includeSubDomains');".to_string(),
                auto_fix_available: false,
            });
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-015: Insecure File Upload
// CWE-434 — CVSS 8.1 — CRITICAL
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpInsecureFileUpload;

impl LangRule for PhpInsecureFileUpload {
    fn id(&self) -> &str { "PHP2-SEC-015" }
    fn name(&self) -> &str { "Insecure File Upload" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let upload_funcs = ["move_uploaded_file", "copy", "file_put_contents"];
        let has_validation = code.contains("exif_imagetype")
            || code.contains("mime_content_type")
            || code.contains("getimagesize")
            || code.contains("finfo_file");

        for call in find_calls(tree, &upload_funcs) {
            if !has_validation && call.arguments.len() > 0 {
                let (start, end) = get_line_offsets(code, call.start_line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: call.callee.clone(),
                    problem: "File upload without proper validation - may accept malicious files".to_string(),
                    fix_hint: "Validate file type using exif_imagetype(), mime_content_type(), and check file extension whitelist.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-016: Loose Comparison
// CWE-20 — CVSS 6.1 — HIGH
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpLooseComparison;

impl LangRule for PhpLooseComparison {
    fn id(&self) -> &str { "PHP2-SEC-016" }
    fn name(&self) -> &str { "Loose Type Comparison" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"\$_\w+\s*==\s*['"][^'"]+['"]"#, "Loose comparison with user input string"),
            (r#"==\s*(?!==)(?!!=)"#, "Loose equality operator - use === for type-safe comparison"),
            (r#"['"][^'"]+['"]\s*==\s*\$_\w+"#, "String compared loosely with user input"),
            (r#"if\s*\(\s*!\s*empty\s*\([^)]+\)\s*\)"#, "empty() with loose check - verify type safety"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Use strict comparison (=== or !==) and validate input types explicitly.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-017: Missing CSRF Protection
// CWE-352 — CVSS 6.0 — MEDIUM
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpMissingCsrf;

impl LangRule for PhpMissingCsrf {
    fn id(&self) -> &str { "PHP2-SEC-017" }
    fn name(&self) -> &str { "Missing CSRF Protection" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let has_csrf_check = code.contains("csrf_token")
            || code.contains("CSRF")
            || code.contains("csrf验证")
            || code.contains("token_verify")
            || code.contains("hash_equals");
        let has_form_post = code.contains("$_POST") || code.contains("form") && code.contains("method");
        let has_session = code.contains("session_start") || code.contains("SESSION");

        if has_form_post && has_session && !has_csrf_check {
            if let Ok(re) = regex::Regex::new(r#"if\s*\(\s*!\s*empty\s*\(\s*\$_\w+\s*\)\s*\)"#) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: "POST form handler detected".to_string(),
                        problem: "Form POST handler without CSRF token validation".to_string(),
                        fix_hint: "Add CSRF token: generate token on form, verify with hash_equals($_SESSION['csrf'], $_POST['csrf']).".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-018: PHP XXE (XML External Entity)
// CWE-611 — CVSS 8.0 — HIGH
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpXxe;

impl LangRule for PhpXxe {
    fn id(&self) -> &str { "PHP2-SEC-018" }
    fn name(&self) -> &str { "PHP XXE Vulnerability" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"simplexml_load_(string|file)"#, "SimpleXML load without XXE protection"),
            (r#"DOMDocument->load(XML|HTML)"#, "DOMDocument load without XXE protection"),
            (r#"xml_parse\s*\("#, "XML parsing without XXE protection"),
            (r#"libxml_set_external_entity_loader"#, "Custom entity loader may enable XXE"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Disable XXE: libxml_disable_entity_loader(true); before parsing.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-019: LDAP Injection
// CWE-90 — CVSS 8.0 — HIGH
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpLdapInjection;

impl LangRule for PhpLdapInjection {
    fn id(&self) -> &str { "PHP2-SEC-019" }
    fn name(&self) -> &str { "LDAP Injection" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let ldap_funcs = ["ldap_search", "ldap_bind", "ldap_connect", "ldap_modify"];

        for call in find_calls(tree, &ldap_funcs) {
            let args_str = call.arguments.join(" ");
            let has_user_input = args_str.contains("$_GET")
                || args_str.contains("$_POST")
                || args_str.contains("$_REQUEST");
            if has_user_input {
                let (start, end) = get_line_offsets(code, call.start_line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: call.callee.clone(),
                    problem: "LDAP injection risk: user input in LDAP query".to_string(),
                    fix_hint: "Escape LDAP special characters: ldap_escape($input, '', LDAP_ESCAPE_FILTER). Use prepared LDAP statements.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-020: Mass Assignment
// CWE-915 — CVSS 6.1 — MEDIUM
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpMassAssignment;

impl LangRule for PhpMassAssignment {
    fn id(&self) -> &str { "PHP2-SEC-020" }
    fn name(&self) -> &str { "Mass Assignment Vulnerability" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"::create\s*\(\s*\$_POST\s*\)"#, "Mass assignment via create with $_POST"),
            (r#"::update\s*\(\s*\$_POST\s*\)"#, "Mass assignment via update with $_POST"),
            (r#"Model\s*::\w+\s*\(\s*\$_(GET|POST|REQUEST)\s*\)"#, "Model method with user input"),
            (r#"\$model\s*->fill\s*\(\s*\$_\w+\s*\)"#, "Fill method with user input"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Use $fillable or $guarded properties in Eloquent. Validate and whitelist allowed fields.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-AI-001: Slopsquatting (AI-Hallucinated Dependencies)
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpSlopsquatting;

impl LangRule for PhpSlopsquatting {
    fn id(&self) -> &str { "PHP2-AI-001" }
    fn name(&self) -> &str { "AI-Hallucinated Dependency (Slopsquatting)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, _code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let hallucinated: Vec<&str> = vec![
            "fakerlib", "jsonify", "phpserialize", "laravelfake",
            "mongomagic", "mysqldriver-fake", "redis-mock",
            "test-pkg-xyz", "mock-ext",
        ];
        for imp in &tree.imports {
            for fake in &hallucinated {
                if imp.module.contains(fake) || imp.name.contains(fake) {
                    let (start, end) = get_line_offsets(_code, imp.start_line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: imp.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: imp.module.clone(),
                        problem: format!("Slopsquatting Risk: The package '{}' appears to be a hallucinated name.", imp.module),
                        fix_hint: "Verify this package exists on packagist.org before installing.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-AI-002: Verbose Error Exposure
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpVerboseError;

impl LangRule for PhpVerboseError {
    fn id(&self) -> &str { "PHP2-AI-002" }
    fn name(&self) -> &str { "Verbose Error Exposure" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r#"echo\s+(['\"]?\s*\$e(rr|rror)?\s*->(getMessage|__toString)\(\)\s*['\"]?)"#, "Echoing error directly to output"),
            (r#"print_r\s*\(\s*\$e(rr|rror)"#, "print_r exposing error details"),
            (r#"var_dump\s*\(\s*\$e(rr|rror)"#, "var_dump exposing error details"),
            (r#"die\s*\(\s*\$e(rr|rror)"#, "die() with error object"),
            (r#"echo\s+['\"]?\s*err(or)?\s*['\"]?\s*\.\s*\$e"#, "String concatenation with error"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Log errors to file, return generic message to user.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-AI-003: Missing Input Validation
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpMissingInputValidation;

impl LangRule for PhpMissingInputValidation {
    fn id(&self) -> &str { "PHP2-AI-003" }
    fn name(&self) -> &str { "Missing Input Validation" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r#"\$_GET\s*\[\s*['\"][^'\"]+['\"]\s*\]"#, "Direct $_GET access without sanitization"),
            (r#"\$_POST\s*\[\s*['\"][^'\"]+['\"]\s*\]"#, "Direct $_POST access without validation"),
            (r#"\$_REQUEST\s*\[\s*['\"][^'\"]+['\"]\s*\]"#, "Direct $_REQUEST without filtering"),
            (r#"filter_input\s*\(\s*INPUT_GET[^)]*\)\s*(?!&&|\|\||\?)"#, "filter_input without immediate check"),
            (r#"htmlspecialchars\s*\([^)]*\$_(GET|POST|REQUEST)"#, "Escaping with htmlspecialchars but missing charset"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Validate and sanitize all user input using filter_input() or custom validation.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-AI-004: AI-Generated Code Marker
// ─────────────────────────────────────────────────────────────────────────────

pub struct PhpAiGenComment;

impl LangRule for PhpAiGenComment {
    fn id(&self) -> &str { "PHP2-AI-004" }
    fn name(&self) -> &str { "AI-Generated Code Marker" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"(?i)generated by (chatgpt|claude|copilot|gemini|llm|gpt|ai|openai|anthropic)"##, "AI generation marker"),
            (r##"(?i)written by (chatgpt|claude|copilot|gemini|llm)"##, "AI authorship claim"),
            (r##"(?i)code generated by (cursor|github|replit)"##, "Code assistant marker"),
            (r##"(?i)AI[_-]?generated"##, "AI-generated marker"),
        ];
        for comment in &tree.comments {
            for (pattern, _) in &patterns {
                if let Ok(re) = regex::Regex::new(pattern) {
                    if re.is_match(&comment.text) {
                        let (start, end) = get_line_offsets(code, comment.start_line);
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: comment.start_line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: comment.text.clone(),
                            problem: "AI-Generated Code Detected".to_string(),
                            fix_hint: "Review AI-generated code carefully before production use.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-026: SameSite Cookie Attribute Missing (CWE-614)
// Severity: medium | OWASP A05:2021
// setcookie, session_set_cookie_params without SameSite parameter
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpSameSiteCookie;

impl LangRule for PhpSameSiteCookie {
    fn id(&self) -> &str { "PHP2-SEC-026" }
    fn name(&self) -> &str { "SameSite Cookie Attribute Missing" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let cookie_funcs = ["setcookie", "setrawcookie", "session_set_cookie_params"];
        let same_site_re = regex::Regex::new(r"(?i)SameSite").unwrap();

        for call in find_calls(_tree, &cookie_funcs) {
            let args_str = call.arguments.join(" ");
            // Check if SameSite is present in the arguments
            if !same_site_re.is_match(&args_str) {
                let (start, end) = get_line_offsets(code, call.start_line);
                let line_text = code.lines().nth(call.start_line - 1).unwrap_or("");
                findings.push(LangFinding {
                    rule_id: "PHP2-SEC-026".to_string(),
                    severity: "medium".to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: "Cookie set without SameSite attribute. Without SameSite, cookies can be sent on cross-site requests, enabling CSRF attacks.".to_string(),
                    fix_hint: "Add SameSite=Lax or SameSite=Strict: setcookie($name, $value, ['samesite' => 'Lax']). Use 'Strict' for sensitive cookies, 'Lax' for general authenticated cookies.".to_string(),
                    auto_fix_available: false,
                });
            }
        }

        // Also check for session configuration without SameSite
        let session_re = Regex::new(r"(?i)session_set_cookie_params\s*\([^)]*\)").unwrap();
        let has_samesite = Regex::new(r"(?i)SameSite").unwrap();
        if session_re.is_match(code) && !has_samesite.is_match(code) {
            for m in session_re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let line_text = code.lines().nth(line - 1).unwrap_or("");
                if !findings.iter().any(|f: &LangFinding| f.line == line) {
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: "PHP2-SEC-026".to_string(),
                        severity: "medium".to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: "Session cookie configuration without SameSite attribute.".to_string(),
                        fix_hint: "Add SameSite parameter to session_set_cookie_params(['samesite' => 'Lax']).".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-027: PHAR Deserialization (CWE-502)
// Severity: critical | OWASP A08:2021
// phar:// wrapper in include/require, file operations with phar://
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpPharDeserialization;

impl LangRule for PhpPharDeserialization {
    fn id(&self) -> &str { "PHP2-SEC-027" }
    fn name(&self) -> &str { "PHAR Deserialization Attack" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let phar_patterns = [
            (r#"phar://"#, "phar:// stream wrapper detected"),
            (r#"file_get_contents\s*\([^)]*phar://"#, "file_get_contents with phar:// wrapper"),
            (r#"include\s*\([^)]*phar://"#, "include with phar:// wrapper"),
            (r#"require\s*\([^)]*phar://"#, "require with phar:// wrapper"),
            (r#"fopen\s*\([^)]*phar://"#, "fopen with phar:// wrapper"),
            (r#"\$img\s*=\s*['\"]image[^'\"]*['\"].*?phar://"#, "Image processing with phar:// wrapper"),
        ];

        for (pat, problem) in &phar_patterns {
            if let Ok(re) = regex::Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = code.lines().nth(line - 1).unwrap_or("");

                    // Check if there's user input involved
                    let has_user_input = line_text.contains("$_GET")
                        || line_text.contains("$_POST")
                        || line_text.contains("$_REQUEST")
                        || line_text.contains("$params")
                        || line_text.contains("$input")
                        || line_text.contains("$filename")
                        || line_text.contains("$file");

                    if has_user_input {
                        findings.push(LangFinding {
                            rule_id: "PHP2-SEC-027".to_string(),
                            severity: "critical".to_string(),
                            line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text.trim().to_string(),
                            problem: format!("PHAR deserialization risk: {}. A crafted PHAR file can cause arbitrary code execution.", problem),
                            fix_hint: "Never use user-controlled file paths with phar:// wrapper. Validate and sanitize all file inputs. Use realpath() to resolve paths and check they don't escape the intended directory.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-028: Type Juggling Bypass (CWE-20)
// Severity: high | OWASP A04:2021
// in_array without strict, empty(), isset() on user input
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpTypeJuggling;

impl LangRule for PhpTypeJuggling {
    fn id(&self) -> &str { "PHP2-SEC-028" }
    fn name(&self) -> &str { "Type Juggling Authentication Bypass" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // in_array without strict parameter
        let weak_in_array_re = regex::Regex::new(
            r##"in_array\s*\(\s*\$[^,]+,\s*\$[^)]+\s*\)"##
        ).unwrap();

        // empty() on variables that could be strings
        let empty_user_input_re = regex::Regex::new(
            r##"empty\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)"##
        ).unwrap();

        // Loose comparison with user input (== instead of ===)
        let loose_comparison_re = regex::Regex::new(
            r##"(\$_(?:GET|POST|REQUEST|COOKIE)\[[^\]]+\])\s*==\s*['\"]?0['\"]?"##
        ).unwrap();

        let auth_keywords = ["password", "passwd", "auth", "login", "credential", "secret"];

        for m in weak_in_array_re.find_iter(code) {
            let line = code[..m.start()].matches('\n').count() + 1;
            let line_text = code.lines().nth(line - 1).unwrap_or("");
            findings.push(LangFinding {
                rule_id: "PHP2-SEC-028".to_string(),
                severity: "high".to_string(),
                line,
                column: 0,
                start_byte: 0,
                end_byte: 0,
                snippet: line_text.trim().to_string(),
                problem: "in_array() used without strict parameter (third arg). This uses loose comparison and can lead to type juggling bypasses (e.g., '0' matches 0, false, 'false').".to_string(),
                fix_hint: "Add third parameter true for strict comparison: in_array($val, $arr, true). Use === instead of == for comparisons.".to_string(),
                auto_fix_available: false,
            });
        }

        for m in empty_user_input_re.find_iter(code) {
            let line = code[..m.start()].matches('\n').count() + 1;
            let line_text = code.lines().nth(line - 1).unwrap_or("");
            if !findings.iter().any(|f: &LangFinding| f.line == line) {
                findings.push(LangFinding {
                    rule_id: "PHP2-SEC-028".to_string(),
                    severity: "high".to_string(),
                    line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: line_text.trim().to_string(),
                    problem: "empty() used on user input. Since empty('0') returns true, this can bypass authentication logic.".to_string(),
                    fix_hint: "Use explicit checks: isset($val) && $val !== '' instead of empty(). For string checks, use strlen() > 0.".to_string(),
                    auto_fix_available: false,
                });
            }
        }

        for caps in loose_comparison_re.captures_iter(code) {
            let line = code[..caps.get(0).unwrap().start()].matches('\n').count() + 1;
            let line_text = code.lines().nth(line - 1).unwrap_or("");
            let captured = caps.get(1).map(|x| x.as_str()).unwrap_or("");
            if auth_keywords.iter().any(|k| line_text.to_lowercase().contains(k)) {
                findings.push(LangFinding {
                    rule_id: "PHP2-SEC-028".to_string(),
                    severity: "high".to_string(),
                    line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: line_text.trim().to_string(),
                    problem: format!("Loose comparison (==) of user input '{}' detected near authentication logic. Use === for type-safe comparison.", captured),
                    fix_hint: "Replace == with === for strict type comparison. Use strcmp() or hash_equals() for string comparison.".to_string(),
                    auto_fix_available: false,
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-029: Dependency Vulnerability (OWASP A06)
// Severity: medium
// composer.json with outdated or vulnerable package versions
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpDependencyVuln;

impl LangRule for PhpDependencyVuln {
    fn id(&self) -> &str { "PHP2-SEC-029" }
    fn name(&self) -> &str { "Outdated / Vulnerable Composer Dependency" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Known vulnerable package patterns in composer.json
        let vuln_packages = [
            (r##"symfony/symfony\s*:\s*['\"]?[2-3]\."##, "symfony 2.x/3.x has known vulnerabilities"),
            (r##"phpunit/phpunit\s*:\s*['\"]?[3-7]\."##, "phpunit versions < 8.x have known vulnerabilities"),
            (r##"guzzlehttp/guzzle\s*:\s*['\"]?[3-6]\."##, "guzzle < 7.0 has known vulnerabilities"),
            (r##"twig/twig\s*:\s*['\"]?[1-2]\."##, "twig < 3.0 has known vulnerabilities"),
            (r##"wordpress/wordpress\s*:\s*['\"]?[3-5]\."##, "WordPress < 6.0 has known vulnerabilities"),
            (r##"drupal/drupal\s*:\s*['\"]?[7-8]\."##, "Drupal < 9.0 has known vulnerabilities"),
            (r##"laravel/framework\s*:\s*['\"]?[5-7]\."##, "Laravel < 8.0 has known vulnerabilities"),
            (r##"'dev-master'"##, "Package pinned to dev-master - unpredictable version"),
            (r##"'\*'"##, "Package with wildcard version '*' - installs any version"),
        ];

        let is_composer_json = code.contains("\"require\"") || code.contains("\"require-dev\"");

        if is_composer_json {
            for (pat, problem) in &vuln_packages {
                if let Ok(re) = regex::Regex::new(pat) {
                    for m in re.find_iter(code) {
                        let line = code[..m.start()].matches('\n').count() + 1;
                        let line_text = code.lines().nth(line - 1).unwrap_or("");
                        let (start, end) = get_line_offsets(code, line);

                        findings.push(LangFinding {
                            rule_id: "PHP2-SEC-029".to_string(),
                            severity: "medium".to_string(),
                            line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text.trim().to_string(),
                            problem: problem.to_string(),
                            fix_hint: "Update to the latest stable version. Run 'composer update --dry-run' to check updates. Regularly audit dependencies with 'composer audit' or OWASP Dependency-Check.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-030: Password Hashing Cost Too Low (CWE-328)
// Severity: low
// password_hash without cost parameter or cost < 10
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpWeakPasswordHashCost;

impl LangRule for PhpWeakPasswordHashCost {
    fn id(&self) -> &str { "PHP2-SEC-030" }
    fn name(&self) -> &str { "Weak Password Hashing Cost" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // password_hash without cost parameter
        let no_cost_re = regex::Regex::new(
            r##"password_hash\s*\(\s*\$[^,)]+\s*,\s*PASSWORD_DEFAULT\s*\)"##
        ).unwrap();

        // Explicit low cost
        let low_cost_re = regex::Regex::new(
            r##"password_hash\s*\([^)]*['\"]cost['\"]\s*=>\s*(\d+)"##
        ).unwrap();

        for m in no_cost_re.find_iter(code) {
            let line = code[..m.start()].matches('\n').count() + 1;
            let line_text = code.lines().nth(line - 1).unwrap_or("");
            let (start, end) = get_line_offsets(code, line);

            findings.push(LangFinding {
                rule_id: "PHP2-SEC-030".to_string(),
                severity: "low".to_string(),
                line,
                column: 0,
                start_byte: start,
                end_byte: end,
                snippet: line_text.trim().to_string(),
                problem: "password_hash() called without explicit cost parameter. While PASSWORD_DEFAULT uses bcrypt, the default cost may be too low for production (currently 10, but was 10 in earlier PHP versions).".to_string(),
                fix_hint: "Set explicit cost: password_hash($password, PASSWORD_DEFAULT, ['cost' => 12]). Cost 12 provides good balance between security and performance. Benchmark your server to find optimal cost.".to_string(),
                auto_fix_available: false,
            });
        }

        for caps in low_cost_re.captures_iter(code) {
            if let Some(cost_match) = caps.get(1) {
                if let Ok(cost) = cost_match.as_str().parse::<u32>() {
                    if cost < 10 {
                        let full_match = caps.get(0).unwrap();
                        let line = code[..full_match.start()].matches('\n').count() + 1;
                        let line_text = code.lines().nth(line - 1).unwrap_or("");
                        let (start, end) = get_line_offsets(code, line);

                        findings.push(LangFinding {
                            rule_id: "PHP2-SEC-030".to_string(),
                            severity: "low".to_string(),
                            line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text.trim().to_string(),
                            problem: format!("password_hash() with cost={}. Costs below 10 are considered weak by modern standards.", cost),
                            fix_hint: "Use cost of 10 or higher (recommended: 12). Higher cost = slower hash = more resistant to brute-force.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-036: RCE via eval/assert/create_function
// Severity: critical | CWE-94
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpRceEval;

impl LangRule for PhpRceEval {
    fn id(&self) -> &str { "PHP2-SEC-036" }
    fn name(&self) -> &str { "Remote Code Execution via eval()" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["eval(", "assert(", "create_function("];

        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: line_text.trim().to_string(),
                    problem: "Code execution function (eval/assert/create_function) called. RCE risk if input is user-controlled.".to_string(),
                    fix_hint: "Avoid eval/assert/create_function. Use whitelist validation or refactor to avoid dynamic code.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-037: LFI/RFI - include/require with user input
// Severity: high | CWE-98
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpLfiRfi;

impl LangRule for PhpLfiRfi {
    fn id(&self) -> &str { "PHP2-SEC-037" }
    fn name(&self) -> &str { "Local/Remote File Inclusion" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["include(", "require(", "include_once(", "require_once("];

        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                let args_str = call.arguments.join(" ");
                let user_input = ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE"];
                if user_input.iter().any(|u| args_str.contains(u)) {
                    let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "File inclusion with user-controlled path. Can lead to LFI/RCE.".to_string(),
                        fix_hint: "Validate and whitelist file paths. Never include files based on user input directly.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-038: Weak Cryptography
// Severity: high | CWE-327
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpWeakCrypto;

impl LangRule for PhpWeakCrypto {
    fn id(&self) -> &str { "PHP2-SEC-038" }
    fn name(&self) -> &str { "Weak Cryptography Usage" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["md5(", "sha1(", "mcrypt_"];

        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: line_text.trim().to_string(),
                    problem: "Weak cryptographic function (md5/sha1/mcrypt) detected.".to_string(),
                    fix_hint: "Use password_hash()/password_verify() for passwords. Use openssl with AES-256 for encryption.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-039: SQL Injection via PDO
// Severity: critical | CWE-89
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpPdoSqlInjection;

impl LangRule for PhpPdoSqlInjection {
    fn id(&self) -> &str { "PHP2-SEC-039" }
    fn name(&self) -> &str { "SQL Injection via PDO" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let sql_funcs = ["query(", "exec("];

        for call in &tree.calls {
            if sql_funcs.iter().any(|d| call.callee.contains(d)) {
                let args_str = call.arguments.join(" ");
                if args_str.contains("$_GET") || args_str.contains("$_POST") || args_str.contains("$_REQUEST") || args_str.contains("'\".") || args_str.contains("\".") {
                    let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "SQL query with user input in string concatenation.".to_string(),
                        fix_hint: "Use prepared statements: $stmt = $pdo->prepare($sql); $stmt->execute([...]);".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-040: Open Redirect
// Severity: medium | CWE-601
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpOpenRedirect;

impl LangRule for PhpOpenRedirect {
    fn id(&self) -> &str { "PHP2-SEC-040" }
    fn name(&self) -> &str { "Open Redirect Vulnerability" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let redirect_funcs = ["header(", "http_redirect(", "Location:"];

        for call in &tree.calls {
            if redirect_funcs.iter().any(|d| call.callee.contains(d)) || call.callee.contains("header") {
                let args_str = call.arguments.join(" ");
                let user_input = ["$_GET", "$_POST", "$_REQUEST"];
                if user_input.iter().any(|u| args_str.contains(u)) {
                    let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "Redirect destination includes user input. Open redirect vulnerability.".to_string(),
                        fix_hint: "Validate redirect URLs against an allowlist of permitted domains.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-AI-009: AI Hardcoded Credentials
// Severity: high | CWE-798
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpAiHardcodedCredentials;

impl LangRule for PhpAiHardcodedCredentials {
    fn id(&self) -> &str { "PHP2-AI-009" }
    fn name(&self) -> &str { "AI: Hardcoded Credentials" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["setPassword", "mysql_connect", "mysqli_connect", "pg_connect"];
        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                let args_str = call.arguments.join(" ");
                if args_str.contains("'") && (args_str.contains("password") || args_str.contains("root") || args_str.contains("admin")) {
                    let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "AI-generated code may contain hardcoded database credentials.".to_string(),
                        fix_hint: "Use environment variables or a secrets manager for credentials.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-AI-010: AI SQL Injection via Concatenation
// Severity: critical | CWE-89
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpAiSqlInjection;

impl LangRule for PhpAiSqlInjection {
    fn id(&self) -> &str { "PHP2-AI-007" }
    fn name(&self) -> &str { "AI: SQL Injection via Concatenation" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let sql_funcs = ["query(", "mysqli_query(", "pg_query("];
        for call in &tree.calls {
            if sql_funcs.iter().any(|d| call.callee.contains(d)) {
                let args_str = call.arguments.join(" ");
                if args_str.contains("\" .") || args_str.contains("' .") || args_str.contains(". $_") {
                    let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "AI-generated SQL query with string concatenation.".to_string(),
                        fix_hint: "Use prepared statements with bound parameters.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-AI-011: AI Command Injection
// Severity: critical | CWE-78
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpAiCommandInjection;

impl LangRule for PhpAiCommandInjection {
    fn id(&self) -> &str { "PHP2-AI-008" }
    fn name(&self) -> &str { "AI: Command Injection - system/exec()" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["system(", "exec(", "shell_exec(", "passthru(", "popen(", "proc_open("];
        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                let args_str = call.arguments.join(" ");
                let user_input = ["$_GET", "$_POST", "$_REQUEST"];
                if user_input.iter().any(|u| args_str.contains(u)) {
                    let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "AI-generated command execution with user-controlled input.".to_string(),
                        fix_hint: "Validate and escape all user input. Use escapeshellarg() for arguments.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-AI-012: AI unserialize() on User Input
// Severity: critical | CWE-502
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpAiUnserialize;

impl LangRule for PhpAiUnserialize {
    fn id(&self) -> &str { "PHP2-AI-005" }
    fn name(&self) -> &str { "AI: unserialize() on User Input" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        for call in &tree.calls {
            if call.callee.contains("unserialize(") {
                let args_str = call.arguments.join(" ");
                if args_str.contains("$_GET") || args_str.contains("$_POST") || args_str.contains("$_REQUEST") {
                    let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "AI-generated code unserializes user input. Can lead to RCE.".to_string(),
                        fix_hint: "Use JSON decoding (json_decode) instead. If PHP unserialize is needed, validate input.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-AI-013: AI Path Traversal
// Severity: high | CWE-22
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpAiPathTraversal;

impl LangRule for PhpAiPathTraversal {
    fn id(&self) -> &str { "PHP2-AI-006" }
    fn name(&self) -> &str { "AI: Path Traversal Vulnerability" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let file_funcs = ["file_get_contents(", "file_put_contents(", "readfile(", "fopen(", "include("];
        for call in &tree.calls {
            if file_funcs.iter().any(|d| call.callee.contains(d)) {
                let args_str = call.arguments.join(" ");
                if args_str.contains("$_GET") || args_str.contains("$_POST") || args_str.contains("$_REQUEST") {
                    let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "AI-generated file operation with user-controlled path.".to_string(),
                        fix_hint: "Validate and sanitize file paths. Use basename() and realpath() for path normalization.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-AI-014: AI XSS via echo of $_GET/$_POST
// Severity: high | CWE-79
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpAiXss;

impl LangRule for PhpAiXss {
    fn id(&self) -> &str { "PHP2-AI-011" }
    fn name(&self) -> &str { "AI: XSS via echo of User Input" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let output_funcs = ["echo ", "print ", "printf(", "print_r("];
        for call in &tree.calls {
            let args_str = call.arguments.join(" ");
            if output_funcs.iter().any(|d| call.callee.contains(d.trim())) || call.callee.contains("echo") {
                if args_str.contains("$_GET") || args_str.contains("$_POST") || args_str.contains("$_REQUEST") {
                    let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "AI-generated code outputs user input without escaping. XSS vulnerability.".to_string(),
                        fix_hint: "Use htmlspecialchars($input, ENT_QUOTES, 'UTF-8') to escape output.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-031: Server-Side Request Forgery (SSRF)
// Severity: high | CWE-918
// file_get_contents, curl_setopt, fopen, readfile, copy with user input or internal IPs
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpSsrfDeep;

impl LangRule for PhpSsrfDeep {
    fn id(&self) -> &str { "PHP2-SEC-031" }
    fn name(&self) -> &str { "Server-Side Request Forgery (SSRF)" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let ssrf_funcs = ["file_get_contents", "fopen", "readfile", "copy", "unlink"];
        let user_inputs = ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE",
                          "$request->get", "$request->param", "$input->get", "$request->query"];
        let internal_ips = ["169.254.169.254", "127.0.0.1", "localhost"];

        for call in &tree.calls {
            if ssrf_funcs.iter().any(|f| call.callee.contains(f)) {
                let args_str = call.arguments.join(" ");
                let has_user_input = user_inputs.iter().any(|i| args_str.contains(i));
                let has_internal_ip = internal_ips.iter().any(|ip| args_str.contains(ip));
                if has_user_input || has_internal_ip {
                    let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "SSRF risk: URL/path with user input or internal IP address.".to_string(),
                        fix_hint: "Validate and whitelist allowed URLs/hosts. Never trust user-supplied URLs.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
            // Check curl_setopt with CURLOPT_URL
            if call.callee.contains("curl_setopt") {
                let args_str = call.arguments.join(" ");
                if args_str.contains("CURLOPT_URL") && (args_str.contains("$_GET") || args_str.contains("$_POST") ||
                    args_str.contains("$_REQUEST") || args_str.contains("$_COOKIE") ||
                    args_str.contains("$request->get") || args_str.contains("$request->param") ||
                    args_str.contains("$input->get") || args_str.contains("$request->query")) {
                    let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "SSRF risk: curl_setopt CURLOPT_URL with user input.".to_string(),
                        fix_hint: "Validate URL against allowlist of permitted hosts. Use parse_url() to extract and verify host.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        // Also scan for direct internal IP references in URLs
        let ip_patterns = [
            (r#"["']https?://[^"']*169\.254\.169\.254"#, "AWS metadata endpoint IP"),
            (r#"["']https?://[^"']*127\.0\.0\.1"#, "Localhost IP"),
            (r#"["']https?://[^"']*localhost"#, "Localhost hostname"),
        ];
        for (pat, _) in &ip_patterns {
            if let Ok(re) = regex::Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or("");
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: "SSRF risk: URL targeting internal resource.".to_string(),
                        fix_hint: "Block access to internal IPs and hostnames. Validate URLs against allowlist.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-032: Weak JWT Verification
// Severity: critical | CWE-345
// Firebase\JWT\JWT::decode with null key, JWT::encode with empty key, etc.
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpWeakJwt;

impl LangRule for PhpWeakJwt {
    fn id(&self) -> &str { "PHP2-SEC-032" }
    fn name(&self) -> &str { "Weak JWT Verification" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Pattern-based detection for JWT with weak/null keys
        let jwt_patterns = [
            (r#"JWT::decode\s*\(\s*\$[^,]+,\s*null"#, "JWT::decode with null key - no signature verification"),
            (r#"Firebase\\JWT\\JWT::decode\s*\(\s*\$[^,]+,\s*null"#, "Firebase\\JWT::decode with null key - no signature verification"),
            (r#"JWT::decode\s*\(\s*\$[^,]+,\s*["']["']"#, "JWT::decode with empty string key"),
            (r#"Firebase\\JWT\\JWT::decode\s*\(\s*\$[^,]+,\s*["']["']"#, "Firebase JWT with empty string key"),
            (r#"JWT::encode\s*\(\s*\$[^,]+,\s*["']["']"#, "JWT::encode with empty key - weak signing"),
            (r#"openssl_verify\s*\([^,]+,\s*null"#, "openssl_verify with null key"),
            (r#"openssl_verify\s*\([^,]+,\s*["']["']"#, "openssl_verify with empty key"),
            (r#"hash_equals\s*\(\s*\$secret,\s*\$provided"#, "hash_equals used - verify secret is not empty or weak"),
        ];

        for (pat, problem) in &jwt_patterns {
            if let Ok(re) = regex::Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!("Weak JWT verification: {}. Tokens can be forged without proper signature verification.", problem),
                        fix_hint: "Use a strong, secret key (minimum 256 bits for HS256). Retrieve the key securely from environment variables or a secrets manager. Never pass null or an empty string as the verification key.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        // Also use tree-based call detection for additional patterns
        for call in &tree.calls {
            // Check for JWT::decode, JWT::encode patterns
            if call.callee.contains("JWT::decode") || call.callee.contains("JWT.decode") {
                let args_str = call.arguments.join(" ");
                if args_str.contains("null") || args_str.contains("''") || args_str.contains("\"\"") {
                    let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                    if !findings.iter().any(|f: &LangFinding| f.line == call.start_line) {
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: call.start_line,
                            column: 0,
                            start_byte: 0,
                            end_byte: 0,
                            snippet: line_text.trim().to_string(),
                            problem: "Weak JWT verification: JWT decode with null or empty key.".to_string(),
                            fix_hint: "Provide a valid secret key for JWT verification.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-AI-015: Slopsquatting via Package Name Typos
// Severity: critical | CWE-1595
// Detect typo variants of popular PHP packages that may be hallucinated dependencies
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpSlopsquattingTypo;

impl LangRule for PhpSlopsquattingTypo {
    fn id(&self) -> &str { "PHP2-AI-010" }
    fn name(&self) -> &str { "AI Slopsquatting: Package Name Typos" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Popular PHP package typos - organized by original package name
        let typo_patterns: Vec<(&str, Vec<&str>)> = vec![
            // Monolog variants
            ("monolog/monolog", vec!["monolog/monolod", "monolog/monolog", "monolog/monolod", "monolig", "monolog", "monolog/monolod"]),
            // Guzzle variants
            ("guzzlehttp/guzzle", vec!["guzzlehttp/guzzel", "guzzlehttp/guzzle", "guzzlehttp/guzzel", "guzzle/guzzle", "guzzle/guzzel", "guzzle/guzzle"]),
            // Symfony variants
            ("symfony/symfony", vec!["symfony/symfony", "symfony/symfnoy", "sympfony", "symfony", "symfnoy", "sympfony"]),
            // Doctrine variants
            ("doctrine/orm", vec!["doctrine/doctrin", "doctrine/doctrine", "doctrine/doctine", "doctrin", "doctrine", "doctine"]),
            // PHPUnit variants
            ("phpunit/phpunit", vec!["phpunit/phpunlt", "phpunit/phpuunit", "phputni", "phpunit", "phpunlt", "phpunit/phpunlt"]),
            // FakerPHP variants
            ("fakerphp/faker", vec!["fakerphp/faker", "faker/faker", "fakep", "fakerphp", "faker/fakerphp", "faker/faker"]),
            // Laravel/Framework variants
            ("laravel/framework", vec!["laravel/framwork", "laravel/framework", "laravel/laravel", "laravel/framwork", "laravel/laravel"]),
            // Composer autoload variants
            ("composer/autoload", vec!["composer/autoload", "composer/autoloader", "composer/autoload", "compser/autoload", "compoer/autoload"]),
            // Additional popular packages with typos
            ("illuminate/database", vec!["illuminate/databse", "illuminate/database", "illumiate/database", "illumnate/database"]),
            ("illuminate/support", vec!["illuminate/suport", "illuminate/support", "illumiate/support", "illumante/support"]),
            ("twig/twig", vec!["twig/twig", "twig/twi", "twig/twgi", "twg", "twig/twig"]),
            ("league/oauth2-server", vec!["league/oauth2-srver", "league/oauth2-server", "league/oauth-server", "league/oauth2_server"]),
            ("predis/predis", vec!["predis/predis", "predis/reddis", "preds", "predis/predis"]),
            ("phpmailer/phpmailer", vec!["phpmailer/phpmailer", "phpmailr", "php-mailer", "phpmailer/phpmailer", "phpmailer/phpmalier"]),
            ("swiftmailer/swiftmailer", vec!["swiftmailer/swiftmailer", "swiftmailer/swiftmailler", "swiftmailer", "swiftmailer/swiftmailer"]),
            ("dompdf/dompdf", vec!["dompdf/dompdf", "dompdf/dompsf", "dompsf", "dompdf", "dompdf/dompdf"]),
            ("mpdf/mpdf", vec!["mpdf/mpdf", "mpdf/mpfd", "mpd", "mpdf/mpdf", "mpdf/mpf"]),
            (" Intervention/image", vec!["intervention/image", "intervation", "interventon", "intervention/image", "intervention/imag"]),
            ("barryvdh/laravel-dompdf", vec!["barryvdh/laravel-dompdf", "barryvdh/laravel-domdpf", "barryvdh/laravel-dompd", "barryvdh/laravel-dompdf"]),
            ("laravel/passport", vec!["laravel/passport", "laravel/passprot", "laravel/passort", "laravel/passport", "laravle/passport"]),
            ("barryvdh/laravel-debugbar", vec!["barryvdh/laravel-debugbar", "barryvdh/laravel-debuger", "barryvdh/laravel-debugbr", "barryvdh/laravel-debugbar"]),
            ("squizlabs/php_codesniffer", vec!["squizlabs/php_codesniffer", "squizlabs/php_codesneffer", "squizlabs/php_codeniffer", "squizlabs/php_codesnifer"]),
            ("phpstan/phpstan", vec!["phpstan/phpstan", "phpstan/phpstn", "phpstn", "phpstan/phpstan", "phpstan/phpstam"]),
            ("friendsofphp/php-cs-fixer", vec!["friendsofphp/php-cs-fixer", "friendsofphp/php-cs-fixer", "friendsofphp/php-cs-fixr", "friendsofphp/php-cs-fixer", "friendsofphp/php-cs-fxier"]),
            ("codeception/codeception", vec!["codeception/codeception", "codecepton", "codeceptio", "codeception/codecepton", "codeception/codeceptio"]),
            ("mockery/mockery", vec!["mockery/mockery", "mockry", "mockrey", "mockery/mockrey", "mockery/mockery"]),
            ("phpunit/phpcov", vec!["phpunit/phpcov", "phpunit/phpcov", "phpunit/phpccov", "phpcov", "phpunit/phpcove"]),
            ("sebastian/phpcpd", vec!["sebastian/phpcpd", "sebastian/phpcpd", "sebastian/phpcp", "phpcpd", "sebastian/phpcpdf"]),
            ("mayflower/mo3dic", vec!["mayflower/mo3dic", "mayflower/mo3dic", "mayflower/moedic", "mayflower/moedic", "mayflower/moedic"]),
            ("laravel/tinker", vec!["laravel/tinker", "laravel/tiner", "laravel/tinkr", "laravel/tinker", "laraveltinker"]),
            ("symfony/console", vec!["symfony/consle", "symfony/console", "sympfony/console", "symfony/consol", "symfony/consle"]),
            ("symfony/http-foundation", vec!["symfony/http-foundaton", "symfony/http-foundation", "sympfony/http-foundation", "symfony/http-foudnation", "symfony/http-foundaton"]),
            ("symfony/routing", vec!["symfony/routng", "symfony/routing", "sympfony/routing", "symfony/routng", "symfony/routing"]),
            ("symfony/validator", vec!["symfony/validtor", "symfony/validator", "sympfony/validator", "symfony/validtor", "symfony/validator"]),
            ("symfony/serializer", vec!["symfony/serialzer", "symfony/serializer", "sympfony/serializer", "symfony/serialzre", "symfony/serialzier"]),
            ("doctrine/dbal", vec!["doctrine/dbal", "doctrine/dba", "doctrne/dbal", "doctrine/dball", "doctrine/dbal"]),
            ("doctrine/migrations", vec!["doctrine/migraions", "doctrine/migrations", "doctrine/migartions", "doctrine/migrations", "doctrine/migartions"]),
            ("elasticsearch/elasticsearch", vec!["elasticsearch/elasticsearch", "elasticseach", "elasticsearc", "elasticsearch/elasticsearc", "elasticsearch/elasticsearch"]),
            ("aws/aws-sdk-php", vec!["aws/aws-sdk-php", "aws/aws-sdk", "aws-sdk-php", "aws/aws-sdphp", "aws/aws-sdk-php"]),
            ("google/cloud-storage", vec!["google/cloud-storage", "google/cloudstorage", "goolge/cloud-storage", "google/cloud-storge", "google/cloud-storage"]),
        ];

        // Check require/include statements
        let require_pattern = Regex::new(r##"(?i)(?:require|require_once|include|include_once)\s*\(?\s*['"]([^'"]+)['"]"##).unwrap();
        for caps in require_pattern.captures_iter(code) {
            if let Some(req_match) = caps.get(1) {
                let pkg_name = req_match.as_str().to_lowercase();

                // Skip if it's the real package
                let is_real = typo_patterns.iter().any(|(real, _)| pkg_name == *real);
                if is_real {
                    continue;
                }

                // Check against all typo patterns
                for (real_pkg, typos) in &typo_patterns {
                    if typos.iter().any(|typo| pkg_name == *typo) {
                        let line = code[..caps.get(0).unwrap().start()].matches('\n').count() + 1;
                        let (start, end) = get_line_offsets(code, line);
                        let line_text = code.lines().nth(line - 1).unwrap_or("").trim().to_string();

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text,
                            problem: format!("Slopsquatting detected: '{}' looks like a typo of '{}'. This may be an AI-hallucinated package name.", pkg_name, real_pkg),
                            fix_hint: format!("Verify '{}' exists on packagist.org before installing. Did you mean '{}'?", pkg_name, real_pkg),
                            auto_fix_available: false,
                        });
                        break;
                    }
                }
            }
        }

        // Check Composer autoload patterns in composer.json
        let composer_pattern = Regex::new(r##"(?i)["']([^"']+/[^"']+)["']\s*:"##).unwrap();
        for caps in composer_pattern.captures_iter(code) {
            if let Some(pkg_match) = caps.get(1) {
                let pkg_name = pkg_match.as_str().to_lowercase();

                // Skip if it's the real package
                let is_real = typo_patterns.iter().any(|(real, _)| pkg_name == *real);
                if is_real {
                    continue;
                }

                // Check against all typo patterns
                for (real_pkg, typos) in &typo_patterns {
                    if typos.iter().any(|typo| pkg_name == *typo) {
                        let line = code[..caps.get(0).unwrap().start()].matches('\n').count() + 1;
                        let (start, end) = get_line_offsets(code, line);
                        let line_text = code.lines().nth(line - 1).unwrap_or("").trim().to_string();

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text,
                            problem: format!("Slopsquatting detected: '{}' looks like a typo of '{}'. This may be an AI-hallucinated package name.", pkg_name, real_pkg),
                            fix_hint: format!("Verify '{}' exists on packagist.org. Did you mean '{}'?", pkg_name, real_pkg),
                            auto_fix_available: false,
                        });
                        break;
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-033: SQL Injection (Laravel Query Builder / string concat bypass)
// Severity: critical | CWE-89
// Laravel's query builder with raw expressions, DB::select, and mysqli_real_escape_string bypass
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpLaravelSqlInjection;

impl LangRule for PhpLaravelSqlInjection {
    fn id(&self) -> &str { "PHP2-SEC-033" }
    fn name(&self) -> &str { "SQL Injection (Laravel Query Builder / String Concat Bypass)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let laravel_patterns = vec![
            (r#"DB::(?:table|select|insert|update|delete|statement)\s*\([^)]*(?:\.\s*|concat|params|input|get|post|request|request\(|request\->)"#, "Laravel DB facade with user input in raw query"),
            (r#"(?:whereRaw|selectRaw|orderByRaw|havingRaw|groupByRaw)\s*\([^)]*\.\s*(?:req|params|input|post|get|request)"#, "Laravel raw query method with string concatenation of user input"),
            (r#"(?:where|select|orderBy)\s*\(\s*["'][^"']*["']\s*,\s*(?:req|params|input|post|get|request)"#, "Laravel query builder with user input passed directly"),
            (r#"mysqli_real_escape_string\s*\([^)]+\)\s*(?:\.\s*|concat)"#, "mysqli_real_escape_string result used in concatenation — still injectable!"),
            (r#"addslashes\s*\([^)]*\)\s*(?:\.\s*)"#, "addslashes() used in SQL — insufficient for SQL injection prevention"),
            (r#"htmlspecialchars\s*\([^)]*\)\s*\.\s*["']"#, "htmlspecialchars() output used in SQL query — not SQL injection prevention"),
        ];

        for (pattern, desc) in &laravel_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    if findings.iter().any(|f: &LangFinding| f.line == line) {
                        continue;
                    }
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!(
                            "SQL injection: {}. CWE-89: Laravel query builder raw methods or string \
                            concatenation bypasses parameterized queries. Attackers can manipulate SQL logic.",
                            desc
                        ),
                        fix_hint: "Use parameterized queries: DB::table('users')->where('name', $name)->first(). \
                            For raw queries: DB::select('SELECT * FROM users WHERE name = ?', [$name]). \
                            Never use whereRaw() or selectRaw() with user input.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-034: Server-Side Template Injection (Twig/Smarty)
// Severity: critical | CWE-1336
// Template engines rendered with user-controlled template paths or content
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpSsti;

impl LangRule for PhpSsti {
    fn id(&self) -> &str { "PHP2-SEC-034" }
    fn name(&self) -> &str { "Server-Side Template Injection (Twig/Smarty)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let template_imports = ["twig/twig", "smarty", "blade", "latte", "plates", "raintpl", "dwoo", "volt"];
        let has_template = tree.imports.iter().any(|imp| {
            template_imports.iter().any(|t| imp.module.contains(t))
        });

        if !has_template && !code.contains("render") && !code.contains("twig") {
            return findings;
        }

        let dangerous_patterns = vec![
            (r#"(?:render|display)\s*\(\s*(?:req|params|input|post|get|request|cookie)"#, "Template render() with user-controlled template name or variables"),
            (r#"new\s+Twig_Environment\s*\([^)]*,\s*(?:req|params|input|post|get|request)"#, "Twig_Environment created with user-controlled config"),
            (r#"(?:addGlobal|addTemplateDir|setTemplateDir)\s*\([^)]*(?:req|params|input|post|get|request)"#, "Template directory set from user input"),
            (r#"(?:fetch|view|make)\s*\(\s*(?:req|params|input|post|get|request|cookie)"#, "View fetched with user-controlled template path"),
            (r#"(?:\\Twig_Loader_Filesystem|Loader)\s*\(\s*(?:req|params|input|post|get|request)"#, "Twig loader initialized with user-controlled path"),
            (r#"(?:assign|display)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)"#, "Template assign/display with superglobal input"),
            (r#"(?:createTemplate|getTemplate)\s*\(\s*(?:req|params|input|post|get|request)"#, "Template created from user input"),
        ];

        for (pattern, desc) in &dangerous_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    if findings.iter().any(|f: &LangFinding| f.line == line) {
                        continue;
                    }
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!(
                            "Server-Side Template Injection (SSTI): {}. CWE-1336: User input \
                            passed to a template engine can execute arbitrary PHP code on the server.",
                            desc
                        ),
                        fix_hint: "Never use user input as template names or paths. Always validate and \
                            whitelist template names. Pass user data as template variables, not as template content. \
                            In Twig: use {{ user_name }} not {{ user_name|raw }}. \
                            Disable dangerous functions in sandbox mode.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP-SEC-035: extract() Variable Overwrite (Mass Assignment)
// Severity: high | CWE-915
// extract() with EXTR_OVERWRITE on user input without prefix overwrites existing variables
// ─────────────────────────────────────────────────────────────────────────────
pub struct PhpExtractOverwrite;

impl LangRule for PhpExtractOverwrite {
    fn id(&self) -> &str { "PHP2-SEC-035" }
    fn name(&self) -> &str { "extract() Variable Overwrite (Mass Assignment)" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let dangerous_patterns = vec![
            // extract with user input (most dangerous)
            (r#"extract\s*\(\s*(?:req|params|input|post|get|request|cookie)"#, "extract() applied to user input — variables can be overwritten"),
            // extract with EXTR_OVERWRITE (default, no prefix)
            (r#"extract\s*\([^)]*(?:EXTR_OVERWRITE|EXTR_SKIP|EXTR_PREFIX_SAME)\s*\)"#, "extract() with overwrite mode — can overwrite existing variables"),
            (r#"extract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\)"#, "extract() applied directly to superglobal — mass variable overwrite"),
            // compact() with user input
            (r#"compact\s*\([^)]*(?:req|params|input|post|get|request)"#, "compact() with user input — reverse of extract, can overwrite context"),
            // parse_str without second argument
            (r#"parse_str\s*\(\s*(?:req|params|input|post|get|request)"#, "parse_str() without second argument — overwrites variables directly"),
            // import_request_variables
            (r#"import_request_variables\s*\([^)]*(?:req|params|input|post|get)"#, "import_request_variables() — imports user input as variables"),
        ];

        for (pattern, desc) in &dangerous_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    if findings.iter().any(|f: &LangFinding| f.line == line) {
                        continue;
                    }
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!(
                            "Mass assignment / variable overwrite: {}. CWE-915: extract() on user input \
                            allows attackers to overwrite arbitrary variables, including session data, \
                            configuration, and security-critical variables.",
                            desc
                        ),
                        fix_hint: "Always use EXTR_PREFIX_ALL or EXTR_PREFIX_SAME with a unique prefix. \
                            Better: explicitly extract only known-safe variables: \
                            $name = $_POST['name'] ?? ''; $email = $_POST['email'] ?? ''; \
                            Never use extract() directly on user input.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// All PHP Security Rules
// ─────────────────────────────────────────────────────────────────────────────

pub fn php_security_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(PhpSqlInjection),
        Box::new(PhpXss),
        Box::new(PhpCommandInjection),
        Box::new(PhpPathTraversal),
        Box::new(PhpWeakHashing),
        Box::new(PhpHardcodedSecrets),
        Box::new(PhpEvalUsage),
        Box::new(PhpSessionFixation),
        Box::new(PhpUnvalidatedRedirect),
        Box::new(PhpObjectInjection),
        Box::new(PhpInsecureCors),
        Box::new(PhpInfoDisclosure),
        Box::new(PhpWeakRandom),
        Box::new(PhpMissingHttps),
        Box::new(PhpInsecureFileUpload),
        Box::new(PhpLooseComparison),
        Box::new(PhpMissingCsrf),
        Box::new(PhpXxe),
        Box::new(PhpLdapInjection),
        Box::new(PhpMassAssignment),
        Box::new(PhpSlopsquatting),
        Box::new(PhpVerboseError),
        Box::new(PhpMissingInputValidation),
        Box::new(PhpAiGenComment),
        Box::new(PhpSameSiteCookie),
        Box::new(PhpPharDeserialization),
        Box::new(PhpTypeJuggling),
        Box::new(PhpDependencyVuln),
        Box::new(PhpWeakPasswordHashCost),
        Box::new(PhpRceEval),
        Box::new(PhpLfiRfi),
        Box::new(PhpWeakCrypto),
        Box::new(PhpPdoSqlInjection),
        Box::new(PhpOpenRedirect),
        Box::new(PhpAiHardcodedCredentials),
        Box::new(PhpAiSqlInjection),
        Box::new(PhpAiCommandInjection),
        Box::new(PhpAiUnserialize),
        Box::new(PhpAiPathTraversal),
        Box::new(PhpAiXss),
        Box::new(PhpSsrfDeep),
        Box::new(PhpSlopsquattingTypo),
        // New rule PHP-SEC-032
        Box::new(PhpWeakJwt),
        // PHP-SEC-033 to PHP-SEC-035: Vulnerable Sink Detection (Reverse-Engineered from hackingtool)
        Box::new(PhpLaravelSqlInjection),
        Box::new(PhpSsti),
        Box::new(PhpExtractOverwrite),
    ]
}
