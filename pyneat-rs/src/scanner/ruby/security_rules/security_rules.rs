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
use crate::scanner::base::{LangRule, LangFinding};
use regex::Regex;

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

fn get_line_text(code: &str, line: usize) -> Option<String> {
    code.lines().nth(line.saturating_sub(1)).map(|s| s.to_string())
}

// Rust rules start below

fn get_line_from_byte(code: &str, byte: usize) -> usize {
    code[..byte].matches('\n').count() + 1
}

/// RUBY-SEC-001: SQL Injection
pub struct RubySqlInjection;

impl LangRule for RubySqlInjection {
    fn id(&self) -> &str { "RUBY-SEC-001" }
    fn name(&self) -> &str { "SQL Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"\.find_by_sql\s*\(\s*['\""].*#\{"##, "ActiveRecord find_by_sql with interpolation"),
            (r##"\.execute\s*\(\s*['\""].*#\{"##, "ActiveRecord execute with interpolation"),
            (r##"\.exec\s*\(\s*['\""].*#\{"##, "ActiveRecord exec with interpolation"),
            (r##"\.query\s*\(\s*['\""].*#\{"##, "ActiveRecord query with interpolation"),
            (r##"find_by_sql\s*\(\s*['\""].*#\{"##, "find_by_sql with interpolation"),
            (r##"connection\.execute\s*\([^)]*#\{"##, "connection.execute with interpolation"),
            (r##"ActiveRecord::Base\.connection\.execute\s*\([^)]*#\{"##, "AR Base.connection.execute with interpolation"),
            (r##"['\"""].*SELECT.*['\"""].*\+["'""##, "SQL with string concatenation (SELECT)"),
            (r##"['\"""].*INSERT.*['\"""].*\+["'""##, "SQL with string concatenation (INSERT)"),
            (r##"['\"""].*UPDATE.*['\"""].*\+["'""##, "SQL with string concatenation (UPDATE)"),
            (r##"['\"""].*DELETE.*['\"""].*\+["'""##, "SQL with string concatenation (DELETE)"),
            (r##"\.where\s*\(\s*['\"""].*#\{"##, "where() with string interpolation"),
            (r##"Model\.where\s*\([^)]*\+["'""##, "Model.where with string concatenation"),
            (r##"\.delete\s*\(\s*params\[[""'""##, "delete() with params"),
            (r##"\.destroy\s*\(\s*params\[[""'""##, "destroy() with params"),
            (r##"SQL\s*\(\s*['\""].*%s["'""##, "SQL() with %s format string"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("SQL Injection (CWE-89): {} detected.", desc),
                        fix_hint: "Use parameterized queries. In ActiveRecord: User.where(email: params[:email]). In raw SQL: use ? placeholders.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-002: OS Command Injection
pub struct RubyCommandInjection;

impl LangRule for RubyCommandInjection {
    fn id(&self) -> &str { "RUBY-SEC-002" }
    fn name(&self) -> &str { "OS Command Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"system\s*\([^)]*#\{"##, "system() with string interpolation"),
            (r##"`[^`]*#\{[^}]+\}`"##, "Backtick command with interpolation"),
            (r##"%x\[.+#\{.+}\]"##, "%x[] with interpolation"),
            (r##"exec\s*\([^)]*#\{"##, "exec() with string interpolation"),
            (r##"spawn\s*\([^)]*shell:\s*true"##, "spawn() with shell: true"),
            (r##"IO\.popen\s*\([^)]*#\{"##, "IO.popen with string interpolation"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("Command Injection (CWE-78): {} detected.", desc),
                        fix_hint: "Avoid shell commands with user input. Use direct exec with array args.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-003: YAML Unsafe Load
pub struct RubyYamlUnsafeLoad;

impl LangRule for RubyYamlUnsafeLoad {
    fn id(&self) -> &str { "RUBY-SEC-003" }
    fn name(&self) -> &str { "YAML Unsafe Load" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"YAML\.load\s*\("##, "YAML.load() - can deserialize arbitrary Ruby objects"),
            (r##"YAML\[\]?\s*\("##, "YAML[] alias for YAML.load"),
            (r##"Psych\.load\s*\("##, "Psych.load() - YAML parser underlying method"),
            (r##"YAML\.load_stream\s*\("##, "YAML.load_stream - can execute arbitrary code"),
            (r##"YAML\.unsafe_load\s*\("##, "YAML.unsafe_load - explicitly unsafe"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("YAML Deserialization (CWE-502): {} detected.", desc),
                        fix_hint: "Use YAML.safe_load with permitted_classes whitelist.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-004: Hardcoded Secrets
pub struct RubyHardcodedSecrets;

impl LangRule for RubyHardcodedSecrets {
    fn id(&self) -> &str { "RUBY-SEC-004" }
    fn name(&self) -> &str { "Hardcoded Secrets" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"(?i)password\s*[=:]\s*['\"""][^'\"]{4,}['\"""]"##, "Hardcoded password"),
            (r##"(?i)secret\s*[=:]\s*['\"""][^'\"]{4,}['\"""]"##, "Hardcoded secret"),
            (r##"(?i)api[_-]?key\s*[=:]\s*['\"""][^'\"]{4,}['\"""]"##, "Hardcoded API key"),
            (r##"(?i)token\s*[=:]\s*['\"""][A-Za-z0-9_\-]{10,}['\"""]"##, "Hardcoded token"),
            (r##"AKIA[A-Z0-9]{16}"##, "AWS Access Key ID"),
            (r##"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"##, "Private Key"),
            (r##"eyJ[A-Za-z0-9_=-]+\.eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+"##, "JWT Token"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("Hardcoded Secret (CWE-798): {} detected.", desc),
                        fix_hint: "Use environment variables: ENV['API_KEY'].".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-005: Eval Usage
pub struct RubyEvalUsage;

impl LangRule for RubyEvalUsage {
    fn id(&self) -> &str { "RUBY-SEC-005" }
    fn name(&self) -> &str { "Dangerous Eval Usage" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let eval_patterns: Vec<(&str, &str)> = vec![
            (r##"\beval\s*\("##, "eval()"),
            (r##"\binstance_eval\s*\("##, "instance_eval()"),
            (r##"\bclass_eval\s*\("##, "class_eval()"),
            (r##"\bmodule_eval\s*\("##, "module_eval()"),
            (r##"\bsend\s*\(\s*:[\w]+\s*,\s*['\"""](?:eval|exec|system)['\"""]"##, ".send with eval/exec/system"),
        ];
        for (pattern, desc) in &eval_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("Dangerous Code Evaluation (CWE-95): {} detected.", desc),
                        fix_hint: "Avoid eval. Use safer alternatives like JSON for data serialization.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-006: Weak Cryptography
pub struct RubyWeakCrypto;

impl LangRule for RubyWeakCrypto {
    fn id(&self) -> &str { "RUBY-SEC-006" }
    fn name(&self) -> &str { "Weak Cryptography" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"(?i)rc4|arc4|arcfour|arcfour"##, "RC4 cipher - deprecated and broken"),
            (r##"Digest::MD5\.new"##, "MD5 hash - insecure for cryptographic use"),
            (r##"Digest::SHA1\.new"##, "SHA1 hash - deprecated"),
            (r##"OpenSSL::Cipher\.new\s*\(['\"""](?:des|rc4|rc2|blowfish)['\"""]"##, "Weak cipher algorithm"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("Weak Cryptography (CWE-327): {} detected.", desc),
                        fix_hint: "Use SHA-256/SHA-3 for hashing. For encryption, use AES-256-GCM.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-007: Mass Assignment
pub struct RubyMassAssignment;

impl LangRule for RubyMassAssignment {
    fn id(&self) -> &str { "RUBY-SEC-007" }
    fn name(&self) -> &str { "Mass Assignment" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"Model\.new\s*\(\s*params\)\s*(?!.*permit)"##, "Model.new(params) without permit"),
            (r##"Model\.create\s*\(\s*params\)\s*(?!.*permit)"##, "Model.create(params) without permit"),
            (r##"Model\.update\s*\(\s*params\)\s*(?!.*permit)"##, "Model.update(params) without permit"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("Mass Assignment (CWE-915): {} detected.", desc),
                        fix_hint: "Use strong parameters: Model.new(permit_params) where permit_params = params.require(:model).permit(:field1, :field2)".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-008: LDAP Injection
pub struct RubyLdapInjection;

impl LangRule for RubyLdapInjection {
    fn id(&self) -> &str { "RUBY-SEC-008" }
    fn name(&self) -> &str { "LDAP Injection" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"ldap\.search\s*\([^)]*params"##, "LDAP search with user-controlled filter"),
            (r##"(?i)distinguished_name\s*[=:]\s*['\"""].*#\{"##, "LDAP DN with string interpolation"),
            (r##"(?i)ldap.*base.*#\{"##, "LDAP base with user input"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("LDAP Injection (CWE-90): {} detected.", desc),
                        fix_hint: "Escape or sanitize LDAP special characters: * ( ) \\ NUL.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-009: Session Security
pub struct RubySessionSecurity;

impl LangRule for RubySessionSecurity {
    fn id(&self) -> &str { "RUBY-SEC-009" }
    fn name(&self) -> &str { "Weak Session Management" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"session\s*\(\s*[:\w]+\s*=>\s*[^,)\n]+,\s*(?!.*secure)"##, "Session cookie without secure flag"),
            (r##"cookies\[.*\]\s*=\s*[^,)\n]+,\s*(?!.*httponly)"##, "Cookie without HttpOnly flag"),
            (r##"cookies\[.*\]\s*=\s*[^,)\n]+,\s*(?!.*secure)"##, "Cookie without secure flag"),
            (r##"session_store\s*[=:]\s*CookieStore"##, "CookieStore without encryption config"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("Weak Session Management (CWE-384): {}", desc),
                        fix_hint: "Set secure: true, httponly: true for cookies.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-010: Open Redirect
pub struct RubyOpenRedirect;

impl LangRule for RubyOpenRedirect {
    fn id(&self) -> &str { "RUBY-SEC-010" }
    fn name(&self) -> &str { "Open Redirect" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"redirect_to\s*\(\s*params\[[""'""##, "redirect_to with params"),
            (r##"redirect_to\s*\(\s*request\.referer"##, "redirect_to with request referer"),
            (r##"redirect_to\s*\(\s*[^,)\n]*\+["'""##, "redirect_to with string concatenation"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("Open Redirect (CWE-601): {} detected.", desc),
                        fix_hint: "Validate redirect URLs against allowlist of permitted domains.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-011: Information Disclosure
pub struct RubyInfoDisclosure;

impl LangRule for RubyInfoDisclosure {
    fn id(&self) -> &str { "RUBY-SEC-011" }
    fn name(&self) -> &str { "Information Disclosure" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"puts\s+ENV"##, "Environment variables printed"),
            (r##"print\s+ENV"##, "Environment variables printed"),
            (r##"logger\.(?:debug|info)\s*\([^)]*params\)"##, "Logging params directly"),
            (r##"Rails\.logger\.debug\s*\([^)]*request\.env\)"##, "Logging full request env"),
            (r##"byebug"##, "byebug debugger left in code"),
            (r##"binding\.pry"##, "pry debugger left in code"),
            (r##"debugger"##, "debugger statement left in code"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("Information Disclosure: {}", desc),
                        fix_hint: "Remove debug statements before production.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-012: Missing CSRF Protection
pub struct RubyMissingCsrf;

impl LangRule for RubyMissingCsrf {
    fn id(&self) -> &str { "RUBY-SEC-012" }
    fn name(&self) -> &str { "Missing CSRF Protection" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let has_csrf = code.contains("protect_from_forgery")
            || code.contains("csrf_token")
            || code.contains("verify_authenticity_token");
        let has_post = code.contains("post :") || code.contains("\"post\"");
        let has_form = code.contains("form_for") || code.contains("form_tag") || code.contains("form_with");

        if (has_post || has_form) && !has_csrf {
            if let Ok(re) = regex::Regex::new(r#"def\s+\w+\s*\n\s*end"#) {
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
                        snippet: "Controller action detected".to_string(),
                        problem: "Missing CSRF protection in Rails controller".to_string(),
                        fix_hint: "Ensure protect_from_forgery is in ApplicationController.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-013: Unsafe File Access (Path Traversal)
pub struct RubyUnsafeFileAccess;

impl LangRule for RubyUnsafeFileAccess {
    fn id(&self) -> &str { "RUBY-SEC-013" }
    fn name(&self) -> &str { "Unsafe File Access (Path Traversal)" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"File\.read\s*\([^)]*\+\s*params"#, "File.read with user input concatenation"),
            (r#"File\.open\s*\([^)]*\+\s*params"#, "File.open with user input concatenation"),
            (r#"File\.read\s*\(\s*params\["#, "File.read with direct params access"),
            (r#"send_file\s*\(\s*params\["#, "send_file with user-controlled path"),
            (r#"render\s*\(\s*file:"#, "render file with potential traversal"),
            (r#"\.\.\/"#, "Path traversal sequence ../ detected"),
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
                        fix_hint: "Use File.basename() to strip directories, validate path against base directory.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-014: Regex DoS (ReDoS)
pub struct RubyRegexDos;

impl LangRule for RubyRegexDos {
    fn id(&self) -> &str { "RUBY-SEC-014" }
    fn name(&self) -> &str { "Regex DoS (ReDoS) Vulnerability" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"\(\.\*\)\{2,\}"#, "Nested quantifier: (.*){2,} - catastrophic backtracking"),
            (r#"\(\.\+\)\{2,\}"#, "Nested quantifier: (.+){2,} - catastrophic backtracking"),
            (r#"\(\.\?\)\{2,\}"#, "Nested quantifier: (.?){2,} - catastrophic backtracking"),
            (r#"\(\[.*?\]\+\)\{2,\}"#, "Nested character class quantifier - catastrophic backtracking"),
            (r#"Regexp\.new\s*\(\s*params"#, "Regexp from user input - ReDoS risk"),
            (r#"eval\s*\(\s*\/.*\/"#, "Regex evaluated from string - potential ReDoS"),
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
                        fix_hint: "Use atomic groups, possessive quantifiers, or simplify regex to prevent backtracking.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-015: AI-Hallucinated Dependency (Slopsquatting)
pub struct RubySlopsquatting;

impl LangRule for RubySlopsquatting {
    fn id(&self) -> &str { "RUBY-SEC-015" }
    fn name(&self) -> &str { "AI-Hallucinated Dependency (Slopsquatting)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, _code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let hallucinated: Vec<&str> = vec![
            "fakerlib", "jsonify", "rubyserialize", "railsify", "mongomagic",
            "fake-org/dataframe-utils", "test-package-xyz", "mock-gem",
        ];
        for import in &tree.imports {
            for fake in &hallucinated {
                if import.module.contains(fake) || import.name.contains(fake) {
                    let (start, end) = get_line_offsets(_code, import.start_line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: import.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: import.module.clone(),
                        problem: format!("Slopsquatting Risk: The gem '{}' appears to be a hallucinated package name.", import.module),
                        fix_hint: "Verify this gem exists at rubygems.org before installing.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-AI-001: AI-Generated Code Marker
pub struct RubyAiGenComment;

impl LangRule for RubyAiGenComment {
    fn id(&self) -> &str { "RUBY-AI-001" }
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
// RUBY-SEC-016: Format String Vulnerability (CWE-134)
// Severity: high | OWASP A03:2021
// sprintf with user input, "%s" % params[:x]
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyFormatString;

impl LangRule for RubyFormatString {
    fn id(&self) -> &str { "RUBY-SEC-024" }
    fn name(&self) -> &str { "Format String Vulnerability" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"(?i)sprintf\s*\([^,)]*\$(?:REQUEST|POST|GET|PARAMS|INPUT)"##, "sprintf with user input"),
            (r##"(?i)%[wdxs]\s*%[^,)]*\$(?:REQUEST|POST|GET|PARAMS|INPUT)"##, "Format string with user input"),
            (r##"(?i)printf\s*\([^,)]*\$_(?:GET|POST|REQUEST|COOKIE)"##, "printf with user input"),
            (r##"(?i)\bputs\s*%[^,)]*\$"##, "puts with format string and user input"),
        ];

        for (pat, problem) in &patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: "RUBY-SEC-016".to_string(),
                        severity: "high".to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!("Format string vulnerability: {}. User-controlled format strings can leak memory addresses or cause crashes.", problem),
                        fix_hint: "Never use user input as format strings. Use argument-based formatting: sprintf('%s', user_input) instead of sprintf(user_input).".to_string(),
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
// RUBY-SEC-017: XSS in Rails Views (CWE-79)
// Severity: high | OWASP A03:2021
// raw(), .html_safe without sanitization, content_tag with user input
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyXssInRails;

impl LangRule for RubyXssInRails {
    fn id(&self) -> &str { "RUBY-SEC-025" }
    fn name(&self) -> &str { "Cross-Site Scripting (XSS) in Rails Views" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"(?i)\braw\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|PARAMS)"##, "raw() with user input - bypasses HTML escaping"),
            (r##"(?i)\.html_safe\b"##, ".html_safe called - disables escaping"),
            (r##"(?i)content_tag\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|PARAMS)"##, "content_tag with user input without escaping"),
            (r##"(?i)link_to\s*\([^,)]*\$_(?:GET|POST|REQUEST|COOKIE|PARAMS)"##, "link_to with unsanitized user input in URL"),
            (r##"(?i)<%=?\s*[^%]*\.(?:html_safe|raw)\s*%>"##, "ERB template with raw/html_safe bypass"),
        ];

        for (pat, problem) in &patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: "RUBY-SEC-017".to_string(),
                        severity: "high".to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!("XSS vulnerability in Rails: {}. This can allow attackers to inject malicious scripts.", problem),
                        fix_hint: "Remove raw() and html_safe() calls with user input. Use the default auto-escaping. If you must allow HTML, use a sanitizer like sanitize() or DOMPurify.".to_string(),
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
// RUBY-SEC-018: Insecure Deserialization - Marshal (CWE-502)
// Severity: critical | OWASP A08:2021
// Marshal.load, YAML.load on user input
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyMarshalDeserialization;

impl LangRule for RubyMarshalDeserialization {
    fn id(&self) -> &str { "RUBY-SEC-026" }
    fn name(&self) -> &str { "Insecure Deserialization (Marshal / YAML)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"(?i)Marshal\.load\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|PARAMS)"##, "Marshal.load with user input"),
            (r##"(?i)Marshal\.restore\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|PARAMS)"##, "Marshal.restore with user input"),
            (r##"(?i)YAML\.load\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|PARAMS)"##, "YAML.load with user input (unsafe)"),
            (r##"(?i)Psych\.load\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|PARAMS)"##, "Psych.load (YAML) with user input"),
            (r##"(?i)YAML\.parse\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|PARAMS)"##, "YAML.parse with user input"),
            (r##"(?i)Marshal\.dump\s*\([^)]*\)\s*(?!\s*#).*$"##, "Marshal.dump used (less dangerous but worth reviewing)"),
        ];

        for (pat, problem) in &patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: "RUBY-SEC-018".to_string(),
                        severity: "critical".to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!("Insecure deserialization: {}. Marshal/YAML can execute arbitrary Ruby code when deserializing untrusted data.", problem),
                        fix_hint: "Never use Marshal.load or YAML.load on untrusted data. Use JSON for data exchange. If you must deserialize, use safe YAML loading with permitted classes: YAML.safe_load(data, permitted_classes: [SpecificClass]).".to_string(),
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
// RUBY-SEC-019: Race Condition in Transactions
// Severity: medium | CWE-362
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyRaceConditionTransaction;

impl LangRule for RubyRaceConditionTransaction {
    fn id(&self) -> &str { "RUBY-SEC-027" }
    fn name(&self) -> &str { "Race Condition in ActiveRecord Transactions" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let has_transaction = code.contains(".transaction") || code.contains("Transaction.");
        let has_lock = code.contains(".lock") || code.contains("with_lock");

        if has_transaction && !has_lock {
            let re = Regex::new(r"(?m)^\s*\.transaction\b").unwrap();
            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: code.lines().nth(line - 1).unwrap_or("").trim().to_string(),
                    problem: "ActiveRecord transaction without row-level locking.".to_string(),
                    fix_hint: "Add .lock or use pessimistic locking: Model.lock.find(id).".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-AI-002: AI Hardcoded Secrets
// Severity: high | CWE-798
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyAiHardcodedSecrets;

impl LangRule for RubyAiHardcodedSecrets {
    fn id(&self) -> &str { "RUBY-AI-002" }
    fn name(&self) -> &str { "AI: Hardcoded Secrets in Code" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:password|secret|api[_-]?key|token)\s*[=:]\s*['"][^'"]{4,}['"]"##, "Hardcoded secret"),
            (r##"(?i)ENV\s*\[\s*['"][^'"]+['"]\s*\]\s*=\s*['"][^'"]{4,}['"]"##, "ENV variable set to hardcoded value"),
        ];
        for (pat, desc) in &patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: code.lines().nth(line - 1).unwrap_or("").trim().to_string(),
                        problem: format!("AI-generated code contains hardcoded {}: credentials exposed.", desc),
                        fix_hint: "Use ENV['KEY'] = nil pattern and require secrets from ENV.".to_string(),
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
// RUBY-AI-003: AI SQL Injection via String Interpolation
// Severity: critical | CWE-89
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyAiSqlInjection;

impl LangRule for RubyAiSqlInjection {
    fn id(&self) -> &str { "RUBY-AI-003" }
    fn name(&self) -> &str { "AI: SQL Injection via String Interpolation" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["find_by_sql", "execute", "query", "where("];
        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                let args_str = call.arguments.join(" ");
                if args_str.contains("#{") || args_str.contains("\"#") || args_str.contains("'") {
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: code.lines().nth(call.start_line - 1).unwrap_or("").trim().to_string(),
                        problem: "AI-generated SQL query with string interpolation.".to_string(),
                        fix_hint: "Use parameterized queries: Model.where(user_id: params[:id]).".to_string(),
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
// RUBY-AI-004: AI Command Injection
// Severity: critical | CWE-78
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyAiCommandInjection;

impl LangRule for RubyAiCommandInjection {
    fn id(&self) -> &str { "RUBY-AI-004" }
    fn name(&self) -> &str { "AI: Command Injection - system/exec" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["system(", "`", "%x{", "exec("];
        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                let args_str = call.arguments.join(" ");
                let user_input = ["params", "request", "ENV"];
                if user_input.iter().any(|u| args_str.contains(u)) {
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: code.lines().nth(call.start_line - 1).unwrap_or("").trim().to_string(),
                        problem: "AI-generated command execution with user input.".to_string(),
                        fix_hint: "Validate and escape all user input. Use Shellwords.escape().".to_string(),
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
// RUBY-AI-005: AI YAML unsafe_load
// Severity: critical | CWE-502
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyAiYamlUnsafeLoad;

impl LangRule for RubyAiYamlUnsafeLoad {
    fn id(&self) -> &str { "RUBY-AI-005" }
    fn name(&self) -> &str { "AI: YAML.unsafe_load Usage" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["YAML.unsafe_load", "YAML.load", "YAML.parse"];
        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: code.lines().nth(call.start_line - 1).unwrap_or("").trim().to_string(),
                    problem: "YAML loading without safe loading. Deserialization vulnerability.".to_string(),
                    fix_hint: "Use YAML.safe_load with permitted classes.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-020: Server-Side Request Forgery (SSRF)
// Severity: high | CWE-918 | OWASP A10:2021
// HTTP requests with user-controlled URLs or internal IP access
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubySsrfDeep;

impl LangRule for RubySsrfDeep {
    fn id(&self) -> &str { "RUBY-SEC-020" }
    fn name(&self) -> &str { "Server-Side Request Forgery (SSRF)" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            // HTTP library calls with user input in URL/params
            (r##"(?i)Net::HTTP\.(?:get|post|put|delete|patch|head)\s*\([^)]*params"##, "Net::HTTP with user-controlled URL/params"),
            (r##"(?i)OpenURI\.open_uri\s*\([^)]*params"##, "OpenURI.open_uri with user input"),
            (r##"(?i)RestClient\.(?:get|post|put|delete|patch|head)\s*\([^)]*params"##, "RestClient with user-controlled URL/params"),
            (r##"(?i)Faraday\.(?:get|post|put|delete|patch|head)\s*\([^)]*params"##, "Faraday with user-controlled URL/params"),
            (r##"(?i)HTTParty\.(?:get|post|put|delete|patch|head)\s*\([^)]*params"##, "HTTParty with user-controlled URL/params"),
            (r##"(?i)Excon\.(?:get|post|put|delete|patch|head)\s*\([^)]*params"##, "Excon with user-controlled URL/params"),
            // Internal IP/hostname access patterns
            (r##"169\.254\.169\.254"##, "AWS metadata endpoint access (169.254.169.254)"),
            (r##"(?i)127\.0\.0\.1|localhost"##, "Localhost/internal IP in URL"),
            // User input sources in HTTP calls
            (r##"(?i)Net::HTTP\.[a-z]+\s*\([^)]*request\.(?:params|query_parameters|url|fullpath)"##, "Net::HTTP with request parameter"),
            (r##"(?i)RestClient\.[a-z]+\s*\([^)]*request\.(?:params|query_parameters|url|fullpath)"##, "RestClient with request parameter"),
            (r##"(?i)open\s*\([^)]*params\[:url\]"##, "open() with params[:url] - SSRF risk"),
            (r##"(?i)open\s*\([^)]*params\[:uri\]"##, "open() with params[:uri] - SSRF risk"),
            (r##"(?i)open\s*\([^)]*request\.(?:params|query_parameters)"##, "open() with request params - SSRF risk"),
            // ENV-based query string access
            (r##"(?i)Net::HTTP\.[a-z]+\s*\([^)]*ENV\['QUERY_STRING'\]"##, "Net::HTTP with ENV['QUERY_STRING']"),
            (r##"(?i)RestClient\.[a-z]+\s*\([^)]*ENV\['QUERY_STRING'\]"##, "RestClient with ENV['QUERY_STRING']"),
            (r##"(?i)query_string"##, "query_string variable used in HTTP request"),
        ];

        for (pat, problem) in &patterns {
            if let Ok(re) = Regex::new(pat) {
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
                        problem: format!("SSRF vulnerability (CWE-918): {}. Attackers can make requests to internal services or metadata endpoints.", problem),
                        fix_hint: "Validate and sanitize all URL inputs against an allowlist of permitted domains. Never use user input directly to construct URLs, especially for internal services.".to_string(),
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
// RUBY-AI-006: Slopsquatting via Gem Name Typos
// Severity: critical | CWE-1595
// Detect typo variants of popular Ruby gems that may be hallucinated dependencies
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubySlopsquattingTypo;

impl LangRule for RubySlopsquattingTypo {
    fn id(&self) -> &str { "RUBY-AI-006" }
    fn name(&self) -> &str { "AI Slopsquatting: Gem Name Typos" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Pattern: gem 'name' or gem "name" in Gemfile
        let gem_pattern = Regex::new(r##"(?i)gem\s+['"]([^'"]+)['"]"##).unwrap();

        // Popular gem typos - organized by original gem name
        let typo_patterns: Vec<(&str, Vec<&str>)> = vec![
            ("rails", vec!["railes", "railz", "ralls", "raild", "raile", "rail"]),
            ("rubygems", vec!["rubygem", "rubygmes", "rubgem", "rubgems", "rubyjgems"]),
            ("nokogiri", vec!["nokogiri", "nokogiri", "nokogir1", "nokogir", "nokogiri", "nokogiri"]),
            ("devise", vec!["devsie", "devis", "devie", "devies", "devise", "devis", "devies"]),
            ("sidekiq", vec!["sidekiq", "sidekig", "sidkq", "sideki", "sidekik", "sidekiq"]),
            ("puma", vec!["pumna", "pumla", "pumaa", "pumm", "puma", "pumna"]),
            ("rspec", vec!["rspeck", "respec", "rspc", "rsep", "rsper", "rspec", "rspeck"]),
            ("factory_bot", vec!["factory_girl", "factorybot", "factory_bot", "factoy_bot"]),
            ("activeadmin", vec!["active_admn", "activ admin", "active_admn", "activeadmn", "activeadmin"]),
            ("carrierwave", vec!["carrier_wave", "carrirwave", "carrierave", "carrierwave"]),
            ("will_paginate", vec!["will_pagante", "willpaginate", "will_paginate", "willpag"]),
            ("bootstrap", vec!["bootstap", "boostrap", "bootstrap", "bootstap", "boostrap"]),
            ("paperclip", vec!["paper_clip", "paperclp", "paperclup", "paperclip"]),
            (" cancancan", vec!["cancan", "cancancan", "can_can", "cancan", "cancancan"]),
            ("pundit", vec!["pundlt", "pundt", "pundlt", "pundit"]),
            ("kaminari", vec!["kaminrai", "kaminari", "kaminarii", "kaminarl"]),
            ("simple_form", vec!["simpleform", "simple_form", "simple_from", "simple_forms"]),
            ("friendly_id", vec!["friendl_id", "friendlyid", "friendlly_id", "friendly_id"]),
            ("redis", vec!["redia", "reds", "reddis", "redsi", "redis"]),
            ("mysql2", vec!["mysq2", "mysql", "mysl2", "mysql", "mysql2"]),
            ("pg", vec!["gp", "pog", "pg", "pgg"]),
            ("sqlite3", vec!["sqlte3", "sqltie3", "sqlte", "sqlite", "sqlite3"]),
            ("aws-sdk", vec!["aws-ssk", "aws_ssk", "aws-sdk", "awssdk", "aws-s3"]),
            ("jwt", vec!["jtw", "jwt", "jwr", "jtw", "jwt"]),
            ("bcrypt", vec!["bcript", "bcrypt", "bcryt", "bycrpt", "bcrypt"]),
            ("whenever", vec!["whnever", "whenver", "whenve", "whenever"]),
            ("dotenv", vec!["dot_env", "dotenv", "dotenv", "doten", "dotenv"]),
            ("figaro", vec!["figaro", "figaro", "figaro", "fgaro", "figaro"]),
            ("httparty", vec!["httpart", "httparty", "httpparty", "httpart", "httparty"]),
            ("faraday", vec!["farady", "faradday", "farady", "faraday"]),
            ("rest-client", vec!["restclient", "rest_client", "rest-client", "restlient"]),
        ];

        for caps in gem_pattern.captures_iter(code) {
            if let Some(gem_match) = caps.get(1) {
                let gem_name = gem_match.as_str().to_lowercase();

                // Skip if it's the real gem
                let is_real_gem = typo_patterns.iter().any(|(real, _)| gem_name == *real);
                if is_real_gem {
                    continue;
                }

                // Check against all typo patterns
                for (real_gem, typos) in &typo_patterns {
                    if typos.iter().any(|typo| gem_name == *typo) {
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
                            problem: format!("Slopsquatting detected: '{}' looks like a typo of popular gem '{}'. This may be an AI-hallucinated package name.", gem_name, real_gem),
                            fix_hint: format!("Verify '{}' exists on rubygems.org before installing. Did you mean '{}'?", gem_name, real_gem),
                            auto_fix_available: false,
                        });
                        break;
                    }
                }
            }
        }

        // Also check require statements
        let require_pattern = Regex::new(r##"(?i)require\s+['"]([^'"]+)['"]"##).unwrap();
        for caps in require_pattern.captures_iter(code) {
            if let Some(req_match) = caps.get(1) {
                let req_name = req_match.as_str().to_lowercase();

                // Skip if it's the real gem/library
                let is_real = typo_patterns.iter().any(|(real, _)| req_name == *real);
                if is_real {
                    continue;
                }

                // Check against all typo patterns
                for (real_lib, typos) in &typo_patterns {
                    if typos.iter().any(|typo| req_name == *typo) {
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
                            problem: format!("Slopsquatting detected: '{}' looks like a typo of '{}'. This may be an AI-hallucinated dependency.", req_name, real_lib),
                            fix_hint: format!("Verify '{}' exists before requiring. Did you mean '{}'?", req_name, real_lib),
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
// RUBY-SEC-021: Weak JWT Verification
// Severity: critical | CWE-345
// JWT.decode with nil/false key, JWT.verify with nil, etc.
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyWeakJwt;

impl LangRule for RubyWeakJwt {
    fn id(&self) -> &str { "RUBY-SEC-021" }
    fn name(&self) -> &str { "Weak JWT Verification" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"JWT\.decode\s*\([^,]+,\s*nil"##, "JWT.decode with nil key - no signature verification"),
            (r##"JWT\.decode\s*\([^,]+,\s*false"##, "JWT.decode with false key - no signature verification"),
            (r##"JWT\.decode\s*\([^,]+,\s*["']["']"##, "JWT.decode with empty string key"),
            (r##"JWT\.verify\s*\([^,]+,\s*nil"##, "JWT.verify with nil key"),
            (r##"JWT::Verification\.verify\s*\([^,]+,\s*nil"##, "JWT::Verification.verify with nil key"),
            (r##"JWT::Base64\.url_decode\s*\([^)]*\)\s*\."##, "JWT Base64 decode in chain - verify signing"),
        ];

        for (pat, problem) in &patterns {
            if let Ok(re) = Regex::new(pat) {
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
                        fix_hint: "Provide a valid secret key or public key for JWT verification. Use ENV['JWT_SECRET'] or retrieve from a secrets manager. Never pass nil or false as the verification key.".to_string(),
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
// RUBY-SEC-022: SQL Injection (Sequel ORM / String Interpolation)
// Severity: critical | CWE-89
// Sequel ORM queries or ActiveRecord with string interpolation of user input
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubySequelSqlInjection;

impl LangRule for RubySequelSqlInjection {
    fn id(&self) -> &str { "RUBY-SEC-022" }
    fn name(&self) -> &str { "SQL Injection (Sequel ORM / String Interpolation)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let db_imports = ["sequel", "sqlite3", "pg", "mysql2", "mysql"];
        let has_db = tree.imports.iter().any(|imp| {
            db_imports.iter().any(|d| imp.module.contains(d))
        });

        if !has_db && !code.contains("DB[:") && !code.contains("Sequel.") {
            return findings;
        }

        let dangerous_patterns = vec![
            // Sequel raw SQL with string interpolation
            (r#"DB\[.*?\]\.from.*?\.\s*sql\s*\(['\"][^'\"]*%\{[^}]*(?:params|request|input|post|get)"#, "Sequel SQL with string interpolation of user input"),
            (r#"DB\[.*?\]\.\s*(?:select|from|where|order|group)\s*\(\s*['\"][^'\"]*\#\{[^}]*(?:params|request|input|post|get)"#, "Sequel query with string interpolation"),
            (r#"DB\.run\s*\(['\"][^'\"]*\#\{[^}]*(?:params|request|input)"#, "Sequel DB.run with string interpolation"),
            (r#"DB\[.*?\]\.\s*get?\s*\([^)]*\+[^)]*(?:params|request|input|post|get)"#, "Sequel get with string concatenation of user input"),
            // ActiveRecord string interpolation (additional to existing)
            (r#"ActiveRecord::Base\.connection\.execute\s*\([^)]*\+[^)]*(?:params|request|input)"#, "ActiveRecord connection.execute with string concat"),
            (r#"find_by_sql\s*\(['\"][^'\"]*\#\{[^}]*(?:params|request|input)"#, "find_by_sql with string interpolation of user input"),
            (r#"by_sql\s*\(['\"][^'\"]*\#\{[^}]*(?:params|request|input)"#, "by_sql with string interpolation"),
            (r#"order\s*\([^)]*\#\{[^}]*(?:params|request|input)"#, "ActiveRecord order() with string interpolation — ORDER BY injection"),
            (r#"select\s*\([^)]*\#\{[^}]*(?:params|request|input)"#, "ActiveRecord select() with string interpolation — column injection"),
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
                            "SQL injection (Sequel/ActiveRecord): {}. CWE-89: Database query built with \
                            string interpolation allows attackers to manipulate SQL logic.",
                            desc
                        ),
                        fix_hint: "Use parameterized queries in Sequel: DB[:users].where(name: params[:name]). \
                            In ActiveRecord: User.where(name: params[:name]). \
                            For ORDER BY: whitelist column names. Never use string interpolation in SQL.".to_string(),
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
// RUBY-SEC-023: Command Injection (system / backticks / exec)
// Severity: critical | CWE-78
// Shell commands executed with user input via system(), backticks, or exec()
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyCommandInjectionDeep;

impl LangRule for RubyCommandInjectionDeep {
    fn id(&self) -> &str { "RUBY-SEC-023" }
    fn name(&self) -> &str { "Command Injection (system/backticks/exec)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let dangerous_patterns = vec![
            // system() with user input
            (r#"system\s*\([^)]*\+[^)]*(?:params|request|input|post|get|env|ARGV)"#, "system() with string concatenation of user input"),
            (r#"system\s*\(`[^`]*\#\{[^}]*(?:params|request|input|post|get)"#, "system() with backtick interpolation of user input"),
            // Backticks with user input
            (r#"`[^`]*\#\{[^}]*(?:params|request|input|post|get|env)"#, "Backtick command with string interpolation of user input"),
            (r#"%x\[.*?\#\{[^}]*(?:params|request|input|post|get|env)"#, "%x[] command with user input interpolation"),
            // exec with user input
            (r#"exec\s*\([^)]*\+[^)]*(?:params|request|input|post|get|env|ARGV)"#, "exec() with string concatenation of user input"),
            (r#"exec\s*\(`[^`]*\#\{[^}]*(?:params|request|input)"#, "exec() with backtick interpolation"),
            // popen with user input
            (r#"IO\.popen\s*\([^)]*\+[^)]*(?:params|request|input|post|get|env)"#, "IO.popen() with string concatenation — command injection"),
            (r#"Open3\.popen3\s*\([^)]*\+[^)]*(?:params|request|input)"#, "Open3.popen3 with string concatenation"),
            // Kernel.system alias
            (r#"`\s*\#\{[^}]*(?:params|request|input|post|get|env|ARGV)"#, "Kernel backtick operator with user input interpolation"),
            // Shellwords bypass
            (r#"system\s*\(\s*shellwords\s*\([^)]*\)\s*\.\s*join"#, "system(shellwords(...).join) — can be bypassed with careful quoting"),
            (r#"system\s*\([^)]*split\s*\(\s*['\"][^'\"]*['\"]\s*\)\s*\."#, "system(array.split) — array split from user input is unsafe"),
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
                            "Command injection: {}. CWE-78: User input passed to shell command execution \
                            allows attackers to run arbitrary commands on the host.",
                            desc
                        ),
                        fix_hint: "Never pass user input to system(), exec(), backticks, or popen(). \
                            Use absolute paths with explicit arguments: system('/path/to/cmd', arg1, arg2). \
                            Validate all input against a strict whitelist of allowed values. \
                            For file names: use File.expand_path and verify the path stays within allowed directory.".to_string(),
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

/// Get all Ruby security rules.
pub fn ruby_security_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(RubySqlInjection),
        Box::new(RubyCommandInjection),
        Box::new(RubyYamlUnsafeLoad),
        Box::new(RubyHardcodedSecrets),
        Box::new(RubyEvalUsage),
        Box::new(RubyWeakCrypto),
        Box::new(RubyMassAssignment),
        Box::new(RubyLdapInjection),
        Box::new(RubySessionSecurity),
        Box::new(RubyOpenRedirect),
        Box::new(RubyInfoDisclosure),
        Box::new(RubyMissingCsrf),
        Box::new(RubyUnsafeFileAccess),
        Box::new(RubyRegexDos),
        Box::new(RubySlopsquatting),
        Box::new(RubyAiGenComment),
        // New rules RUBY-SEC-016 to RUBY-SEC-018
        Box::new(RubyFormatString),
        Box::new(RubyXssInRails),
        Box::new(RubyMarshalDeserialization),
        Box::new(RubyRaceConditionTransaction),
        Box::new(RubyAiHardcodedSecrets),
        Box::new(RubyAiSqlInjection),
        Box::new(RubyAiCommandInjection),
        Box::new(RubyAiYamlUnsafeLoad),
        Box::new(RubySsrfDeep),
        Box::new(RubySlopsquattingTypo),
        // New rule RUBY-SEC-021
        Box::new(RubyWeakJwt),
        // RUBY-SEC-022 to RUBY-SEC-023: Vulnerable Sink Detection (Reverse-Engineered from hackingtool)
        // RUBY-SEC-022: Sequel ORM SQL Injection
        Box::new(RubySequelSqlInjection),
        // RUBY-SEC-023: Command Injection (system/backticks)
        Box::new(RubyCommandInjectionDeep),
    ]
}
