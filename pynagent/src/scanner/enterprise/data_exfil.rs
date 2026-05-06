//! Data Loss Prevention (DLP) Rules
//!
//! Detects data exfiltration channels and hardcoded secrets.

use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{LangRule, LangFinding};
use regex::Regex;

fn get_line_text(code: &str, line: usize) -> Option<String> {
    code.lines().nth(line.saturating_sub(1)).map(|l| l.to_string())
}

// ─── DLP-001: Sensitive Data Sent to External Endpoint ────────────────────

pub struct DlpSensitiveDataExternal;

impl LangRule for DlpSensitiveDataExternal {
    fn id(&self) -> &str { "DLP-001" }
    fn name(&self) -> &str { "Sensitive Data Sent to External Endpoint" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let http_methods = [
            r"(?i)(fetch|axios|got|request|http\.post|http\.put|HttpClient\.Send|requests\.post|requests\.put)\s*\(",
        ];
        let sensitive_fields = [
            r"(?i)(password|passwd|pwd|secret|token|auth|bearer|api_key|apikey|private_key)",
            r"(?i)(access_key|secret_key|client_secret|auth_token|session_id)",
        ];

        let lines: Vec<_> = code.lines().enumerate().collect();
        let lines_count = lines.len();

        for (line_idx, line) in &lines {
            let is_http = http_methods.iter().any(|hp| {
                Regex::new(hp).map_or(false, |re| re.is_match(line))
            });
            if is_http {
                let start = *line_idx;
                let end = (*line_idx + 3).min(lines_count);
                let context: String = lines[start..end].iter().map(|(_, l)| *l).collect::<Vec<_>>().join("\n");
                let has_sensitive = sensitive_fields.iter().any(|sf| {
                    Regex::new(sf).map_or(false, |re| re.is_match(&context))
                });
                if has_sensitive {
                    let snippet = line.to_string();
                    findings.push(LangFinding::new(
                        self.id(), self.severity(), line_idx + 1,
                        &snippet,
                        "HTTP request may send sensitive data (credentials, tokens) to an external endpoint.",
                        "Review the destination URL. Ensure credentials are not being sent to untrusted endpoints.",
                    ));
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── DLP-002: Database Credentials Exfiltrated ─────────────────────────────

pub struct DlpDbCredentialsExfil;

impl LangRule for DlpDbCredentialsExfil {
    fn id(&self) -> &str { "DLP-002" }
    fn name(&self) -> &str { "Database Credentials Exfiltrated via Network" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let db_conn_patterns = [
            r"(?i)(connection_string|conn_str|dsn|database_url|db_url)\b",
            r"(?i)(postgres|mysql|mongodb|redis):\/\/[^@\s]+:[^@\s]+@",
            r"(?i)(host|port|user|password|dbname)\s*[=:]",
        ];
        let exfil_patterns = [
            r"(?i)(fetch|axios|post|send|http)\s*\([^)]*(password|connection|dsn|conn)",
            r"(?i)console\.(log|error)\s*\([^)]*(connection_string|conn_str|dsn|db_url)",
            r"(?i)fmt\.Print(f)?\s*\([^)]*(connection_string|conn_str|dsn|db_url)",
            r"(?i)(log|logger)\.(info|error|debug)\s*\([^)]*(password|secret).*(connection|dsn)",
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let has_db_conn = db_conn_patterns.iter().any(|dcp| {
                Regex::new(dcp).map_or(false, |re| re.is_match(line))
            });
            if has_db_conn {
                let start = line_idx.saturating_sub(2);
                let end = (line_idx + 3).min(code.lines().count());
                let context: String = code.lines().skip(start).take(end - start).collect::<Vec<_>>().join(" ");
                let is_exfil = exfil_patterns.iter().any(|ep| {
                    Regex::new(ep).map_or(false, |re| re.is_match(&context))
                });
                if is_exfil {
                    let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                    findings.push(LangFinding::new(
                        self.id(), self.severity(), line_idx + 1,
                        &snippet,
                        "Database connection string or credentials potentially sent via network.",
                        "Never log or send connection strings externally. Use environment variables for credentials.",
                    ));
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── DLP-003: Hardcoded Cloud Credentials ──────────────────────────────────

pub struct DlpHardcodedCloudCreds;

impl LangRule for DlpHardcodedCloudCreds {
    fn id(&self) -> &str { "DLP-003" }
    fn name(&self) -> &str { "Hardcoded Cloud Provider Credentials (AWS/GCP/Azure)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let cloud_cred_patterns = [
            r#"(?i)(aws_access_key_id|aws_secret_access_key|aws_session_token)\s*[=:]\s*["'][^$][^"']{10,}["']"#,
            r#"(?i)(AZURE_CLIENT_SECRET|AZURE_CLIENT_ID|AZURE_TENANT_ID|AZURE_SUBSCRIPTION_ID)\s*[=:]\s*["'][^$][^"']+["']"#,
            r#"(?i)(GCP_SERVICE_ACCOUNT_KEY|GCP_PROJECT_ID|GOOGLE_APPLICATION_CREDENTIALS)\s*[=:]\s*["'][^$][^"']+["']"#,
            r#"(?i)(heroku_api_key|STRIPE_SECRET_KEY|STRIPE_PUBLISHABLE_KEY)\s*[=:]\s*["'][^$][^"']+["']"#,
        ];
        let env_pattern = Regex::new(r"(?i)(process\.env|os\.environ|getenv|ENV\[)").unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            for pat in &cloud_cred_patterns {
                if let Ok(re) = Regex::new(pat) {
                    if re.is_match(line) && !env_pattern.is_match(line) {
                        let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                        findings.push(LangFinding::new(
                            self.id(), self.severity(), line_idx + 1,
                            &snippet,
                            "Hardcoded cloud provider credentials in source code.",
                            "Move credentials to environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault).",
                        ));
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── DLP-004: API Keys / Tokens in Source Code ────────────────────────────

pub struct DlpApiKeysInCode;

impl LangRule for DlpApiKeysInCode {
    fn id(&self) -> &str { "DLP-004" }
    fn name(&self) -> &str { "API Keys and Tokens in Source Code" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        // Use single-quoted strings in regex to avoid backslash escaping issues
        let key_patterns: Vec<(String, &'static str)> = vec![
            (format!(r#"{}\w{{20,}}"#, "sk_live_"), "Stripe secret key"),
            (format!(r#"{}\w{{20,}}"#, "pk_live_"), "Stripe publishable key"),
            (format!(r#"{}\w{{36,}}"#, "ghp_"), "GitHub personal access token"),
            (format!(r#"{}\w{{36,}}"#, "gho_"), "GitHub OAuth token"),
            (format!(r#"xoxb-[\w-]{{20,}}"#), "Slack bot token"),
            (format!(r#"xoxp-[\w-]{{20,}}"#), "Slack user token"),
            (format!(r#"AIza[\w_-]{{35,}}"#), "Google API key"),
            (format!(r#"SG\.[\w_-]{{22,}}\.[\w_-]{{43,}}"#), "SendGrid API key"),
            (format!(r#"AKIA[A-Z0-9]{{16}}"#), "AWS access key ID"),
            (format!(r#"sq0csp-[\w_-]{{43,}}"#), "Square API key"),
            (format!(r#"sq0atp-[\w_-]{{22,}}"#), "Square access token"),
            (format!(r#"eyJ[\w_-]+\.eyJ[\w_-]+\.[\w_-]+"#), "JWT token"),
        ];

        for (line_idx, line) in code.lines().enumerate() {
            for (pat, desc) in &key_patterns {
                if let Ok(re) = Regex::new(pat) {
                    for m in re.find_iter(line) {
                        let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                        findings.push(LangFinding::new(
                            self.id(), self.severity(), line_idx + 1,
                            &snippet,
                            &format!("Potential {} detected: {}", desc, &m.as_str()[..m.as_str().len().min(24)]),
                            "Remove API key from source code. Use environment variables or a secrets manager.",
                        ));
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── DLP-005: Private Keys in Repository ───────────────────────────────────

pub struct DlpPrivateKeysInRepo;

impl LangRule for DlpPrivateKeysInRepo {
    fn id(&self) -> &str { "DLP-005" }
    fn name(&self) -> &str { "Private Keys in Repository" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let private_key_patterns = [
            (r"-----BEGIN\s+(PRIVATE\s+KEY|RSA\s+PRIVATE\s+KEY|EC\s+PRIVATE\s+KEY|DSA\s+PRIVATE\s+KEY|OPENSSH\s+PRIVATE\s+KEY)-----", "PEM private key"),
            (r"-----BEGIN\s+CERTIFICATE-----", "PEM certificate (may contain private key)"),
            (r"(?i)ssh-rsa\s+AAAAB", "SSH public key (verify private not committed)"),
        ];

        for (line_idx, line) in code.lines().enumerate() {
            for (pat, desc) in &private_key_patterns {
                if let Ok(re) = Regex::new(pat) {
                    if re.is_match(line) {
                        let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                        findings.push(LangFinding::new(
                            self.id(), self.severity(), line_idx + 1,
                            &snippet,
                            &format!("{} found in source code.", desc),
                            "Remove private keys from repository immediately. Use a secrets manager.",
                        ));
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

pub fn data_exfil_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(DlpSensitiveDataExternal),
        Box::new(DlpDbCredentialsExfil),
        Box::new(DlpHardcodedCloudCreds),
        Box::new(DlpApiKeysInCode),
        Box::new(DlpPrivateKeysInRepo),
    ]
}
