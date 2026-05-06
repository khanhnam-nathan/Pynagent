//! OAuth / SSO Misconfiguration Rules
//!
//! Detects OAuth, SSO, and session management security issues.

use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{LangRule, LangFinding};
use regex::Regex;

fn get_line_text(code: &str, line: usize) -> Option<String> {
    code.lines().nth(line.saturating_sub(1)).map(|l| l.to_string())
}

// ─── SSO-001: SSO Provider Config Hardcoded ────────────────────────────────

pub struct SsoHardcodedConfig;

impl LangRule for SsoHardcodedConfig {
    fn id(&self) -> &str { "SSO-001" }
    fn name(&self) -> &str { "SSO Provider Config Hardcoded in Source Code" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let sso_config_patterns = [
            r#"(?i)(client_id|client_secret|issuer_url|authority)\s*[=:]\s*['"]?[^\'"$]{5,}['"]?"#,
            r#"(?i)(okta|auth0|keycloak|onelogin)\s*[=:]\s*['"]?[^\'"$]{5,}"#,
        ];
        let env_pattern = Regex::new(r"(?i)(process[.]env|os[.]environ|getenv|ENV\[)").unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            for pat in &sso_config_patterns {
                if let Ok(re) = Regex::new(pat) {
                    if re.is_match(line) && !env_pattern.is_match(line) {
                        let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                        findings.push(LangFinding::new(
                            self.id(), self.severity(), line_idx + 1,
                            &snippet,
                            "SSO/OAuth configuration hardcoded in source code.",
                            "Use environment variables or a secret manager for OAuth client_id and client_secret.",
                        ));
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── SSO-002: Missing SAML Certificate Validation ──────────────────────────

pub struct SsoMissingSamlValidation;

impl LangRule for SsoMissingSamlValidation {
    fn id(&self) -> &str { "SSO-002" }
    fn name(&self) -> &str { "Missing SAML Certificate Validation" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let saml_patterns = [
            r"(?i)skipSignatureValidation\s*[=:]\s*(true|True)",
            r"(?i)wantAssertionsSigned\s*[=:]\s*(false|False|0)",
            r"(?i)wantAuthnStatementSigned\s*[=:]\s*(false|False|0)",
            r"(?i)validateSignature\s*[=:]\s*(false|False|0)",
            r"(?i)verifySignature\s*[=:]\s*(false|False|0)",
            r"(?i)allowUnsignedAssertions\s*[=:]\s*(true|True)",
            r"(?i)disableSignatureValidation\s*[=:]\s*(true|True)",
        ];

        for (line_idx, line) in code.lines().enumerate() {
            for pat in &saml_patterns {
                if let Ok(re) = Regex::new(pat) {
                    if re.is_match(line) {
                        let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                        findings.push(LangFinding::new(
                            self.id(), self.severity(), line_idx + 1,
                            &snippet,
                            "SAML signature validation disabled.",
                            "Enable SAML certificate validation. Set skipSignatureValidation=false.",
                        ));
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── SSO-003: Session Does Not Expire After Inactivity ────────────────────

pub struct SsoInfiniteSession;

impl LangRule for SsoInfiniteSession {
    fn id(&self) -> &str { "SSO-003" }
    fn name(&self) -> &str { "Session Does Not Expire After Inactivity" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let infinite_session_patterns = [
            (r"(?i)(session|cookie)[.]?(maxAge|max_age)\s*[=:]\s*(-1|0|false)", "infinite session expiry"),
            (r"(?i)expireOnClose\s*[=:]\s*false", "session does not expire on close"),
            (r"(?i)(session|token)[.]duration\s*[=:]\s*0", "zero duration session"),
            (r"(?i)slidingExpiration\s*[=:]\s*false", "sliding expiration disabled"),
        ];

        for (line_idx, line) in code.lines().enumerate() {
            for (pat, desc) in &infinite_session_patterns {
                if let Ok(re) = Regex::new(pat) {
                    if re.is_match(line) {
                        let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                        findings.push(LangFinding::new(
                            self.id(), self.severity(), line_idx + 1,
                            &snippet,
                            &format!("Session configuration allows infinite expiry: {}", desc),
                            "Set appropriate session timeout (e.g., 30 minutes) and enable sliding expiration.",
                        ));
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── SSO-004: Missing MFA Enforcement ──────────────────────────────────────

pub struct SsoMissingMfaEnforcement;

impl LangRule for SsoMissingMfaEnforcement {
    fn id(&self) -> &str { "SSO-004" }
    fn name(&self) -> &str { "Missing MFA Enforcement Option" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let mfa_disabled = [
            r"(?i)(mfa_enabled|mfaEnabled|mfa_required|mfaRequired|mfa)\s*[=:]\s*(false|False|0)",
            r"(?i)(skip_mfa|skipMfa|skip_mfa_check)\s*[=:]\s*(true|True|1)",
            r"(?i)(require_mfa|requireMfa|force_mfa)\s*[=:]\s*(false|False|0)",
            r"(?i)(mfa_enforced|mfaEnforced)\s*[=:]\s*(false|False|0)",
        ];
        let auth_endpoint = [
            r"(?i)(login|auth|signin|authenticate)\s*[=:]\s*(async\s+)?function",
            r"(?i)(login|auth|signin|authenticate)\s*\([^)]*\)\s*\{",
            r"(?i)@PostMapping.*(login|auth|signin)",
            r"(?i)@GetMapping.*(login|auth|signin)",
        ];

        let has_mfa_disabled = mfa_disabled.iter().any(|p| {
            Regex::new(p).map_or(false, |re| re.is_match(code))
        });
        if has_mfa_disabled {
            // Also report findings directly on lines where MFA is disabled
            for (line_idx, line) in code.lines().enumerate() {
                for mp in &mfa_disabled {
                    if let Ok(re) = Regex::new(mp) {
                        if re.is_match(line) {
                            let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                            findings.push(LangFinding::new(
                                self.id(), self.severity(), line_idx + 1,
                                &snippet,
                                "MFA explicitly disabled in source code.",
                                "Enable MFA enforcement by setting mfa_enabled=true or remove skip_mfa flag.",
                            ));
                        }
                    }
                }
            }
            // Also check auth endpoints for additional context
            for (line_idx, line) in code.lines().enumerate() {
                for ap in &auth_endpoint {
                    if let Ok(re) = Regex::new(ap) {
                        if re.is_match(line) {
                            let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                            findings.push(LangFinding::new(
                                self.id(), self.severity(), line_idx + 1,
                                &snippet,
                                "Authentication endpoint has MFA explicitly disabled.",
                                "Enable MFA enforcement by setting mfa_enabled=true or remove skip_mfa flag.",
                            ));
                        }
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── SSO-005: API Token Has No Expiration ──────────────────────────────────

pub struct SsoTokenNoExpiration;

impl LangRule for SsoTokenNoExpiration {
    fn id(&self) -> &str { "SSO-005" }
    fn name(&self) -> &str { "API Token Has No Expiration" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let token_gen_patterns = [
            r"(?i)(jwt|JWT)[.]?(sign|encode|create)\s*\([^)]*expiresIn\s*[=:]\s*(0|null|undefined|never|false)",
            r"(?i)(jwt|JWT)[.]?(sign|encode|create)\s*\([^)]*(null|never|0)[^)]*\)",
            r"(?i)(token|Token)[.](\sexpires|\sexpiration|\sexp)\s*[=:]\s*(0|null|undefined|-1)",
            r"(?i)(access_token|accessToken)\s*=\s*[^;]*[.](\sexpiresIn|\sexpiration|\sexp)\s*[=:]\s*(0|null|undefined)",
            r"(?i)sign\([^)]*(0|null|never)\s*[),]",
            r"(?i)(api_key|apikey|apiKey)[.](\sexpires|\sexpiration)\s*[=:]\s*(0|null|never)",
        ];

        for (line_idx, line) in code.lines().enumerate() {
            for pat in &token_gen_patterns {
                if let Ok(re) = Regex::new(pat) {
                    if re.is_match(line) {
                        let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                        findings.push(LangFinding::new(
                            self.id(), self.severity(), line_idx + 1,
                            &snippet,
                            "API or JWT token generated without expiration.",
                            "Set token expiration (e.g., expiresIn: 3600 for 1 hour). Use refresh tokens for long-lived sessions.",
                        ));
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

pub fn oauth_sso_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(SsoHardcodedConfig),
        Box::new(SsoMissingSamlValidation),
        Box::new(SsoInfiniteSession),
        Box::new(SsoMissingMfaEnforcement),
        Box::new(SsoTokenNoExpiration),
    ]
}
