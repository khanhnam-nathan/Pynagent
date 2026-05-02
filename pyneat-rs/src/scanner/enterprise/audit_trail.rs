//! Audit Trail Security Rules
//!
//! Detects missing audit logging for sensitive operations.

use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{LangRule, LangFinding};
use regex::Regex;

fn get_line_text(code: &str, line: usize) -> Option<String> {
    code.lines().nth(line.saturating_sub(1)).map(|l| l.to_string())
}

// ─── AUDIT-001: Missing Audit Log for Sensitive Operations ─────────────────

pub struct AuditMissingSensitiveOps;

impl LangRule for AuditMissingSensitiveOps {
    fn id(&self) -> &str { "AUDIT-001" }
    fn name(&self) -> &str { "Missing Audit Log for Sensitive Operations" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let sensitive_ops = [
            (r"(?i)(DELETE|DROP|ALTER|TRUNCATE|REMOVE)\s+", "data deletion"),
            (r"(?i)(grant|revoke)\s+", "permission change"),
            (r"(?i)(CREATE\s+(ROLE|USER|PRIVILEGE))\s+", "user/role creation"),
            (r"(?i)(UPDATE\s+\w+\s+SET\s+role|admin)\s*=", "admin role change"),
            (r"(?i)executes?\s*\(.*(DROP|DELETE|TRUNCATE)", "dangerous SQL via exec"),
        ];
        let audit_patterns = [
            r"(?i)audit", r"(?i)log.*(action|event|activity)",
            r"(?i)record.*(action|event)", r"(?i)track.*(action|event)",
            r"(?i)security.*log", r"(?i)log_event",
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let mut is_sensitive = false;
            let mut op_desc = "";
            for (pat, desc) in &sensitive_ops {
                if let Ok(re) = Regex::new(pat) {
                    if re.is_match(line) {
                        is_sensitive = true;
                        op_desc = desc;
                        break;
                    }
                }
            }
            if is_sensitive {
                let has_audit = audit_patterns.iter().any(|ap| {
                    let start = line_idx.saturating_sub(3);
                    let end = (line_idx + 4).min(code.lines().count());
                    let context: String = code.lines().skip(start).take(end - start).collect::<Vec<_>>().join(" ");
                    Regex::new(ap).map_or(false, |re| re.is_match(&context))
                });
                if !has_audit {
                    let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                    findings.push(LangFinding::new(
                        self.id(), self.severity(), line_idx + 1,
                        &snippet,
                        &format!("Sensitive operation ({}) without audit logging.", op_desc),
                        "Add audit logging before this operation: audit.log(action='{}', ...)",
                    ));
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── AUDIT-002: Audit Log without Timestamp or User ID ────────────────────

pub struct AuditLogMissingContext;

impl LangRule for AuditLogMissingContext {
    fn id(&self) -> &str { "AUDIT-002" }
    fn name(&self) -> &str { "Audit Log without Timestamp or User ID" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let log_patterns = [
            r"(?i)log\.(info|warn|error|debug)\s*\(",
            r"(?i)logger\.(info|warn|error|debug)\s*\(",
            r"(?i)console\.(log|error|warn)\s*\(",
            r"(?i)audit\.",
            r"(?i)_audit\.",
        ];
        let context_patterns = [
            r"(?i)(user_id|userId|user_id|user_uuid)",
            r"(?i)(timestamp|ts|created_at|logged_at)",
            r"(?i)(action_id|actionId|action_type|event_type)",
            r"(?i)(request_id|correlation_id|trace_id)",
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let is_log = log_patterns.iter().any(|lp| {
                Regex::new(lp).map_or(false, |re| re.is_match(line))
            });
            if is_log {
                let has_context = context_patterns.iter().any(|cp| {
                    Regex::new(cp).map_or(false, |re| re.is_match(line))
                });
                if !has_context {
                    let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                    findings.push(LangFinding::new(
                        self.id(), self.severity(), line_idx + 1,
                        &snippet,
                        "Log statement without user ID, timestamp, or action ID.",
                        "Include user_id, timestamp, and action_id in every audit log entry.",
                    ));
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── AUDIT-003: Sensitive Actions Not Logged ───────────────────────────────

pub struct AuditSensitiveActionsNotLogged;

impl LangRule for AuditSensitiveActionsNotLogged {
    fn id(&self) -> &str { "AUDIT-003" }
    fn name(&self) -> &str { "Sensitive Actions Not Logged" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let sensitive_actions = [
            (r"(?i)\bexec(?:ute)?\s*\(", "system command execution"),
            (r"(?i)\bsystem\s*\(", "system call"),
            (r"(?i)\beval\s*\(", "dynamic code evaluation"),
            (r"(?i)\bprocess\.spawn\s*\(", "process spawning"),
            (r"(?i)\bshell_exec\s*\(", "shell execution (PHP)"),
            (r"(?i)\bsubprocess\.call\s*\(", "subprocess call (Python)"),
            (r"(?i)\bos\.exec\s*\(", "OS command execution"),
        ];
        let audit_patterns = [
            r"(?i)audit", r"(?i)log.*action", r"(?i)record.*event",
            r"(?i)track.*call", r"(?i)security.*log",
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let mut action_desc = "";
            let is_dangerous = sensitive_actions.iter().any(|(pat, desc)| {
                if let Ok(re) = Regex::new(pat) {
                    if re.is_match(line) {
                        action_desc = desc;
                        return true;
                    }
                }
                false
            });
            if is_dangerous {
                let start = line_idx.saturating_sub(2);
                let end = (line_idx + 3).min(code.lines().count());
                let context: String = code.lines().skip(start).take(end - start).collect::<Vec<_>>().join(" ");
                let has_audit = audit_patterns.iter().any(|ap| {
                    Regex::new(ap).map_or(false, |re| re.is_match(&context))
                });
                if !has_audit {
                    let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                    findings.push(LangFinding::new(
                        self.id(), self.severity(), line_idx + 1,
                        &snippet,
                        &format!("Sensitive action ({}) without logging.", action_desc),
                        "Add security logging before executing: audit.log(action='exec', ...)",
                    ));
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

pub fn audit_trail_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(AuditMissingSensitiveOps),
        Box::new(AuditLogMissingContext),
        Box::new(AuditSensitiveActionsNotLogged),
    ]
}
