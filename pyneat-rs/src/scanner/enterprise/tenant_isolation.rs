//! Multi-Tenant Isolation Rules
//!
//! Detects missing tenant isolation checks in SaaS applications.

use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{LangRule, LangFinding};
use regex::Regex;

fn get_line_text(code: &str, line: usize) -> Option<String> {
    code.lines().nth(line.saturating_sub(1)).map(|l| l.to_string())
}

// ─── SAAS-001: Tenant Data Leak ────────────────────────────────────────────

pub struct SaasTenantDataLeak;

impl LangRule for SaasTenantDataLeak {
    fn id(&self) -> &str { "SAAS-001" }
    fn name(&self) -> &str { "Tenant Data Leak - Query Without Tenant Filter" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let select_patterns = [
            r"(?i)(SELECT|find|findAll|findMany)\s+[^;]*(FROM|JOIN)\s+",
        ];
        let tenant_filter_patterns = [
            r"(?i)WHERE\s+[^;]*(tenant_id|organization_id|org_id|account_id)",
            r"(?i)\.where\s*\([^)]*(tenant_id|organization_id|org_id|account_id)",
            r"(?i)\.filter\s*\([^)]*(tenant_id|organization_id|org_id|account_id)",
            r"(?i)\.scoped.*(tenant|org)",
        ];

        let lines: Vec<_> = code.lines().enumerate().collect();
        let lines_count = lines.len();

        for (line_idx, line) in &lines {
            let is_select = select_patterns.iter().any(|sp| {
                Regex::new(sp).map_or(false, |re| re.is_match(line))
            });
            if is_select {
                let start = line_idx.saturating_sub(2);
                let end = (*line_idx + 5).min(lines_count);
                let context: String = lines[start..end].iter().map(|(_, l)| *l).collect::<Vec<_>>().join(" ");
                let has_tenant_filter = tenant_filter_patterns.iter().any(|tfp| {
                    Regex::new(tfp).map_or(false, |re| re.is_match(&context))
                });
                if !has_tenant_filter {
                    let snippet = line.to_string();
                    findings.push(LangFinding::new(
                        self.id(), self.severity(), line_idx + 1,
                        &snippet,
                        "Database query without tenant_id/organization_id filter - potential cross-tenant data leak.",
                        "Add tenant filter: WHERE tenant_id = :currentTenantId or .where({ tenant_id })",
                    ));
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── SAAS-002: Missing Tenant ID Validation in Queries ─────────────────────

pub struct SaasMissingTenantValidation;

impl LangRule for SaasMissingTenantValidation {
    fn id(&self) -> &str { "SAAS-002" }
    fn name(&self) -> &str { "Missing Tenant ID Validation in ORM Queries" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let orm_patterns = [
            r"(?i)\.(find|findOne|findById|findAll|get|select|query)\s*\(",
            r"(?i)(User|Account|Resource|File|Document|Project)\.(find|get|query)",
            r"(?i)\.(execute|run)\s*\(\s*SELECT",
        ];
        let tenant_scope_patterns = [
            r"(?i)scope\s*[=:]\s*['](tenant|org)",
            r"(?i)\.where\s*\([^)]*(tenant_id|organization_id|org_id)",
            r"(?i)\.filter\s*\([^)]*(tenant_id|organization_id|org_id)",
            r"(?i)\.setTenant\s*\(",
            r"(?i)@TenantId|@OrganizationId",
        ];

        let lines: Vec<_> = code.lines().enumerate().collect();
        let lines_count = lines.len();

        for (line_idx, line) in &lines {
            let is_orm = orm_patterns.iter().any(|op| {
                Regex::new(op).map_or(false, |re| re.is_match(line))
            });
            if is_orm {
                let start = line_idx.saturating_sub(2);
                let end = (*line_idx + 5).min(lines_count);
                let context: String = lines[start..end].iter().map(|(_, l)| *l).collect::<Vec<_>>().join(" ");
                let has_tenant_scope = tenant_scope_patterns.iter().any(|tsp| {
                    Regex::new(tsp).map_or(false, |re| re.is_match(&context))
                });
                if !has_tenant_scope {
                    let snippet = line.to_string();
                    findings.push(LangFinding::new(
                        self.id(), self.severity(), line_idx + 1,
                        &snippet,
                        "ORM query without tenant scope validation.",
                        "Add tenant scope: .where({ tenant_id: currentUser.tenant_id }) or .setTenant(ctx)",
                    ));
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── SAAS-003: Shared Cache Key Without Tenant Prefix ─────────────────────

pub struct SaasCacheKeyNoTenantPrefix;

impl LangRule for SaasCacheKeyNoTenantPrefix {
    fn id(&self) -> &str { "SAAS-003" }
    fn name(&self) -> &str { "Shared Cache Key Without Tenant Prefix" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let cache_patterns = [
            r"(?i)cache\.(get|set|delete)\s*\(",
            r"(?i)(redis|memcached|ioredis)\.(get|set|del)\s*\(",
            r"(?i)(Redis|Memcache)\.(get|set|delete)\s*\(",
            r"(?i)\.cache\b",
        ];
        let tenant_prefix_patterns = [
            r"(?i)(tenant_id|org_id|organization_id|account_id).*\+",
            r"(?i)key\s*[=:]\s*[`].*\$\{.*(tenant|org)",
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let is_cache = cache_patterns.iter().any(|cp| {
                Regex::new(cp).map_or(false, |re| re.is_match(line))
            });
            if is_cache {
                let has_tenant_prefix = tenant_prefix_patterns.iter().any(|tp| {
                    Regex::new(tp).map_or(false, |re| re.is_match(line))
                });
                if !has_tenant_prefix {
                    let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                    findings.push(LangFinding::new(
                        self.id(), self.severity(), line_idx + 1,
                        &snippet,
                        "Cache key without tenant prefix - potential cross-tenant data access.",
                        "Prefix cache keys with tenant ID: `tenant:${tenantId}:${key}`",
                    ));
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── SAAS-004: File Upload Without Tenant Ownership Check ──────────────────

pub struct SaasFileUploadNoTenantCheck;

impl LangRule for SaasFileUploadNoTenantCheck {
    fn id(&self) -> &str { "SAAS-004" }
    fn name(&self) -> &str { "File Upload Without Tenant Ownership Check" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let upload_patterns = [
            r"(?i)(upload|uploadFile|uploadToS3|saveFile|writeFile)\s*\(",
            r"(?i)(s3|storage|disk)\.(put|upload|write|save)\s*\(",
            r"(?i)(multipart|formidable|multer)\.(upload|handle)",
        ];
        let tenant_check_patterns = [
            r"(?i)(tenant_id|organization_id|org_id|account_id).*==",
            r"(?i)\.belongsTo\s*\([^)]*(tenant|org|account)",
            r"(?i)verify.*(tenant|ownership|owner)",
            r"(?i)check.*(tenant|permission|authorization)",
        ];

        let lines: Vec<_> = code.lines().enumerate().collect();
        let lines_count = lines.len();

        for (line_idx, line) in &lines {
            let is_upload = upload_patterns.iter().any(|up| {
                Regex::new(up).map_or(false, |re| re.is_match(line))
            });
            if is_upload {
                let start = line_idx.saturating_sub(3);
                let end = (*line_idx + 5).min(lines_count);
                let context: String = lines[start..end].iter().map(|(_, l)| *l).collect::<Vec<_>>().join(" ");
                let has_tenant_check = tenant_check_patterns.iter().any(|tcp| {
                    Regex::new(tcp).map_or(false, |re| re.is_match(&context))
                });
                if !has_tenant_check {
                    let snippet = line.to_string();
                    findings.push(LangFinding::new(
                        self.id(), self.severity(), line_idx + 1,
                        &snippet,
                        "File upload operation without tenant ownership validation.",
                        "Verify uploader's tenant matches the resource's tenant before saving: check tenant_id == resource.tenant_id",
                    ));
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── SAAS-005: API Key With Admin Privileges by Default ───────────────────

pub struct SaasApiKeyAdminDefault;

impl LangRule for SaasApiKeyAdminDefault {
    fn id(&self) -> &str { "SAAS-005" }
    fn name(&self) -> &str { "API Key With Admin Privileges by Default" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let admin_key_patterns = [
            r"(?i)(api_key|apikey|key|token)\s*[=:]\s*\{[^}]*\b(admin|role)\b[^}]*(admin|superuser|super_admin)",
            r"(?i)(admin|role)\s*[=:]\s*(admin|superuser|super_admin)[^}]*(api_key|apikey|key|token)",
            r"(?i)createApiKey\s*\([^)]*\brole\s*[=:]\s*",
            r#"(?i)(api_key|apikey)\s*[=:]\s*\{[^}]*\brole\s*[=:]\s*['"]?admin"#,
            r#"(?i)\brole\s*[=:]\s*['"]?admin['"]?\s*[,\}][^}]*(api_key|apikey|token|secret)"#,
            r"(?i)defaultRole\s*[=:]\s*admin",
            r"(?i)PRIVILEGES\s*[=:]\s*ALL",
        ];

        for (line_idx, line) in code.lines().enumerate() {
            for pat in &admin_key_patterns {
                if let Ok(re) = Regex::new(pat) {
                    if re.is_match(line) {
                        let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                        findings.push(LangFinding::new(
                            self.id(), self.severity(), line_idx + 1,
                            &snippet,
                            "API key created with admin privileges by default.",
                            "Use least-privilege principle. Default API keys should have minimal permissions.",
                        ));
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

pub fn tenant_isolation_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(SaasTenantDataLeak),
        Box::new(SaasMissingTenantValidation),
        Box::new(SaasCacheKeyNoTenantPrefix),
        Box::new(SaasFileUploadNoTenantCheck),
        Box::new(SaasApiKeyAdminDefault),
    ]
}
