//! GDPR / PII Detection and PCI-DSS Compliance Rules

use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{LangRule, LangFinding};
use regex::Regex;

fn get_line_text(code: &str, line: usize) -> Option<String> {
    code.lines().nth(line.saturating_sub(1)).map(|l| l.to_string())
}

// ─── GDPR-001: Hardcoded PII ────────────────────────────────────────────────

pub struct GdprHardcodedPii;

impl LangRule for GdprHardcodedPii {
    fn id(&self) -> &str { "GDPR-001" }
    fn name(&self) -> &str { "Hardcoded PII - Email, SSN, Passport, Phone" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "email address"),
            (r"\b\d{3}-\d{2}-\d{4}\b", "SSN"),
            (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "phone number"),
            (r#""\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}""#, "potential credit card number"),
        ];
        for (line_idx, line) in code.lines().enumerate() {
            for (pat, desc) in &patterns {
                if let Ok(re) = Regex::new(pat) {
                    for m in re.find_iter(line) {
                        let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                        findings.push(LangFinding::new(
                            self.id(),
                            self.severity(),
                            line_idx + 1,
                            &snippet,
                            &format!("Potential {} detected in code: {}", desc, m.as_str()),
                            "Remove or externalize sensitive data. Use environment variables or a secret manager.",
                        ));
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GDPR-002: Data Logging without Anonymization ────────────────────────────

pub struct GdprLoggingWithoutAnonymization;

impl LangRule for GdprLoggingWithoutAnonymization {
    fn id(&self) -> &str { "GDPR-002" }
    fn name(&self) -> &str { "Data Logging without Anonymization" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let pii_field_patterns = [
            r"(?i)email", r"(?i)ssn", r"(?i)phone", r"(?i)address", r"(?i)passport",
            r"(?i)credit_card", r"(?i)name", r"(?i)surname", r"(?i)birth", r"(?i)dob",
        ];
        let log_patterns = [
            r"(?i)log\.(info|warn|error|debug)\s*\([^)]*\b(email|ssn|phone|address|passport|name|birth|credit_card)\b",
            r"(?i)console\.(log|error|warn)\s*\([^)]*\b(email|ssn|phone|address|passport|name|birth|credit_card)\b",
            r"(?i)fmt\.Print(f)?\s*\([^)]*\b(email|ssn|phone|address|passport|name|birth|credit_card)\b",
            r"(?i)print\s*\([^)]*\b(email|ssn|phone|address|passport|name|birth|credit_card)\b",
            r"(?i)logger\.(info|error|warn)\s*\([^)]*\b(email|ssn|phone|address|passport|name|birth|credit_card)\b",
        ];

        for (line_idx, line) in code.lines().enumerate() {
            for lp in &log_patterns {
                if let Ok(re) = Regex::new(lp) {
                    if re.is_match(line) {
                        for pp in &pii_field_patterns {
                            if let Ok(ppr) = Regex::new(pp) {
                                if ppr.is_match(line) {
                                    let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                                    findings.push(LangFinding::new(
                                        self.id(), self.severity(), line_idx + 1,
                                        &snippet,
                                        "Logging statement may output PII data without anonymization.",
                                        "Use data masking or anonymization before logging. Replace with user_id or hash.",
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GDPR-003: Missing Data Retention Policy ────────────────────────────────

pub struct GdprMissingRetentionPolicy;

impl LangRule for GdprMissingRetentionPolicy {
    fn id(&self) -> &str { "GDPR-003" }
    fn name(&self) -> &str { "Missing Data Retention Policy" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let retention_keywords = [
            r"(?i)retention", r"(?i)lifetime", r"(?i)expires", r"(?i)ttl",
            r"(?i)purge", r"(?i)cleanup", r"(?i)delete_after",
        ];
        let create_table_pattern = Regex::new(
            r"(?i)(CREATE\s+TABLE|CREATE\s+COLLECTION|createTable|@Entity)"
        ).unwrap();

        let has_retention = retention_keywords.iter().any(|kw| {
            Regex::new(kw).map_or(false, |re| re.is_match(code))
        });

        if !has_retention && create_table_pattern.is_match(code) {
            let lines: Vec<_> = code.lines().enumerate().collect();
            for (idx, line) in lines {
                if create_table_pattern.is_match(line) {
                    let snippet = line.to_string();
                    findings.push(LangFinding::new(
                        self.id(), self.severity(), idx + 1,
                        &snippet,
                        "Database table/collection definition without retention policy comment.",
                        "Add a retention policy comment: -- @retention: 90_days or @expires: 2026-01-01",
                    ));
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── PCI-001: Credit Card Data Not Encrypted ────────────────────────────────

pub struct PciUnencryptedCardData;

impl LangRule for PciUnencryptedCardData {
    fn id(&self) -> &str { "PCI-001" }
    fn name(&self) -> &str { "Credit Card Data Not Encrypted" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let card_field_patterns = [
            r"(?i)\b(card_number|credit_card|cc_number|pan|card_num)\b",
            r"(?i)\b(card_holder|cc_holder|cardholder)\b",
            r"(?i)\b(expiry_date|expiration_date|cc_exp|cc_expiry)\b",
        ];
        let encrypt_patterns = [
            r"(?i)encrypt", r"(?i)aes\.encrypt", r"(?i)crypto\.encrypt",
            r"(?i)encrypt_card", r"(?i)hash_.*card",
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let has_card_field = card_field_patterns.iter().any(|p| {
                Regex::new(p).map_or(false, |re| re.is_match(line))
            });
            if has_card_field {
                let has_encrypt = encrypt_patterns.iter().any(|p| {
                    Regex::new(p).map_or(false, |re| re.is_match(line))
                });
                if !has_encrypt {
                    let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                    findings.push(LangFinding::new(
                        self.id(), self.severity(), line_idx + 1,
                        &snippet,
                        "Credit card data stored without encryption.",
                        "Use field-level encryption (AES-256) or tokenization for card data.",
                    ));
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── PCI-002: Hardcoded PAN ────────────────────────────────────────────────

pub struct PciHardcodedPan;

impl LangRule for PciHardcodedPan {
    fn id(&self) -> &str { "PCI-002" }
    fn name(&self) -> &str { "Hardcoded PAN (Credit Card Number)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let card_patterns = [
            r"\b4[0-9]{12}(?:[0-9]{3})?\b",  // Visa
            r"\b5[1-5][0-9]{14}\b",           // MasterCard
            r"\b3[47][0-9]{13}\b",            // American Express
            r"\b6(?:011|5[0-9]{2})[0-9]{12}\b", // Discover
        ];

        for (line_idx, line) in code.lines().enumerate() {
            for pat in &card_patterns {
                if let Ok(re) = Regex::new(pat) {
                    for m in re.find_iter(line) {
                        let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                        findings.push(LangFinding::new(
                            self.id(), self.severity(), line_idx + 1,
                            &snippet,
                            &format!("Potential PAN detected: {} ({} digits)", m.as_str(), m.as_str().len()),
                            "Remove the PAN from source code. Use tokenization or vault storage.",
                        ));
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── PCI-003: Prohibited Data Storage ──────────────────────────────────────

pub struct PciProhibitedDataStorage;

impl LangRule for PciProhibitedDataStorage {
    fn id(&self) -> &str { "PCI-003" }
    fn name(&self) -> &str { "Prohibited Payment Data Storage (CVV, PIN, Magnetic Stripe)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let prohibited = [
            r"(?i)\b(cvv|cvc|cvc2|cid|card_verification)\s*=",
            r"(?i)\b(pin|password_pin)\s*=",
            r"(?i)\b(magstripe|track_?1|track_?2|swipe_data)\b",
        ];

        for (line_idx, line) in code.lines().enumerate() {
            for pat in &prohibited {
                if let Ok(re) = Regex::new(pat) {
                    if re.is_match(line) {
                        let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                        findings.push(LangFinding::new(
                            self.id(), self.severity(), line_idx + 1,
                            &snippet,
                            "Prohibited payment data (CVV, PIN, or magnetic stripe) stored in code.",
                            "PCI-DSS forbids storage of CVV, PIN, and magnetic stripe data. Remove immediately.",
                        ));
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── PCI-004: Missing Encryption at Rest ───────────────────────────────────

pub struct PciMissingEncryptionAtRest;

impl LangRule for PciMissingEncryptionAtRest {
    fn id(&self) -> &str { "PCI-004" }
    fn name(&self) -> &str { "Missing Encryption at Rest for Sensitive Data" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let sensitive_fields = [
            r"(?i)@Column\s*\([^)]*\b(name|address|phone|email|ssn|credit_card|account|tax)\b",
            r"(?i)column_definition[^encrypt]",
            r"(?i)string\s+\w+_?(?:name|address|phone|email|account)\s*=",
        ];
        let encrypt_indicators = [
            r"(?i)@Encrypted", r"(?i)encrypt\s*=", r"(?i)encrypted_column",
            r"(?i)field_encryption", r"(?i)#\[Encrypt\]",
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let has_sensitive = sensitive_fields.iter().any(|p| {
                Regex::new(p).map_or(false, |re| re.is_match(line))
            });
            if has_sensitive {
                let has_encrypt = encrypt_indicators.iter().any(|p| {
                    Regex::new(p).map_or(false, |re| re.is_match(line))
                });
                if !has_encrypt {
                    let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                    findings.push(LangFinding::new(
                        self.id(), self.severity(), line_idx + 1,
                        &snippet,
                        "Database column with sensitive data without encryption annotation.",
                        "Add encryption annotation (e.g., @Column(encrypted=true)) or use database-level encryption.",
                    ));
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── PCI-005: Cardholder Data Flow Not Documented ─────────────────────────

pub struct PciMissingDataFlowDoc;

impl LangRule for PciMissingDataFlowDoc {
    fn id(&self) -> &str { "PCI-005" }
    fn name(&self) -> &str { "Cardholder Data Flow Not Documented" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let card_data_indicators = [
            r"(?i)(process|handle|validate|tokenize|payment|charge)\s*[a-zA-Z]*\s*[^\n]{0,50}\b(card|payment|pan|credit|charge)\b",
            r"(?i)\bprocessPayment\b",
            r"(?i)(cardholder|payment)_?data",
            r"(?i)(card|pan)_?(token|holder|name)",
        ];
        let doc_indicators = [
            r"@CardholderData", r"@PaymentData", r"/\*\*.*card.*\*/",
            r"cardholder_data_flow", r"# Cardholder Data",
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let has_card_data = card_data_indicators.iter().any(|p| {
                Regex::new(p).map_or(false, |re| re.is_match(line))
            });
            if has_card_data {
                let has_doc = doc_indicators.iter().any(|p| {
                    Regex::new(p).map_or(false, |re| re.is_match(line))
                });
                if !has_doc {
                    let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                    findings.push(LangFinding::new(
                        self.id(), self.severity(), line_idx + 1,
                        &snippet,
                        "Function handling card data without PCI-DSS documentation annotation.",
                        "Add @CardholderData or @PaymentData annotation with data flow description.",
                    ));
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── Registry ──────────────────────────────────────────────────────────────

pub fn gdpr_pii_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(GdprHardcodedPii),
        Box::new(GdprLoggingWithoutAnonymization),
        Box::new(GdprMissingRetentionPolicy),
        Box::new(PciUnencryptedCardData),
        Box::new(PciHardcodedPan),
        Box::new(PciProhibitedDataStorage),
        Box::new(PciMissingEncryptionAtRest),
        Box::new(PciMissingDataFlowDoc),
    ]
}
