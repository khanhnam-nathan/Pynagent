//! Rate Limiting Rules
//!
//! Detects missing or insufficient rate limiting on API endpoints.

use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{LangRule, LangFinding};
use regex::Regex;

fn get_line_text(code: &str, line: usize) -> Option<String> {
    code.lines().nth(line.saturating_sub(1)).map(|l| l.to_string())
}

// ─── RATE-001: API Endpoint Without Rate Limit ─────────────────────────────

pub struct RateLimitMissing;

impl LangRule for RateLimitMissing {
    fn id(&self) -> &str { "RATE-001" }
    fn name(&self) -> &str { "API Endpoint Without Rate Limiting" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let route_patterns = [
            r"(?i)app[.](\s*get|\s*post|\s*put|\s*patch|\s*delete)\s*\(",
            r"(?i)router[.](\s*get|\s*post|\s*put|\s*patch|\s*delete)\s*\(",
            r"(?i)@app[.]route\s*\(",
            r"(?i)@GetMapping|@PostMapping|@PutMapping|@DeleteMapping",
            r"(?i)fastify[.](\s*get|\s*post|\s*put|\s*patch|\s*delete)\s*\(",
            r"(?i)http[.]\s*(HandleFunc|Handle)\s*\(",
        ];
        let rate_limit_patterns = [
            r"(?i)rateLimit", r"(?i)rate_limit", r"(?i)throttle",
            r"(?i)limiter", r"(?i)maxRequests", r"(?i)rate[.]limit",
            r"(?i)@RateLimit", r"(?i)@Throttle", r"(?i)rate.*limit",
            r"(?i)slowDown", r"(?i)maxHits", r"(?i)requestsPerMinute",
        ];

        let lines: Vec<_> = code.lines().enumerate().collect();
        let lines_count = lines.len();

        for (line_idx, line) in &lines {
            let is_route = route_patterns.iter().any(|rp| {
                Regex::new(rp).map_or(false, |re| re.is_match(line))
            });
            if is_route {
                let start = line_idx.saturating_sub(2);
                let end = (*line_idx + 10).min(lines_count);
                let context: String = lines[start..end].iter().map(|(_, l)| *l).collect::<Vec<_>>().join("\n");
                let has_rate_limit = rate_limit_patterns.iter().any(|rlp| {
                    Regex::new(rlp).map_or(false, |re| re.is_match(&context))
                });
                if !has_rate_limit {
                    let snippet = line.to_string();
                    findings.push(LangFinding::new(
                        self.id(), self.severity(), line_idx + 1,
                        &snippet,
                        "HTTP route handler without rate limiting middleware.",
                        "Add rate limiting: express-rate-limit, @RateLimit annotation, or middleware.",
                    ));
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── RATE-002: Missing Request Quota Enforcement ───────────────────────────

pub struct RateLimitMissingQuota;

impl LangRule for RateLimitMissingQuota {
    fn id(&self) -> &str { "RATE-002" }
    fn name(&self) -> &str { "Missing Request Quota Enforcement" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let code_lower = code.to_lowercase();
        // Check if quota is declared
        let has_quota_decl = code_lower.contains("quota");
        // Check for enforcement indicators
        let enforcement_indicators = ["quota >", "quota <", "quota ==", "quota !=", "enforce", "check quota", "if quota", "throw", "429"];
        let has_enforcement = enforcement_indicators.iter().any(|ind| code_lower.contains(ind));

        if has_quota_decl && !has_enforcement {
            for (line_idx, line) in code.lines().enumerate() {
                if line.to_lowercase().contains("quota") {
                    let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                    findings.push(LangFinding::new(
                        self.id(), self.severity(), line_idx + 1,
                        &snippet,
                        "Quota declared but not enforced in code.",
                        "Implement quota check: if (requests > quota) return 429 TooManyRequests.",
                    ));
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── RATE-003: Bulk Upload Without Size Limit ──────────────────────────────

pub struct RateLimitMissingUploadSize;

impl LangRule for RateLimitMissingUploadSize {
    fn id(&self) -> &str { "RATE-003" }
    fn name(&self) -> &str { "Bulk Upload Without Size Limit" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let upload_patterns = [
            r"(?i)(upload|multer|formidable|busboy|multipart)\s*\(",
            r"(?i)bodyParser|body-parser|bodyparser",
            r"(?i)(fileSize|maxFileSize|file_size|upload_max)\s*[=:]",
            r"(?i)@RequestParam.*(file|upload)",
            r"(?i)[.]fileUpload|[.]upload|[.]postFile",
        ];
        let size_limit_patterns = [
            r"(?i)(maxSize|max_size|fileSize|limit)\s*[=:]\s*\d+",
            r"(?i)@SizeMax|@SizeLimit|@MaxFileSize",
        ];

        let lines: Vec<_> = code.lines().enumerate().collect();
        let lines_count = lines.len();

        for (line_idx, line) in &lines {
            let is_upload = upload_patterns.iter().any(|up| {
                Regex::new(up).map_or(false, |re| re.is_match(line))
            });
            if is_upload {
                let start = line_idx.saturating_sub(2);
                let end = (*line_idx + 8).min(lines_count);
                let context: String = lines[start..end].iter().map(|(_, l)| *l).collect::<Vec<_>>().join("\n");
                let has_size_limit = size_limit_patterns.iter().any(|slp| {
                    Regex::new(slp).map_or(false, |re| re.is_match(&context))
                });
                if !has_size_limit {
                    let snippet = line.to_string();
                    findings.push(LangFinding::new(
                        self.id(), self.severity(), line_idx + 1,
                        &snippet,
                        "File upload handler without size limit.",
                        "Set max file size: multer({ limits: { fileSize: 5 * 1024 * 1024 } }).",
                    ));
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── RATE-004: Concurrent Request Not Limited ─────────────────────────────

pub struct RateLimitConcurrentUnlimited;

impl LangRule for RateLimitConcurrentUnlimited {
    fn id(&self) -> &str { "RATE-004" }
    fn name(&self) -> &str { "Concurrent Request Not Limited" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let concurrency_patterns = [
            r"(?i)Semaphore\s*\([^)]*0[)^]",
            r"(?i)(maxConcurrent|max_concurrent|concurrency)\s*[=:]\s*(0|null|undefined|Infinity)",
            r"(?i)(pool|worker|queue)\s*[=:]\s*new\s+.*[.]\s*(1|0)\b",
            r"(?i)setInterval\s*\([^)]*0[)]",
            r"(?i)(parallel|concurrent|pool)\s*[=:]\s*Infinity",
        ];

        for (line_idx, line) in code.lines().enumerate() {
            for pat in &concurrency_patterns {
                if let Ok(re) = Regex::new(pat) {
                    if re.is_match(line) {
                        let snippet = get_line_text(code, line_idx + 1).unwrap_or_default();
                        findings.push(LangFinding::new(
                            self.id(), self.severity(), line_idx + 1,
                            &snippet,
                            "Concurrent execution or pool without bounded limit.",
                            "Set a maximum concurrency limit to prevent resource exhaustion.",
                        ));
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

pub fn rate_limit_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(RateLimitMissing),
        Box::new(RateLimitMissingQuota),
        Box::new(RateLimitMissingUploadSize),
        Box::new(RateLimitConcurrentUnlimited),
    ]
}
