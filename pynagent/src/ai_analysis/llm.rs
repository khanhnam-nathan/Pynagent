//! LLM-based Code Analysis for Pynagent
//!
//! Sends suspicious code snippets to an LLM API for semantic vulnerability analysis.
//! Requires user-provided API key — cannot be bundled.
//!
//! Copyright (C) 2026 Pynagent Authors

#[allow(dead_code)]

use serde::{Deserialize, Serialize};

/// Result of LLM analysis of a code snippet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmAnalysisResult {
    /// Whether the code is vulnerable.
    pub is_vulnerable: bool,
    /// CWE IDs matched by the LLM.
    pub cwe_ids: Vec<String>,
    /// Explanation of the vulnerability.
    pub explanation: String,
    /// Suggested fix (if any).
    pub suggested_fix: Option<String>,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
    /// How an attacker could exploit this (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_scenario: Option<String>,
    /// Alternative fix options (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alternative_fixes: Option<Vec<String>>,
    /// Reference links (CWE, OWASP, CVE documentation) (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<String>>,
    /// Confidence in the suggested fix (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_confidence: Option<f64>,
}

/// A structured AI-suggested fix for a finding.
#[derive(Debug, Clone)]
pub struct AiFix {
    /// The replacement code suggested by the LLM.
    pub replacement: String,
    /// Why this fix resolves the vulnerability.
    pub explanation: String,
    /// How an attacker could exploit the original code.
    pub attack_scenario: Option<String>,
    /// Alternative fix approaches.
    pub alternative_fixes: Vec<String>,
    /// Links to CWE/OWASP/CVE documentation.
    pub references: Vec<String>,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
}

impl From<LlmAnalysisResult> for Option<AiFix> {
    fn from(result: LlmAnalysisResult) -> Self {
        if let Some(fix) = result.suggested_fix {
            Some(AiFix {
                replacement: fix,
                explanation: result.explanation,
                attack_scenario: result.attack_scenario,
                alternative_fixes: result.alternative_fixes.unwrap_or_default(),
                references: result.references.unwrap_or_default(),
                confidence: result.fix_confidence.unwrap_or(result.confidence),
            })
        } else {
            None
        }
    }
}

/// LLM analysis engine.
pub struct LlmAnalyzer {
    client: reqwest::Client,
    base_url: String,
    model: String,
}

impl LlmAnalyzer {
    pub fn new(_api_key: &str, base_url: Option<&str>, model: Option<&str>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url
                .unwrap_or("https://api.openai.com/v1")
                .trim_end_matches('/')
                .to_string(),
            model: model.unwrap_or("gpt-4o").to_string(),
        }
    }

    /// Analyze a code snippet using LLM.
    pub async fn analyze(&self, code: &str, context: &str) -> Result<LlmAnalysisResult, LlmAnalysisError> {
        let prompt = format!(
            r#"Analyze this code snippet for security vulnerabilities.

Context: {}
Language: auto-detect

Code:
```
{}
```

Respond with JSON only (no markdown):
{{
  "is_vulnerable": true/false,
  "cwe_ids": ["CWE-XXX", ...],
  "explanation": "brief explanation of WHY this is vulnerable",
  "attack_scenario": "How an attacker would exploit this (1-2 sentences)",
  "suggested_fix": "complete fixed code that resolves the vulnerability",
  "alternative_fixes": ["alternative fix option 1", "alternative fix option 2"],
  "references": ["https://cwe.mitre.org/data/definitions/XXX.html", "https://owasp.org/..."],
  "confidence": 0.0-1.0,
  "fix_confidence": 0.0-1.0
}}"#,
            context, code
        );

        let body = serde_json::json!({
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1,
            "max_tokens": 500
        });

        let response = self.client
            .post(format!("{}/chat/completions", self.base_url))
            .header("Authorization", format!("Bearer {}", "REDACTED"))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| LlmAnalysisError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(LlmAnalysisError::ApiError(status.as_u16(), body));
        }

        let resp_body: serde_json::Value = response.json().await
            .map_err(|e| LlmAnalysisError::ParseError(e.to_string()))?;

        let content = resp_body["choices"][0]["message"]["content"]
            .as_str()
            .ok_or_else(|| LlmAnalysisError::ParseError("No content in response".to_string()))?;

        let trimmed = content.trim();
        let json_str = if trimmed.starts_with("```json") {
            &trimmed[7..].trim_end_matches("```").trim()
        } else if trimmed.starts_with("```") {
            &trimmed[3..].trim_end_matches("```").trim()
        } else {
            trimmed
        };

        let parsed: LlmAnalysisResult = serde_json::from_str(json_str)
            .map_err(|e| LlmAnalysisError::ParseError(format!("JSON parse error: {} — body: {}", e, &json_str[..json_str.len().min(200)])))?;

        Ok(parsed)
    }

    /// Analyze multiple snippets in batch.
    pub async fn analyze_batch(
        &self,
        snippets: Vec<(&str, &str)>, // (code, context)
    ) -> Vec<Result<LlmAnalysisResult, LlmAnalysisError>> {
        let mut results = Vec::new();
        for (code, ctx) in snippets {
            results.push(self.analyze(code, ctx).await);
        }
        results
    }
}

/// Error types for LLM analysis.
#[derive(Debug)]
pub enum LlmAnalysisError {
    NetworkError(String),
    ApiError(u16, String),
    ParseError(String),
    MissingApiKey,
}

impl std::fmt::Display for LlmAnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LlmAnalysisError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            LlmAnalysisError::ApiError(code, body) => write!(f, "API error {}: {}", code, body),
            LlmAnalysisError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            LlmAnalysisError::MissingApiKey => write!(f, "API key not provided"),
        }
    }
}

impl std::error::Error for LlmAnalysisError {}

/// Check if an API key is available.
pub fn has_api_key() -> bool {
    std::env::var("Pynagent_LLM_API_KEY").is_ok()
        || std::env::var("OPENAI_API_KEY").is_ok()
        || std::env::var("ANTHROPIC_API_KEY").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_api_key() {
        // No key set by default
        let _ = has_api_key();
    }

    #[test]
    fn test_analysis_result_deserialization() {
        let json = r#"{"is_vulnerable": true, "cwe_ids": ["CWE-78"], "explanation": "Command injection", "confidence": 0.9}"#;
        let result: LlmAnalysisResult = serde_json::from_str(json).unwrap();
        assert!(result.is_vulnerable);
        assert_eq!(result.cwe_ids, vec!["CWE-78"]);
    }
}
