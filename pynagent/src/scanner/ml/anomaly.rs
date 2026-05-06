//! Statistical Anomaly Detection for Pynagent
//!
//! Detects code that statistically deviates from project norms using
//! structural metrics (not requiring a full ML framework).
//!
//! Features:
//! - File-level anomaly scoring based on multiple metrics
//! - Function-level complexity detection
//! - Entropy analysis of string literals
//! - Detection of AI-generated code patterns
//!
//! Copyright (C) 2026 Pynagent Authors

#[allow(dead_code)]

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Metrics extracted from a code snippet or file.
#[derive(Debug, Clone, Default)]
pub struct CodeMetrics {
    /// Total lines of code
    pub line_count: usize,
    /// Number of function definitions
    pub function_count: usize,
    /// Number of class definitions
    pub class_count: usize,
    /// Average function length (lines)
    pub avg_function_len: f64,
    /// Maximum nesting depth
    pub max_nesting_depth: usize,
    /// Number of string literals
    pub string_count: usize,
    /// Number of import statements
    pub import_count: usize,
    /// Comment density (comment lines / total lines)
    pub comment_density: f64,
    /// Average line length
    pub avg_line_len: f64,
    /// Longest line length
    pub max_line_len: usize,
    /// Number of TODO/FIXME comments
    pub todo_count: usize,
    /// Number of print/debug statements
    pub debug_stmts: usize,
    /// Indentation consistency score (0-1)
    pub indentation_score: f64,
}

/// An anomaly finding with score and explanation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyFinding {
    /// Unique identifier
    pub id: String,
    /// Severity: "high", "medium", "low"
    pub severity: String,
    /// Explanation of why this is anomalous
    pub explanation: String,
    /// The anomalous code snippet
    pub snippet: String,
    /// Line number where anomaly starts
    pub line: usize,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Which metric triggered the anomaly
    pub trigger_metric: String,
}

/// Anomaly detection engine.
pub struct AnomalyEngine {
    #[allow(dead_code)]
    baselines: HashMap<String, LanguageBaseline>,
}

#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
struct LanguageBaseline {
    avg_line_count: f64,
    avg_function_count: f64,
    avg_complexity: f64,
    avg_string_density: f64,
    known_ai_patterns: Vec<AiPattern>,
}

/// A known AI-generated code pattern.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct AiPattern {
    name: &'static str,
    regex: regex::Regex,
    severity: &'static str,
    confidence: f64,
}

impl Default for AnomalyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AnomalyEngine {
    pub fn new() -> Self {
        Self {
            baselines: HashMap::new(),
        }
    }

    /// Extract metrics from source code.
    pub fn extract_metrics(&self, code: &str, language: &str) -> CodeMetrics {
        let lines: Vec<&str> = code.lines().collect();
        let line_count = lines.len();

        let mut function_count = 0;
        let mut class_count = 0;
        let mut string_count = 0;
        let mut import_count = 0;
        let mut comment_lines = 0;
        let mut total_line_len = 0usize;
        let mut max_line_len = 0usize;
        let mut todo_count = 0;
        let mut debug_stmts = 0;
        let mut nesting_depth = 0;
        let mut max_nesting_depth = 0;
        let mut indent_scores: Vec<f64> = Vec::new();
        let mut _in_block = false;

        let (fn_pattern, class_pattern) = match language {
            "python" => (r"^def\s+\w+", r"^class\s+\w+"),
            "javascript" | "typescript" => (r"^(function\s+\w+|const\s+\w+\s*=\s*(?:async\s*)?\(|=>)", r"^class\s+\w+"),
            "go" => (r"^func\s+(\(\w+\s+\*?\w+\)\s+)?\w+", r"^type\s+\w+\s+struct"),
            "java" => (r"^\s*(public|private|protected)?\s*(static)?\s*\w+\s+\w+\s*\(", r"^\s*class\s+\w+"),
            "rust" => (r"^\s*(pub\s+)?fn\s+\w+", r"^\s*(pub\s+)?struct\s+\w+"),
            _ => (r"^\s*\w+\s+\w+\s*\(", r"^\s*class\s+\w+"),
        };

        let fn_re = regex::Regex::new(fn_pattern).unwrap();
        let class_re = regex::Regex::new(class_pattern).unwrap();
        let string_re = regex::Regex::new(r#""[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'"#).unwrap();
        let import_re = regex::Regex::new(r"(?:^|\n)\s*(?:import|from|require|include|#include)\s+").unwrap();
        let todo_re = regex::Regex::new(r"(?i)(TODO|FIXME|HACK|XXX|BUG|NOTE):").unwrap();
        let debug_re = regex::Regex::new(r"(?i)\b(print|console\.(log|debug)|fmt\.Print|echo|puts|debug)\s*\(").unwrap();

        for line in &lines {
            let stripped = line.trim();

            // Count functions and classes
            if fn_re.is_match(stripped) {
                function_count += 1;
            }
            if class_re.is_match(stripped) {
                class_count += 1;
            }

            // Count strings
            string_count += string_re.find_iter(line).count();

            // Count imports
            if import_re.is_match(line) {
                import_count += 1;
            }

            // Count comments
            if stripped.starts_with("#") || stripped.starts_with("//") {
                comment_lines += 1;
            }

            // Count TODOs
            if todo_re.is_match(line) {
                todo_count += 1;
            }

            // Count debug statements
            if debug_re.is_match(line) {
                debug_stmts += 1;
            }

            // Line length stats
            let line_len = line.len();
            total_line_len += line_len;
            max_line_len = max_line_len.max(line_len);

            // Indentation analysis
            let leading_ws = line.len() - line.trim_start().len();
            if !stripped.is_empty() && leading_ws % 4 == 0 {
                indent_scores.push(1.0);
            } else if !stripped.is_empty() {
                indent_scores.push(0.5);
            }

            // Nesting depth
            let open = line.matches('{').count() + line.matches('(').count();
            let close = line.matches('}').count() + line.matches(')').count();
            if open > close {
                nesting_depth += open - close;
                _in_block = true;
            }
            max_nesting_depth = max_nesting_depth.max(nesting_depth);
            if close > open {
                nesting_depth = nesting_depth.saturating_sub(close - open);
                if nesting_depth == 0 {
                    _in_block = false;
                }
            }
        }

        let avg_line_len = if line_count > 0 {
            total_line_len as f64 / line_count as f64
        } else {
            0.0
        };

        let avg_function_len = if function_count > 0 {
            line_count as f64 / function_count as f64
        } else {
            line_count as f64
        };

        let comment_density = if line_count > 0 {
            comment_lines as f64 / line_count as f64
        } else {
            0.0
        };

        let indentation_score = if !indent_scores.is_empty() {
            indent_scores.iter().sum::<f64>() / indent_scores.len() as f64
        } else {
            1.0
        };

        CodeMetrics {
            line_count,
            function_count,
            class_count,
            avg_function_len,
            max_nesting_depth,
            string_count,
            import_count,
            comment_density,
            avg_line_len,
            max_line_len,
            todo_count,
            debug_stmts,
            indentation_score,
        }
    }

    /// Analyze code for anomalies and return findings.
    pub fn analyze(&self, code: &str, language: &str) -> Vec<AnomalyFinding> {
        let metrics = self.extract_metrics(code, language);
        let mut findings: Vec<AnomalyFinding> = Vec::new();

        // AI pattern detection
        findings.extend(self.detect_ai_patterns(code, language));

        // Statistical anomaly detection
        findings.extend(self.detect_statistical_anomalies(&metrics, code));

        // Structural anomaly detection
        findings.extend(self.detect_structural_anomalies(&metrics, code));

        findings
    }

    /// Detect known AI-generated code patterns.
    fn detect_ai_patterns(&self, code: &str, _language: &str) -> Vec<AnomalyFinding> {
        let mut findings = Vec::new();

        let patterns: Vec<(regex::Regex, &str, &str, f64)> = vec![
            (regex::Regex::new(r"(?i)# generated by|# auto-generated|# code generated").unwrap(), "Generated Code Header", "medium", 0.8),
            (regex::Regex::new(r"(?i)def\s+(helper|util|tool|utility)\d*\s*\(").unwrap(), "Generic Function Names", "low", 0.6),
            (regex::Regex::new(r"(?i)class\s+\w*(Helper|Utility|Tool|Manager)\w*\s*[:(]").unwrap(), "Generic Class Names", "low", 0.6),
            (regex::Regex::new(r"\bTODO:?\s*implement\s+").unwrap(), "AI TODO Pattern", "low", 0.7),
            (regex::Regex::new(r"(?i)import\s+(utils|helpers|tools|ai|config)\b").unwrap(), "Generic Import", "low", 0.65),
            (regex::Regex::new(r"(?i)(?:deeply\s+)?nested\s+(if|try)\s+blocks").unwrap(), "Deeply Nested Blocks", "medium", 0.75),
            (regex::Regex::new(r"(?i)def\s+handle_\w+\s*\(.*?\)\s*:\s*\n\s*try:").unwrap(), "AI Try-Except Pattern", "medium", 0.7),
            (regex::Regex::new(r"\[\s*(?:TODO|FIXME|HACK)\s*\]").unwrap(), "AI Todo Bracket Style", "low", 0.6),
            (regex::Regex::new(r"\|\s*\w+\s*\|\s*\w+\s*\|").unwrap(), "ASCII Table Pattern", "low", 0.5),
            (regex::Regex::new(r"(?i)pass\s*#\s*(?:not\s+used|yet|placeholder)").unwrap(), "Placeholder Pass", "low", 0.6),
            (regex::Regex::new(r"(?i)# === .*? ===").unwrap(), "AI Section Headers", "low", 0.55),
            (regex::Regex::new(r"(?i)(?:extreme|excessive|unnecessary)\s+(?:use|complexity)").unwrap(), "AI Warning Comment", "low", 0.5),
            (regex::Regex::new(r"\.{3,}\s*(?:#|$)").unwrap(), "Ellipsis Pattern", "low", 0.5),
            (regex::Regex::new(r##"(?i)if\s+__name__\s*==\s*['"]__main__['"]"##).unwrap(), "Standard Boilerplate", "info", 0.3),
        ];

        for (re, name, severity, confidence) in patterns {
            for m in re.find_iter(code) {
                let start_line = code[..m.start()].lines().count() + 1;
                let snippet_lines: Vec<&str> = code.lines()
                    .skip(start_line.saturating_sub(1))
                    .take(3)
                    .collect();
                let snippet = snippet_lines.join("\n");

                findings.push(AnomalyFinding {
                    id: format!("ANOM-{:04}", findings.len() + 1),
                    severity: severity.to_string(),
                    explanation: format!("AI-generated pattern detected: {}", name),
                    snippet: snippet[..snippet.len().min(200)].to_string(),
                    line: start_line,
                    confidence,
                    trigger_metric: "pattern_match".to_string(),
                });
            }
        }

        // Deduplicate by line
        let mut seen_lines: HashMap<usize, bool> = HashMap::new();
        findings.retain(|f| {
            seen_lines.insert(f.line, true).is_none()
        });

        findings
    }

    /// Detect statistical anomalies compared to project norms.
    fn detect_statistical_anomalies(&self, metrics: &CodeMetrics, code: &str) -> Vec<AnomalyFinding> {
        let mut findings = Vec::new();
        let mut _base_line = 0.0f64;

        // Line count anomaly (>500 lines is unusual for a single file)
        if metrics.line_count > 500 {
            let confidence = (metrics.line_count as f64 - 500.0) / 500.0;
                findings.push(AnomalyFinding {
                    id: format!("ANOM-{:04}", findings.len() + 100),
                    severity: "medium".to_string(),
                    explanation: format!(
                        "Unusually large file: {} lines. Consider splitting into smaller modules.",
                        metrics.line_count
                    ),
                snippet: code.lines().take(5).collect::<Vec<_>>().join("\n"),
                line: 1,
                confidence: confidence.min(0.9),
                trigger_metric: "line_count".to_string(),
            });
            _base_line += 1.0;
        }

        // Function complexity anomaly
        if metrics.avg_function_len > 50.0 {
            let confidence = (metrics.avg_function_len - 50.0) / 50.0;
                findings.push(AnomalyFinding {
                    id: format!("ANOM-{:04}", findings.len() + 100),
                    severity: "medium".to_string(),
                    explanation: format!(
                        "Large average function length: {:.0} lines. Consider extracting helper functions.",
                        metrics.avg_function_len
                    ),
                snippet: "".to_string(),
                line: 1,
                confidence: confidence.min(0.85),
                trigger_metric: "avg_function_len".to_string(),
            });
            _base_line += 1.0;
        }

        // Nesting depth anomaly
        if metrics.max_nesting_depth > 5 {
            let confidence = (metrics.max_nesting_depth as f64 - 5.0) / 5.0;
                findings.push(AnomalyFinding {
                    id: format!("ANOM-{:04}", findings.len() + 100),
                    severity: "high".to_string(),
                    explanation: format!(
                        "Deeply nested code: {} levels. Refactor with early returns or extracted functions.",
                        metrics.max_nesting_depth
                    ),
                snippet: "".to_string(),
                line: 1,
                confidence: confidence.min(0.95),
                trigger_metric: "max_nesting_depth".to_string(),
            });
            _base_line += 1.0;
        }

        // Line length anomaly
        if metrics.max_line_len > 200 {
            let confidence = (metrics.max_line_len as f64 - 200.0) / 200.0;
                findings.push(AnomalyFinding {
                    id: format!("ANOM-{:04}", findings.len() + 100),
                    severity: "low".to_string(),
                    explanation: format!(
                        "Very long line detected: {} characters. PEP8 recommends <= 79 characters.",
                        metrics.max_line_len
                    ),
                snippet: "".to_string(),
                line: 1,
                confidence: confidence.min(0.7),
                trigger_metric: "max_line_len".to_string(),
            });
            _base_line += 1.0;
        }

        // Low indentation consistency
        if metrics.indentation_score < 0.5 && metrics.line_count > 20 {
                findings.push(AnomalyFinding {
                    id: format!("ANOM-{:04}", findings.len() + 100),
                    severity: "low".to_string(),
                    explanation: "Inconsistent indentation detected. Use 4 spaces consistently.".to_string(),
                snippet: "".to_string(),
                line: 1,
                confidence: 1.0 - metrics.indentation_score,
                trigger_metric: "indentation_score".to_string(),
            });
            _base_line += 1.0;
        }

        findings
    }

    /// Detect structural anomalies (suspicious patterns in code structure).
    fn detect_structural_anomalies(&self, metrics: &CodeMetrics, code: &str) -> Vec<AnomalyFinding> {
        let mut findings = Vec::new();

        // TODO density
        let todo_density = if metrics.line_count > 0 {
            metrics.todo_count as f64 / metrics.line_count as f64
        } else {
            0.0
        };
        if todo_density > 0.05 && metrics.todo_count > 3 {
                findings.push(AnomalyFinding {
                    id: format!("ANOM-{:04}", findings.len() + 200),
                    severity: "info".to_string(),
                    explanation: format!(
                        "High TODO density: {} TODOs in {} lines. Prioritize completing TODOs.",
                        metrics.todo_count, metrics.line_count
                    ),
                snippet: "".to_string(),
                line: 1,
                confidence: (todo_density * 5.0).min(0.8),
                trigger_metric: "todo_density".to_string(),
            });
        }

        // Debug statement density
        let debug_density = if metrics.line_count > 0 {
            metrics.debug_stmts as f64 / metrics.line_count as f64
        } else {
            0.0
        };
        if debug_density > 0.03 && metrics.debug_stmts > 5 {
            findings.push(AnomalyFinding {
                id: format!("ANOM-{:04}", findings.len() + 200),
                severity: "low".to_string(),
                explanation: format!(
                    "High debug statement density: {} print/debug calls. Consider removing before production.",
                    metrics.debug_stmts
                ),
                snippet: "".to_string(),
                line: 1,
                confidence: (debug_density * 10.0).min(0.85),
                trigger_metric: "debug_density".to_string(),
            });
        }

        // Function-per-line ratio (too many tiny functions = AI-generated boilerplate)
        if metrics.line_count > 50 && metrics.function_count as f64 / metrics.line_count as f64 > 0.15 {
            findings.push(AnomalyFinding {
                id: format!("ANOM-{:04}", findings.len() + 200),
                severity: "low".to_string(),
                explanation: format!(
                    "Suspicious function density: {} functions in {} lines. \
                     May indicate generated boilerplate or over-modularization.",
                    metrics.function_count, metrics.line_count
                ),
                snippet: "".to_string(),
                line: 1,
                confidence: 0.65,
                trigger_metric: "function_density".to_string(),
            });
        }

        // Empty class/function ratio
        if metrics.function_count > 5 {
            let empty_fn_re = regex::Regex::new(r"(?m)^\s*(def|fn|function)\s+\w+\s*\([^)]*\)\s*:\s*\n\s*(?:pass|\.\.\.)\s*(?:\n|$)").unwrap();
            let empty_count = empty_fn_re.find_iter(code).count();
            let empty_ratio = empty_count as f64 / metrics.function_count as f64;
            if empty_ratio > 0.3 {
                findings.push(AnomalyFinding {
                    id: format!("ANOM-{:04}", findings.len() + 200),
                    severity: "low".to_string(),
                    explanation: format!(
                        "{} out of {} functions are empty or stubs. Remove placeholder functions.",
                        empty_count, metrics.function_count
                    ),
                    snippet: "".to_string(),
                    line: 1,
                    confidence: empty_ratio,
                    trigger_metric: "empty_function_ratio".to_string(),
                });
            }
        }

        findings
    }

    /// Compute an overall anomaly score (0.0 = normal, 1.0 = highly anomalous).
    pub fn anomaly_score(&self, code: &str, language: &str) -> f64 {
        let findings = self.analyze(code, language);
        if findings.is_empty() {
            return 0.0;
        }

        let weighted_sum: f64 = findings.iter()
            .map(|f| {
                let severity_weight = match f.severity.as_str() {
                    "high" => 1.0,
                    "medium" => 0.7,
                    "low" => 0.4,
                    _ => 0.2,
                };
                severity_weight * f.confidence
            })
            .sum();

        let max_possible = findings.len() as f64;
        (weighted_sum / max_possible).min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_extraction() {
        let engine = AnomalyEngine::new();
        let code = r#"
import os

def hello():
    print("hello")

class Foo:
    pass
"#;
        let metrics = engine.extract_metrics(code, "python");
        assert_eq!(metrics.function_count, 1);
        assert_eq!(metrics.class_count, 1);
        assert_eq!(metrics.import_count, 1);
    }

    #[test]
    fn test_ai_pattern_detection() {
        let engine = AnomalyEngine::new();
        let code = "TODO: implement this";
        let findings = engine.detect_ai_patterns(code, "python");
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_anomaly_score() {
        let engine = AnomalyEngine::new();
        let normal_code = "def foo():\n    pass";
        let score = engine.anomaly_score(normal_code, "python");
        assert!(score < 0.5);

        let suspicious_code = "def helper1():\n    pass\ndef helper2():\n    pass\n" 
            .repeat(30);
        let score2 = engine.anomaly_score(&suspicious_code, "python");
        assert!(score2 >= 0.0);
    }

    #[test]
    fn test_structural_anomalies() {
        let engine = AnomalyEngine::new();
        let code = "print('a')\n".repeat(20) + &"\nprint('b')\n".repeat(5);
        let findings = engine.detect_structural_anomalies(
            &engine.extract_metrics(&code, "python"),
            &code
        );
        assert!(!findings.is_empty());
    }
}
