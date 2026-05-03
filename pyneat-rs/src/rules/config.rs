//! Configurable Rule System for PyNEAT
//!
//! Provides a configuration framework that allows rules to be customized
//! via YAML/JSON config files or Python API parameters.
//!
//! Copyright (C) 2026 PyNEAT Authors

#[allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

/// Rule configuration - controls whether a rule is enabled and its parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    /// Whether the rule is enabled.
    pub enabled: bool,
    /// Rule-specific parameters.
    #[serde(default)]
    pub params: HashMap<String, serde_json::Value>,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            params: HashMap::new(),
        }
    }
}

impl RuleConfig {
    /// Create a new enabled rule config with no params.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a disabled rule config.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            params: HashMap::new(),
        }
    }

    /// Create a new rule config with params.
    pub fn with_params(params: HashMap<String, serde_json::Value>) -> Self {
        Self { enabled: true, params }
    }

    /// Get a parameter as a specific type, returning the default if missing or wrong type.
    pub fn get_param<T: for<'de> Deserialize<'de>>(&self, key: &str, default: T) -> T {
        self.params
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or(default)
    }

    /// Get a string parameter.
    pub fn get_string(&self, key: &str) -> Option<String> {
        self.params.get(key).and_then(|v| v.as_str().map(String::from))
    }

    /// Get a bool parameter.
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.params.get(key).and_then(|v| v.as_bool())
    }

    /// Get a f64 parameter.
    pub fn get_f64(&self, key: &str) -> Option<f64> {
        self.params.get(key).and_then(|v| v.as_f64())
    }

    /// Get a Vec<String> parameter.
    pub fn get_string_list(&self, key: &str) -> Option<Vec<String>> {
        self.params.get(key).and_then(|v| {
            v.as_array()
                .and_then(|arr| {
                    let mut out = Vec::new();
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            out.push(s.to_string());
                        } else {
                            return None;
                        }
                    }
                    Some(out)
                })
        })
    }

    /// Get the minimum entropy threshold for hardcoded secrets detection.
    pub fn min_entropy(&self) -> f64 {
        self.get_param("min_entropy", 4.0)
    }

    /// Get skip patterns for hardcoded secrets.
    pub fn skip_patterns(&self) -> Vec<String> {
        self.get_string_list("skip_patterns")
            .unwrap_or_else(Vec::new)
    }

    /// Get include patterns for hardcoded secrets.
    pub fn include_patterns(&self) -> Vec<String> {
        self.get_string_list("include_patterns")
            .unwrap_or_else(Vec::new)
    }

    /// Get minimum hash bits for weak hash detection.
    pub fn min_hash_bits(&self) -> usize {
        self.get_param::<f64>("min_hash_bits", 256.0) as usize
    }
}

/// A rule that can be configured with parameters.
///
/// This trait extends the base `Rule` trait with configuration capabilities.
/// Rules implementing this trait can be instantiated with custom parameters
/// from a `.pyneat.yaml` config file or via Python API.
///
/// Note: Individual rule implementations should provide their own impl blocks.
/// This trait is separate from the base Rule trait to allow configuration
/// without modifying the core rule interface.
pub trait ConfigurableRule: Send + Sync {
    /// Get the unique identifier for this rule.
    fn id(&self) -> &str;

    /// Create a new instance of this rule with the given config.
    fn with_config(&self, config: &RuleConfig) -> Box<dyn crate::rules::base::Rule>;

    /// Get the default (unconfigured) instance of this rule.
    fn default_rule(&self) -> Box<dyn crate::rules::base::Rule>;

    /// Get the schema for this rule's parameters (for docs/validation).
    fn param_schema(&self) -> Option<&'static str> {
        None
    }
}

/// Global registry for configurable rules.
/// Allows registering rules and looking them up by ID.
pub struct RuleConfigRegistry {
    rules: RwLock<HashMap<String, Box<dyn ConfigurableRule>>>,
}

impl Default for RuleConfigRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleConfigRegistry {
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(HashMap::new()),
        }
    }

    /// Register a configurable rule.
    pub fn register(&self, rule: Box<dyn ConfigurableRule>) {
        let id = rule.id().to_string();
        let mut rules = self.rules.write().unwrap();
        rules.insert(id, rule);
    }

    /// Get a configurable rule by ID.
    pub fn get(&self, id: &str) -> Option<Box<dyn ConfigurableRule>> {
        let rules = self.rules.read().unwrap();
        rules.get(id).map(|_r| -> Box<dyn ConfigurableRule> {
            // Safety: we clone through the trait by constructing a new box via default_rule
            // This is a workaround since we can't Clone Box<dyn ConfigurableRule> directly
            panic!("use create_rule instead")
        })
    }

    /// Get all registered rule IDs.
    pub fn all_ids(&self) -> Vec<String> {
        let rules = self.rules.read().unwrap();
        rules.keys().cloned().collect()
    }

    /// Create a configured rule from a RuleConfig.
    /// Returns None if the rule ID is not registered.
    pub fn create_rule(&self, id: &str, config: &RuleConfig) -> Option<Box<dyn crate::rules::base::Rule>> {
        let rules = self.rules.read().unwrap();
        rules.get(id).map(|r| r.with_config(config))
    }
}

/// Builder pattern for creating RuleConfig instances fluently.
#[derive(Debug, Clone, Default)]
pub struct RuleConfigBuilder {
    enabled: bool,
    params: HashMap<String, serde_json::Value>,
}

impl RuleConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn param<T: Into<serde_json::Value>>(mut self, key: impl Into<String>, value: T) -> Self {
        self.params.insert(key.into(), value.into());
        self
    }

    pub fn min_entropy(mut self, value: f64) -> Self {
        self.params.insert("min_entropy".to_string(), serde_json::json!(value));
        self
    }

    pub fn skip_patterns(mut self, patterns: Vec<String>) -> Self {
        let arr: Vec<serde_json::Value> = patterns.into_iter().map(|v| serde_json::json!(v)).collect();
        self.params.insert("skip_patterns".to_string(), serde_json::json!(arr));
        self
    }

    pub fn include_patterns(mut self, patterns: Vec<String>) -> Self {
        let arr: Vec<serde_json::Value> = patterns.into_iter().map(|v| serde_json::json!(v)).collect();
        self.params.insert("include_patterns".to_string(), serde_json::json!(arr));
        self
    }

    pub fn min_hash_bits(mut self, bits: usize) -> Self {
        self.params.insert("min_hash_bits".to_string(), serde_json::json!(bits));
        self
    }

    pub fn build(self) -> RuleConfig {
        RuleConfig {
            enabled: self.enabled,
            params: self.params,
        }
    }
}
