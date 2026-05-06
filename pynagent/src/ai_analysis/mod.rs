//! AI Analysis Module for Pynagent
//!
//! Provides LLM-based code analysis capabilities.
//!
//! Copyright (C) 2026 Pynagent Authors

pub mod llm;

pub use llm::{LlmAnalyzer, LlmAnalysisResult, AiFix, has_api_key};
