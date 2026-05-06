"""Agentic module — AI-powered PR security agent using multi-provider LLM.

This module provides the Pynagent AI Agent that combines:
- Pynagent SAST scanning (Rust-based)
- AI analysis (DeepSeek, Ollama, AMD Cloud, OpenAI, Anthropic)
- LangChain tools (MCP integration)

Provider auto-detection: DeepSeek > Ollama > AMD Cloud > OpenAI > Anthropic

Copyright (c) 2026 Pynagent Authors
Licensed under GNU AGPL v3.
"""

from .agent import (
    PynagentAgent,
    PRContext,
    AgentConfig,
    LLMConfig,
    LLMProvider,
    AnalysisResult,
    FindingExplainer,
    TruePositiveAnalyzer,
    FindingPrioritizer,
    create_agent,
    create_llm_client,
    # Backwards-compatibility aliases
    AMDCloudConfig,
    AMDCloudLLM,
)
from .langchain_tools import get_langchain_tools

__all__ = [
    # Core
    "PynagentAgent",
    "PRContext",
    "AgentConfig",
    "LLMConfig",
    "LLMProvider",
    "create_agent",
    "create_llm_client",
    # Analyzers
    "AnalysisResult",
    "FindingExplainer",
    "TruePositiveAnalyzer",
    "FindingPrioritizer",
    # LangChain
    "get_langchain_tools",
    # Backwards-compat
    "AMDCloudConfig",
    "AMDCloudLLM",
]
