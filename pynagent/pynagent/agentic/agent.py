"""Pynagent AI Agent — LangChain agent with MCP tools and multi-provider LLM support.

Supports AMD Cloud (Qwen/Llama), Ollama (local/cloud), DeepSeek, OpenAI,
Anthropic, and any OpenAI-compatible API endpoint.

Copyright (c) 2026 Pynagent Authors
Licensed under GNU AGPL v3.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Provider defaults
# ---------------------------------------------------------------------------

class LLMProvider(Enum):
    """Supported LLM providers."""
    DEEPSEEK = "deepseek"
    OLLAMA = "ollama"
    AMD_CLOUD = "amd_cloud"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    NONE = "none"


# ---------------------------------------------------------------------------
# Unified LLM Configuration
# ---------------------------------------------------------------------------

@dataclass
class LLMConfig:
    """Unified configuration for any LLM provider.

    Provider auto-detection (in priority order):
    1. DEEPSEEK_API_KEY  → DeepSeek 671B on Ollama Cloud
    2. OLLAMA_BASE_URL   → Ollama (local or cloud)
    3. AMD_API_KEY       → AMD Developer Cloud
    4. OPENAI_API_KEY    → OpenAI GPT-4o
    5. ANTHROPIC_API_KEY → Anthropic Claude

    Environment variables:
      DEEPSEEK_API_KEY    DeepSeek API key (for Ollama Cloud DeepSeek)
      DEEPSEEK_BASE_URL   DeepSeek endpoint (default: https://api.deepseek.com)
      DEEPSEEK_MODEL      DeepSeek model (default: deepseek-chat)
      OLLAMA_BASE_URL     Ollama endpoint (default: http://localhost:11434/v1)
      OLLAMA_MODEL        Ollama model (default: qwen2.5-72b-instruct)
      AMD_API_KEY         AMD Developer Cloud API key
      AMD_API_URL        AMD Cloud endpoint (default: https://api.amd.com/v1)
      AMD_MODEL          AMD Cloud model (default: qwen-2.5-72b-instruct)
      OPENAI_API_KEY     OpenAI API key
      OPENAI_MODEL       OpenAI model (default: gpt-4o-mini)
      ANTHROPIC_API_KEY  Anthropic API key
      ANTHROPIC_MODEL    Claude model (default: claude-3-5-sonnet-latest)
      LLM_TEMPERATURE    Temperature (default: 0.1)
      LLM_MAX_TOKENS     Max tokens (default: 2048)
      LLM_TIMEOUT        Request timeout seconds (default: 120)
      LLM_MAX_RETRIES    Max retry attempts (default: 3)
      LLM_CACHE_TTL      Cache TTL in hours (default: 24)
      AI_ANALYSIS_CACHE_TTL_HOURS  Alias for LLM_CACHE_TTL
    """
    provider: LLMProvider = LLMProvider.NONE
    api_key: str = ""
    base_url: str = ""
    model: str = ""
    temperature: float = 0.1
    max_tokens: int = 2048
    timeout_seconds: int = 120
    max_retries: int = 3
    cache_ttl_hours: int = 24

    @classmethod
    def from_env(cls) -> "LLMConfig":
        """Auto-detect provider from environment variables."""
        # Priority: DeepSeek > Ollama > AMD > OpenAI > Anthropic
        if os.environ.get("DEEPSEEK_API_KEY"):
            return cls(
                provider=LLMProvider.DEEPSEEK,
                api_key=os.environ["DEEPSEEK_API_KEY"],
                base_url=os.environ.get(
                    "DEEPSEEK_BASE_URL",
                    "https://api.deepseek.com"
                ),
                model=os.environ.get("DEEPSEEK_MODEL", "deepseek-chat"),
                temperature=float(os.environ.get("LLM_TEMPERATURE", "0.1")),
                max_tokens=int(os.environ.get("LLM_MAX_TOKENS", "2048")),
                timeout_seconds=int(os.environ.get("LLM_TIMEOUT", "120")),
                max_retries=int(os.environ.get("LLM_MAX_RETRIES", "3")),
                cache_ttl_hours=int(os.environ.get(
                    "AI_ANALYSIS_CACHE_TTL_HOURS",
                    os.environ.get("LLM_CACHE_TTL", "24")
                )),
            )

        if os.environ.get("OLLAMA_BASE_URL"):
            return cls(
                provider=LLMProvider.OLLAMA,
                api_key=os.environ.get("OLLAMA_API_KEY", "ollama"),
                base_url=os.environ["OLLAMA_BASE_URL"].rstrip("/") + "/v1",
                model=os.environ.get("OLLAMA_MODEL", "qwen2.5-72b-instruct"),
                temperature=float(os.environ.get("LLM_TEMPERATURE", "0.1")),
                max_tokens=int(os.environ.get("LLM_MAX_TOKENS", "2048")),
                timeout_seconds=int(os.environ.get("LLM_TIMEOUT", "120")),
                max_retries=int(os.environ.get("LLM_MAX_RETRIES", "3")),
                cache_ttl_hours=int(os.environ.get(
                    "AI_ANALYSIS_CACHE_TTL_HOURS",
                    os.environ.get("LLM_CACHE_TTL", "24")
                )),
            )

        if os.environ.get("AMD_API_KEY"):
            return cls(
                provider=LLMProvider.AMD_CLOUD,
                api_key=os.environ["AMD_API_KEY"],
                base_url=os.environ.get(
                    "AMD_API_URL",
                    os.environ.get("AMD_API_BASE_URL", "https://api.amd.com/v1")
                ),
                model=os.environ.get("AMD_MODEL", "qwen-2.5-72b-instruct"),
                temperature=float(os.environ.get("AMD_TEMPERATURE", "0.1")),
                max_tokens=int(os.environ.get("AMD_MAX_TOKENS", os.environ.get("LLM_MAX_TOKENS", "2048"))),
                timeout_seconds=int(os.environ.get("AMD_TIMEOUT", os.environ.get("LLM_TIMEOUT", "120"))),
                max_retries=int(os.environ.get("AMD_MAX_RETRIES", "3")),
                cache_ttl_hours=int(os.environ.get("AI_ANALYSIS_CACHE_TTL_HOURS", "24")),
            )

        if os.environ.get("OPENAI_API_KEY"):
            return cls(
                provider=LLMProvider.OPENAI,
                api_key=os.environ["OPENAI_API_KEY"],
                base_url="https://api.openai.com/v1",
                model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
                temperature=float(os.environ.get("LLM_TEMPERATURE", "0.1")),
                max_tokens=int(os.environ.get("LLM_MAX_TOKENS", "2048")),
                timeout_seconds=int(os.environ.get("LLM_TIMEOUT", "120")),
                max_retries=int(os.environ.get("LLM_MAX_RETRIES", "3")),
                cache_ttl_hours=int(os.environ.get(
                    "AI_ANALYSIS_CACHE_TTL_HOURS",
                    os.environ.get("LLM_CACHE_TTL", "24")
                )),
            )

        if os.environ.get("ANTHROPIC_API_KEY"):
            return cls(
                provider=LLMProvider.ANTHROPIC,
                api_key=os.environ["ANTHROPIC_API_KEY"],
                base_url="https://api.anthropic.com/v1",
                model=os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest"),
                temperature=float(os.environ.get("LLM_TEMPERATURE", "0.1")),
                max_tokens=int(os.environ.get("LLM_MAX_TOKENS", "2048")),
                timeout_seconds=int(os.environ.get("LLM_TIMEOUT", "120")),
                max_retries=int(os.environ.get("LLM_MAX_RETRIES", "3")),
                cache_ttl_hours=int(os.environ.get(
                    "AI_ANALYSIS_CACHE_TTL_HOURS",
                    os.environ.get("LLM_CACHE_TTL", "24")
                )),
            )

        return cls(provider=LLMProvider.NONE)

    def is_configured(self) -> bool:
        return self.provider != LLMProvider.NONE and bool(self.api_key)

    def __str__(self) -> str:
        return f"LLMConfig({self.provider.value}, model={self.model}, url={self.base_url})"


# ---------------------------------------------------------------------------
# LLM Client (abstract base + OpenAI-compatible implementation)
# ---------------------------------------------------------------------------

class LLMClient(ABC):
    """Abstract LLM client interface."""

    @abstractmethod
    def complete(self, prompt: str, **kwargs) -> str:
        """Generate a completion for a prompt."""
        ...

    @abstractmethod
    async def acomplete(self, prompt: str, **kwargs) -> str:
        """Async version of complete."""
        ...


class OpenAICompatibleLLM(LLMClient):
    """Generic OpenAI-compatible LLM client.

    Works with any provider that exposes an OpenAI-compatible /v1/chat/completions
    endpoint, including:
    - DeepSeek on Ollama Cloud
    - Ollama (local/cloud)
    - AMD Developer Cloud
    - LM Studio
    - LocalAI
    - vLLM
    - SGLang
    """

    def __init__(self, config: LLMConfig):
        self.config = config
        self._cache: Dict[str, Tuple[str, float]] = {}  # key -> (response, expiry_time)

    def _get_cache_key(self, prompt: str, **kwargs) -> str:
        import hashlib
        data = json.dumps({"prompt": prompt, **kwargs}, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()

    def _get_cached(self, key: str) -> Optional[str]:
        if key not in self._cache:
            return None
        response, expiry = self._cache[key]
        if time.time() > expiry:
            del self._cache[key]
            return None
        return response

    def _set_cached(self, key: str, response: str) -> None:
        expiry = time.time() + self.config.cache_ttl_hours * 3600
        if len(self._cache) > 1000:
            oldest_keys = sorted(self._cache.keys(), key=lambda k: self._cache[k][1])[:500]
            for k in oldest_keys:
                del self._cache[k]
        self._cache[key] = (response, expiry)

    def complete(self, prompt: str, **kwargs) -> str:
        return asyncio.get_event_loop().run_until_complete(
            self.acomplete(prompt, **kwargs)
        )

    async def acomplete(
        self,
        prompt: str,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        system: Optional[str] = None,
        **kwargs,
    ) -> str:
        """Call the configured LLM API for text completion."""
        cache_key = self._get_cache_key(prompt, temperature=temperature, max_tokens=max_tokens, system=system)
        cached = self._get_cached(cache_key)
        if cached:
            logger.debug("%s cache hit", self.config.provider.value)
            return cached

        import urllib.request
        import urllib.error

        url = f"{self.config.base_url}/chat/completions"

        messages: List[Dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        # Build payload — OpenAI-compatible format
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": temperature if temperature is not None else self.config.temperature,
            "max_tokens": max_tokens or self.config.max_tokens,
        }
        # Merge extra kwargs (e.g., top_p, frequency_penalty, etc.)
        payload.update(kwargs)

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.api_key}",
        }

        last_error = None
        for attempt in range(self.config.max_retries):
            try:
                data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    url,
                    data=data,
                    headers=headers,
                    method="POST",
                )

                with urllib.request.urlopen(
                    req,
                    timeout=self.config.timeout_seconds
                ) as response:
                    result = json.loads(response.read().decode("utf-8"))

                choices = result.get("choices", [])
                if not choices:
                    return f"No response from {self.config.provider.value}."

                content = choices[0].get("message", {}).get("content", "")
                self._set_cached(cache_key, content)
                return content

            except urllib.error.HTTPError as e:
                last_error = e
                body = e.read().decode("utf-8") if e.fp else ""
                logger.warning(
                    "%s API HTTP %d (attempt %d/%d): %s",
                    self.config.provider.value, e.code, attempt + 1,
                    self.config.max_retries, body[:200]
                )
                if e.code in (400, 401, 403):
                    break

            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last_error = e
                logger.warning(
                    "%s API error (attempt %d/%d): %s",
                    self.config.provider.value, attempt + 1,
                    self.config.max_retries, e
                )

            if attempt < self.config.max_retries - 1:
                await asyncio.sleep(2 ** attempt)

        return f"[{self.config.provider.value} error after {self.config.max_retries} attempts: {last_error}]"


def create_llm_client(config: Optional[LLMConfig] = None) -> Optional[LLMClient]:
    """Factory: create the appropriate LLM client from config."""
    if config is None:
        config = LLMConfig.from_env()

    if not config.is_configured():
        return None

    return OpenAICompatibleLLM(config)


# ---------------------------------------------------------------------------
# True Positive Analysis
# ---------------------------------------------------------------------------

ANALYSIS_SYSTEM_PROMPT = """You are Pynagent, an AI-powered code security analyst.
Your job is to analyze security scan findings and determine if they are true positives or false positives.

Be CONSERVATIVE — only mark as false positive if the code clearly cannot be exploited.
When in doubt, mark as TRUE POSITIVE.

For each finding, provide:
1. VERDICT: TRUE_POSITIVE or FALSE_POSITIVE or NEEDS_MANUAL_REVIEW
2. REASONING: Why you reached this conclusion
3. EXPLOIT_SCENARIO: How an attacker could exploit this (if true positive)
4. CONTEXT: Surrounding code that confirms or denies the finding

Be specific and cite the exact code you're analyzing."""


ANALYSIS_USER_TEMPLATE = """Analyze this security finding:

## Finding
- **Rule**: {rule_id}
- **Severity**: {severity}
- **Location**: {file}:{line}
- **Message**: {message}
- **CWE**: {cwe_id}
- **Code Snippet**:
```language
{code_snippet}
```

## Context (surrounding code):
```language
{context_code}
```

## Usage Pattern
{usage_pattern}

Analyze this and determine if it's a true positive or false positive."""


@dataclass
class AnalysisResult:
    """Result of AI analysis of a finding."""
    marker_id: str
    verdict: str           # TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_MANUAL_REVIEW
    reasoning: str
    exploit_scenario: Optional[str] = None
    ai_confidence: float = 1.0
    enriched_message: Optional[str] = None
    raw_response: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "marker_id": self.marker_id,
            "verdict": self.verdict,
            "reasoning": self.reasoning,
            "exploit_scenario": self.exploit_scenario,
            "ai_confidence": self.ai_confidence,
            "enriched_message": self.enriched_message,
        }


class TruePositiveAnalyzer:
    """Uses AI to analyze findings for false positive reduction."""

    def __init__(self, llm: Optional[LLMClient], config: Optional[LLMConfig] = None):
        self.llm = llm
        self.config = config or LLMConfig.from_env()

    def analyze(
        self,
        finding: Dict[str, Any],
        context_code: str = "",
        usage_pattern: str = "",
    ) -> AnalysisResult:
        """Analyze a single finding for false positive reduction."""
        if self.llm is None:
            return AnalysisResult(
                marker_id=finding.get("marker_id", ""),
                verdict="NEEDS_MANUAL_REVIEW",
                reasoning="No LLM configured (set DEEPSEEK_API_KEY, OLLAMA_BASE_URL, AMD_API_KEY, or OPENAI_API_KEY)",
            )
        return asyncio.get_event_loop().run_until_complete(
            self.aanalyze(finding, context_code, usage_pattern)
        )

    async def aanalyze(
        self,
        finding: Dict[str, Any],
        context_code: str = "",
        usage_pattern: str = "",
    ) -> AnalysisResult:
        """Async analysis of a single finding."""
        prompt = ANALYSIS_USER_TEMPLATE.format(
            rule_id=finding.get("rule_id", "unknown"),
            severity=finding.get("severity", "unknown"),
            file=finding.get("file", "?"),
            line=finding.get("line", "?"),
            message=finding.get("message", ""),
            cwe_id=finding.get("cwe_id", "N/A"),
            code_snippet=finding.get("snippet", "N/A"),
            context_code=context_code or "No additional context available.",
            usage_pattern=usage_pattern or "No usage pattern information available.",
        )

        try:
            response = await self.llm.acomplete(
                prompt,
                system=ANALYSIS_SYSTEM_PROMPT,
            )
            return self._parse_analysis_response(finding, response)
        except Exception as e:
            logger.error("AI analysis failed for %s: %s", finding.get("marker_id", "?"), e)
            return AnalysisResult(
                marker_id=finding.get("marker_id", ""),
                verdict="NEEDS_MANUAL_REVIEW",
                reasoning=f"AI analysis failed: {e}",
                raw_response=str(e),
            )

    def _parse_analysis_response(self, finding: Dict[str, Any], response: str) -> AnalysisResult:
        """Parse the AI response to extract structured analysis."""
        verdict = "NEEDS_MANUAL_REVIEW"
        reasoning = response
        exploit_scenario = None

        upper = response.upper()
        if "VERDICT: TRUE_POSITIVE" in upper or "VERDICT:TRUE_POSITIVE" in upper:
            verdict = "TRUE_POSITIVE"
        elif "VERDICT: FALSE_POSITIVE" in upper or "VERDICT:FALSE_POSITIVE" in upper:
            verdict = "FALSE_POSITIVE"
        elif "VERDICT: NEEDS_MANUAL" in upper:
            verdict = "NEEDS_MANUAL_REVIEW"

        exploit_match = re.search(
            r"(?:EXPLOIT_SCENARIO|EXPLOIT SCENARIO)[:\s]*(.*?)(?=\n\n|\n##|\Z)",
            response,
            re.DOTALL | re.IGNORECASE,
        )
        if exploit_match:
            exploit_scenario = exploit_match.group(1).strip()

        confidence = 1.0
        conf_match = re.search(r"CONFIDENCE[:\s]*(\d+\.?\d*)", upper)
        if conf_match:
            confidence = float(conf_match.group(1))
            if confidence > 1:
                confidence = min(confidence / 100, 1.0)

        enriched = self._build_enriched_message(finding, verdict, response)

        return AnalysisResult(
            marker_id=finding.get("marker_id", ""),
            verdict=verdict,
            reasoning=reasoning[:500],
            exploit_scenario=exploit_scenario,
            ai_confidence=confidence,
            enriched_message=enriched,
            raw_response=response,
        )

    def _build_enriched_message(self, finding: Dict, verdict: str, response: str) -> str:
        emoji = {"TRUE_POSITIVE": "🚨", "FALSE_POSITIVE": "⚠️", "NEEDS_MANUAL_REVIEW": "🤔"}.get(
            verdict, "❓"
        )
        verdict_label = verdict.replace("_", " ").title()

        lines = [
            f"{emoji} **AI Analysis: {verdict_label}**",
            "",
        ]

        if verdict == "TRUE_POSITIVE":
            lines.append("This finding represents a genuine security vulnerability.")
        elif verdict == "FALSE_POSITIVE":
            lines.append("This finding is likely a false positive — the code cannot be exploited in this context.")
        else:
            lines.append("Manual review recommended to determine if this is a real vulnerability.")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Finding Explainer
# ---------------------------------------------------------------------------

EXPLAIN_SYSTEM_PROMPT = """You are Pynagent, an expert code security analyst.
Your job is to explain security vulnerabilities in plain English to developers.
For each vulnerability, explain:
1. WHAT the vulnerability is (in one sentence)
2. WHY it's dangerous (real-world impact)
3. HOW to fix it (specific, actionable steps)
4. WHAT not to do (common mistakes to avoid)

Be clear, concise, and educational. Use plain language, not jargon."""


EXPLAIN_USER_TEMPLATE = """Explain this security vulnerability in plain English:

**Vulnerability**: {rule_id}
**Severity**: {severity}
**CWE**: {cwe_id}
**OWASP**: {owasp_id}
**CVSS**: {cvss}
**Location**: {file}:{line}

**Description**: {message}

**Code snippet**:
```language
{code_snippet}
```

Please provide a plain-English explanation suitable for a developer who may not be a security expert."""


class FindingExplainer:
    """Uses AI to generate human-readable explanations."""

    def __init__(self, llm: Optional[LLMClient]):
        self.llm = llm

    def explain(self, finding: Dict[str, Any]) -> str:
        """Generate a plain-English explanation for a finding."""
        if self.llm is None:
            return "[AI explanation unavailable — no LLM configured]"
        return asyncio.get_event_loop().run_until_complete(
            self.aexplain(finding)
        )

    async def aexplain(self, finding: Dict[str, Any]) -> str:
        """Async explanation generation."""
        prompt = EXPLAIN_USER_TEMPLATE.format(
            rule_id=finding.get("rule_id", "?"),
            severity=finding.get("severity", "?"),
            cwe_id=finding.get("cwe_id", "N/A"),
            owasp_id=finding.get("owasp_id", "N/A"),
            cvss=finding.get("cvss_score", "N/A"),
            file=finding.get("file", "?"),
            line=finding.get("line", "?"),
            message=finding.get("message", "No description available."),
            code_snippet=finding.get("snippet", "No code snippet available."),
        )

        try:
            return await self.llm.acomplete(
                prompt,
                system=EXPLAIN_SYSTEM_PROMPT,
                max_tokens=512,
            )
        except Exception as e:
            logger.error("Failed to explain finding %s: %s", finding.get("marker_id", "?"), e)
            return f"[AI explanation unavailable: {e}]"


# ---------------------------------------------------------------------------
# Finding Prioritizer
# ---------------------------------------------------------------------------

class FindingPrioritizer:
    """Ranks findings by severity, exploitability, and business impact."""

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    EXPLOITABILITY_SCORES: Dict[str, float] = {
        "sql_injection": 1.0,
        "command_injection": 1.0,
        "path_traversal": 0.9,
        "xss": 0.8,
        "xxe": 0.9,
        "ssrf": 0.8,
        "deserialization": 0.9,
        "hardcoded_secret": 0.7,
        "weak_crypto": 0.7,
        "insecure_auth": 0.8,
        "prompt_injection": 0.6,
    }

    def prioritize(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort findings by priority score (severity × exploitability × confidence)."""
        scored = []
        for f in findings:
            score = self._compute_priority_score(f)
            scored.append({**f, "_priority_score": score})

        scored.sort(key=lambda x: x["_priority_score"], reverse=True)
        return scored

    def _compute_priority_score(self, finding: Dict[str, Any]) -> float:
        sev = finding.get("severity", "info")
        sev_order = self.SEVERITY_ORDER.get(sev, 4)

        issue_type = finding.get("issue_type", "").lower()
        exploitability = self.EXPLOITABILITY_SCORES.get(issue_type, 0.5)

        confidence = float(finding.get("confidence", 1.0))
        has_fix = bool(finding.get("auto_fix_available", False))

        score = (5 - sev_order) * exploitability * confidence
        if has_fix:
            score *= 1.2

        return round(score, 3)


# ---------------------------------------------------------------------------
# Main Agent
# ---------------------------------------------------------------------------

@dataclass
class PRContext:
    """Context about the pull request for the agent."""
    owner: str
    repo: str
    pr_number: int
    title: str
    description: str
    author: str
    base_branch: str
    head_branch: str
    head_sha: str
    changed_files: List[Dict[str, Any]] = field(default_factory=list)
    diff_content: str = ""


@dataclass
class AgentConfig:
    """Configuration for the Pynagent AI agent."""
    enable_analysis: bool = True
    analysis_min_severity: str = "high"
    max_findings_to_analyze: int = 20
    explain_findings: bool = True
    max_explain_findings: int = 10
    use_cache: bool = True


class PynagentAgent:
    """Main AI agent that orchestrates the Pynagent scan → AI analysis → report pipeline.

    Supports multiple LLM providers: DeepSeek (Ollama Cloud), Ollama, AMD Cloud,
    OpenAI, and Anthropic — auto-detected from environment variables.
    """

    def __init__(
        self,
        Pynagent_cli,
        llm_config: Optional[LLMConfig] = None,
        agent_config: Optional[AgentConfig] = None,
    ):
        self.Pynagent = Pynagent_cli
        self.llm_config = llm_config or LLMConfig.from_env()
        self.agent_config = agent_config or AgentConfig()

        # Initialize LLM client
        if self.llm_config.is_configured():
            self.llm = OpenAICompatibleLLM(self.llm_config)
            self.analyzer = TruePositiveAnalyzer(self.llm, self.llm_config)
            self.explainer = FindingExplainer(self.llm)
            logger.info(
                "AI agent initialized with %s (model: %s, provider: %s)",
                self.llm_config.provider.value,
                self.llm_config.model,
                self.llm_config.base_url,
            )
        else:
            self.llm = None
            self.analyzer = None
            self.explainer = None
            logger.warning(
                "No LLM configured — AI analysis disabled. "
                "Set DEEPSEEK_API_KEY, OLLAMA_BASE_URL, AMD_API_KEY, "
                "OPENAI_API_KEY, or ANTHROPIC_API_KEY to enable."
            )

        self.prioritizer = FindingPrioritizer()

    @property
    def is_ai_enabled(self) -> bool:
        return self.llm is not None

    def get_llm_info(self) -> Dict[str, Any]:
        """Get LLM provider information for display/logging."""
        if not self.llm_config.is_configured():
            return {"configured": False, "provider": "none", "message": "No LLM configured"}

        return {
            "configured": True,
            "provider": self.llm_config.provider.value,
            "model": self.llm_config.model,
            "base_url": self.llm_config.base_url,
        }

    async def run(self, pr_context: PRContext) -> Dict[str, Any]:
        """Run the full agent pipeline on a PR.

        Returns a dict with scan results, AI analysis, and formatted report.
        """
        start_time = time.time()
        logger.info(
            "Pynagent Agent running for %s/%s PR #%d",
            pr_context.owner, pr_context.repo, pr_context.pr_number
        )

        # Step 1: Run Pynagent scan
        scan_result = await self._run_scan(pr_context)
        if scan_result.exit_code not in (0, 1):
            return {
                "status": "error",
                "error": scan_result.error_message,
                "duration": time.time() - start_time,
            }

        findings = scan_result.findings
        logger.info(
            "Scan complete: %d findings (%d security)",
            len(findings),
            scan_result.security_count
        )

        # Step 2: Prioritize findings
        prioritized = self.prioritizer.prioritize([f.to_dict() for f in findings])

        # Step 3: AI analysis (if enabled and there are relevant findings)
        analysis_results: List[AnalysisResult] = []
        if self.is_ai_enabled and self.agent_config.enable_analysis:
            analysis_results = await self._run_analysis(prioritized, pr_context)

        # Step 4: Generate explanations (if enabled)
        explanations: Dict[str, str] = {}
        if self.is_ai_enabled and self.agent_config.explain_findings:
            top_findings = prioritized[: self.agent_config.max_explain_findings]
            explanations = await self._run_explanations(top_findings)

        # Step 5: Build final report
        report = self._build_report(
            scan_result,
            prioritized,
            analysis_results,
            explanations,
        )

        report["duration_seconds"] = time.time() - start_time
        report["ai_enabled"] = self.is_ai_enabled
        report["llm_info"] = self.get_llm_info()

        return report

    async def _run_scan(self, pr_context: PRContext):
        """Run Pynagent scan on PR changed files."""
        changed_files = [f["filename"] for f in pr_context.changed_files]

        if not changed_files:
            return self.Pynagent.scan_directory(pr_context.repo)

        return self.Pynagent.scan_directory(
            pr_context.repo,
            changed_files=changed_files,
        )

    async def _run_analysis(
        self,
        prioritized_findings: List[Dict[str, Any]],
        pr_context: PRContext,
    ) -> List[AnalysisResult]:
        """Run AI false-positive analysis on findings."""
        min_sev = self.agent_config.analysis_min_severity
        min_order = self.prioritizer.SEVERITY_ORDER.get(min_sev, 1)

        relevant = [
            f for f in prioritized_findings
            if self.prioritizer.SEVERITY_ORDER.get(f["severity"], 5) <= min_order
        ]
        relevant = relevant[: self.agent_config.max_findings_to_analyze]

        logger.info(
            "Running AI analysis on %d findings (min severity: %s)",
            len(relevant), min_sev
        )

        results = []
        for finding in relevant:
            context_code = self._get_context_code(finding, pr_context)
            usage_pattern = self._get_usage_pattern(finding, pr_context)

            result = await self.analyzer.aanalyze(finding, context_code, usage_pattern)
            results.append(result)

            await asyncio.sleep(1)  # Rate limit

        return results

    def _get_context_code(self, finding: Dict[str, Any], pr_context: PRContext) -> str:
        """Get surrounding context code for a finding."""
        return f"File: {finding.get('file', '?')}, Line: {finding.get('line', '?')}"

    def _get_usage_pattern(self, finding: Dict[str, Any], pr_context: PRContext) -> str:
        """Get usage patterns for a finding."""
        return ""

    async def _run_explanations(
        self,
        findings: List[Dict[str, Any]],
    ) -> Dict[str, str]:
        """Generate explanations for findings."""
        explanations = {}
        for finding in findings:
            marker_id = finding.get("marker_id", finding.get("rule_id", "?"))
            try:
                explanation = await self.explainer.aexplain(finding)
                explanations[marker_id] = explanation
                await asyncio.sleep(0.5)
            except Exception as e:
                logger.error("Failed to explain %s: %s", marker_id, e)

        return explanations

    def _build_report(
        self,
        scan_result,
        prioritized_findings: List[Dict[str, Any]],
        analysis_results: List[AnalysisResult],
        explanations: Dict[str, str],
    ) -> Dict[str, Any]:
        """Build the final structured report."""
        analysis_map = {r.marker_id: r for r in analysis_results}

        enriched_findings = []
        for f in prioritized_findings:
            marker_id = f.get("marker_id", f.get("rule_id", "?"))
            analysis = analysis_map.get(marker_id)
            explanation = explanations.get(marker_id)

            enriched = {**f}
            if analysis:
                enriched["ai_analysis"] = analysis.to_dict()
            if explanation:
                enriched["ai_explanation"] = explanation

            enriched_findings.append(enriched)

        return {
            "status": "success",
            "scan_result": scan_result.to_dict(),
            "findings": enriched_findings,
            "total_findings": len(enriched_findings),
            "severity_summary": scan_result.severity_summary,
            "analysis_count": len(analysis_results),
            "true_positives": sum(
                1 for r in analysis_results if r.verdict == "TRUE_POSITIVE"
            ),
            "false_positives": sum(
                1 for r in analysis_results if r.verdict == "FALSE_POSITIVE"
            ),
            "needs_review": sum(
                1 for r in analysis_results if r.verdict == "NEEDS_MANUAL_REVIEW"
            ),
        }


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def create_agent(
    Pynagent_cli=None,
    llm_config: Optional[LLMConfig] = None,
    **agent_kwargs,
) -> PynagentAgent:
    """Create a fully configured Pynagent AI agent.

    LLM provider auto-detected from environment (priority order):
    1. DEEPSEEK_API_KEY    → DeepSeek (recommended for this hackathon)
    2. OLLAMA_BASE_URL     → Ollama (local or cloud)
    3. AMD_API_KEY         → AMD Developer Cloud
    4. OPENAI_API_KEY      → OpenAI GPT-4o
    5. ANTHROPIC_API_KEY   → Anthropic Claude
    """
    if Pynagent_cli is None:
        from Pynagent.github_app.Pynagent_wrapper import create_Pynagent_cli
        Pynagent_cli = create_Pynagent_cli()

    config = llm_config or LLMConfig.from_env()
    agent_cfg = AgentConfig(**agent_kwargs)

    return PynagentAgent(
        Pynagent_cli=Pynagent_cli,
        llm_config=config,
        agent_config=agent_cfg,
    )


# ---------------------------------------------------------------------------
# Backwards-compatibility aliases
# ---------------------------------------------------------------------------

#: Alias for backwards compatibility with existing code
AMDCloudConfig = LLMConfig

#: Alias for backwards compatibility
AMDCloudLLM = OpenAICompatibleLLM
