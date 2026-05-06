"""LangChain tools exposing Pynagent MCP tools as LangChain-compatible tools.

These tools wrap the existing Pynagent MCP server tools and expose them
as LangChain tools for use in AI agents.

Copyright (c) 2026 Pynagent Authors
Licensed under GNU AGPL v3.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helper functions (used by tool implementations)
# ---------------------------------------------------------------------------

def _format_markers_text(markers: List) -> str:
    """Format markers grouped by severity."""
    if not markers:
        return "No issues found."

    severity_order = ["critical", "high", "medium", "low", "info"]
    sections = []

    for sev in severity_order:
        sev_markers = [m for m in markers if m.severity == sev]
        if not sev_markers:
            continue
        sections.append(f"\n## {sev.upper()} severity ({len(sev_markers)} issue(s))\n")
        for m in sev_markers:
            sections.append(_format_marker_text(m))
            sections.append("")

    summary = [
        f"Total: {len(markers)} issue(s)",
        f"  Critical: {len([m for m in markers if m.severity == 'critical'])}",
        f"  High:     {len([m for m in markers if m.severity == 'high'])}",
        f"  Medium:   {len([m for m in markers if m.severity == 'medium'])}",
        f"  Low:      {len([m for m in markers if m.severity == 'low'])}",
        f"  Info:     {len([m for m in markers if m.severity == 'info'])}",
    ]

    return "\n".join(["SCAN SUMMARY", "=" * 60] + summary) + "\n" + "\n".join(sections)


def _format_marker_text(marker) -> str:
    """Format a single marker as readable text."""
    lines = [
        f"=== {marker.marker_id} ===",
        f"  Type:      {marker.issue_type}",
        f"  Rule:      {marker.rule_id}",
        f"  Severity:  {marker.severity.upper()}",
        f"  Location:  line {marker.line}",
    ]
    if marker.severity in ("critical", "high"):
        if marker.cwe_id:
            lines.append(f"  CWE:       {marker.cwe_id}")
        if marker.owasp_id:
            lines.append(f"  OWASP:     {marker.owasp_id}")
        if marker.cvss_score:
            lines.append(f"  CVSS:      {marker.cvss_score}")
    if marker.why:
        lines.append(f"  WHY:       {marker.why}")
    if marker.hint:
        lines.append(f"  HINT:      {marker.hint}")
    if marker.impact:
        lines.append(f"  IMPACT:    {marker.impact}")
    if marker.snippet:
        snippet = marker.snippet.replace("\n", "\\n")
        lines.append(f"  SNIPPET:   {snippet[:120]}")
    if marker.can_auto_fix and marker.auto_fix_available:
        lines.append(f"  AUTO-FIX:  available")
    return "\n".join(lines)


def _get_rule_explanation(rule_id: Optional[str] = None, issue_type: Optional[str] = None) -> str:
    """Get rule metadata as formatted text."""
    try:
        from Pynagent.tools.mcp_server import RULE_METADATA, ISSUE_TYPE_METADATA
    except ImportError:
        return "ERROR: Could not load rule metadata"

    if rule_id:
        rule_meta = RULE_METADATA.get(rule_id)
        if rule_meta:
            lines = [
                f"Rule: {rule_id}",
                "=" * 60,
                f"Description: {rule_meta['description']}",
                f"Severity range: {rule_meta['severity_range']}",
                f"Can auto-fix: {rule_meta['can_auto_fix']}",
            ]
            if rule_meta["cwe_ids"]:
                lines.append(f"CWE IDs: {', '.join(rule_meta['cwe_ids'])}")
            if rule_meta["owasp_ids"]:
                lines.append(f"OWASP IDs: {', '.join(rule_meta['owasp_ids'])}")
            if rule_meta["resources"]:
                lines.append("Resources:")
                for r in rule_meta["resources"]:
                    lines.append(f"  - {r}")
            return "\n".join(lines)

    if issue_type:
        key = issue_type.lower().replace(" ", "_").replace("-", "_")
        issue_meta = ISSUE_TYPE_METADATA.get(key)
        if issue_meta:
            lines = [
                f"Issue Type: {issue_type}",
                "=" * 60,
                f"Problem: {issue_meta['problem']}",
                f"Severity: {issue_meta['severity'].upper()}",
                f"CVSS Base: {issue_meta['cvss_base']}",
                f"CWE: {issue_meta['cwe_id']}",
                f"OWASP: {issue_meta['owasp_id']}",
            ]
            lines.append("Fix Constraints:")
            for fc in issue_meta["fix_constraints"]:
                lines.append(f"  - {fc}")
            lines.append("Common Mistakes:")
            for dn in issue_meta["do_not"]:
                lines.append(f"  - {dn}")
            lines.append("Resources:")
            for r in issue_meta["resources"]:
                lines.append(f"  - {r}")
            return "\n".join(lines)

    lines = ["Available rules:"]
    for name, meta in sorted(RULE_METADATA.items()):
        lines.append(f"  {name}: {meta['description'][:80]}...")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Standalone dict tools (when LangChain is not installed)
# ---------------------------------------------------------------------------

def _get_dict_tools() -> List[Dict[str, Any]]:
    """Return tools as plain dicts (when LangChain is not available)."""
    return [
        {
            "name": "Pynagent_scan",
            "description": "Scan code for security vulnerabilities using Pynagent.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Source code to scan"},
                    "language": {"type": "string", "description": "Language (default: python)"},
                },
                "required": ["code"],
            },
        },
        {
            "name": "Pynagent_scan_file",
            "description": "Scan a file on disk for security issues.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                    "language": {"type": "string"},
                },
                "required": ["file_path"],
            },
        },
        {
            "name": "Pynagent_explain",
            "description": "Get rule metadata (CWE, OWASP, CVSS).",
            "input_schema": {
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string"},
                    "issue_type": {"type": "string"},
                },
            },
        },
        {
            "name": "Pynagent_auto_fix",
            "description": "Apply auto-fix for a marker.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "marker_id": {"type": "string"},
                    "code": {"type": "string"},
                    "language": {"type": "string"},
                    "dry_run": {"type": "boolean"},
                },
                "required": ["marker_id", "code"],
            },
        },
        {
            "name": "Pynagent_list_rules",
            "description": "List all Pynagent rules.",
            "input_schema": {"type": "object", "properties": {}},
        },
        {
            "name": "analyze_context",
            "description": "AI-analyze a finding to determine if it's a true positive or false positive.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "pr_diff": {"type": "string"},
                    "finding_json": {"type": "string"},
                },
                "required": ["pr_diff", "finding_json"],
            },
        },
    ]


# ---------------------------------------------------------------------------
# LangChain tool wrappers
# ---------------------------------------------------------------------------

def get_langchain_tools():
    """Get all Pynagent tools as LangChain v0.2+ tools.

    Returns a list of BaseTool instances compatible with LangChain agents.
    Falls back to dict format if LangChain is not installed.
    """
    # Try to import LangChain
    try:
        from langchain_core.tools import tool
    except ImportError:
        logger.warning("LangChain not installed — returning dict-format tools")
        return _get_dict_tools()

    # Import Pynagent core
    try:
        from Pynagent.core.engine import RuleEngine
        from Pynagent.core.types import CodeFile, TransformationResult
    except ImportError as e:
        logger.error("Failed to import Pynagent core: %s", e)
        return []

    # ---------------------------------------------------------------------------
    # Pynagent_scan tool
    # ---------------------------------------------------------------------------

    @tool
    def Pynagent_scan(code: str, language: str = "python") -> str:
        """Scan code for security vulnerabilities and quality issues using Pynagent.

        Args:
            code: Source code to scan (multiline string).
            language: Programming language (python, javascript, typescript, java, go, rust, php, ruby).

        Returns:
            Formatted text output with all findings, grouped by severity.
            Each finding includes: marker_id, rule_id, severity, CWE, OWASP, CVSS,
            explanation, fix hints, and auto-fix availability.
        """
        engine = RuleEngine()
        code_file = CodeFile(path=__import__("pathlib").Path("<input>"), content=code, language=language)
        result: TransformationResult = engine.process_code_file(code_file)

        if not result.agent_markers:
            return "No issues found."

        return _format_markers_text(result.agent_markers)

    # ---------------------------------------------------------------------------
    # Pynagent_scan_file tool
    # ---------------------------------------------------------------------------

    @tool
    def Pynagent_scan_file(file_path: str, language: Optional[str] = None) -> str:
        """Scan an entire file on disk for security and quality issues.

        Args:
            file_path: Absolute or relative path to the file to scan.
            language: Optional programming language override (auto-detected from extension if omitted).

        Returns:
            Formatted text output with all findings in the file.
        """
        from pathlib import Path as Path_

        path = Path_(file_path)
        if not path.exists():
            return f"ERROR: File not found: {file_path}"

        engine = RuleEngine()
        result: TransformationResult = engine.process_file(path, language=language or "auto")

        if not result.agent_markers:
            return f"No issues found in {file_path}."

        return _format_markers_text(result.agent_markers)

    # ---------------------------------------------------------------------------
    # Pynagent_explain tool
    # ---------------------------------------------------------------------------

    @tool
    def Pynagent_explain(rule_id: Optional[str] = None, issue_type: Optional[str] = None) -> str:
        """Get full rule metadata and CWE/OWASP mapping for a specific rule or vulnerability type.

        Args:
            rule_id: Rule name (e.g., 'SecurityScannerRule', 'DeadCodeRule').
            issue_type: Vulnerability type (e.g., 'sql_injection', 'xss', 'hardcoded_secret').

        Returns:
            Full description, severity, CWE, OWASP, CVSS, fix constraints,
            common mistakes, verification steps, and resources.
        """
        return _get_rule_explanation(rule_id, issue_type)

    # ---------------------------------------------------------------------------
    # Pynagent_auto_fix tool
    # ---------------------------------------------------------------------------

    @tool
    def Pynagent_auto_fix(
        marker_id: str,
        code: str,
        language: str = "python",
        dry_run: bool = True,
    ) -> str:
        """Apply the auto-fix for a specific security or quality marker.

        Args:
            marker_id: The marker ID to fix (e.g., 'PYN-SEC-0001').
            code: The source code containing the issue.
            language: Programming language of the code.
            dry_run: If True (default), return the diff without applying changes.

        Returns:
            The proposed fix diff, or instructions on how to apply it manually.
        """
        from pathlib import Path as Path_

        engine = RuleEngine()
        code_file = CodeFile(path=Path_("<input>"), content=code, language=language)
        result: TransformationResult = engine.process_code_file(code_file)

        target = None
        for m in result.agent_markers:
            if m.marker_id == marker_id:
                target = m
                break

        if target is None:
            return f"ERROR: Marker '{marker_id}' not found in scan results."

        if not target.auto_fix_available:
            return (
                f"Marker {marker_id} is not auto-fixable.\n"
                f"HINT: {target.hint or 'No hint available.'}\n"
                f"WHY: {target.why or 'No explanation available.'}"
            )

        if target.auto_fix_before and target.auto_fix_after:
            diff = f"--- before\n+++ after\n{marker_id}: {target.auto_fix_after}"
            if dry_run:
                return f"[DRY RUN] Auto-fix diff for {marker_id}:\n{diff}"
            return f"Auto-fix available:\n{diff}"

        return (
            f"Auto-fix for {marker_id} is available but the fix diff was not pre-computed.\n"
            f"Use the CLI: Pynagent fix --marker {marker_id} <file>"
        )

    # ---------------------------------------------------------------------------
    # Pynagent_list_rules tool
    # ---------------------------------------------------------------------------

    @tool
    def Pynagent_list_rules() -> str:
        """List all available Pynagent rules with their names, descriptions, enabled status, and priorities.

        Returns:
            A formatted list of all rules with metadata.
        """
        engine = RuleEngine()
        stats = engine.get_rule_stats()

        lines = ["Pynagent Rules", "=" * 60]
        lines.append(f"Total rules: {stats['total_rules']} | Enabled: {stats['enabled_rules']}")
        lines.append("")

        for rule_info in stats["rules"]:
            enabled = "ON" if rule_info["enabled"] else "OFF"
            lines.append(f"  [{enabled}] {rule_info['name']}")
            desc = rule_info["description"] or ""
            if desc:
                lines.append(f"         {desc[:80]}")
            lines.append(f"         priority={rule_info['priority']}")
            lines.append("")

        return "\n".join(lines)

    # ---------------------------------------------------------------------------
    # analyze_context tool — uses any configured LLM (DeepSeek, Ollama, AMD, OpenAI, Claude)
    # ---------------------------------------------------------------------------

    @tool
    def analyze_context(pr_diff: str, finding_json: str) -> str:
        """Use AI to analyze whether a Pynagent finding is a true positive by examining the full PR context.

        Supports DeepSeek, Ollama, AMD Cloud, OpenAI, and Anthropic — auto-detected
        from environment variables (DEEPSEEK_API_KEY, OLLAMA_BASE_URL, AMD_API_KEY, etc.).

        Args:
            pr_diff: The full diff/patch of the PR containing the finding.
            finding_json: JSON string of the finding to analyze (with file, line, snippet).

        Returns:
            AI analysis with verdict (TRUE_POSITIVE/FALSE_POSITIVE/NEEDS_MANUAL_REVIEW),
            reasoning, exploit scenario, and confidence score.
        """
        try:
            finding = json.loads(finding_json)
        except json.JSONDecodeError:
            return f"ERROR: Invalid JSON in finding_json: {finding_json}"

        try:
            from Pynagent.agentic.agent import LLMConfig, create_llm_client, TruePositiveAnalyzer

            config = LLMConfig.from_env()
            if not config.is_configured():
                return "ERROR: No LLM configured. Set DEEPSEEK_API_KEY, OLLAMA_BASE_URL, AMD_API_KEY, or OPENAI_API_KEY."

            llm = create_llm_client(config)
            if llm is None:
                return "ERROR: Failed to create LLM client."
            analyzer = TruePositiveAnalyzer(llm, config)

            result = analyzer.analyze(finding, context_code=pr_diff)

            lines = [
                f"## AI Analysis for {result.marker_id}",
                "",
                f"**Verdict**: {result.verdict}",
                f"**Confidence**: {result.ai_confidence:.0%}",
                "",
                f"**Reasoning**: {result.reasoning}",
            ]

            if result.exploit_scenario:
                lines.append("")
                lines.append(f"**Exploit Scenario**: {result.exploit_scenario}")

            return "\n".join(lines)

        except ImportError as e:
            return f"ERROR: Agent module not available: {e}"
        except Exception as e:
            return f"ERROR: AI analysis failed: {e}"

    return [
        Pynagent_scan,
        Pynagent_scan_file,
        Pynagent_explain,
        Pynagent_auto_fix,
        Pynagent_list_rules,
        analyze_context,
    ]
