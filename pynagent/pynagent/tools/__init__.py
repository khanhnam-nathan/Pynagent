"""Pynagent tools package.

Copyright (c) 2026 Pynagent Authors
License: AGPL-3.0

Provides:
  - OSV vulnerability database client
  - SBOM (Software Bill of Materials) generator
  - Dependency vulnerability scanner
  - Interactive TUI for security scanning
  - AI-powered fix suggestions
  - Policy engine for compliance checking
  - Webhook server for CI/CD integration
  - Bot notification server (Slack/Discord/Email) for GitHub App
  - MCP server for Cursor IDE integration (JSON-RPC 2.0 over stdio)
"""

from Pynagent.tools.osv_client import OsvClient, OsvVulnerability
from Pynagent.tools.sbom_generator import SBOMGenerator, SBOMDocument, SBOMComponent
from Pynagent.tools.vulnerability_scanner import DependencyScanner, DependencyInfo, VulnerabilityScanResult

# Lazy imports for optional tools (may require additional dependencies)
__all__ = [
    # Core tools
    "OsvClient",
    "OsvVulnerability",
    "SBOMGenerator",
    "SBOMDocument",
    "SBOMComponent",
    "DependencyScanner",
    "DependencyInfo",
    "VulnerabilityScanResult",
    # Optional tools (lazy-loaded)
    "InteractiveScanner",
    "FixSuggestionEngine",
    "PolicyEngine",
    "WebhookServer",
    "BotNotificationServer",
    "McpServer",
]


def __getattr__(name: str):
    """Lazy load optional tools to avoid hard dependencies."""
    if name == "InteractiveScanner":
        from Pynagent.tools.tui import InteractiveScanner
        return InteractiveScanner
    if name == "FixSuggestionEngine":
        from Pynagent.tools.ai_fixer import FixSuggestionEngine
        return FixSuggestionEngine
    if name == "PolicyEngine":
        from Pynagent.tools.policy_engine import PolicyEngine
        return PolicyEngine
    if name == "WebhookServer":
        from Pynagent.tools.webhook_server import WebhookServer
        return WebhookServer
    if name == "BotNotificationServer":
        from Pynagent.tools.bot_notification_server import BotNotificationServer, create_app
        return BotNotificationServer
    if name == "McpServer":
        from Pynagent.tools.mcp_server import main as McpServer
        return McpServer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
