"""SARIF upload and Checks API integration for the GitHub App.

This module provides utilities for:
- Uploading SARIF results to GitHub Code Scanning
- Creating and updating GitHub Check Runs
- Posting PR comments with scan summaries

Copyright (c) 2026 Pynagent Authors
Licensed under GNU AGPL v3.
"""

from __future__ import annotations

import json
import logging
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class CheckRunOptions:
    """Options for creating a GitHub Check Run."""
    name: str = "Pynagent/scan"
    status: str = "completed"          # in_progress | completed
    conclusion: Optional[str] = None   # success | failure | action_required | neutral | cancelled
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    output_title: str = "Pynagent Scan"
    output_summary: str = ""
    output_text: str = ""
    actions: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class SarifUploadOptions:
    """Options for SARIF upload to GitHub Code Scanning."""
    commit_sha: str
    category: str = "Pynagent-scan"
    ref: Optional[str] = None


@dataclass
class PRCommentOptions:
    """Options for PR comment posting."""
    show_inline_comments: bool = False
    max_findings: int = 20
    show_snippets: bool = True
    show_fix_hints: bool = True


# ---------------------------------------------------------------------------
# SARIF helpers
# ---------------------------------------------------------------------------

def build_pr_sarif(
    findings: List[Dict[str, Any]],
    repository: str,
    branch: str,
    commit_sha: str,
    tool_name: str = "Pynagent",
    tool_version: str = "3.0.0",
) -> Dict[str, Any]:
    """Build a SARIF v2.1.0 file from Pynagent findings.

    This is a convenience wrapper around the existing Pynagent.core.manifest
    SARIF export, useful when you have raw finding dicts from the CLI wrapper.
    """
    runs = []

    for run_data in _group_by_file(findings):
        file_uri = run_data["file"]
        file_findings = run_data["findings"]

        results = []
        for f in file_findings:
            level_map = {
                "critical": "error",
                "high": "error",
                "medium": "warning",
                "low": "note",
                "info": "note",
            }
            level = level_map.get(f.get("severity", "warning"), "warning")

            rule_id = f.get("rule_id", "unknown")

            result = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f.get("message", ""),
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": f.get("line", 1),
                                "startColumn": f.get("column", 1),
                                "endLine": f.get("end_line") or f.get("line", 1),
                                "snippet": {
                                    "text": f.get("snippet", ""),
                                } if f.get("snippet") else None,
                            }.copy(),
                        }
                    }
                ],
                "properties": {
                    "severity": f.get("severity", "unknown"),
                    "confidence": f.get("confidence", 1.0),
                    "confidence_note": f.get("confidence_note"),
                    "cvss_score": f.get("cvss_score"),
                    "cwe_id": f.get("cwe_id"),
                    "owasp_id": f.get("owasp_id"),
                    "marker_id": f.get("marker_id"),
                    "auto_fix_available": f.get("auto_fix_available", False),
                },
            }

            if f.get("auto_fix_diff"):
                result["fixes"] = [
                    {
                        "description": {
                            "text": "Auto-fix suggestion",
                        },
                        "artifactChanges": [
                            {
                                "artifactLocation": {"uri": file_uri},
                                "replacement": {
                                    "offset": 0,
                                    "insertedText": f.get("auto_fix_diff", ""),
                                },
                            }
                        ],
                    }
                ]

            results.append(result)

        run = {
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": "https://github.com/Pynagent/Pynagent",
                    "rules": _build_rules_array(findings),
                    "properties": {
                        "files_scanned": [file_uri],
                        "repository": repository,
                        "branch": branch,
                        "commit_sha": commit_sha,
                    },
                }
            },
            "results": results,
            "properties": {
                "repository": repository,
                "branch": branch,
                "commit_sha": commit_sha,
                "scanned_at": datetime.now().isoformat(),
            },
        }

        runs.append(run)

    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": runs,
    }

    return sarif


def _group_by_file(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group findings by file."""
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        file_uri = f.get("file", "unknown")
        if file_uri not in by_file:
            by_file[file_uri] = []
        by_file[file_uri].append(f)
    return [{"file": k, "findings": v} for k, v in by_file.items()]


def _build_rules_array(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build the rules array for SARIF from findings."""
    seen = set()
    rules = []

    for f in findings:
        rule_id = f.get("rule_id", "unknown")
        if rule_id in seen:
            continue
        seen.add(rule_id)

        rule = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {
                "text": f.get("message", "")[:200],
            },
            "fullDescription": {
                "text": f.get("message", ""),
            },
            "properties": {
                "tags": [],
                "precision": "high",
            },
        }

        cwe = f.get("cwe_id")
        if cwe:
            rule["properties"]["tags"].append(cwe)

        owasp = f.get("owasp_id")
        if owasp:
            rule["properties"]["tags"].append(f"OWASP-{owasp}")

        rules.append(rule)

    return rules


# ---------------------------------------------------------------------------
# Check Run helpers
# ---------------------------------------------------------------------------

def build_check_run_output(
    scan_result: Dict[str, Any],
    max_findings: int = 10,
) -> Dict[str, Any]:
    """Build GitHub Check Run output from scan result dict.

    Args:
        scan_result: Structured scan result from Pynagent_wrapper.ScanResult.to_dict()
        max_findings: Maximum number of findings to include in the text output

    Returns:
        A dict compatible with the GitHub Checks API output field.
    """
    severity_summary = scan_result.get("severity_summary", {})
    findings = scan_result.get("findings", [])
    total = scan_result.get("total", 0)
    duration = scan_result.get("duration_seconds", 0)
    files_scanned = scan_result.get("files_scanned", 0)

    critical = severity_summary.get("critical", 0)
    high = severity_summary.get("high", 0)

    # Build summary (used in the PR checks UI)
    if critical > 0:
        summary_parts = [f"🚨 **{critical} critical** and **{high} high** severity issues detected."]
    elif total > 0:
        summary_parts = [f"✅ Found **{total}** issue(s)."]
    else:
        summary_parts = ["✅ **No issues found.**"]

    summary_parts.extend([
        "",
        "| Severity | Count |",
        "|---------|-------|",
        f"| 🔴 Critical | {critical} |",
        f"| 🟠 High | {high} |",
        f"| 🟡 Medium | {severity_summary.get('medium', 0)} |",
        f"| 🔵 Low | {severity_summary.get('low', 0)} |",
        f"| ⚪ Info | {severity_summary.get('info', 0)} |",
        "",
        f"Files scanned: {files_scanned} · Duration: {duration:.1f}s",
    ])

    # Build text (full details shown when clicking the check)
    lines = [
        "# Pynagent Security Scan Results",
        "",
        f"Total: {total} finding(s) | Files: {files_scanned} | Duration: {duration:.1f}s",
        "",
    ]

    if total > 0:
        lines.extend(["## Findings", ""])
        for f in findings[:max_findings]:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(
                f.get("severity", "?"), "⚪"
            )
            lines.append(f"{emoji} **{f.get('rule_id', '?')}** at {f.get('file', '?')}:{f.get('line', '?')}")
            lines.append(f"   {f.get('message', '')[:100]}")
            if f.get("cwe_id"):
                lines.append(f"   CWE: {f.get('cwe_id')}")
            if f.get("auto_fix_available"):
                lines.append("   🛠️ Auto-fix available")
            lines.append("")

    lines.extend([
        "---",
        "Powered by [Pynagent](https://github.com/Pynagent/Pynagent) v3.0 with AI analysis by AMD Cloud.",
    ])

    return {
        "title": f"Pynagent Scan — {total} Finding{'s' if total != 1 else ''}",
        "summary": "\n".join(summary_parts),
        "text": "\n".join(lines),
    }


def get_check_conclusion(scan_result: Dict[str, Any]) -> str:
    """Determine the GitHub Check Run conclusion from scan result."""
    critical = scan_result.get("severity_summary", {}).get("critical", 0)
    high = scan_result.get("severity_summary", {}).get("high", 0)
    total = scan_result.get("total", 0)

    if critical > 0:
        return "failure"
    elif high > 0:
        return "action_required"
    elif total > 0:
        return "neutral"
    else:
        return "success"


# ---------------------------------------------------------------------------
# GitHub API helpers (REST client)
# ---------------------------------------------------------------------------

async def upload_sarif_github(
    octokit,
    owner: str,
    repo: str,
    sarif_data: Dict[str, Any],
    commit_sha: str,
    category: str = "Pynagent-scan",
) -> Dict[str, Any]:
    """Upload SARIF results to GitHub Code Scanning via REST API.

    Args:
        octokit: Authenticated Octokit instance
        owner: Repository owner
        repo: Repository name
        sarif_data: The SARIF data dict (will be serialized to JSON)
        commit_sha: The commit SHA to associate with the upload
        category: Category label for the upload

    Returns:
        The API response data
    """
    import gzip
    import base64

    # GitHub requires SARIF to be gzip compressed and base64 encoded
    sarif_json = json.dumps(sarif_data, indent=2).encode("utf-8")
    compressed = gzip.compress(sarif_json)
    encoded = base64.b64encode(compressed).decode()

    response = await octokit.rest.codeScanning.uploadSarif({
        owner,
        repo,
        sarif: encoded,
        commit_sha,
        category,
    })

    return response.data


async def create_or_update_check_run(
    octokit,
    owner: str,
    repo: str,
    head_sha: str,
    output: Dict[str, Any],
    conclusion: str,
    check_name: str = "Pynagent/scan",
) -> Dict[str, Any]:
    """Create or update a GitHub Check Run.

    First checks for an existing Pynagent/scan check run for the given SHA
    and updates it, or creates a new one if none exists.
    """
    # Check for existing check run
    existing = None
    try:
        response = await octokit.rest.checks.listForRef({
            owner,
            repo,
            ref: head_sha,
            check_name,
            status: "completed",
            per_page: 1,
        })
        existing = response.data.check_runs[0] if response.data.check_runs else None
    except Exception as e:
        logger.warning("Failed to check for existing check run: %s", e)

    now = datetime.now().isoformat() + "Z"

    if existing:
        response = await octokit.rest.checks.update({
            owner,
            repo,
            check_run_id: existing.id,
            status: "completed",
            conclusion,
            completed_at=now,
            output=output,
        })
        logger.info("Updated check run %s", existing.id)
    else:
        response = await octokit.rest.checks.create({
            owner,
            repo,
            name=check_name,
            head_sha,
            status="completed",
            conclusion,
            completed_at=now,
            output=output,
            actions=[
                {
                    "label": "View Full Report",
                    "description": "View all scan findings",
                    "identifier": "view_report",
                },
            ],
        })
        logger.info("Created check run %s", response.data.id)

    return response.data


# ---------------------------------------------------------------------------
# Convenience: scan and upload pipeline
# ---------------------------------------------------------------------------

async def scan_and_upload(
    Pynagent_cli,
    octokit,
    owner: str,
    repo: str,
    head_sha: str,
    target: str,
    changed_files: Optional[List[str]] = None,
    check_name: str = "Pynagent/scan",
    upload_sarif: bool = True,
) -> Dict[str, Any]:
    """Run Pynagent scan and upload results to GitHub Checks + SARIF.

    This is a convenience function that combines:
    1. Running Pynagent scan
    2. Building check run output
    3. Creating/updating the GitHub Check Run
    4. Optionally uploading SARIF to GitHub Code Scanning

    Args:
        Pynagent_cli: PynagentCLI wrapper instance
        octokit: Authenticated Octokit instance
        owner: Repository owner
        repo: Repository name
        head_sha: The commit SHA to scan
        target: Directory or file to scan
        changed_files: Optional list of changed files (for PR filtering)
        check_name: Name of the check run
        upload_sarif: Whether to also upload to GitHub Code Scanning

    Returns:
        Dict with scan_result, check_run, and sarif_upload keys
    """
    # Run scan
    scan_result = await Pynagent_cli.scan_async(target, changed_files=changed_files)
    scan_dict = scan_result.to_dict()

    # Build output
    output = build_check_run_output(scan_dict)
    conclusion = get_check_conclusion(scan_dict)

    # Create/update check run
    check_run = await create_or_update_check_run(
        octokit, owner, repo, head_sha, output, conclusion, check_name
    )

    result = {
        "scan_result": scan_dict,
        "check_run": check_run,
        "sarif_upload": None,
    }

    # Upload SARIF
    if upload_sarif:
        findings = [f.to_dict() for f in scan_result.findings]
        sarif_data = build_pr_sarif(
            findings,
            repository=f"{owner}/{repo}",
            branch="",
            commit_sha=head_sha,
        )

        try:
            sarif_result = await upload_sarif_github(
                octokit, owner, repo, sarif_data, head_sha
            )
            result["sarif_upload"] = sarif_result
        except Exception as e:
            logger.error("SARIF upload failed: %s", e)
            result["sarif_upload_error"] = str(e)

    return result
