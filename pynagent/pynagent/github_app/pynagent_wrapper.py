"""Pynagent CLI subprocess wrapper for the GitHub App.

Runs `Pynagent scan` on changed files in a PR, parses SARIF output,
and returns structured JSON findings.

Copyright (c) 2026 Pynagent Authors
Licensed under GNU AGPL v3.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class ScanConfig:
    """Configuration for Pynagent scan execution."""
    cli_path: str = "Pynagent"
    format: str = "sarif"          # sarif | codeclimate | json | markdown
    min_severity: str = "low"      # critical | high | medium | low | info
    fail_on: str = "critical"      # exit non-zero if findings >= this severity
    languages: List[str] = field(default_factory=lambda: [
        "python", "javascript", "typescript", "go", "java", "rust", "ruby", "php"
    ])
    auto_fix: bool = False
    timeout_seconds: int = 300


@dataclass
class Finding:
    """A structured security or quality finding from Pynagent."""
    rule_id: str
    severity: str          # critical | high | medium | low | info
    message: str
    file: str
    line: int
    end_line: Optional[int] = None
    column: Optional[int] = None
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None
    cvss_score: Optional[float] = None
    snippet: Optional[str] = None
    auto_fix_available: bool = False
    auto_fix_diff: Optional[str] = None
    confidence: float = 1.0
    confidence_note: Optional[str] = None
    marker_id: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "end_line": self.end_line,
            "column": self.column,
            "cwe_id": self.cwe_id,
            "owasp_id": self.owasp_id,
            "cvss_score": self.cvss_score,
            "snippet": self.snippet,
            "auto_fix_available": self.auto_fix_available,
            "auto_fix_diff": self.auto_fix_diff,
            "confidence": self.confidence,
            "confidence_note": self.confidence_note,
            "marker_id": self.marker_id,
        }

    @property
    def is_security(self) -> bool:
        return self.severity in ("critical", "high") or bool(self.cwe_id)

    @property
    def severity_emoji(self) -> str:
        return {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪",
        }.get(self.severity, "⚪")


@dataclass
class ScanResult:
    """Result of a Pynagent scan on a set of files."""
    findings: List[Finding]
    exit_code: int
    duration_seconds: float
    files_scanned: int
    languages: List[str]
    error_message: Optional[str] = None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "low")

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "info")

    @property
    def security_count(self) -> int:
        return sum(1 for f in self.findings if f.is_security)

    @property
    def severity_summary(self) -> Dict[str, int]:
        return {
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "info": self.info_count,
        }

    @property
    def total(self) -> int:
        return len(self.findings)

    _fail_on_severity: str = "critical"

    @property
    def has_blocking_findings(self) -> bool:
        return any(
            self._severity_order(f.severity) <= self._severity_order(self._fail_on_severity)
            for f in self.findings
        )

    def _severity_order(self, severity: str) -> int:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return order.get(severity.lower(), 99)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "severity_summary": self.severity_summary,
            "total": self.total,
            "security_count": self.security_count,
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "files_scanned": self.files_scanned,
            "languages": self.languages,
            "error_message": self.error_message,
            "has_blocking_findings": self.has_blocking_findings,
        }


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

LANG_EXTENSIONS: Dict[str, List[str]] = {
    "python": [".py"],
    "javascript": [".js", ".mjs", ".cjs"],
    "typescript": [".ts", ".tsx", ".mts", ".cts"],
    "jsx": [".jsx", ".tsx"],
    "go": [".go"],
    "java": [".java"],
    "rust": [".rs"],
    "ruby": [".rb"],
    "php": [".php"],
    "c": [".c", ".h"],
    "csharp": [".cs"],
    "cpp": [".cpp", ".cc", ".cxx", ".hpp", ".hh"],
    "terraform": [".tf"],
    "yaml": [".yaml", ".yml"],
    "json": [".json"],
}


def detect_language(file_path: str) -> Optional[str]:
    """Detect programming language from file extension."""
    ext = Path(file_path).suffix.lower()
    for lang, exts in LANG_EXTENSIONS.items():
        if ext in exts:
            return lang
    return None


def get_language_for_file(file_path: str) -> str:
    """Get the best language tag for Pynagent CLI --lang flag."""
    detected = detect_language(file_path)
    if detected in ("jsx", "tsx"):
        return "typescript"
    return detected or "python"


# ---------------------------------------------------------------------------
# CLI wrapper
# ---------------------------------------------------------------------------

class PynagentCLI:
    """Subprocess wrapper for the Pynagent CLI."""

    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self.log = logging.getLogger("Pynagent-cli")

    def _build_cmd(
        self,
        target: str,
        language: Optional[str] = None,
        output_path: Optional[Path] = None,
        extra_args: Optional[List[str]] = None,
    ) -> List[str]:
        """Build the Pynagent command line arguments."""
        cmd = [self.config.cli_path, "check", str(target)]

        if language:
            cmd.extend(["--lang", language])

        cmd.extend(["--severity", "--format", self.config.format])

        if self.config.min_severity:
            cmd.extend(["--min-severity", self.config.min_severity])

        if output_path:
            cmd.extend(["--output", str(output_path)])

        if self.config.auto_fix:
            cmd.append("--fix")

        if extra_args:
            cmd.extend(extra_args)

        return cmd

    def check_availability(self) -> Tuple[bool, str]:
        """Check if Pynagent CLI is available and get version."""
        try:
            result = subprocess.run(
                [self.config.cli_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return True, result.stdout.strip()
            return False, result.stderr.strip() or "Unknown error"
        except FileNotFoundError:
            return False, f"Command not found: {self.config.cli_path}"
        except subprocess.TimeoutExpired:
            return False, "Version check timed out"
        except Exception as e:
            return False, str(e)

    def scan_file(
        self,
        file_path: str,
        language: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> ScanResult:
        """Scan a single file and return structured findings."""
        lang = language or get_language_for_file(file_path)
        timeout = timeout or self.config.timeout_seconds

        output_path = Path(tempfile.mktemp(suffix=".sarif"))
        start_time = datetime.now()

        try:
            cmd = self._build_cmd(file_path, language=lang, output_path=output_path)
            self.log.debug("Running: %s", " ".join(cmd))

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            duration = (datetime.now() - start_time).total_seconds()
            findings = self._parse_output(output_path, lang)

            return ScanResult(
                findings=findings,
                exit_code=result.returncode,
                duration_seconds=duration,
                files_scanned=1,
                languages=[lang],
                error_message=result.stderr if result.returncode != 0 else None,
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                findings=[],
                exit_code=124,
                duration_seconds=timeout,
                files_scanned=1,
                languages=[lang],
                error_message=f"Scan timed out after {timeout}s",
            )
        except FileNotFoundError:
            return ScanResult(
                findings=[],
                exit_code=127,
                duration_seconds=0,
                files_scanned=0,
                languages=[],
                error_message=f"Pynagent CLI not found: {self.config.cli_path}",
            )
        except Exception as e:
            return ScanResult(
                findings=[],
                exit_code=1,
                duration_seconds=0,
                files_scanned=0,
                languages=[],
                error_message=str(e),
            )
        finally:
            if output_path.exists():
                output_path.unlink(missing_ok=True)

    def scan_directory(
        self,
        directory: str,
        languages: Optional[List[str]] = None,
        changed_files: Optional[List[str]] = None,
        timeout: Optional[int] = None,
    ) -> ScanResult:
        """Scan a directory, optionally filtering to changed files only."""
        langs = languages or self.config.languages
        timeout = timeout or self.config.timeout_seconds
        start_time = datetime.now()

        all_findings: List[Finding] = []
        total_files = 0
        errors: List[str] = []

        if changed_files:
            # Scan only the files that were changed in this PR
            for file_path in changed_files:
                lang = get_language_for_file(file_path)
                if lang not in langs:
                    continue
                if not Path(file_path).exists():
                    continue

                self.log.debug("Scanning changed file: %s (lang=%s)", file_path, lang)
                result = self.scan_file(file_path, language=lang, timeout=timeout)
                all_findings.extend(result.findings)
                total_files += 1
                if result.error_message:
                    errors.append(f"{file_path}: {result.error_message}")
        else:
            # Scan the entire directory per language
            for lang in langs:
                output_path = Path(tempfile.mktemp(suffix=".sarif"))
                try:
                    cmd = self._build_cmd(directory, language=lang, output_path=output_path)
                    self.log.debug("Running: %s", " ".join(cmd))

                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                    )

                    findings = self._parse_output(output_path, lang)
                    all_findings.extend(findings)

                    if output_path.exists():
                        try:
                            data = json.loads(output_path.read_text())
                            files = data.get("runs", [{}])[0].get("tool", {}).get(
                                "driver", {}
                            ).get("properties", {}).get("files_scanned", [])
                            total_files += len(files) if isinstance(files, list) else 1
                        except Exception:
                            total_files += 1

                    if result.stderr:
                        errors.append(f"[{lang}] {result.stderr[:200]}")
                except subprocess.TimeoutExpired:
                    errors.append(f"[{lang}] Scan timed out after {timeout}s")
                except Exception as e:
                    errors.append(f"[{lang}] {str(e)}")
                finally:
                    if output_path.exists():
                        output_path.unlink(missing_ok=True)

        duration = (datetime.now() - start_time).total_seconds()
        error_msg = "\n".join(errors) if errors else None

        return ScanResult(
            findings=all_findings,
            exit_code=1 if errors else 0,
            duration_seconds=duration,
            files_scanned=total_files,
            languages=langs,
            error_message=error_msg,
        )

    def _parse_output(self, output_path: Path, language: str) -> List[Finding]:
        """Parse Pynagent SARIF output into Finding objects."""
        if not output_path.exists():
            return []

        try:
            data = json.loads(output_path.read_text())
        except (json.JSONDecodeError, IOError) as e:
            self.log.warning("Failed to parse SARIF output: %s", e)
            return []

        return self._parse_sarif(data, language)

    def _parse_sarif(self, data: Dict[str, Any], language: str) -> List[Finding]:
        """Parse SARIF v2.1.0 format into Finding objects."""
        findings = []

        for run in data.get("runs", []):
            driver = run.get("tool", {}).get("driver", {})
            rules_map = {}

            # Build rule lookup from tool driver
            for rule in driver.get("rules", []):
                rule_id = rule.get("id", "")
                rules_map[rule_id] = rule

            # Parse results
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                level = result.get("level", "warning")

                severity_map = {
                    "error": "critical" if level == "error" else "high",
                    "warning": "medium",
                    "note": "low",
                }

                severity = severity_map.get(level, "info")

                # Try to extract from properties
                props = result.get("properties", {}) or {}
                location = result.get("locations", [{}])[0] or {}
                physical = location.get("physicalLocation", {}) or {}
                artifact = physical.get("artifactLocation", {}) or {}
                region = physical.get("region", {}) or {}

                file_uri = artifact.get("uri", "unknown")
                # Normalize to relative path if it's a full URI
                if file_uri.startswith("file://"):
                    file_uri = file_uri[7:]

                message_text = result.get("message", {}).get("text", "")
                if isinstance(result.get("message"), str):
                    message_text = result.get("message", "")

                finding = Finding(
                    rule_id=rule_id,
                    severity=severity,
                    message=message_text,
                    file=file_uri,
                    line=region.get("startLine", 1),
                    end_line=region.get("endLine"),
                    column=region.get("startColumn"),
                    snippet=region.get("snippet"),
                    confidence=props.get("confidence", 1.0),
                    confidence_note=props.get("confidence_note"),
                    raw=result,
                )

                # Enrich from rule metadata
                rule_meta = rules_map.get(rule_id, {})
                if rule_meta:
                    cwe_tags = [t for t in rule_meta.get("properties", {}).get("tags", []) if t.startswith("CWE-")]
                    if cwe_tags:
                        finding.cwe_id = cwe_tags[0]

                    owasp = rule_meta.get("properties", {}).get("owasp")
                    if owasp:
                        finding.owasp_id = owasp

                    if props.get("cvss_score"):
                        finding.cvss_score = float(props["cvss_score"])

                # Try to extract marker_id from message
                marker_match = re.search(r"PYN-[A-Z]+-\d+", message_text)
                if marker_match:
                    finding.marker_id = marker_match.group(0)

                # Check for auto-fix
                fix = result.get("fixes", [])
                if fix:
                    finding.auto_fix_available = True
                if fix[0].get("artifactChanges"):
                    changes = fix[0]["artifactChanges"]
                    if changes and changes[0].get("replacement"):
                            finding.auto_fix_diff = self._build_fix_diff(
                                changes[0]["replacement"]
                            )

                findings.append(finding)

        return findings

    def _build_fix_diff(self, replacement: Dict[str, Any]) -> str:
        """Build a unified diff from a SARIF replacement."""
        lines = []
        for change in replacement.get("changes", []):
            delete_count = change.get("deleteCount", 0)
            offset = change.get("offset", 0)
            text = change.get("insertedText", "")

            lines.append(f"@@ -{offset},{delete_count} +{offset},{len(text.splitlines())} @@")
            lines.append(text)

        return "\n".join(lines)

    async def scan_async(
        self,
        target: str,
        language: Optional[str] = None,
        changed_files: Optional[List[str]] = None,
    ) -> ScanResult:
        """Async version of scan_directory using asyncio."""
        loop = asyncio.get_event_loop()

        def _sync_scan():
            return self.scan_directory(target, changed_files=changed_files)

        return await loop.run_in_executor(None, _sync_scan)


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def create_Pynagent_cli(
    cli_path: Optional[str] = None,
    languages: Optional[List[str]] = None,
    **kwargs,
) -> PynagentCLI:
    """Create a Pynagent CLI wrapper from environment variables."""
    return PynagentCLI(
        config=ScanConfig(
            cli_path=cli_path or os.environ.get("Pynagent_CLI_PATH", "Pynagent"),
            languages=languages or (
                os.environ.get("Pynagent_LANGUAGES", "python,javascript,typescript,go,java,rust,ruby,php")
                .split(",")
            ),
            format=os.environ.get("Pynagent_FORMAT", "sarif"),
            min_severity=os.environ.get("Pynagent_MIN_SEVERITY", "low"),
            fail_on=os.environ.get("Pynagent_FAIL_ON", "critical"),
            auto_fix=os.environ.get("Pynagent_AUTO_FIX", "false").lower() == "true",
            **kwargs,
        )
    )
