"""Bot notification webhook server — extends the existing webhook_server.py.

This FastAPI server receives scan results from the GitHub App and
forwards them to Slack, Discord, email, and other notification channels.

New endpoints:
  - POST /bot/scan-result  — receive scan result from GitHub App
  - POST /bot/notify        — manual notification trigger
  - GET  /bot/status        — bot status and channel health
  - GET  /bot/stats         — scan statistics

Copyright (c) 2026 Pynagent Authors
Licensed under GNU AGPL v3.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import smtplib
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from fastapi import FastAPI, HTTPException, Request, Response, Depends
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    BaseModel = object

try:
    import aiohttp
except ImportError:
    aiohttp = None

# Re-use the existing notification channel types from webhook_server
try:
    from Pynagent.tools.webhook_server import NotificationChannel, WebhookEvent
except ImportError:
    @dataclass
    class NotificationChannel:
        channel_type: str
        url: str
        enabled: bool = True
        secret: Optional[str] = None
        filters: Dict[str, Any] = field(default_factory=dict)
        retry_count: int = 3
        retry_delay: float = 1.0

    @dataclass
    class WebhookEvent:
        event_type: str
        payload: Dict[str, Any]
        timestamp: float = field(default_factory=time.time)
        source_ip: str = ""
        headers: Dict[str, str] = field(default_factory=dict)
        signature: Optional[str] = None


# ---------------------------------------------------------------------------
# Pydantic models for the bot API
# ---------------------------------------------------------------------------

class FindingPayload(BaseModel):
    rule_id: str
    severity: str
    message: str
    file: str
    line: int
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None
    cvss_score: Optional[float] = None
    snippet: Optional[str] = None
    marker_id: Optional[str] = None


class ScanResultPayload(BaseModel):
    """Payload from the GitHub App when a scan completes."""
    scan_id: str
    target: str
    findings_count: int
    findings: List[FindingPayload] = Field(default_factory=list)
    severity_summary: Dict[str, int] = Field(default_factory=dict)
    duration: float
    timestamp: str
    repository: Optional[str] = None
    pr_number: Optional[int] = None
    pr_title: Optional[str] = None
    branch: Optional[str] = None
    commit_sha: Optional[str] = None
    owner: Optional[str] = None
    repo: Optional[str] = None
    installation_id: Optional[int] = None
    ai_analysis_enabled: bool = False
    total_findings: int = 0
    true_positives: int = 0
    false_positives: int = 0


class NotifyRequest(BaseModel):
    """Manual notification trigger request."""
    channel: str = Field(..., description="slack | discord | email | webhook | github")
    severity_filter: str = Field(
        default="all",
        description="all | critical | high | medium"
    )
    message: Optional[str] = None
    custom_payload: Optional[Dict[str, Any]] = None


class BotStats(BaseModel):
    """Bot statistics."""
    total_scans: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    notifications_sent: int = 0
    notifications_failed: int = 0
    channels_configured: List[str] = Field(default_factory=list)
    uptime_seconds: float = 0
    last_scan_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Bot Notification Server
# ---------------------------------------------------------------------------

class BotNotificationServer:
    """FastAPI-based notification server that extends the existing webhook_server."""

    def __init__(self):
        self.started_at = time.time()
        self.total_scans = 0
        self.total_findings = 0
        self.critical_findings = 0
        self.high_findings = 0
        self.notifications_sent = 0
        self.notifications_failed = 0
        self._channels: Dict[str, NotificationChannel] = {}
        self._secret = os.environ.get("Pynagent_WEBHOOK_SECRET", "")
        self._rate_limits: Dict[str, List[float]] = {}
        self._rate_limit_window = 60
        self._rate_limit_max = 100

        self._load_channels_from_env()

    def _load_channels_from_env(self) -> None:
        """Load notification channels from environment variables."""
        if os.environ.get("SLACK_WEBHOOK_URL"):
            self._channels["slack"] = NotificationChannel(
                channel_type="slack",
                url=os.environ["SLACK_WEBHOOK_URL"],
                enabled=True,
            )

        if os.environ.get("DISCORD_WEBHOOK_URL"):
            self._channels["discord"] = NotificationChannel(
                channel_type="discord",
                url=os.environ["DISCORD_WEBHOOK_URL"],
                enabled=True,
            )

        if os.environ.get("SMTP_HOST") and os.environ.get("SMTP_USER"):
            self._channels["email"] = NotificationChannel(
                channel_type="email",
                url=os.environ.get("SMTP_HOST", "smtp://localhost"),
                enabled=True,
            )

        logger.info("Loaded %d notification channels: %s", len(self._channels), list(self._channels.keys()))

    def verify_signature(self, body: bytes, signature: str) -> bool:
        """Verify HMAC signature of the incoming webhook payload."""
        if not self._secret:
            return True
        expected = hmac.new(
            self._secret.encode(),
            body,
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(f"sha256={expected}", signature)

    def check_rate_limit(self, ip: str) -> bool:
        """Check if an IP is within rate limits."""
        now = time.time()
        window_start = now - self._rate_limit_window

        if ip not in self._rate_limits:
            self._rate_limits[ip] = []

        self._rate_limits[ip] = [t for t in self._rate_limits[ip] if t > window_start]

        if len(self._rate_limits[ip]) >= self._rate_limit_max:
            return False

        self._rate_limits[ip].append(now)
        return True

    async def handle_scan_result(self, payload: ScanResultPayload) -> Dict[str, Any]:
        """Process a scan result and send notifications to all configured channels."""
        self.total_scans += 1
        self.total_findings += payload.total_findings
        self.critical_findings += payload.severity_summary.get("critical", 0)
        self.high_findings += payload.severity_summary.get("high", 0)

        # Build event payload
        event = WebhookEvent(
            event_type="scan.completed",
            payload=asdict(payload),
            timestamp=time.time(),
        )

        results = {
            "scan_id": payload.scan_id,
            "notifications_sent": 0,
            "notifications_failed": 0,
            "errors": [],
        }

        # Send to all configured channels
        for channel_type, channel in self._channels.items():
            if not channel.enabled:
                continue

            try:
                if channel_type == "slack":
                    await self._send_slack(channel, payload)
                elif channel_type == "discord":
                    await self._send_discord(channel, payload)
                elif channel_type == "email":
                    self._send_email(channel, payload)
                elif channel_type == "webhook":
                    await self._send_webhook(channel, event)

                self.notifications_sent += 1
                results["notifications_sent"] += 1

            except Exception as e:
                self.notifications_failed += 1
                results["notifications_failed"] += 1
                results["errors"].append(f"[{channel_type}] {str(e)}")
                logger.error("Failed to send %s notification: %s", channel_type, e)

        return results

    async def _send_slack(self, channel: NotificationChannel, payload: ScanResultPayload) -> None:
        """Send notification to Slack."""
        if aiohttp is None:
            logger.warning("aiohttp not installed, skipping Slack notification")
            return

        severity = payload.severity_summary
        repo = payload.repository or f"{payload.owner}/{payload.repo}"
        pr_info = f" PR `#{payload.pr_number}`" if payload.pr_number else ""
        pr_title = f" — *{payload.pr_title}*" if payload.pr_title else ""

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"Pynagent Scan Complete{pr_info}{pr_title}",
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Repo:*\n{repo}"},
                    {"type": "mrkdwn", "text": f"*Branch:*\n{payload.branch or 'N/A'}"},
                    {"type": "mrkdwn", "text": f"*Findings:*\n{payload.total_findings}"},
                    {"type": "mrkdwn", "text": f"*Duration:*\n{payload.duration:.1f}s"},
                ]
            },
        ]

        # Severity breakdown
        sev_parts = []
        if severity.get("critical"):
            sev_parts.append(f":red_circle: *CRITICAL:* {severity['critical']}")
        if severity.get("high"):
            sev_parts.append(f":orange_circle: *HIGH:* {severity['high']}")
        if severity.get("medium"):
            sev_parts.append(f":yellow_circle: *MEDIUM:* {severity['medium']}")

        if sev_parts:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": " · ".join(sev_parts)}
            })

        # Critical/High findings
        critical_high = [f for f in payload.findings if f.severity in ("critical", "high")]
        if critical_high:
            finding_lines = []
            for f in critical_high[:5]:
                loc = f"{f.file}:{f.line}" if f.file else "?"
                finding_lines.append(f"• `{f.rule_id}` at `{loc}` — {f.message[:60]}")
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*Critical/High Findings:*\n" + "\n".join(finding_lines)}
            })

        # AI analysis summary
        if payload.ai_analysis_enabled:
            tp = payload.true_positives
            fp = payload.false_positives
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":robot_face: *AI Analysis (AMD Cloud):* {tp} true positives, {fp} false positives"
                }
            })

        blocks.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"Pynagent v3.0 · {datetime.now().isoformat()}"}
            ]
        })

        data = {"blocks": blocks}

        async with aiohttp.ClientSession() as session:
            await session.post(
                channel.url,
                json=data,
                timeout=aiohttp.ClientTimeout(total=10),
            )

    async def _send_discord(self, channel: NotificationChannel, payload: ScanResultPayload) -> None:
        """Send notification to Discord."""
        if aiohttp is None:
            logger.warning("aiohttp not installed, skipping Discord notification")
            return

        severity = payload.severity_summary

        if severity.get("critical"):
            color = 0xFF0000
        elif severity.get("high"):
            color = 0xFFA500
        elif severity.get("medium"):
            color = 0xFFFF00
        else:
            color = 0x00FF00

        repo = payload.repository or f"{payload.owner}/{payload.repo}"

        embed = {
            "title": f"Pynagent Scan: {repo}{f' PR #{payload.pr_number}' if payload.pr_number else ''}",
            "color": color,
            "fields": [
                {"name": "Total Findings", "value": str(payload.total_findings), "inline": True},
                {"name": "Duration", "value": f"{payload.duration:.1f}s", "inline": True},
            ],
            "footer": {"text": "Pynagent AI Security Bot · AMD Cloud"},
            "timestamp": datetime.now().isoformat(),
        }

        severity_text = "\n".join(
            f"**{k.upper()}**: {v}" for k, v in severity.items() if v > 0
        )
        if severity_text:
            embed["fields"].append({
                "name": "Severity Breakdown",
                "value": severity_text,
                "inline": False,
            })

        data = {"embeds": [embed]}

        async with aiohttp.ClientSession() as session:
            await session.post(
                channel.url,
                json=data,
                timeout=aiohttp.ClientTimeout(total=10),
            )

    def _send_email(self, channel: NotificationChannel, payload: ScanResultPayload) -> None:
        """Send email notification for critical findings."""
        if not payload.severity_summary.get("critical"):
            return  # Only email on critical findings

        smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
        smtp_port = int(os.environ.get("SMTP_PORT", "587"))
        smtp_user = os.environ.get("SMTP_USER", "")
        smtp_pass = os.environ.get("SMTP_PASS", "")
        smtp_from = os.environ.get("SMTP_FROM", smtp_user)
        smtp_to = os.environ.get("SMTP_TO", "")

        if not all([smtp_user, smtp_pass, smtp_to]):
            logger.warning("Email not configured, skipping email notification")
            return

        severity = payload.severity_summary
        repo = payload.repository or f"{payload.owner}/{payload.repo}"

        msg = MIMEMultipart("alternative")
        msg["Subject"] = (
            f"[CRITICAL] Pynagent: {severity['critical']} critical finding(s) in {repo}"
            f"{f' PR #{payload.pr_number}' if payload.pr_number else ''}"
        )
        msg["From"] = smtp_from
        msg["To"] = smtp_to

        critical_high = [f for f in payload.findings if f.severity in ("critical", "high")]

        text_body = f"""
Pynagent Security Scan Alert
==========================

Repository: {repo}
{f'PR #{payload.pr_number}: {payload.pr_title}' if payload.pr_number else ''}
Branch: {payload.branch or 'N/A'}
Scanned: {payload.timestamp}

Severity Summary:
  Critical: {severity.get('critical', 0)}
  High: {severity.get('high', 0)}
  Medium: {severity.get('medium', 0)}
  Low: {severity.get('low', 0)}

Critical/High Findings ({len(critical_high)}):
{chr(10).join(f'  - {f.rule_id}: {f.message[:80]}' for f in critical_high[:10])}

Duration: {payload.duration:.1f}s

---
Pynagent AI Security Bot powered by AMD Cloud (Qwen/Llama)
        """.strip()

        html_body = f"""
        <html><body>
        <h2>Pynagent Security Scan Alert</h2>
        <table>
        <tr><td><strong>Repository</strong></td><td>{repo}</td></tr>
        {f'<tr><td><strong>PR</strong></td><td>#{payload.pr_number}: {payload.pr_title}</td></tr>' if payload.pr_number else ''}
        <tr><td><strong>Branch</strong></td><td>{payload.branch or 'N/A'}</td></tr>
        <tr><td><strong>Scanned</strong></td><td>{payload.timestamp}</td></tr>
        </table>

        <h3>Severity Summary</h3>
        <ul>
        <li style="color:red"><strong>Critical: {severity.get('critical', 0)}</strong></li>
        <li style="color:orange">High: {severity.get('high', 0)}</li>
        <li style="color:#c8a800">Medium: {severity.get('medium', 0)}</li>
        <li style="color:#888">Low: {severity.get('low', 0)}</li>
        </ul>

        <h3>Critical/High Findings</h3>
        <ul>
        {''.join(f'<li><code>{f.rule_id}</code>: {f.message} <small>({f.file}:{f.line})</small></li>' for f in critical_high[:10])}
        </ul>

        <hr>
        <small>Pynagent AI Security Bot powered by AMD Cloud (Qwen/Llama)</small>
        </body></html>
        """

        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        try:
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.ehlo()
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
            logger.info("Email notification sent to %s", smtp_to)
        except Exception as e:
            logger.error("Failed to send email: %s", e)
            raise

    async def _send_webhook(self, channel: NotificationChannel, event: WebhookEvent) -> None:
        """Forward event to a generic webhook."""
        if aiohttp is None:
            logger.warning("aiohttp not installed, skipping webhook notification")
            return

        data = {
            "event": event.event_type,
            "timestamp": event.timestamp,
            "payload": event.payload,
        }

        async with aiohttp.ClientSession() as session:
            await session.post(
                channel.url,
                json=data,
                timeout=aiohttp.ClientTimeout(total=10),
            )

    def get_stats(self) -> BotStats:
        """Get current bot statistics."""
        return BotStats(
            total_scans=self.total_scans,
            total_findings=self.total_findings,
            critical_findings=self.critical_findings,
            high_findings=self.high_findings,
            notifications_sent=self.notifications_sent,
            notifications_failed=self.notifications_failed,
            channels_configured=list(self._channels.keys()),
            uptime_seconds=time.time() - self.started_at,
            last_scan_at=datetime.fromtimestamp(
                self.started_at + (time.time() - self.started_at)
            ).isoformat() if self.total_scans > 0 else None,
        )


# ---------------------------------------------------------------------------
# FastAPI app factory
# ---------------------------------------------------------------------------

def create_app() -> Optional[Any]:
    """Create the FastAPI app for the bot notification server."""
    if not HAS_FASTAPI:
        logger.warning("FastAPI not installed. Run: pip install fastapi uvicorn")
        return None

    app = FastAPI(
        title="Pynagent Bot Notification Server",
        description="Webhook server for Pynagent GitHub App bot notifications",
        version="1.0.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    server = BotNotificationServer()

    @app.post("/bot/scan-result", response_model=Dict[str, Any])
    async def handle_scan_result(
        request: Request,
        payload: ScanResultPayload,
    ):
        """Receive scan results from the GitHub App and send notifications."""
        client_ip = request.client.host if request.client else "unknown"

        if not server.check_rate_limit(client_ip):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        # Verify signature
        body = await request.body()
        signature = request.headers.get("x-Pynagent-signature", "")
        if signature and not server.verify_signature(body, signature):
            raise HTTPException(status_code=401, detail="Invalid signature")

        results = await server.handle_scan_result(payload)
        return results

    @app.post("/bot/notify", response_model=Dict[str, Any])
    async def send_notification(
        request: Request,
        body: NotifyRequest,
    ):
        """Manually trigger a notification."""
        client_ip = request.client.host if request.client else "unknown"

        if not server.check_rate_limit(client_ip):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        # Build a minimal payload for the notification
        payload = ScanResultPayload(
            scan_id=f"manual-{int(time.time())}",
            target="manual-trigger",
            findings_count=0,
            findings=[],
            severity_summary={"all": 0},
            duration=0.0,
            timestamp=datetime.now().isoformat(),
            repository=os.environ.get("GITHUB_REPOSITORY", "unknown"),
        )

        results = await server.handle_scan_result(payload)
        return results

    @app.get("/bot/status", response_model=Dict[str, Any])
    async def get_status():
        """Get bot status and channel health."""
        stats = server.get_stats()
        return {
            "status": "healthy",
            "channels": {
                ch_type: {"enabled": ch.enabled, "url_set": bool(ch.url)}
                for ch_type, ch in server._channels.items()
            },
            "stats": asdict(stats),
        }

    @app.get("/bot/stats", response_model=Dict[str, Any])
    async def get_stats():
        """Get detailed bot statistics."""
        return asdict(server.get_stats())

    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {"status": "healthy", "service": "Pynagent-bot"}

    @app.get("/metrics")
    async def metrics():
        """Prometheus-compatible metrics endpoint."""
        stats = server.get_stats()
        lines = [
            f'# HELP Pynagent_bot_scans_total Total number of scans',
            f'# TYPE Pynagent_bot_scans_total counter',
            f'Pynagent_bot_scans_total {stats.total_scans}',
            f'# HELP Pynagent_bot_findings_total Total number of findings',
            f'# TYPE Pynagent_bot_findings_total counter',
            f'Pynagent_bot_findings_total {stats.total_findings}',
            f'# HELP Pynagent_bot_notifications_sent_total Total notifications sent',
            f'# TYPE Pynagent_bot_notifications_sent_total counter',
            f'Pynagent_bot_notifications_sent_total {stats.notifications_sent}',
            f'# HELP Pynagent_bot_notifications_failed_total Total notification failures',
            f'# TYPE Pynagent_bot_notifications_failed_total counter',
            f'Pynagent_bot_notifications_failed_total {stats.notifications_failed}',
        ]
        return Response(content="\n".join(lines), media_type="text/plain")

    return app


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------

def run_server(host: str = "0.0.0.0", port: int = 8080) -> None:
    """Run the bot notification server with uvicorn."""
    app = create_app()
    if app is None:
        print("FastAPI not available. Run: pip install fastapi uvicorn aiohttp")
        return

    try:
        import uvicorn
        uvicorn.run(app, host=host, port=port, log_level="info")
    except ImportError:
        print("uvicorn not available. Run: pip install uvicorn")
        print(f"Alternatively, run directly: uvicorn {__name__}:create_app --factory --host {host} --port {port}")


if __name__ == "__main__":
    run_server()
