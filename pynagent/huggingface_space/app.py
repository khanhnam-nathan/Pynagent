# Hugging Face Space — Pynagent AI Security Bot Demo
#
# This Space demonstrates the Pynagent AI Security Bot capabilities:
# - Live code scanning
# - PR scan simulation
# - Bot activity feed
# - MCP tools demo
#
# To deploy your own HF Space:
#   1. Fork this repo to your GitHub account
# 2. Create a new HF Space at https://huggingface.co/new-space
# 3. Select "Gradio" as the SDK
# 4. Set the repo URL to your fork
# 5. The space will automatically build and deploy
#
# Space metadata is in README.md frontmatter above.
# The Gradio app is defined in app.py below.

import gradio as gr
import json
import time
import datetime
import uuid
from typing import List, Dict, Any, Optional

# ---------------------------------------------------------------------------
# Demo data
# ---------------------------------------------------------------------------

DEMO_FINDINGS = [
    {
        "rule_id": "sql_injection",
        "severity": "critical",
        "message": "User-controlled input is passed to an SQL query without parameterization",
        "file": "app/routes.py",
        "line": 42,
        "cwe_id": "CWE-89",
        "owasp_id": "A03",
        "cvss_score": 9.8,
        "marker_id": "PYN-SEC-0001",
        "auto_fix_available": True,
        "confidence": 0.95,
        "snippet": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    },
    {
        "rule_id": "hardcoded_secret",
        "severity": "high",
        "message": "Hardcoded AWS credentials detected in source code",
        "file": "config.py",
        "line": 15,
        "cwe_id": "CWE-798",
        "owasp_id": "A02",
        "cvss_score": 7.5,
        "marker_id": "PYN-SEC-0002",
        "auto_fix_available": True,
        "confidence": 1.0,
        "snippet": "AWS_SECRET_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
    },
    {
        "rule_id": "command_injection",
        "severity": "critical",
        "message": "User input flows into subprocess command without sanitization",
        "file": "utils/shell.py",
        "line": 28,
        "cwe_id": "CWE-78",
        "owasp_id": "A03",
        "cvss_score": 9.1,
        "marker_id": "PYN-SEC-0003",
        "auto_fix_available": False,
        "confidence": 0.88,
        "snippet": "subprocess.run(f'ping {hostname}', shell=True)",
    },
    {
        "rule_id": "xss_reflected",
        "severity": "medium",
        "message": "Unescaped user input rendered in HTML response",
        "file": "app/views.py",
        "line": 103,
        "cwe_id": "CWE-79",
        "owasp_id": "A03",
        "cvss_score": 6.1,
        "marker_id": "PYN-SEC-0004",
        "auto_fix_available": True,
        "confidence": 0.92,
        "snippet": "return f'<h1>Hello {name}</h1>'",
    },
    {
        "rule_id": "insecure_deserialization",
        "severity": "critical",
        "message": "Untrusted pickle data is deserialized without validation",
        "file": "api/parser.py",
        "line": 67,
        "cwe_id": "CWE-502",
        "owasp_id": "A08",
        "cvss_score": 9.3,
        "marker_id": "PYN-SEC-0005",
        "auto_fix_available": False,
        "confidence": 0.97,
        "snippet": "data = pickle.loads(request.body)",
    },
    {
        "rule_id": "unused_import",
        "severity": "info",
        "message": "Imported name 'json' is never used in this module",
        "file": "app/routes.py",
        "line": 3,
        "cwe_id": None,
        "owasp_id": None,
        "cvss_score": None,
        "marker_id": "PYN-QUAL-0001",
        "auto_fix_available": True,
        "confidence": 1.0,
        "snippet": "import json",
    },
]

DEMO_ACTIVITY = [
    {
        "event": "pr.opened",
        "repo": "example/webapp",
        "pr": 142,
        "findings": 5,
        "critical": 2,
        "high": 1,
        "time": "2 minutes ago",
    },
    {
        "event": "scan.completed",
        "repo": "acme/api-service",
        "pr": 89,
        "findings": 12,
        "critical": 0,
        "high": 3,
        "time": "15 minutes ago",
    },
    {
        "event": "pr.commented",
        "repo": "startup/ml-pipeline",
        "pr": 34,
        "findings": 8,
        "critical": 1,
        "high": 2,
        "time": "1 hour ago",
    },
    {
        "event": "check_run.completed",
        "repo": "corp/auth-service",
        "pr": 201,
        "findings": 3,
        "critical": 0,
        "high": 1,
        "time": "2 hours ago",
    },
]

DEMO_MCP_TOOLS = [
    {
        "name": "Pynagent_scan",
        "description": "Scan code for security vulnerabilities and quality issues",
        "parameters": ["code (string)", "language (string, default: python)"],
        "example": '{"code": "import pickle\\ndata = pickle.loads(user_input)", "language": "python"}',
    },
    {
        "name": "Pynagent_scan_file",
        "description": "Scan an entire file on disk for issues",
        "parameters": ["file_path (string)", "language (string, optional)"],
        "example": '{"file_path": "app/routes.py"}',
    },
    {
        "name": "Pynagent_explain",
        "description": "Get full rule metadata including CWE, OWASP, CVSS mapping",
        "parameters": ["rule_id (string)", "issue_type (string)"],
        "example": '{"issue_type": "sql_injection"}',
    },
    {
        "name": "Pynagent_auto_fix",
        "description": "Apply auto-fix for a specific security marker",
        "parameters": ["marker_id (string)", "code (string)", "language (string)", "dry_run (boolean)"],
        "example": '{"marker_id": "PYN-SEC-0001", "code": "...", "dry_run": true}',
    },
    {
        "name": "Pynagent_list_rules",
        "description": "List all available Pynagent rules",
        "parameters": [],
        "example": "{}",
    },
    {
        "name": "analyze_context",
        "description": "Use AMD Cloud AI to determine if a finding is a true positive",
        "parameters": ["pr_diff (string)", "finding_json (string)"],
        "example": '{"pr_diff": "...", "finding_json": "{\\"rule_id\\": \\"sql_injection\\"}"}',
    },
]


# ---------------------------------------------------------------------------
# UI Helpers
# ---------------------------------------------------------------------------

def severity_color(severity: str) -> str:
    return {
        "critical": "#FF1744",
        "high": "#FF6D00",
        "medium": "#FFD600",
        "low": "#2979FF",
        "info": "#9E9E9E",
    }.get(severity, "#9E9E9E")


def severity_emoji(severity: str) -> str:
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }.get(severity, "⚪")


def format_finding_card(f: Dict[str, Any]) -> str:
    emoji = severity_emoji(f["severity"])
    color = severity_color(f["severity"])

    tags = []
    if f.get("cwe_id"):
        tags.append(f"[{f['cwe_id']}](https://cwe.mitre.org/)")
    if f.get("owasp_id"):
        tags.append(f"[OWASP A{f['owasp_id']}](https://owasp.org/Top10/)")
    if f.get("cvss_score"):
        tags.append(f"CVSS {f['cvss_score']}")
    tags_str = " · ".join(tags)

    auto_fix = "🛠️ Auto-fix available" if f.get("auto_fix_available") else "Manual review required"

    return f"""
### {emoji} {f['marker_id']} — {f['rule_id'].replace('_', ' ').title()}

**Location**: `{f['file']}:{f['line']}`  **Severity**: {f['severity'].upper()}

{f['message']}

> {tags_str}

```python
{f['snippet']}
```

**Confidence**: {f.get('confidence', 1.0):.0%} · {auto_fix}
"""


def format_pr_comment(finding: Dict[str, Any]) -> str:
    emoji = severity_emoji(finding["severity"])
    color = severity_color(finding["severity"])

    tags = []
    if finding.get("cwe_id"):
        tags.append(f"**CWE:** [{finding['cwe_id']}](https://cwe.mitre.org/)")
    if finding.get("owasp_id"):
        tags.append(f"**OWASP:** A{finding['owasp_id']}")
    if finding.get("cvss_score"):
        tags.append(f"**CVSS:** {finding['cvss_score']}")
    tags_str = " · ".join(tags) if tags else ""

    return f"""{emoji} **`{finding['rule_id']}`** at `{finding['file']}:{finding['line']}`

{finding['message']}

{tags_str}

```python
{finding['snippet']}
```

> 🤖 Scanned by [Pynagent](https://github.com/Pynagent/Pynagent) v3.0 · AI analysis by AMD Cloud
"""


# ---------------------------------------------------------------------------
# Gradio UI
# ---------------------------------------------------------------------------

def build_demo_tab():
    """Demo tab — simulates PR scan with pre-loaded findings."""
    demo_findings_md = "\n\n---\n\n".join(format_finding_card(f) for f in DEMO_FINDINGS)

    severity_counts = {"critical": 2, "high": 1, "medium": 1, "low": 0, "info": 1}

    summary_md = f"""## Scan Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {severity_counts['critical']} |
| 🟠 High | {severity_counts['high']} |
| 🟡 Medium | {severity_counts['medium']} |
| 🔵 Low | {severity_counts['low']} |
| ⚪ Info | {severity_counts['info']} |

**Total: {len(DEMO_FINDINGS)} findings** in 3 files · Scanned in 1.2s
"""

    with gr.Row():
        with gr.Column(scale=2):
            gr.Markdown("## 🔍 Live Scan Simulation")
            code_input = gr.Code(
                label="Enter code to scan (or use the demo below)",
                language="python",
                value='''# Demo: vulnerable code snippet
import pickle
import subprocess

def fetch_user(user_id):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

def ping_host(hostname):
    # Command injection vulnerability
    subprocess.run(f"ping {hostname}", shell=True)

def load_data(user_input):
    # Insecure deserialization
    return pickle.loads(user_input)

# AWS credentials hardcoded
AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"

def render_user(name):
    # XSS vulnerability
    return f"<h1>Hello {name}</h1>"
''',
                lines=18,
            )
            scan_btn = gr.Button("🔒 Run Pynagent Scan", variant="primary")
            scan_btn.click(fn=lambda x: gr.update(visible=True), inputs=[code_input], outputs=[])

        with gr.Column(scale=3):
            gr.Markdown("## 🛡️ Demo: PR Scan Results")
            gr.Markdown(summary_md)
            gr.Markdown("## 📋 All Findings")
            gr.Markdown(demo_findings_md)

    return [code_input, scan_btn]


def build_pr_simulation_tab():
    """PR simulation tab — simulates a full PR scan."""
    with gr.Row():
        with gr.Column(scale=1):
            gr.Markdown("### PR Configuration")
            repo = gr.Textbox(label="Repository", value="example/webapp", interactive=True)
            pr_num = gr.Number(label="PR Number", value=142, interactive=True)
            pr_title = gr.Textbox(label="PR Title", value="feat: add user profile API endpoint", interactive=True)
            scan_btn = gr.Button("🔒 Simulate PR Scan", variant="primary")

        with gr.Column(scale=2):
            gr.Markdown("### 🤖 Bot Activity Feed")
            for activity in DEMO_ACTIVITY:
                emoji = {
                    "pr.opened": "🆕",
                    "scan.completed": "✅",
                    "pr.commented": "💬",
                    "check_run.completed": "🔍",
                }.get(activity["event"], "📋")

                verdict = "🚨 **BLOCKED**" if activity["critical"] > 0 else "✅ Passed"
                gr.Markdown(
                    f"{emoji} **{activity['event']}** on `{activity['repo']}` "
                    f"PR #{activity['pr']} — {activity['findings']} findings "
                    f"(🔴{activity['critical']} 🟠{activity['high']}) · {activity['time']}"
                )

            gr.Markdown("### 💬 Simulated PR Comment")
            comment = "\n\n---\n\n".join(format_pr_comment(f) for f in DEMO_FINDINGS[:3])
            gr.Markdown(comment)

    return [repo, pr_num, pr_title, scan_btn]


def build_mcp_tools_tab():
    """MCP tools tab — shows available MCP tools."""
    for tool in DEMO_MCP_TOOLS:
        params_str = "\n".join(f"- `{p}`" for p in tool["parameters"]) if tool["parameters"] else "*No parameters*"

        gr.Markdown(f"""
### `{tool['name']}`

**Description**: {tool['description']}

**Parameters**:
{params_str}

**Example Input**:
```json
{tool['example']}
```
""")

    gr.Markdown("""
### Using MCP Tools

These tools are available via the **Model Context Protocol (MCP)** over stdio.
Pynagent's MCP server can be invoked as:

```bash
# List all tools
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | python -m Pynagent.tools.mcp_server

# Scan code
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"Pynagent_scan","arguments":{"code":"import pickle\\ndata = pickle.loads(user_input)","language":"python"}}}' | python -m Pynagent.tools.mcp_server
```

In Cursor, configure the MCP server in `.cursor/mcp.json`:
```json
{{
  "mcpServers": {{
    "Pynagent": {{
      "command": "python",
      "args": ["-m", "Pynagent.tools.mcp_server"]
    }}
  }}
}}
```
""")


def build_architecture_tab():
    """Architecture tab — shows system diagram and components."""
    gr.Markdown("""
## System Architecture

```mermaid
flowchart TD
    A["GitHub PR Event (webhook)"] --> B["GitHub App (Probot/Node.js)"]
    B --> C["Job Queue (BullMQ/Redis)"]
    C --> D["Pynagent Scanner (Rust SAST)"]
    D --> E["AI Analysis (Qwen/Llama on AMD MI300X)"]
    E --> F{{"Finding Severity?"}}
    F -->|Critical/High| G["GitHub PR Comment (inline review)"]
    F -->|Critical| H["Slack/Email Alert"]
    G --> I["PR Status Check (pass/fail)"]
    H --> I
    D --> J["SARIF Upload (GitHub Code Scanning)"]
```

## Components

| Component | Technology | Purpose |
|-----------|-----------|---------|
| GitHub App | Probot (Node.js) | Receive webhook events |
| Scanner | Pynagent (Rust) | SAST vulnerability detection |
| AI Analysis | Qwen/Llama (AMD Cloud) | False positive reduction |
| Job Queue | BullMQ + Redis | Async scan processing |
| Notifications | FastAPI | Slack/Discord/Email alerts |
| Code Scanning | SARIF | GitHub Code Scanning integration |

## Tech Stack

- **Language**: Python 3.9+ + Rust (PyO3)
- **AI**: AMD Cloud (Qwen-2.5-72B / Llama-3.3-70B)
- **Framework**: LangChain + MCP
- **CI/CD**: GitHub Actions
- **Deploy**: Render / Railway / Fly.io
""")


def build_deployment_tab():
    """Deployment tab — setup instructions."""
    gr.Markdown("""
## Quick Start

### 1. Install the GitHub App

1. Go to **Settings → Developer settings → GitHub Apps → New GitHub App**
2. Fill in the details (see `app.yml` manifest)
3. Generate a private key and note the App ID
4. Install the app on your repositories

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your credentials
```

### 3. Deploy the Server

**Option A: Render (free tier)**
```bash
# Create a new Web Service on Render
# Connect your GitHub repo
# Set build command: npm install
# Set start command: probot run ./index.js
```

**Option B: Fly.io**
```bash
fly launch
fly deploy
```

**Option C: Railway**
```bash
railway init
railway up
```

### 4. Set Webhook URL

Point your GitHub App webhook to: `https://your-server.com/event-handler`

### 5. Configure AMD Cloud

Get your AMD Developer Cloud API key at https://developer.amd.com/

Set `AMD_API_KEY` in your environment.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `APP_ID` | Yes | GitHub App ID |
| `WEBHOOK_SECRET` | Yes | Random secret for webhook verification |
| `PRIVATE_KEY_PATH` | Yes | Path to private key PEM |
| `AMD_API_KEY` | Yes | AMD Cloud API key |
| `AMD_API_URL` | Yes | AMD Cloud endpoint |
| `REDIS_URL` | No | Redis URL for BullMQ |
| `SLACK_WEBHOOK_URL` | No | Slack webhook for notifications |
| `DISCORD_WEBHOOK_URL` | No | Discord webhook for notifications |

## Hackathon Submission Checklist

- [ ] Public GitHub repo
- [ ] HF Space running demo
- [ ] Video demo (3-5 minutes)
- [ ] GitHub App manifest (`app.yml`)
- [ ] Probot server deployed
- [ ] LangChain agent integrated
- [ ] Pynagent wrapper working
- [ ] Notification server configured
- [ ] Demo vulnerable repo
""")

    return []


# ---------------------------------------------------------------------------
# Main Gradio app
# ---------------------------------------------------------------------------

css = """
.gradio-container { max-width: 1400px !important; margin: auto; }
h1 { color: #2D7DD2; }
h2 { color: #1A1A2E; }
h3 { color: #16213E; }
footer { display: none !important; }
"""

with gr.Blocks(
    title="Pynagent AI Security Bot",
    theme=gr.themes.Soft(
        primary_hue="blue",
        secondary_hue="red",
    ),
    css=css,
) as demo:
    gr.Markdown("""
    # 🛡️ Pynagent AI Security Bot
    ### AI-powered code review bot powered by Pynagent + AMD Cloud

    ---

    This demo showcases the **Pynagent AI Security Agent Bot** — a GitHub App that:
    1. Scans pull requests for security vulnerabilities using Pynagent (Rust SAST)
    2. Analyzes findings with Qwen/Llama on AMD Cloud to reduce false positives
    3. Comments directly on PRs with detailed, AI-enriched explanations
    4. Posts status checks and uploads SARIF to GitHub Code Scanning
    5. Sends Slack/Discord/Email alerts for critical findings

    **Built for the AMD Developer Hackathon** — Track 1: AI Agents & Agentic Workflows
    """)

    with gr.Tabs():
        with gr.Tab("🔍 Live Scan Demo"):
            build_demo_tab()

        with gr.Tab("📊 PR Simulation"):
            build_pr_simulation_tab()

        with gr.Tab("🛠️ MCP Tools"):
            build_mcp_tools_tab()

        with gr.Tab("🏗️ Architecture"):
            build_architecture_tab()

        with gr.Tab("🚀 Deploy"):
            build_deployment_tab()

    gr.Markdown("""
    ---
    **Pynagent** · SAST Scanner · [GitHub](https://github.com/Pynagent/Pynagent) · [Documentation](https://Pynagent.dev)
    · Powered by AMD Cloud (Qwen/Llama) · [AMD Developer Hackathon 2026](https://developer.amd.com)
    """)

demo.launch(
    server_name="0.0.0.0",
    server_port=7860,
    share=True,
)
