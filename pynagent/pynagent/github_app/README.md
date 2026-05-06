# Pynagent AI Security Agent Bot

**AI-powered GitHub App for automated security code review, powered by Pynagent (Rust SAST) and Qwen/Llama on AMD Cloud.**

Built for the **AMD Developer Hackathon** — Track 1: AI Agents & Agentic Workflows.

---

## What it does

The Pynagent AI Security Bot automatically scans every pull request for security vulnerabilities, uses AMD Cloud AI (Qwen/Llama) to reduce false positives, and posts detailed findings directly on the PR with CWE/OWASP/CVSS mappings, auto-fix suggestions, and AI-generated explanations.

---

## Architecture

```
GitHub PR Event (webhook)
    │
    ▼
GitHub App (Probot/Node.js)
    │
    ▼
Job Queue (BullMQ/Redis)
    │
    ├──────────────────────────────┐
    ▼                              ▼
Pynagent Scanner (Rust SAST)    AMD Cloud AI (Qwen/Llama)
    │                              │
    │                              │
    └──────────┬───────────────────┘
               ▼
         Finding Analysis
               │
    ┌──────────┼──────────┐
    ▼          ▼          ▼
PR Comment  Check Run  SARIF Upload
    │          │          │
    └──────────┴──────────┘
               │
         GitHub PR Status
               │
    ┌──────────┴──────────┐
    ▼          ▼          ▼
  Slack     Discord      Email
```

---

## Features

| Feature | Description |
|---------|-------------|
| **Multi-language SAST** | Python, JavaScript, TypeScript, Go, Java, Rust, Ruby, PHP |
| **AI Analysis** | AMD Cloud Qwen/Llama for false positive reduction |
| **PR Comments** | Detailed inline findings with fix suggestions |
| **GitHub Checks API** | Pass/fail status checks with summary |
| **SARIF Upload** | Results appear in GitHub Security tab |
| **Notifications** | Slack, Discord, Email for critical issues |
| **LangChain MCP** | Available as MCP tools for AI agent integration |
| **Auto-fix** | Automatic fix suggestions for supported rules |

---

## Quick Start

### 1. Create the GitHub App

1. Go to GitHub → Settings → Developer Settings → GitHub Apps → **New GitHub App**
2. Fill in the details using the manifest in `Pynagent-rs/Pynagent/github_app/app.yml`
3. Generate a private key (download the PEM file)
4. Note your **App ID**

Or use the manifest directly:
```bash
# Import the manifest
curl -X POST https://github.com/settings/apps/new?yaml=1 \
  -H "Accept: application/vnd.github+json" \
  -d @Pynagent-rs/Pynagent/github_app/app.yml
```

### 2. Deploy the server

**Option A: Render (free tier)**
```bash
cd Pynagent-rs/Pynagent/github_app
npm install
cp .env.example .env
# Edit .env with your credentials
npm start
```

**Option B: Fly.io**
```bash
cd Pynagent-rs/Pynagent/github_app
fly launch
fly deploy
```

**Option C: Railway**
```bash
cd Pynagent-rs/Pynagent/github_app
railway init
railway up
```

### 3. Configure environment

```bash
# Required
APP_ID=123456
WEBHOOK_SECRET=your_random_secret_here
PRIVATE_KEY_PATH=./private-key.pem

# AMD Cloud (for AI analysis)
AMD_API_KEY=your_amd_api_key
AMD_API_URL=https://api.amd.com/v1
AMD_MODEL=qwen-2.5-72b-instruct

# Optional
REDIS_URL=redis://localhost:6379
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
SMTP_HOST=smtp.gmail.com
```

### 4. Point GitHub App to your server

In your GitHub App settings, set the **Webhook URL** to your server (e.g., `https://your-server.com/event-handler`).

### 5. Install the app

Install the GitHub App on your repositories from the GitHub Apps settings page.

---

## Project Structure

```
Pynagent-rs/
├── Pynagent/
│   ├── github_app/           # GitHub App (Probot + Node.js)
│   │   ├── index.js          # Probot entry point
│   │   ├── handlers.js       # Webhook event handlers
│   │   ├── github_helpers.js # PR comments, reviews, checks
│   │   ├── Pynagent_wrapper.py # Python subprocess wrapper
│   │   ├── queue.js          # BullMQ job queue
│   │   ├── logger.js         # Winston logging
│   │   ├── diff_utils.js     # Diff parsing utilities
│   │   ├── app.yml           # GitHub App manifest
│   │   ├── package.json
│   │   └── .env.example
│   │
│   ├── agentic/              # AI Agent (Python)
│   │   ├── agent.py          # Main LangChain agent
│   │   ├── langchain_tools.py # MCP tools as LangChain tools
│   │   └── __init__.py
│   │
│   └── tools/
│       ├── mcp_server.py     # MCP server (existing, re-used)
│       └── bot_notification_server.py  # FastAPI notification server
│
└── huggingface_space/        # HF Space demo
    ├── app.py                # Gradio app
    └── README.md
```

---

## How it works

### PR Scan Flow

1. **Webhook received** — Probot receives `pull_request.opened` or `pull_request.synchronize`
2. **Job queued** — Job added to BullMQ for async processing
3. **Pynagent scan** — Changed files scanned by Pynagent (Rust SAST)
4. **AI analysis** — AMD Cloud Qwen/Llama analyzes high/critical findings
5. **Results posted** — PR comment, check run, and SARIF upload created

### AI False Positive Reduction

The agent analyzes each finding using:
- The code snippet itself
- Surrounding context code
- How the code is used in the PR

And outputs:
- **TRUE_POSITIVE** — Genuine vulnerability
- **FALSE_POSITIVE** — Not exploitable in this context
- **NEEDS_MANUAL_REVIEW** — Ambiguous, human review required

---

## Using the AI Agent

```python
from Pynagent.agentic import create_agent, PRContext
from Pynagent.github_app.Pynagent_wrapper import create_Pynagent_cli
from Pynagent.agentic.agent import AMDCloudConfig

# Configure AMD Cloud
amd_config = AMDCloudConfig.from_env()

# Create agent
agent = create_agent(
    Pynagent_cli=create_Pynagent_cli(),
    amd_config=amd_config,
)

# Run on a PR
pr_context = PRContext(
    owner="myorg",
    repo="myrepo",
    pr_number=42,
    title="Add user API",
    description="...",
    author="developer",
    base_branch="main",
    head_branch="feat/user-api",
    head_sha="abc123",
)

result = await agent.run(pr_context)

print(f"Found {result['total_findings']} findings")
print(f"True positives: {result['true_positives']}")
print(f"False positives: {result['false_positives']}")
```

---

## Using MCP Tools in Cursor

Add to your `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "Pynagent": {
      "command": "python",
      "args": ["-m", "Pynagent.tools.mcp_server"]
    }
  }
}
```

Then use the tools in any Cursor chat:
- `Pynagent_scan` — scan code for security issues
- `Pynagent_explain` — get rule metadata (CWE, OWASP, CVSS)
- `Pynagent_auto_fix` — apply auto-fix for a finding
- `analyze_context` — AI-analyze a finding using AMD Cloud

---

## AMD Cloud Setup

1. Sign up at [AMD Developer Cloud](https://developer.amd.com/)
2. Generate an API key
3. Choose a model: **Qwen-2.5-72B-Instruct** or **Llama-3.3-70B-Instruct**
4. Set environment variables:

```bash
export AMD_API_KEY=your_key_here
export AMD_API_URL=https://api.amd.com/v1
export AMD_MODEL=qwen-2.5-72b-instruct
```

---

## Screenshots

### PR Comment with AI Analysis

> **🔴 CRITICAL: SQL Injection** at `app/routes.py:42`
>
> User-controlled input is passed to an SQL query without parameterization
>
> **CWE-89** · **OWASP A03** · **CVSS 9.8**
>
> ```python
> cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
> ```
>
> 🤖 AI Analysis: **TRUE POSITIVE** — This query is directly exposed to user input via the `user_id` parameter without any sanitization. An attacker could inject SQL to extract, modify, or delete database records.
>
> **Fix**: Use parameterized queries: `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))`

### GitHub Check Run

```
Pynagent Scan — 5 Findings
🚨 2 critical · 🟠 1 high · 🟡 1 medium · ⚪ 1 info

View all findings in GitHub Code Scanning →
```

---

## Hackathon Submission

- **Public GitHub repo**: ✅ (this repo)
- **HF Space**: https://huggingface.co/spaces/Pynagent/Pynagent-security-bot
- **GitHub App manifest**: `Pynagent-rs/Pynagent/github_app/app.yml`
- **LangChain agent**: `Pynagent-rs/Pynagent/agentic/agent.py`
- **AMD Cloud integration**: `Pynagent-rs/Pynagent/agentic/agent.py` (AMDCloudLLM class)
- **Demo video**: Recording in progress

---

## License

GNU AGPL v3 — see [LICENSE](LICENSE)

---

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
