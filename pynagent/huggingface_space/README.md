---
title: Pynagent AI Security Bot
emoji: ":shield:"
colorFrom: blue
colorTo: red
sdk: gradio
sdk_version: 4.44.0
app_file: app.py
pinned: false
library_name: gradio
license: agpl-3.0
short_description: AI-powered GitHub security bot using Pynagent SAST scanner + AMD Cloud AI (Qwen/Llama)
---

# Pynagent AI Security Bot

AI-powered GitHub App for automated security code review, powered by **Pynagent** (Rust SAST scanner) and **Qwen/Llama on AMD Cloud**.

[Live Demo](https://huggingface.co/spaces/Pynagent/Pynagent-security-bot) · [GitHub](https://github.com/Pynagent/Pynagent) · [Docs](https://Pynagent.dev)

## Features

- **SAST Scanning** — Multi-language security scanning (Python, JavaScript, TypeScript, Go, Java, Rust, Ruby, PHP)
- **AI False Positive Reduction** — Uses AMD Cloud (Qwen/Llama) to determine if findings are real vulnerabilities
- **PR Comments** — Posts detailed findings with CWE/OWASP/CVSS mapping, auto-fix suggestions
- **GitHub Checks API** — Creates status checks with pass/fail blocking
- **SARIF Upload** — Uploads to GitHub Code Scanning for Security tab integration
- **Notifications** — Slack, Discord, and Email alerts for critical findings
- **LangChain MCP Tools** — Available as MCP tools for AI agent integration

## Quick Start

```python
from Pynagent.agentic import create_agent

agent = create_agent(
    Pynagent_cli=Pynagent_cli,
    amd_config=amd_config,
)
result = await agent.run(pr_context)
```

## Architecture

```
GitHub PR → Probot → BullMQ → Pynagent (Rust) → AMD Cloud AI → GitHub Comment/Check
```

## License

GNU AGPL v3
