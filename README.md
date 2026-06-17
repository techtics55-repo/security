# Aegis — AI Security & Governance Layer

**Monitor. Verify. Protect.**

Aegis is a deterministic (zero-AI) security monitoring and governance platform for AI applications, agents, and workflows. It sits between users and AI providers, inspecting every request and response for security threats, policy violations, and data leakage.

## What Aegis Does

- **Prompt Injection Detection** — Identifies jailbreak attempts, DAN attacks, hidden instructions, and encoding-based evasion
- **PII & Secret Leakage Detection** — Scans prompts and responses for emails, phones, SSNs, API keys, passwords, credit cards
- **Malicious Code Detection** — Flags dangerous code in AI outputs: file operations, network calls, exec/eval, crypto miners
- **Data Flow Tracking** — Maps where user data is sent: endpoints, headers, payload inspection
- **Agent & Workflow Detection** — Identifies autonomous AI agents, automation pipelines, and multi-step action sequences
- **Policy Enforcement** — Define rules per agent/application. Actions outside scope are blocked and alerted
- **Audit Logging** — Immutable, encrypted log of all AI interactions for compliance and forensics

## Why No AI?

Every scanner in Aegis is **deterministic** — regex, entropy analysis, pattern matching, structural validation. This means:

- **No GPU required** — runs on any machine
- **No API costs** — zero recurring per-request fees
- **Auditable** — every decision can be explained and verified
- **Low latency** — milliseconds per check
- **Privacy-preserving** — no data sent to third-party AI for analysis

## Architecture

```
[User/AI App/Agent] → [Aegis Local Agent] → [AI Provider API]
                             │
                    ┌────────┴────────┐
                    │  Scanner Engine │ (deterministic rules)
                    │  Policy Engine  │ (per-agent policies)
                    │  Audit Store    │ (encrypted SQLite)
                    └────────┬────────┘
                             │ (optional sync)
                    ┌────────┴────────┐
                    │  Aegis Cloud    │ (SaaS dashboard)
                    │  FastAPI + SQL  │
                    └─────────────────┘
```

## Quick Start

```bash
# Install
pip install -r requirements.txt

# Start the monitoring agent
python -m agent.cli start --port 8080

# Configure your AI app to use the proxy
# export OPENAI_BASE_URL=http://localhost:8080/v1

# View real-time alerts
python -m agent.cli monitor

# View audit logs
python -m agent.cli logs --tail 50
```

## License

Proprietary — All rights reserved.
