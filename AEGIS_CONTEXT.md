# Aegis — AI Security & Governance Platform
## Comprehensive Context Document

---

## 1. What We Have Built So Far

### Overview
Aegis is a **deterministic (zero-AI) security monitoring and governance platform** for AI applications, agents, and workflows. It sits between users and AI providers, inspecting every request and response for security threats, policy violations, and data leakage. All scanners use regex, entropy analysis, pattern matching, and structural validation — no GPU required, no API costs, auditable, low latency, and privacy-preserving.

### Complete Architecture

```
[User / AI App / Agent] ──→ [Aegis Local Agent / Proxy] ──→ [AI Provider API]
                                     │
                            ┌────────┴────────┐
                            │  Scanner Engine  │  11 deterministic scanners
                            │  Policy Engine   │  per-agent policies
                            │  Audit Store     │  encrypted SQLite
                            └────────┬────────┘
                                     │ (optional sync)
                            ┌────────┴────────┐
                            │  Aegis Cloud     │  SaaS dashboard
                            │  FastAPI + SQL   │  web console, auth, billing
                            └─────────────────┘
                                     │
                            ┌────────┴────────┐
                            │  Desktop Agent   │  native app (Windows/macOS/Linux)
                            │  System tray     │  webview dashboard, background service
                            └─────────────────┘
```

### Codebase Structure

| Directory | Purpose |
|---|---|
| `agent/` | Local Python agent — proxy server, 11 scanners, policy engine, audit store, CLI |
| `agent/scanners/` | 13 scanner modules (injection, PII, code, data flow, behavior, response safety, hallucination, thinking monitor, vibe-code, VPI, black box ledger, autonomous escrow + base) |
| `agent/detectors/` | Detection helpers for agent behavior analysis |
| `agent/policies/` | Policy engine — defines rules per agent, evaluates compliance |
| `backend/` | FastAPI cloud backend — auth, billing, logs, agents, scanner features, downloads, TaaS endpoints |
| `backend/routes/` | 7 route modules (auth, logs, agents, billing, scanner_features, downloads, plus TaaS sub-routes) |
| `backend/middleware/` | JWT auth middleware |
| `static/` | Web frontend — `index.html` (landing/login), `app.html` (full dashboard) |
| `rules/` | 7 JSON rule files — injection patterns, PII patterns, dangerous code, agent behavior, data endpoints, thinking patterns, vulnerability patterns |
| `agent_app/` | Native desktop application — service manager, system tray, webview UI, CLI, PyInstaller build |
| `scripts/` | Build scripts — Windows (.bat), macOS (.sh), Linux (.sh), Inno Setup installer, zipapp builder |
| `dist/` | Built executables — `AegisAgent.exe` (~40MB) |
| `downloads/` | Download artifacts — `aegis-agent-x86_64.exe`, `aegis-cli.pyz` |
| `tests/` | Scanner test suite |

### Completed Features

**Scanners (11 total):**
1. **Prompt Injection Detection** — Jailbreak detection, DAN attacks, hidden instructions, encoding-based evasion, multilingual attacks
2. **PII & Secrets Scan** — Emails, phones, SSNs, API keys (OpenAI, AWS, Stripe, GitHub), passwords, credit cards, connection strings
3. **Malicious Code Detection** — File operations, network calls, exec/eval, crypto miners, reverse shells, dangerous system commands across 10+ languages
4. **Data Flow Mapping** — Maps data destinations, inspects endpoints, headers, payloads, flags suspicious domains and high-risk TLDs
5. **Rogue Agent Detection** — Detects LangChain, AutoGen, CrewAI agents, automation pipelines, rapid sequential calls, tool abuse
6. **Policy Enforcement Engine** — Define rules per agent using equals, contains, regex, range checks. Violations blocked and alerted instantly
7. **Hallucination Detection** — Detects factual inaccuracies, fabricated citations, hallucinated data, statistical anomalies in AI responses
8. **Response Safety Analysis** — Analyzes AI responses for toxicity, hate speech, dangerous instructions, self-harm content, policy violations
9. **AI Thinking Monitor** — Inspects chain-of-thought reasoning for unethical rationalization, manipulation, hidden backend instructions
10. **Vibe-Code Security Scanner** — Scans AI-generated code for SQLi, XSS, command injection, SSRF, hardcoded secrets, insecure crypto, path traversal
11. **Oracle Node — TaaS** (3-layer protocol):
    - **Layer A — VPI (Verified Persona Identity):** ECDSA identity certificates + encrypted instruction mandates, proof creation and verification, cryptographically verifiable that AI outputs comply with human instructions
    - **Layer B — Black Box Ledger:** SHA3-256 PoW chain-of-thought recording, encrypted payloads, AI TRiSM metadata (transparency, risk assessment, security controls, model governance, compliance), tamper-evident audit trail
    - **Layer C — Autonomous Escrow:** Smart-contract-like financial buffer between humans and AI agents, 11-state FSM (draft → funding → funded → locked → in_progress → verifying → released/disputed/refunded), Oracle commission model, arbitration support

**Backend API (FastAPI):**
- Authentication: Email/password register/login + Google OAuth (client ID: `600604731878-86okrr6barhl3oivft08qp03gpdha72t.apps.googleusercontent.com`)
- JWT bearer token middleware
- Scan log ingestion, listing, stats
- Agent registration, verification, listing
- Billing plans, upgrade, subscription management
- 20+ TaaS endpoints (VPI certificates, mandates, proofs, verification; Ledger trails, sealing, verification, custody reports; Escrow CRUD, funding, locking, completion, disputes, arbitration, refunds)
- Download endpoint serving built artifacts (`/downloads/{platform}`)
- Static file serving for web dashboard

**Frontend (Web Dashboard):**
- Landing page (`index.html`) with login/signup, Google OAuth, feature showcase
- Full dashboard (`app.html`) with navigation: Dashboard, Scanners, Billing, Docs, Settings, Help, Cookies Policy
- Real-time stats display, scan log viewer, agent management
- Billing page with 3 plan cards, scanner comparison table, live upgrade
- Download page with platform detection, real binary download via `/downloads/`

**Desktop Agent (`agent_app/`):**
- Backend service manager — auto-starts FastAPI on a free port, logs to `~/.aegis/agent.log`
- Cross-platform system tray (pystray) — show/hide window, enable/disable security, open dashboard, quit
- Native webview window (pywebview) — wraps the dashboard as a desktop app, falls back to browser
- CLI interface — `start|stop|status|enable|disable`
- Windows installer (Inno Setup `.iss`) — installs to Program Files, adds to Start Menu, auto-start with Windows
- PyInstaller `.exe` build (~40MB, x86_64)

**Build Artifacts:**
- `dist/AegisAgent.exe` — Windows portable executable
- `downloads/aegis-agent-x86_64.exe` — served by download endpoint
- `downloads/aegis-cli.pyz` — cross-platform CLI zipapp
- Inno Setup installer script for Windows

---

## 2. What We Are Building (Current Sprint)

### Desktop Application Reliability
- Ensuring the downloaded `.exe` runs correctly on end-user machines
- Proper error handling, logging, and fallback mechanisms
- The `.exe` starts the backend, opens a webview window, and shows a system tray icon
- Fixing any "not compatible with your system" errors caused by placeholder fallbacks

### Billing & Pricing Consolidation
Current plan structure (tiered scanner lists):

| Plan | Price (INR) | Requests/Day | Scanners Included |
|---|---|---|---|
| **Starter** | ₹99 | 150 | Prompt Injection, PII & Secrets, Malicious Code, Data Flow, Rogue Agents (5) |
| **Medium** | ₹499 | 1,000 | Starter's 5 + Policy Enforcement, Hallucination Detection, Response Safety (8) |
| **Ultimate** | ₹2,199 | 10,000 | All 11 scanners |

- Backend `/billing/upgrade` and `/billing/subscription` endpoints are functional
- Frontend has plan cards with per-plan scanner lists and a comparison table
- Live upgrade via fetch POST to backend

### Cross-Platform Builds
- Windows: PyInstaller `.exe` + Inno Setup installer — **done**
- macOS: Build script ready (`build_macos.sh`), needs to be run on macOS
- Linux: Build script ready (`build_linux.sh`), needs to be run on Linux

---

## 3. What We Will Build (Future Plans)

### 1. Stable Desktop Application
- Full Windows installer (MSI) for enterprise distribution
- Code signing for Windows (remove SmartScreen warnings)
- macOS `.dmg` with notarization
- Linux `.deb` + `.AppImage`
- Auto-update mechanism (check for new versions, download and install)
- Background service mode (Windows Service / systemd / launchd)
- Startup registration (already in Inno Setup script)

### 2. Enhanced Scanner Capabilities
- Real-time scanning dashboard showing live threat detections
- Scanner performance metrics and benchmarking
- Custom scanner plugin API — users write their own scanners
- AI model-specific optimizations (GPT, Claude, Gemini, Llama)

### 3. Cloud SaaS Platform
- Multi-tenant cloud dashboard
- Team management and role-based access control
- Usage analytics and billing reports
- Webhook integrations (Slack, Discord, PagerDuty, email)
- API key management with rate limiting

### 4. TaaS (Trust as a Service) Production Readiness
- Smart contract deployment (Ethereum/Solana) for escrow settlements
- Decentralized identity verification via blockchain
- Verifiable computation proofs for AI reasoning chains
- Oracle Node network — distributed verification

### 5. Enterprise Features
- SSO / SAML authentication
- SOC 2 / ISO 27001 compliance reporting
- Data residency controls
- Audit log export (JSON, CSV, Splunk, ELK)
- Role-based access control with granular permissions

### 6. Agent Ecosystem
- npm/PyPI packages for direct integration
- SDK for popular frameworks (LangChain, AutoGen, CrewAI, Vercel AI SDK)
- API gateway integration (Kong, Apigee, Envoy)
- Kubernetes sidecar deployment

### 7. Mobile Companion App
- Real-time push notifications for threats
- Quick enable/disable toggle
- Scan log browsing

---

## 4. What Is in the Software (Complete Feature Inventory)

### Scanner Engine (11 Scanners)
| # | Scanner | Detection Method | What It Catches |
|---|---|---|---|
| 1 | Prompt Injection | Regex patterns, encoding detection, multilingual analysis | Jailbreaks, DAN attacks, hidden instructions, base64/hex evasion |
| 2 | PII & Secrets | Regex + entropy analysis | Emails, phones, SSNs, API keys (OpenAI, AWS, Stripe, GitHub), passwords, credit cards, connection strings |
| 3 | Malicious Code | AST pattern matching + regex | File I/O, network calls, eval/exec, crypto miners, reverse shells, dangerous commands (Python, JS, Bash, PowerShell, etc.) |
| 4 | Data Flow | URL/endpoint inspection, header analysis | Suspicious domains, high-risk TLDs, unauthorized data destinations |
| 5 | Rogue Agents | Behavioral pattern analysis | Automated agent frameworks, rapid sequential calls, tool abuse, automation pipelines |
| 6 | Policy Enforcement | Rule engine (equals/contains/regex/range) | Per-agent policy violations, out-of-scope actions |
| 7 | Hallucination | Statistical analysis, citation verification | Fabricated facts, fake citations, numerical inconsistencies |
| 8 | Response Safety | NLP pattern matching | Toxicity, hate speech, dangerous instructions, self-harm, policy violations |
| 9 | AI Thinking Monitor | Chain-of-thought inspection | Unethical rationalization, manipulation, hidden instructions in reasoning |
| 10 | Vibe-Code Security | Vulnerability pattern matching | SQLi, XSS, command injection, SSRF, hardcoded secrets, insecure crypto, path traversal |
| 11 | Oracle TaaS | Cryptographic protocols | ECDSA identity, SHA3-256 PoW ledger, smart-contract escrow |

### Backend API Endpoints
| Route | Method | Description |
|---|---|---|
| `/` | GET | Landing page (HTML) |
| `/app` | GET | Dashboard (HTML) |
| `/billing` | GET | Dashboard (HTML) |
| `/docs` | GET | Swagger UI |
| `/health` | GET | Health check |
| `/auth/register` | POST | Email/password registration |
| `/auth/login` | POST | Email/password login |
| `/auth/google/config` | GET | Google OAuth client ID |
| `/auth/google` | POST | Google OAuth login |
| `/auth/me` | GET | Current user profile |
| `/logs/ingest` | POST | Ingest scan log |
| `/logs/` | GET | List scan logs (filtered) |
| `/logs/stats` | GET | Scan statistics |
| `/agents/register` | POST | Register an AI agent |
| `/agents/verify` | POST | Verify agent action |
| `/agents/` | GET | List registered agents |
| `/billing/plans` | GET | List billing plans |
| `/billing/upgrade` | POST | Upgrade subscription |
| `/billing/subscription` | GET | Get current subscription |
| `/downloads/{platform}` | GET | Download built artifacts |
| `/taas/*` | * | 20+ TaaS endpoints (VPI, Ledger, Escrow) |

### Desktop Agent Features
- **Backend Launcher** — Starts FastAPI server on a free port, persists config to `~/.aegis/config.json`
- **System Tray** — Status display, show/hide window, enable/disable security, open dashboard in browser, quit
- **Webview Window** — Native OS webview showing the dashboard (falls back to browser if unavailable)
- **CLI** — `start`, `stop`, `status`, `enable`, `disable` commands
- **Logging** — All activity logged to `~/.aegis/agent.log`
- **Auto-start** — Registered via Inno Setup installer

### Data Models (SQLite)
- **User** — email, hashed password, plan, Google ID, Stripe customer ID, API key, request tracking
- **ScanLog** — timestamp, session_id, agent_id, scanner_name, passed, severity, message, details, prompt/response hashes
- **Agent** — agent_id, name, metadata, policies, active status
- **AuditEntry** — action, agent_id, session_id, details, verifier, policy_violation
- **Policy** — name, description, rules (JSON), action (block/alert), priority
- **Subscription** — user_id, plan, status, period start/end

### Build & Deployment
- **Development:** `uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000`
- **Windows Build:** `scripts/build_windows.bat` (PyInstaller + optional Inno Setup)
- **macOS Build:** `scripts/build_macos.sh` (py2app + DMG creation)
- **Linux Build:** `scripts/build_linux.sh` (PyInstaller)
- **CLI Zipapp:** `scripts/build_zipapp.py`
- **Agent Runtime Deps:** pystray, Pillow, pywebview, uvicorn, fastapi, sqlalchemy, python-jose, passlib, bcrypt, pydantic, google-auth
- **Server Deps:** fastapi, uvicorn, sqlalchemy, python-jose, passlib, python-multipart, pydantic, pydantic-settings, stripe, python-dotenv
- **Agent Deps:** requests, rich, cryptography, PyJWT, pyyaml, typer
