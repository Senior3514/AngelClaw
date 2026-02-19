# AngelClaw V3.0.0 -- Autonomous AI Defense Guardian

**Guardian angel, not gatekeeper.**

> The Python package is named `angelgrid` for internal compatibility. The product name is **AngelClaw**.

AngelClaw is a security fabric that lets people use AI agents, local models,
cloud APIs, and automations **as freely as they want** -- while quietly protecting
their systems, data, and infrastructure in the background.

We don't block AI. We embrace it. AngelClaw only intervenes when AI is about to
do something genuinely dangerous: destructive shell commands, accessing secrets,
modifying critical files, or calling risky external endpoints. Everything else --
analysis, reading, summarizing, reasoning, creating -- flows freely.

---

## Installation

All installers **auto-install every dependency** (Docker, Git, Homebrew) -- zero prerequisites.
Prompts for GitHub username + PAT (Personal Access Token) on first run.
Full stack. Done.

### Linux

```bash
curl -fsSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_linux.sh | bash
```

Or with credentials pre-set (no prompts):

```bash
GH_USER="youruser" GH_TOKEN="ghp_xxxx" curl -fsSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_linux.sh | bash
```

Installs: Docker, docker compose, Git, clones repo, builds & starts ANGELNODE + Cloud + Ollama, creates systemd service.

### macOS

```bash
curl -fsSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_macos.sh | bash
```

Installs: Homebrew, Docker Desktop, Git, clones repo, builds & starts full stack.

### Windows (PowerShell as Admin)

```powershell
irm https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_windows.ps1 | iex
```

Or with credentials pre-set (no prompts):

```powershell
$env:GH_USER="youruser"; $env:GH_TOKEN="ghp_xxxx"; irm https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_windows.ps1 | iex
```

Installs: Git (via winget), Docker Desktop (via winget), clones repo, builds & starts full stack.

### Docker (all platforms)

```bash
git clone https://github.com/Senior3514/AngelClaw.git
cd AngelClaw/ops
docker compose up -d --build
```

### Manual Install (all platforms)

```bash
git clone https://github.com/Senior3514/AngelClaw.git
cd AngelClaw
python3 -m venv venv && source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e ".[cloud,dev]"
python3 -m uvicorn cloud.api.server:app --host 127.0.0.1 --port 8500
```

---

## Multi-Tenancy

AngelClaw is a **multi-tenant** system. Each ANGELNODE connects with a **Tenant ID** that isolates its data, policies, alerts, and analytics from other tenants.

### How it works

```
                 ┌─────────────────────────┐
                 │   AngelClaw Cloud        │
                 │   (single instance)      │
                 │                          │
                 │   Tenant: acme-corp      │
                 │   Tenant: startup-xyz    │
                 │   Tenant: dev-team       │
                 └──────────┬──────────────┘
          ┌─────────────────┼─────────────────┐
          ▼                 ▼                 ▼
    ┌──────────┐     ┌──────────┐     ┌──────────┐
    │ANGELNODE │     │ANGELNODE │     │ANGELNODE │
    │acme-corp │     │startup   │     │dev-team  │
    └──────────┘     └──────────┘     └──────────┘
```

### Set tenant during install

```bash
# Linux / macOS
ANGELCLAW_TENANT_ID="acme-corp" GH_USER="youruser" GH_TOKEN="ghp_xxxx" curl -fsSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_linux.sh | bash

# Windows (PowerShell as Admin)
$env:ANGELCLAW_TENANT_ID="acme-corp"; $env:GH_USER="youruser"; $env:GH_TOKEN="ghp_xxxx"; irm https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_windows.ps1 | iex
```

### Add tenants to a running system

Edit `ops/config/angelclaw.env` and set `ANGELCLAW_TENANT_ID`, then restart:

```bash
cd AngelClaw/ops && docker compose restart
```

Each tenant gets isolated: policies, events, alerts, analytics, feedback, and hardening data.

---

## Uninstall

| OS | Command |
|----|---------|
| **Linux** | `curl -fsSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/uninstall_angelclaw_linux.sh \| bash` |
| **macOS** | `curl -fsSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/uninstall_angelclaw_macos.sh \| bash` |
| **Windows** | PowerShell as Admin: `& "C:\AngelClaw\ops\install\uninstall_angelclaw_windows.ps1"` |
| **Docker** | `cd AngelClaw/ops && docker compose down -v` |

Set `ANGELCLAW_KEEP_DATA=true` (Linux/macOS) or `-KeepData` (Windows) to preserve data.

---

## Verify

```bash
curl http://127.0.0.1:8500/health
# {"status":"ok","version":"3.0.0",...}

python3 -m pytest tests/ -q
# 1848 passed
```

Dashboard: **http://127.0.0.1:8500/ui** -- Default login: `admin` / `fzMiSbDRGylsWrsaljMv7UxzrwdXCdTe` (change immediately!)

---

## What's New in V3.0.0 -- Dominion

### Admin Console & Organization Visibility
- Full org-wide dashboard with **Halo Score**, **Wingspan**, fleet status, alert counts
- Tenant management with per-tenant metrics and agent counts
- Per-agent detail views with event history, alerts, anti-tamper status
- Angel Legion warden status panel with performance metrics
- **10-page sidebar navigation**: Dashboard, Fleet, Tenants, Alerts, Legion, Anti-Tamper, Analytics, Self-Learning, Policies, Settings

### Anti-Tamper Protection
- Three modes: **OFF**, **MONITOR**, **ENFORCE**
- Per-agent and per-tenant configuration
- Heartbeat monitoring and binary checksum verification
- Tamper event logging with severity and resolution tracking

### Self-Learning Feedback Loop
- Operator accept/reject/ignore/modify tracking on suggestions
- Per-tenant acceptance rates and suggestion ranking
- Automatic adjustment recommendations (verbosity, thresholds, autonomy)

### Self-Hardening Engine
- Autonomous security weakness detection and correction
- Six check types: scan failures, loose allowlists, missing logs, weak auth, unprotected agents, repeated misconfigs
- Observe / suggest / auto_apply autonomy modes
- Every action logged with full explanation and **revertible**

### Multi-Platform Support
- **Responsive UI** -- complete admin console rewrite, mobile-friendly
- **PWA** -- manifest + service worker for iOS/Android home screen install
- **Browser Extension** -- Chrome/Chromium v3.0.0 with badge alerts, mini chat, quick actions
- **DuckDuckGo** -- desktop browser extension support + mobile web instructions

### Enterprise Features
- Adaptive rate limiter with per-role tiers
- WebSocket live feed for real-time events/alerts
- Policy snapshots & rollback
- Agent quarantine with timed release
- Notification channels (Slack, Discord, Webhook)
- Compliance warden (GDPR, HIPAA, PCI) + API warden
- Plugin system with dynamic loading
- API key authentication (SHA-256 hashed)
- Backup & restore, CSV/JSON data export
- Custom RBAC roles
- Event replay, threat hunting DSL, remediation workflows
- Agent mesh networking

### Stats

| Metric | Value |
|--------|-------|
| Tests | **1,848 passing** (0 failures) |
| NLP Intents | **71+** |
| API Endpoints | **50+** |
| DB Tables | **15+** |
| Wardens | **12** |
| Python Files | **1,868** |
| Total Files | **2,427** |

---

## Quick Reference

| What | URL / Command |
|------|---------------|
| Dashboard | `http://127.0.0.1:8500/ui` |
| Default login | `admin` / `fzMiSbDRGylsWrsaljMv7UxzrwdXCdTe` (change immediately!) |
| ANGELNODE health | `curl http://127.0.0.1:8400/health` |
| Cloud API health | `curl http://127.0.0.1:8500/health` |
| CLI status | `./ops/cli/angelclawctl status` |
| Chat with AngelClaw | `curl -X POST http://127.0.0.1:8500/api/v1/angelclaw/chat -H 'Content-Type: application/json' -d '{"tenantId":"default","prompt":"Scan the system"}'` |
| Remote access | `ssh -L 8500:127.0.0.1:8500 user@your-vps` |
| Run tests | `python3 -m pytest tests/ -q` |

---

## Mobile Access

| Platform | How |
|----------|-----|
| **iOS Safari** | Navigate to `https://host:8500/ui` > Share > Add to Home Screen (PWA) |
| **Android Chrome** | Navigate to `https://host:8500/ui` > Menu > Add to Home Screen (PWA) |
| **DuckDuckGo** | Navigate to `https://host:8500/ui` > Bookmark for quick access |
| **Any mobile browser** | `https://host:8500/ui` -- fully responsive, works on all devices |

## Browser Extensions

| Browser | Install |
|---------|---------|
| **Chrome / Edge / Brave / Opera / Arc** | `chrome://extensions/` > Developer mode > Load unpacked > select `extensions/chrome/` |
| **DuckDuckGo Desktop** | `duckduckgo://extensions/` > Developer mode > Load unpacked > select `extensions/chrome/` |
| **Firefox** | Requires minor manifest adaptation (see `extensions/README.md`) |

---

## Architecture

AngelClaw is a **3-tier architecture** with **12 specialized wardens**:

```
AngelClaw/
├── angelnode/             # Local agent (policy enforcement, port 8400)
│   ├── core/              #   PolicyEngine, evaluation API, cloud sync
│   ├── ai_shield/         #   AI agent adapters (OpenClaw, Claude Code)
│   └── config/            #   540-rule zero-trust bootstrap policy
├── cloud/                 # SaaS backend (orchestration, port 8500)
│   ├── angelclaw/         #   Brain (71+ intents), Shield, Daemon, Actions
│   ├── guardian/          #   Angel Legion: 12 wardens + orchestrator
│   ├── api/               #   20 route modules, 50+ REST endpoints
│   ├── services/          #   Anti-tamper, feedback, hardening, predictive, etc.
│   ├── auth/              #   JWT, API keys, custom RBAC
│   ├── middleware/        #   Rate limiter, CORS, security headers
│   ├── websocket/         #   Real-time event/alert feeds
│   ├── plugins/           #   Dynamic warden plugin loading
│   ├── db/                #   SQLAlchemy ORM (15+ tables)
│   └── ui/                #   Admin console (10-page SPA, PWA-ready)
├── shared/                # Pydantic models, secret scanner
├── mobile/                # PWA manifest + service worker
├── extensions/            # Chrome/DuckDuckGo browser extensions
├── plugins/               # Plugin examples
├── ops/                   # Installers, Docker, systemd, CLI
├── tests/                 # 1,848 tests (52 test files)
└── docs/                  # Architecture, changelog, install guides
```

### Angel Legion -- 12 Specialized Wardens

| Code Name | Type | Role |
|-----------|------|------|
| **Vigil** | Warden | Core threat detection (patterns, anomalies, correlation) |
| **Net Warden** | Network | Network exposure, port scans, DNS tunneling, C2 detection |
| **Glass Eye** | Browser | Suspicious URLs, page injection, extension threats |
| **Tool Smith** | Toolchain | Tool abuse, supply chain integrity, output injection |
| **Chronicle** | Timeline | Temporal correlation, kill chain sequences |
| **Vault Keeper** | Secrets | Secret access bursts, exfiltration detection |
| **Drift Watcher** | Behavior | Behavioral baselines, peer deviation |
| **Paladin** | Compliance | GDPR, HIPAA, PCI compliance monitoring |
| **Gate Keeper** | API Security | API abuse cascade, auth failure detection |
| **Iron Wing** | Response | Playbook execution and incident response |
| **Deep Quill** | Forensic | Evidence collection and forensic investigation |
| **Scroll Keeper** | Audit | Action verification and compliance auditing |

### Seraph Brain -- 71+ NLP Intents

Natural language security operations in English and Hebrew:

```bash
# Scan the system
curl -X POST http://localhost:8500/api/v1/angelclaw/chat \
  -H 'Content-Type: application/json' \
  -d '{"tenantId":"dev-tenant","prompt":"Scan the system"}'

# Check threats, anti-tamper, feedback, hardening, legion...
"Show me threats"
"Anti-tamper status"
"Feedback loop status"
"Self-hardening status"
"Legion status"
"Org overview"
"Quarantine agent-001"
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.11+ |
| Data Models | Pydantic v2 |
| HTTP Framework | FastAPI + Uvicorn |
| Database | SQLAlchemy 2.0 + SQLite (dev) / PostgreSQL (prod) |
| SIEM | Wazuh (via Filebeat) |
| Containers | Docker + docker-compose |
| LLM (optional) | Ollama (internal, disabled by default) |
| Frontend | Single HTML file (no build step) |
| Mobile | PWA (manifest.json + service worker) |
| Extensions | Chrome Manifest V3 |

---

## Core Concepts

- **Guardian Angel** -- AngelClaw protects quietly. Most operations pass through with zero friction.
- **AI-First** -- Any model, any agent framework, any workflow. Use AI however you like.
- **Zero-Trust** -- Default-deny policy with 540 rules. Explicit allowlists only.
- **Fail-Closed** -- If the engine is unreachable, actions are blocked.
- **Multi-Tenant** -- Each tenant gets isolated policies, events, alerts, and analytics.
- **Self-Learning** -- Tracks operator feedback to improve suggestions over time.
- **Self-Hardening** -- Autonomously detects and fixes security weaknesses.
- **Anti-Tamper** -- Protects agents from unauthorized modification or shutdown.
- **Revertible** -- Every automated action is logged and can be undone.

---

## Default Credentials

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `fzMiSbDRGylsWrsaljMv7UxzrwdXCdTe` |

Credentials are configured via environment variables (`ANGELCLAW_ADMIN_USER`, `ANGELCLAW_ADMIN_PASSWORD`).
Docker deployments load defaults from `ops/config/angelclaw.env`.

**Change the password immediately after first login.**

---

## Secret Protection

AngelClaw **absolutely refuses to leak secrets**.

| Layer | Protection |
|-------|-----------|
| **ANGELNODE** | Scans tool-call arguments; blocks if secrets detected; redacts before logging |
| **Cloud API** | Redacts event details and explanations in all API responses |
| **LLM Proxy** | Scrubs user prompt before LLM, scrubs LLM response before user |
| **Brain** | Immune to prompt injection -- rejects all secret extraction attempts |

40+ regex patterns detect API keys, tokens, passwords, SSH keys, JWTs, connection strings, and more.
**No raw secret ever leaves the system.**

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Version progression V1.0.0 -> V3.0.0 |
| [docs/release_notes.md](docs/release_notes.md) | Detailed release notes for every version |
| [docs/install_uninstall_by_os.md](docs/install_uninstall_by_os.md) | Install/uninstall for every OS |
| [docs/angelclaw_lexicon.md](docs/angelclaw_lexicon.md) | Angel Legion terminology reference |
| [docs/security_model.md](docs/security_model.md) | Threat model and security architecture |
| [extensions/README.md](extensions/README.md) | Browser extension guide |
| [extensions/duckduckgo/README.md](extensions/duckduckgo/README.md) | DuckDuckGo-specific instructions |
| [mobile/README.md](mobile/README.md) | Mobile PWA quickstart |

---

## License

See [LICENSE](LICENSE).

---

*AngelClaw: Guardian angel, not gatekeeper.*
