# AngelClaw V8.1.0 -- Nexus Prime: Quantum Crypto, Attack Surface, Runtime Protection

**Guardian angel, not gatekeeper.**

> The Python package is named `angelgrid` for internal compatibility. The product name is **AngelClaw**.

AngelClaw is a **full autonomous AI defense fabric** protecting every endpoint,
AI agent, and autonomous system across **SaaS, Hybrid & On-Prem** environments.

We don't block AI. We embrace it. AngelClaw only intervenes when AI is about to
do something genuinely dangerous: destructive shell commands, accessing secrets,
modifying critical files, or calling risky external endpoints. Everything else --
analysis, reading, summarizing, reasoning, creating -- flows freely.

---

## Version History

| Version | Codename | Highlights |
|---------|----------|------------|
| **V8.1.0** | **Nexus Prime** | AGI Defense Engine, Autonomous Response, Cross-Org Threat Federation, SOC Autopilot |
| V7.9.0 | Apex Predator | Ooda Loop, Self Healing, Breach Prevention |
| V7.8.0 | Ghost Protocol | Pentest Auto, Red Team |
| V7.7.0 | Mind Link | Deception Depth, Moving Target |
| V7.6.0 | Storm Watch | Intel Marketplace, Report Generator |
| V7.5.0 | Iron Vault | Disaster Recovery, Chaos Testing |
| V7.4.0 | Dark Web Radar | Dlp Engine, Data Classification |
| V7.3.0 | Sentinel Eye | Darkweb Monitor, Supply Chain |
| V7.2.0 | Neural Mesh | Log Analytics, Distributed Tracing |
| V7.1.0 | Quantum Shield | Traffic Analysis, Dns Security |
| V7.0.0 | Empyrion | Ueba, Threat Scoring |
| V6.5.0 | Prometheus | Threat Hunter, MITRE ATT&CK Mapper, Adversary Simulation, Intel Correlation |
| V6.0.0 | Omniguard | Multi-Cloud Defense (AWS/Azure/GCP/OCI/Alibaba), CSPM, SaaS Shield, Hybrid Mesh |
| V5.5.0 | Convergence | Real-Time Engine, Halo Score, Fleet Orchestrator, Dashboard Aggregator |
| V5.0.0 | Transcendence | AI Model Orchestration, NL Policies, Deception, Forensics, Compliance-as-Code |
| V4.5.0 | Sovereign | Zero Trust: Microsegmentation, Identity Policies, Device Trust, Adaptive Auth |
| V4.2.0 | Nexus | SIEM Connector, Container Security, IaC Scanner, CI/CD Gate |
| V4.1.0 | Prophecy | ML Anomaly Detection, Behavior Profiling, Attack Path Analysis, Risk Forecasting |
| V4.0.0 | Omniscience | Asset Inventory, Topology, Vulnerability Mgmt, SOAR, SLA, Incident Timeline |
| V3.5.0 | Sentinel | Threat Intel Feeds, IOC Matching, Reputation Service |
| V3.0.0 | Dominion | Admin Console, Anti-Tamper, Self-Learning, Self-Hardening, Browser Extension |
| V2.x | Legacy | Angel Legion, Plugin System, Policy Engine, Brain NLP |
| V1.0.0 | Genesis | ANGELNODE agent, Cloud API, Zero-Trust Bootstrap |

See [docs/CHANGELOG.md](docs/CHANGELOG.md) and [docs/release_notes.md](docs/release_notes.md) for full details.

---

## Installation

All installers **auto-install every dependency** (Docker, Git, Homebrew) -- zero prerequisites.
One command. Full stack. Done.

### Linux (Ubuntu / Debian / RHEL / Fedora / Arch)

```bash
curl -fsSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_linux.sh | bash
```

Installs: Docker, docker compose, Git, clones repo, builds & starts ANGELNODE + Cloud + Ollama, creates systemd service.

### macOS (Intel & Apple Silicon)

```bash
curl -fsSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_macos.sh | bash
```

Installs: Homebrew, Docker Desktop, Git, clones repo, builds & starts full stack.

### Windows -- Client Agent (CMD as Admin)

```cmd
curl -fsSL -o %TEMP%\install.cmd https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_windows.cmd && %TEMP%\install.cmd
```

Or with server URL pre-set:

```cmd
set ANGELCLAW_CLOUD_URL=http://YOUR-SERVER-IP:8500 && curl -fsSL -o %TEMP%\install.cmd https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_windows.cmd && %TEMP%\install.cmd
```

Installs: Python + Git (via winget), ANGELNODE agent natively. **No Docker required.** Auto-starts on boot.

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

## Installing from a Private Repository

If your AngelClaw repo is **private**, the one-liner `curl | bash` approach won't work without authentication. Use one of these methods:

### Option 1: SSH Key (Recommended)

Ensure your SSH key is added to GitHub, then clone via SSH:

```bash
# Linux / macOS
git clone git@github.com:YOUR-ORG/AngelClaw.git
cd AngelClaw/ops
docker compose up -d --build
```

```cmd
:: Windows (CMD as Admin)
git clone git@github.com:YOUR-ORG/AngelClaw.git
cd AngelClaw\ops
docker compose up -d --build
```

### Option 2: GitHub Personal Access Token (PAT)

Generate a PAT at [github.com/settings/tokens](https://github.com/settings/tokens) with `repo` scope.

```bash
# Linux / macOS
git clone https://YOUR_PAT@github.com/YOUR-ORG/AngelClaw.git
cd AngelClaw/ops
docker compose up -d --build
```

```cmd
:: Windows (CMD as Admin)
git clone https://YOUR_PAT@github.com/YOUR-ORG/AngelClaw.git
cd AngelClaw\ops
docker compose up -d --build
```

**Tip:** For CI/CD, store the PAT as a secret (e.g., `GITHUB_TOKEN`) and use:

```bash
git clone https://${GITHUB_TOKEN}@github.com/YOUR-ORG/AngelClaw.git
```

### Option 3: GitHub CLI (gh)

```bash
# Authenticate once
gh auth login

# Clone private repo
gh repo clone YOUR-ORG/AngelClaw
cd AngelClaw/ops
docker compose up -d --build
```

### Option 4: One-Liner for Private Repo (Linux/macOS)

Download the installer script manually with a PAT, then run it:

```bash
# Set your PAT
export GH_PAT="ghp_your_token_here"

# Download and run
curl -fsSL -H "Authorization: token $GH_PAT" \
  https://raw.githubusercontent.com/YOUR-ORG/AngelClaw/main/ops/install/install_angelclaw_linux.sh | bash
```

### Option 5: Deploy Key (Server / CI environments)

1. Generate a deploy key: `ssh-keygen -t ed25519 -f ~/.ssh/angelclaw_deploy -N ""`
2. Add the public key to your repo: **Settings > Deploy Keys > Add**
3. Configure SSH:

```bash
# ~/.ssh/config
Host github-angelclaw
  HostName github.com
  User git
  IdentityFile ~/.ssh/angelclaw_deploy
  IdentitiesOnly yes
```

4. Clone: `git clone github-angelclaw:YOUR-ORG/AngelClaw.git`

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
ANGELCLAW_TENANT_ID="acme-corp" curl -fsSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_linux.sh | bash
```

```cmd
:: Windows (CMD as Admin)
set ANGELCLAW_TENANT_ID=acme-corp && curl -fsSL -o %TEMP%\install.cmd https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_windows.cmd && %TEMP%\install.cmd
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
| **Windows** | CMD as Admin: `C:\AngelClaw\ops\install\uninstall_angelclaw_windows.cmd` |
| **Docker** | `cd AngelClaw/ops && docker compose down -v` |

Set `ANGELCLAW_KEEP_DATA=true` (Linux/macOS) or `-KeepData` (Windows) to preserve data.

---

## Verify

```bash
curl http://127.0.0.1:8500/health
# {"status":"ok","version":"7.0.0",...}

python3 -m pytest tests/ -q
# 931+ passed
```

Dashboard: **http://127.0.0.1:8500/ui** -- Default login: `admin` / `fzMiSbDRGylsWrsaljMv7UxzrwdXCdTe` (change immediately!)

---

## What's New in V7.0.0 -- Empyrion

### AGI Defense Engine (V7.0)
- **Self-programming defense rules**: threat pattern analysis, auto-generation, validation, kill-switch deployment
- **Autonomous Incident Response**: full containment/eradication/recovery lifecycle with human override
- **Cross-Org Threat Federation**: organization trust network, anonymous indicator sharing, collective defense scoring
- **SOC Autopilot**: AGI-driven triage, investigation orchestration, analyst assignment, shift handoff, workload balancing

### Autonomous Threat Hunting (V6.5)
- **Threat Hunter**: hypothesis-driven hunting, IOC correlation, hunt playbooks
- **MITRE ATT&CK Mapper**: technique classification, coverage analysis, gap identification, kill chain visualization
- **Adversary Simulation**: purple team attack scenarios, defense validation, gap reporting
- **Intel Correlation**: cross-source event correlation, pattern discovery, campaign attribution

### Multi-Cloud Defense Fabric (V6.0)
- **Cloud Connector**: AWS, Azure, GCP, OCI, Alibaba -- credential storage, health checking, resource discovery
- **CSPM**: CIS benchmark checks, misconfiguration detection, remediation recommendations
- **SaaS Shield**: OAuth/SAML monitoring, API abuse detection, shadow IT discovery
- **Hybrid Mesh**: on-prem/cloud/edge federation, cross-environment policy sync, latency-aware routing

### Real-Time Defense Fabric (V5.5)
- **Real-Time Engine**: event streaming, live dashboard metrics, sliding window stats
- **Halo Score**: 6-dimension weighted security posture scoring (0-100)
- **Fleet Orchestrator**: fleet node management, OS distribution, batch command dispatch
- **Dashboard Aggregator**: unified command center, wingspan stats, threat landscape

### AGI Empyrion Platform (V5.0)
- AI Model Orchestration, Natural Language Policies, Incident Commander
- Deception Technology (honey tokens), Automated Digital Forensics
- Compliance-as-Code (SOC2/HIPAA/PCI-DSS/GDPR/NIST), Self-Evolving Detection Rules

### Previous Versions (V4.5 -- V3.0)
- Zero Trust Architecture (Microsegmentation, Identity Policies, Device Trust, Adaptive Auth)
- Integration Hub (SIEM, Container Security, IaC Scanner, CI/CD Gate)
- Predictive ML Engine (Anomaly Detection, Behavior Profiling, Attack Paths, Risk Forecasting)
- Situational Awareness (Asset Inventory, Topology, Vulnerability Mgmt, SOAR, SLA)
- Threat Intelligence Platform (Feeds, IOC Matching, Reputation)
- Admin Console, Anti-Tamper, Self-Learning, Self-Hardening, Browser Extension

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

## API Endpoints Overview

| Module | Prefix | Endpoints |
|--------|--------|-----------|
| Core | `/api/v1/angelclaw` | Chat, scan, health, brain status |
| Events & Alerts | `/api/v1/events`, `/api/v1/alerts` | Event ingestion, alert management |
| Policies | `/api/v1/policies` | Policy CRUD, snapshots, rollback |
| Legion | `/api/v1/legion` | Warden status, orchestrator sweep |
| Threat Intel | `/api/v1/intel` | Feeds, IOCs, reputation |
| ML & Analytics | `/api/v1/ml` | Anomaly detection, behavior, attack paths |
| Assets & Topology | `/api/v1/assets` | Inventory, topology, vulnerability |
| SOAR | `/api/v1/soar` | Playbooks, SLA, incident timeline |
| SIEM | `/api/v1/siem` | Connector management, event sync |
| Zero Trust | `/api/v1/zerotrust` | Microsegmentation, identity, device trust |
| Transcendence | `/api/v1/transcendence` | AI orchestrator, NL policies, forensics |
| Convergence | `/api/v1/convergence` | Real-time engine, Halo Score, fleet |
| Omniguard | `/api/v1/omniguard` | Cloud connectors, CSPM, SaaS, hybrid mesh |
| Prometheus | `/api/v1/prometheus` | Threat hunting, MITRE, adversary sim |
| Empyrion | `/api/v1/empyrion` | AGI defense, autonomous response, SOC |

**100+ REST API endpoints** across 27 route modules.

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

AngelClaw is a **3-tier architecture** with **12 specialized wardens** and **50+ services**:

```
AngelClaw/
├── angelnode/             # Local agent (policy enforcement, port 8400)
│   ├── core/              #   PolicyEngine, evaluation API, cloud sync
│   ├── ai_shield/         #   AI agent adapters (OpenClaw, Claude Code)
│   └── config/            #   540-rule zero-trust bootstrap policy
├── cloud/                 # SaaS backend (orchestration, port 8500)
│   ├── angelclaw/         #   Brain (95+ intents), Shield, Daemon (25 cycles), Actions
│   ├── guardian/          #   Angel Legion: 12 wardens + orchestrator
│   ├── api/               #   27 route modules, 100+ REST endpoints
│   ├── services/          #   50+ services (AI, ML, SOAR, SIEM, zero-trust, etc.)
│   ├── auth/              #   JWT, API keys, custom RBAC
│   ├── middleware/        #   Rate limiter, CORS, security headers
│   ├── websocket/         #   Real-time event/alert feeds
│   ├── plugins/           #   Dynamic warden plugin loading
│   ├── db/                #   SQLAlchemy ORM (30+ tables)
│   └── ui/                #   Admin console (10-page SPA, PWA-ready, dark cyberpunk theme)
├── shared/                # Pydantic models, secret scanner
├── mobile/                # PWA manifest + service worker
├── extensions/            # Chrome/DuckDuckGo browser extensions
├── plugins/               # Plugin examples
├── ops/                   # Installers, Docker, systemd, CLI
├── tests/                 # 931+ tests (8 test suites)
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

### Seraph Brain -- 95+ NLP Intents

Natural language security operations in English and Hebrew:

```bash
# Chat with AngelClaw
curl -X POST http://localhost:8500/api/v1/angelclaw/chat \
  -H 'Content-Type: application/json' \
  -d '{"tenantId":"dev-tenant","prompt":"Scan the system"}'

# Example prompts
"Show me threats"               # Threat overview
"Halo score"                    # Security posture score
"Fleet status"                  # All connected nodes
"Zero trust status"             # ZT architecture health
"Run a threat hunt"             # Start hypothesis-driven hunt
"MITRE coverage"                # ATT&CK technique coverage
"Cloud security posture"        # CSPM scan results
"SOC workload"                  # Analyst shift & workload
"AGI defense status"            # Self-programming rules status
"Compliance status"             # SOC2/HIPAA/PCI/GDPR/NIST
```

---

## Autonomous Daemon -- 25 Cycle Steps

The daemon runs continuously in the background, executing a 25-step cycle:

| # | Cycle | Version |
|---|-------|---------|
| 1-8 | Shield scan, drift, health, learning, legion sweep, hardening, feedback, anti-tamper | V1.0-V3.0 |
| 9-11 | Threat intel polling, IOC matching | V3.5 |
| 12 | ML anomaly batch detection | V4.1 |
| 13 | Zero-trust session reassessment | V4.5 |
| 14-15 | Deception token monitoring, evolving rule evolution | V5.0 |
| 16-17 | Real-time metrics aggregation, Halo Score recomputation | V5.5 |
| 18 | CSPM cloud posture scan | V6.0 |
| 19-20 | Autonomous threat hunt, intel correlation | V6.5 |
| 21-22 | AGI defense rule generation, SOC autopilot triage | V7.0 |

---

## Stats

| Metric | Value |
|--------|-------|
| Tests | **931+ passing** (0 failures) |
| NLP Intents | **95+** |
| API Endpoints | **100+** |
| Route Modules | **27** |
| Services | **50+** |
| DB Tables | **30+** |
| Daemon Cycles | **25** |
| Wardens | **12** |
| Version | **7.0.0** |

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
| Frontend | React + Vite + Tailwind CSS (dark cyberpunk theme) |
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
- **AGI Autonomous** -- Self-programming defense rules, autonomous incident response, SOC autopilot.
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
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Version progression V1.0.0 -> V7.0.0 |
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

*AngelClaw V7.0.0 -- Empyrion: Full AGI Autonomous Defense.*
*Guardian angel, not gatekeeper.*
