# AngelClaw

**Guardian angel, not gatekeeper.**

AngelClaw is an autonomous AI defense platform that protects endpoints, AI agents, and autonomous systems. It doesn't block AI — it embraces it. AngelClaw only intervenes when something genuinely dangerous is about to happen.

Everything else flows freely.

---

## Quick Start

```bash
# Docker (recommended)
git clone https://github.com/Senior3514/AngelClaw.git
cd AngelClaw/ops
docker compose up -d --build
```

Dashboard: **http://127.0.0.1:8500/ui**
Default login: `admin` / `fzMiSbDRGylsWrsaljMv7UxzrwdXCdTe` (change immediately)

### One-Line Install

| Platform | Command |
|----------|---------|
| Linux | `curl -fsSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_linux.sh \| bash` |
| macOS | `curl -fsSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_macos.sh \| bash` |
| Windows | `curl -fsSL -o %TEMP%\install.cmd https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_windows.cmd && %TEMP%\install.cmd` |

All installers auto-install every dependency. Zero prerequisites.

### Manual Install

```bash
git clone https://github.com/Senior3514/AngelClaw.git && cd AngelClaw
python3 -m venv venv && source venv/bin/activate
pip install -e ".[cloud,dev]"
uvicorn cloud.api.server:app --host 127.0.0.1 --port 8500
```

---

## What It Does

AngelClaw runs a continuous autonomous defense cycle across your entire infrastructure:

- **Threat Detection** — Pattern analysis, anomaly detection, kill chain correlation
- **AI Agent Protection** — Prompt injection blocking, output sanitization, behavioral boundaries
- **Zero Trust** — Default-deny with 540 rules, continuous session risk assessment, micro-segmentation
- **Self-Healing** — Autonomous incident response, golden image restoration, patch management
- **Self-Learning** — Tracks operator feedback, auto-adjusts thresholds, evolves detection rules
- **Compliance** — Continuous SOC2/HIPAA/PCI-DSS/GDPR/NIST auditing

### Dashboard — 10 Real-Time Pages

Every value is live from real API endpoints. Zero mock data.

| Page | What You See |
|------|-------------|
| **Dashboard** | Halo Score gauge, threat landscape chart, fleet OS distribution, guardian activity feed |
| **Fleet** | Mesh topology, agent table with health, micro-segmentation zones |
| **Alerts** | Real-time alert feed with severity badges, SOAR stats, WebSocket auto-refresh |
| **Angel Legion** | 12 warden status cards, threat matrix, orchestrator health |
| **Threat Intel** | Live feeds, IOC matches, MITRE ATT&CK coverage map |
| **Analytics** | 7-day threat matrix, ML anomaly stats, learning feedback loop |
| **AI Engine** | Seraph Brain health gauge, model registry, AGI defense status |
| **Zero Trust** | Trust score distribution, session stats, device assessment |
| **Policies** | Policy snapshots, natural language policy builder, playbooks |
| **Settings** | Org overview, tenant management, RBAC configuration |

---

## Architecture

```
AngelClaw/
├── angelnode/        # Edge agent — policy enforcement (port 8400)
│   ├── core/         #   PolicyEngine, zero-trust evaluation
│   ├── ai_shield/    #   AI agent adapters (LLM guardrails)
│   └── config/       #   540-rule bootstrap policy
├── cloud/            # Cloud backend — orchestration (port 8500)
│   ├── angelclaw/    #   Seraph Brain (119+ NLP intents)
│   ├── guardian/     #   Angel Legion (12 wardens)
│   ├── api/          #   600+ REST endpoints
│   ├── services/     #   96+ services
│   ├── db/           #   30+ tables (SQLAlchemy)
│   └── ui/           #   Console (10-page SPA)
├── tests/            # 2988+ tests
└── ops/              # Docker, installers, CLI
```

### Angel Legion — 12 Wardens

| Warden | Role |
|--------|------|
| **Vigil** | Threat detection, anomaly correlation |
| **Net Warden** | Network segmentation, C2 detection |
| **Glass Eye** | Browser security, extension monitoring |
| **Tool Smith** | Supply chain integrity, build security |
| **Chronicle** | Kill chain correlation, forensics |
| **Vault Keeper** | Secret protection, data loss prevention |
| **Drift Watcher** | Behavioral baselines, deviation detection |
| **Paladin** | Compliance automation (SOC2/HIPAA/GDPR) |
| **Gate Keeper** | API security, rate limiting |
| **Iron Wing** | Patch management, self-healing |
| **Deep Quill** | Evidence collection, chain of custody |
| **Scroll Keeper** | Audit logging, compliance trail |

### Seraph Brain

Natural language security operations:

```bash
curl -X POST http://localhost:8500/api/v1/angelclaw/chat \
  -H 'Content-Type: application/json' \
  -d '{"tenantId":"dev-tenant","prompt":"Show me threats"}'
```

119+ intents covering threat analysis, fleet management, compliance, threat hunting, and more.

---

## Core Principles

| Principle | What It Means |
|-----------|---------------|
| **Guardian Angel** | Protects quietly. Most operations pass with zero friction. |
| **AI-First** | Any model, any framework, any workflow. |
| **Zero-Trust** | Default-deny. Explicit allowlists only. |
| **Fail-Closed** | If the engine is unreachable, actions are blocked. |
| **Multi-Tenant** | Isolated policies, events, alerts per tenant. |
| **Revertible** | Every automated action is logged and can be undone. |
| **Anti-Tamper** | Agents resist unauthorized modification or shutdown. |

---

## API

600+ REST endpoints across 29 route modules. Key areas:

| Module | Prefix | Purpose |
|--------|--------|---------|
| Core | `/api/v1/angelclaw` | Chat, scan, daemon, shield |
| Guardian | `/api/v1/guardian` | Alerts, reports, wardens |
| Intel | `/api/v1/intel` | Threat feeds, IOCs, reputation |
| ML | `/api/v1/ml` | Anomaly detection, behavior, attack paths |
| SOAR | `/api/v1/soar` | Playbooks, SLA, incident timeline |
| Zero Trust | `/api/v1/zerotrust` | Segments, identity, device trust |
| Assets | `/api/v1/assets` | Inventory, topology, vulnerabilities |
| Convergence | `/api/v1/convergence` | Real-time engine, Halo Score, fleet |
| Policies | `/api/v1/policies` | Snapshots, rollback, NL policies |
| Auth | `/api/v1/auth` | JWT, API keys, RBAC |

Full API docs: `http://127.0.0.1:8500/docs`

---

## Multi-Tenancy

Each ANGELNODE connects with a Tenant ID. Data is fully isolated.

```bash
# Set tenant during install
ANGELCLAW_TENANT_ID="acme-corp" curl -fsSL .../install_angelclaw_linux.sh | bash

# Or edit ops/config/angelclaw.env and restart
```

---

## Secret Protection

AngelClaw refuses to leak secrets at every layer:

| Layer | Protection |
|-------|-----------|
| ANGELNODE | Blocks tool calls containing secrets |
| Cloud API | Redacts secrets in all API responses |
| LLM Proxy | Scrubs prompts and responses |
| Brain | Immune to prompt injection extraction |

40+ regex patterns detect API keys, tokens, passwords, SSH keys, JWTs, and connection strings.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.11+ |
| Framework | FastAPI + Uvicorn |
| Database | SQLAlchemy 2.0 + SQLite / PostgreSQL |
| Frontend | Vanilla HTML/CSS/JS (glassmorphic dark theme) |
| Containers | Docker + docker-compose |
| Mobile | PWA (manifest + service worker) |
| Extensions | Chrome Manifest V3 |
| LLM | Ollama (optional, internal only) |

---

## Verify

```bash
curl http://127.0.0.1:8500/health
# {"status":"ok","version":"10.0.0"}

python3 -m pytest tests/ -q
# 2988+ passed
```

---

## Uninstall

| OS | Command |
|----|---------|
| Linux | `curl -fsSL .../uninstall_angelclaw_linux.sh \| bash` |
| macOS | `curl -fsSL .../uninstall_angelclaw_macos.sh \| bash` |
| Windows | `C:\AngelClaw\ops\install\uninstall_angelclaw_windows.cmd` |
| Docker | `cd AngelClaw/ops && docker compose down -v` |

---

## Stats

| Metric | Value |
|--------|-------|
| Version | **10.0.0** |
| Tests | **2988+** |
| API Endpoints | **600+** |
| NLP Intents | **119+** |
| Wardens | **12** |
| Services | **96+** |
| DB Tables | **30+** |
| Policy Rules | **540** |

---

## Documentation

See [docs/](docs/) for architecture, changelog, security model, and deployment guides.

## License

[MIT](LICENSE)

---

*AngelClaw V10.0.0 — Guardian angel, not gatekeeper.*
