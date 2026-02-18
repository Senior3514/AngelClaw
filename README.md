# AngelClaw -- Autonomous AI Defense Guardian

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

## What's New in V2.1.0 -- Angel Legion: Seraph Core

AngelClaw V2.1.0 upgrades the Seraph Brain with an enhanced internal cognition protocol for deeper cross-domain synthesis, expert-level strategic reasoning, and maximum processing capability. All enhancements are internal -- the user-facing API surface remains stable and backward-compatible.

### V2.0.0 Highlights -- Angel Legion

AngelClaw V2.0.0 introduced the **Angel Legion** -- a swarm of 10 specialized sub-agents orchestrated by the Seraph (orchestrator) with a dynamic registry. The system evolved from 4 hardcoded agents to a fully extensible, registry-based architecture.

### Angel Legion -- 7 New Specialized Wardens

| Code Name | Agent Type | Role |
|-----------|-----------|------|
| **Vigil** | Warden | Core threat detection (patterns, anomalies, correlation) |
| **Net Warden** | Network | Network exposure, port scans, suspicious DNS, C2 detection |
| **Glass Eye** | Browser | Suspicious URLs, page injection, extension threats, data abuse |
| **Tool Smith** | Toolchain | Tool abuse, supply chain integrity, output injection detection |
| **Chronicle** | Timeline | Temporal correlation, kill chain sequences, time clustering |
| **Vault Keeper** | Secrets | Secret access bursts, brute force, exfiltration detection |
| **Drift Watcher** | Behavior | Behavioral baselines, peer deviation, severity escalation |
| **Iron Wing** | Response | Playbook execution and incident response |
| **Deep Quill** | Forensic | Evidence collection and forensic investigation |
| **Scroll Keeper** | Audit | Action verification and compliance auditing |

### V2.0.0 Architecture Changes
- **Dynamic Agent Registry** -- `AgentRegistry` manages N agents without hardcoding; agents register by type
- **Serenity Scale** -- AngelClaw-themed risk levels (Serene/Whisper/Murmur/Disturbed/Storm)
- **Registry-based orchestrator** -- all API routes and metrics iterate agents dynamically
- **Per-warden permissions** -- fine-grained permission model (READ_NETWORK, READ_SECRETS, READ_TOOLS, READ_BROWSER, READ_TIMELINE)
- **Base agent timeout enforcement** -- `SubAgent.execute()` wraps all tasks with timeout, error handling, and status tracking
- **1130 tests passing** -- 84% code coverage, all new wardens at 94-100% coverage

### V1.1.0 Summary (Previous Release)

AngelClaw has evolved from a simple policy engine into a **full-stack, enterprise-grade, autonomous AGI security suite** across 38 commits. Here is a complete summary of all major improvements and changes:

### Architecture & Core Engine
- **Complete stack redesign** -- from a single policy evaluator to a 3-tier architecture: ANGELNODE (local agent) + Cloud API (SaaS backend) + Web Dashboard
- **Policy engine rewrite** -- first-match-wins rule evaluation with 29 built-in rules across 5 categories (shell, network, file, database, AI tools)
- **Extended match syntax** -- regex patterns, list membership, numeric comparisons, and burst detection in policy rules
- **Category defaults** -- configurable fallback actions (BLOCK/ALLOW/ALERT/AUDIT) per category when no rule matches
- **Fail-closed design** -- if the engine is unreachable, all actions are blocked as a safety net

### Autonomous Brain (V0.5.0+)
- **29 NLP intents** -- natural language understanding for security commands ("scan the system", "show me threats", "block that agent")
- **Context-aware responses** -- the AI brain considers recent events, agent state, and threat landscape when answering
- **Always-on daemon** -- continuous background scans, shield assessments, drift detection, and agent health monitoring
- **Action framework** -- 11 action types (block_agent, tighten_policy, quarantine, etc.) with dry-run proposals, confirmation workflow, and full audit trail

### Threat Detection Shield (V0.7.0+)
- **13 prompt injection patterns** -- detects jailbreak attempts, role override, instruction manipulation
- **6 data leakage detectors** -- catches exfiltration of PII, credentials, internal data
- **7 evil AGI patterns** -- identifies deceptive behavior, goal manipulation, sandbox escape attempts
- **Lethal Trifecta monitoring** -- simultaneous detection of resource acquisition + deception + goal divergence
- **6-stage MITRE ATT&CK chain detection** -- tracks reconnaissance through exfiltration across correlated events

### Secret Protection
- **40+ regex patterns** -- detects API keys, tokens, passwords, SSH keys, JWTs, connection strings, AWS credentials, and more
- **3-layer redaction pipeline** -- secrets are scrubbed at ANGELNODE (before logging), at Cloud API (before responses), and at LLM Proxy (before/after inference)
- **Zero-leak guarantee** -- no raw secret ever leaves the system through any API, log, or LLM response

### Security Hardening (V1.1.0)
- **JWT authentication** -- all API endpoints require authentication by default
- **3-role RBAC** -- viewer (read-only), secops (operational), admin (full control)
- **Input sanitization** -- XSS prevention, SQL injection protection, path traversal blocking on all inputs
- **SHA256 skills integrity** -- cryptographic verification of all core modules with drift detection alerts
- **Security-first defaults** -- loopback-only binding, auth enabled, LLM disabled, Ollama network-isolated

### Fleet Management & Cloud
- **Agent registration** -- ANGELNODE agents auto-register with Cloud on startup
- **Policy distribution** -- centralized policy management with automatic sync every 60 seconds
- **Heartbeat monitoring** -- agent health tracking with last-seen timestamps
- **Behavioral fingerprinting** -- agent identity verification based on behavioral patterns
- **Multi-tenant support** -- tenant isolation via `X-TENANT-ID` header scoping

### AI Shield & Integrations
- **AI agent adapters** -- built-in support for OpenClaw, MoltBot, and Claude Code agent frameworks
- **Tool-call mediation** -- every AI tool call is evaluated against the policy engine before execution
- **Secret-aware blocking** -- any tool call flagged with `accesses_secrets: true` is blocked regardless of tool name
- **Burst detection** -- alerts when >30 AI tool calls occur within 10 seconds

### Enterprise Dashboard
- **Single-page web UI** -- served at `/ui` with zero build step (single HTML file)
- **Real-time fleet status** -- agent list with health, tags, trust state, last sync
- **Threat landscape chart** -- events by category over the last 24 hours
- **Active alerts feed** -- live security events with severity icons
- **AngelClaw AI chat** -- ask questions about incidents, policies, and security posture directly from the dashboard

### LLM Proxy
- **Guardian angel for LLMs** -- optional proxy at `/api/v1/llm/chat` for safe local AI usage
- **Mandatory system prompt** -- enforced security-analyst persona that cannot be overridden
- **Bidirectional scrubbing** -- user prompts scrubbed before LLM, LLM responses scrubbed before user
- **Network isolation** -- Ollama has no host port; only reachable from Docker internal network

### DevOps & Quality
- **Docker Compose deployment** -- single-command production deployment with 3 services (angelnode, cloud, ollama)
- **systemd integration** -- automatic start on boot for Linux servers
- **Cross-platform installers** -- one-command install for Linux, macOS, and Windows
- **Wazuh SIEM integration** -- Filebeat log shipping with custom detection rules
- **1130 tests passing** -- 84% code coverage across the entire codebase
- **CI/CD pipeline** -- GitHub Actions with linting (ruff), testing (pytest), and cross-platform validation
- **Windows compatibility** -- path handling, PowerShell installer, and CI validation on Windows

### API Surface
- **40+ REST endpoints** -- comprehensive API covering agents, events, policies, analytics, assistant, guardian, auth, and LLM proxy
- **AI Assistant API** -- incident summarization, policy proposals, and event explanation endpoints
- **Guardian Chat API** -- unified chat interface for security operations
- **Analytics API** -- threat matrix, AI traffic inspection, session analytics, agent timeline, policy evolution

---

## Installation

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Docker | 20.10+ | Docker Desktop (macOS/Windows) or Docker Engine (Linux) |
| Docker Compose | v2+ | Included with Docker Desktop; `docker compose` plugin on Linux |
| Git | 2.x+ | For cloning the repository |
| Python | 3.11+ | Only needed for local development (not Docker) |

---

## Linux (Full Stack)

### Install -- One Command

```bash
curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_linux.sh | bash
```

Installs Docker (if missing), clones the repo, builds all 3 containers, registers systemd service.

### Uninstall -- One Command

```bash
curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/uninstall_angelclaw_linux.sh | bash
```

Stops containers, removes systemd service, Docker images, volumes, and the install directory.

### Clean (keep files, reset containers)

```bash
cd /root/AngelClaw/ops && docker compose down --volumes --remove-orphans
docker system prune -f
```

### Reinstall -- One Command

```bash
curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/uninstall_angelclaw_linux.sh | bash && curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_linux.sh | bash
```

### Verify

```bash
curl http://127.0.0.1:8400/health   # ANGELNODE
curl http://127.0.0.1:8500/health   # Cloud API
curl http://127.0.0.1:8500/ui       # Dashboard
systemctl status angelclaw          # Service status
```

---

## macOS (Full Stack)

### Install -- One Command

```bash
curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_macos.sh | bash
```

Installs Homebrew + Docker Desktop (if missing), clones the repo, builds the full stack.

### Uninstall -- One Command

```bash
curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/uninstall_angelclaw_macos.sh | bash
```

Stops containers, removes Docker images, volumes, and the install directory.

### Clean (keep files, reset containers)

```bash
cd ~/AngelClaw/ops && docker compose down --volumes --remove-orphans
docker system prune -f
```

### Reinstall -- One Command

```bash
curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/uninstall_angelclaw_macos.sh | bash && curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_macos.sh | bash
```

### Verify

```bash
curl http://127.0.0.1:8400/health   # ANGELNODE
curl http://127.0.0.1:8500/health   # Cloud API
open http://127.0.0.1:8500/ui       # Dashboard
```

---

## Windows (ANGELNODE Agent Only)

> Windows runs the lightweight ANGELNODE agent only. The Cloud backend runs on your Linux/macOS server. Replace `YOUR-VPS-IP` with your server's IP.

### Install

PowerShell (as Administrator):

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
git clone https://github.com/Senior3514/AngelClaw.git C:\AngelClaw
C:\AngelClaw\ops\install\install_angelclaw_windows.ps1 -CloudUrl "http://YOUR-VPS-IP:8500"
```

**Already installed? The installer auto-detects and updates:**

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
C:\AngelClaw\ops\install\install_angelclaw_windows.ps1 -CloudUrl "http://YOUR-VPS-IP:8500"
```

### Uninstall

PowerShell (as Administrator):

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
C:\AngelClaw\ops\install\uninstall_angelclaw_windows.ps1
```

### Clean (keep files, reset containers)

```powershell
cd C:\AngelClaw\ops; docker compose down --volumes --remove-orphans
docker system prune -f
```

### Force Reinstall

PowerShell (as Administrator):

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
C:\AngelClaw\ops\install\uninstall_angelclaw_windows.ps1
git clone https://github.com/Senior3514/AngelClaw.git C:\AngelClaw
C:\AngelClaw\ops\install\install_angelclaw_windows.ps1 -CloudUrl "http://YOUR-VPS-IP:8500" -Force
```

### Verify

```powershell
curl http://127.0.0.1:8400/health
curl http://127.0.0.1:8400/status
docker ps
```

---

## Development Setup (All Platforms)

```bash
# Option 1: Docker Compose (recommended)
git clone https://github.com/Senior3514/AngelClaw.git
cd AngelClaw/ops
docker compose up --build

# Option 2: Local Python
git clone https://github.com/Senior3514/AngelClaw.git
cd AngelClaw
pip install -e ".[dev,cloud]"
uvicorn angelnode.core.server:app --host 127.0.0.1 --port 8400 &
uvicorn cloud.api.server:app --host 127.0.0.1 --port 8500
```

---

## Default Credentials

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `angelclaw` |

**Change the password immediately after first login.**

---

### Quick Reference

| What | URL / Command |
|------|---------------|
| Dashboard | `http://127.0.0.1:8500/ui` |
| ANGELNODE health | `curl http://127.0.0.1:8400/health` |
| Cloud API health | `curl http://127.0.0.1:8500/health` |
| CLI status | `./ops/cli/angelclawctl status` |
| Chat with AngelClaw | `curl -X POST http://127.0.0.1:8500/api/v1/angelclaw/chat -H 'Content-Type: application/json' -d '{"tenantId":"default","prompt":"Scan the system"}'` |
| Remote access (SSH tunnel) | `ssh -L 8500:127.0.0.1:8500 user@your-vps` |

---

## AngelClaw AGI Guardian (V2.1.0)

AngelClaw is a **full-stack, enterprise-grade, autonomous AGI security suite** with the **Angel Legion** -- 10 specialized sub-agents:

- **Angel Legion** -- 10 sub-agents: 7 wardens (network, browser, toolchain, timeline, secrets, behavior, core) + response + forensic + audit
- **Seraph Orchestrator** -- Dynamic agent registry, parallel warden dispatch, autonomy modes (Observe/Suggest/Auto-Apply)
- **Autonomous Brain** -- 32+ NLP intents, natural language security chat, context-aware responses
- **Threat Shield** -- 13 prompt injection patterns, 6 data leakage detectors, 7 evil AGI patterns, Lethal Trifecta monitoring, 6-stage ATT&CK attack chain detection
- **Always-On Daemon** -- Continuous scans, shield assessments, drift detection, agent health monitoring
- **Action Framework** -- 11 action types with dry-run proposals, confirmation workflow, full audit trail
- **Auth & RBAC** -- JWT authentication, 3 roles (viewer/secops/admin), no unauthenticated access by default
- **Secret Protection** -- 40+ pattern secret scanner, 3-layer redaction pipeline, NEVER leaks secrets
- **Skills Integrity** -- SHA256 verification of all core modules, drift detection with HIGH severity alerts
- **Fleet Management** -- Agent registration, policy distribution, heartbeat monitoring
- **Guardian Chat** -- Unified AI chat for incidents, threats, policies, scans, and general security guidance
- **Enterprise Dashboard** -- Real-time fleet status, threat landscape, alerts, AngelClaw AI chat

See [docs/angelclaw_lexicon.md](docs/angelclaw_lexicon.md) for the canonical Angel Legion terminology reference.

## Repository Structure

```
AngelClaw/
├── angelnode/           # Local autonomous protection agent
│   ├── core/            #   Policy engine, evaluation API, structured logging
│   ├── ai_shield/       #   AI agent adapters (OpenClaw, MoltBot, Claude Code)
│   ├── sensors/         #   Future: process/file/network monitors
│   └── config/          #   Default policies and configuration
├── cloud/               # SaaS backend (AngelClaw Cloud)
│   ├── api/             #   FastAPI REST endpoints, AI Assistant, analytics
│   ├── ai_assistant/    #   Security analysis (read-only, deterministic)
│   ├── llm_proxy/       #   Optional LLM proxy for Ollama / external models
│   ├── ui/              #   Guardian Angel web dashboard (single-page app)
│   ├── db/              #   SQLAlchemy ORM models and session management
│   └── services/        #   Business logic (policy compilation, incidents)
├── agentless/           # Cloud connectors and legacy scanners
│   ├── connectors/      #   AWS/Azure/GCP API connectors
│   └── scanners/        #   Misconfiguration scanners
├── shared/              # Shared models, security helpers, config schemas
│   ├── models/          #   Pydantic data models (Event, Policy, Incident, etc.)
│   ├── security/        #   Cryptographic helpers and input sanitization
│   └── config/          #   Configuration schemas
├── ops/                 # Deployment and integrations
│   ├── cli/             #   angelclawctl operator CLI
│   ├── install/         #   Linux, macOS, and Windows installers
│   ├── systemd/         #   systemd unit files
│   ├── config/          #   Environment config templates
│   ├── docker/          #   Dockerfiles and compose configurations
│   ├── wazuh/           #   Wazuh SIEM integration configs and rules
│   └── infra/           #   Future: Terraform/Pulumi modules
├── tests/               # 1130 tests — 84% coverage
└── docs/                # Architecture, threat model, concepts
```

## Tech Stack

| Component       | Technology                          |
|-----------------|-------------------------------------|
| Language        | Python 3.11+                        |
| Data Models     | Pydantic v2                         |
| HTTP Framework  | FastAPI + Uvicorn                   |
| Database        | SQLAlchemy 2.0 + SQLite (dev) / PostgreSQL (prod) |
| SIEM            | Wazuh (via Filebeat)                |
| Containers      | Docker + docker-compose             |
| LLM (optional)  | Ollama (internal, disabled by default) |

## Core Concepts

- **Guardian Angel** -- AngelClaw protects quietly. Most operations pass through with zero friction -- only genuinely dangerous actions get blocked.
- **AI-First** -- We support any model (Ollama, Claude, OpenAI), any agent framework (OpenClaw, Claude Code, MoltBot), and any workflow. Use AI however you like.
- **ANGELNODE** -- Lightweight agent that evaluates actions locally. Fast, autonomous, always-on.
- **AI Shield** -- Mediator for AI agent tool calls. Safe tools flow freely; risky ones get flagged.
- **Fail-Closed** -- If the engine is unreachable, actions are blocked. Safety net of last resort, not the normal mode.

See [docs/concepts/glossary.md](docs/concepts/glossary.md) for the full glossary and
[docs/concepts/angelgrid_ai.md](docs/concepts/angelgrid_ai.md) for our product philosophy.

---

## Policy Rules Reference

The bootstrap policy (`angelnode/config/default_policy.json`) ships with **29 rules**
organized by category. Rules are evaluated top-down; **first match wins**.

### Shell Rules

| Rule ID | Action | What it does |
|---------|--------|--------------|
| `block-shell-destructive-rm` | BLOCK | Regex catches `rm -rf`, `rm -fr`, and flag variants |
| `block-shell-no-preserve-root` | BLOCK | Catches `--no-preserve-root` in any command |
| `block-shell-format-disk` | BLOCK | Blocks `mkfs.*` and `dd ... of=/dev/` |
| `block-shell-privilege-escalation` | ALERT | Detects `sudo`, world-writable `chmod`, `chown root`, `passwd` |
| `block-shell-reverse-shell` | BLOCK | Blocks `/dev/tcp/`, `nc -e`, `ncat`, `mkfifo`, `bash -i` |
| `alert-shell-burst` | ALERT | Fires when >20 shell execs occur within 10 seconds |

### Network Rules (Egress Allowlist)

| Rule ID | Action | What it does |
|---------|--------|--------------|
| `allow-network-cloud-api` | ALLOW | Permits connections to Cloud API (internal) |
| `allow-network-package-registries` | AUDIT | Permits PyPI, npm, Docker Hub, GHCR, Alpine CDN |
| `allow-network-dns-ntp` | ALLOW | Permits DNS (port 53) and NTP (port 123) |
| `alert-network-exfil-post` | ALERT | Flags outbound POST to suspicious destinations |
| `alert-network-large-upload` | ALERT | Flags uploads > 1 MB |
| *(no match)* | **BLOCK** | Category default: all other network traffic is blocked |

**To add your own allowed destinations**, add a rule before the alert rules with
`"destination_pattern": "^https://your-domain\\.com"` and `"action": "allow"`.

### File Rules

| Rule ID | Action | What it does |
|---------|--------|--------------|
| `block-file-read-ssh-keys` | BLOCK | SSH keys, `authorized_keys` |
| `block-file-read-credentials` | BLOCK | `.env`, AWS creds, kube config, `/etc/shadow`, secret YAMLs |
| `alert-file-read-sensitive-dirs` | ALERT | `/etc`, `/var/secrets`, `/root/.*`, `/proc/*/environ` |
| `allow-file-read-safe` | AUDIT | All other reads pass (logged) |
| `block-file-write-system` | BLOCK | Writes to `/etc`, `/boot`, `/usr/bin`, package state |
| `audit-file-write` | AUDIT | All other writes pass (logged) |

### Database Rules

| Rule ID | Action | What it does |
|---------|--------|--------------|
| `allow-db-read` | AUDIT | `SELECT` queries pass (logged) |
| `alert-db-write` | ALERT | `INSERT` / `UPDATE` / `DELETE` flagged |
| `block-db-ddl` | BLOCK | `DROP` / `ALTER` / `TRUNCATE` / `CREATE` blocked |

### AI Tool Rules

| Rule ID | Action | What it does |
|---------|--------|--------------|
| `block-ai-tool-secrets-access` | **BLOCK** | Any tool call flagged with `accesses_secrets: true` -- **evaluated first** |
| `allow-ai-tool-read-file` | AUDIT | `read_file`, `search`, `grep`, `glob`, `list_files` |
| `allow-ai-tool-analysis` | ALLOW | `summarize`, `explain`, `analyze`, `diff`, `status` |
| `alert-ai-tool-shell` | ALERT | `bash`, `shell`, `exec`, `terminal`, `run_command` |
| `alert-ai-tool-write` | ALERT | `write_file`, `edit`, `patch`, `create_file` |
| `alert-ai-tool-burst` | ALERT | >30 AI tool calls within 10 seconds |
| *(no match)* | **BLOCK** | Category default: unknown AI tools are blocked |

> **Key**: `block-ai-tool-secrets-access` is first in the AI tool section so that
> secret-touching operations are **always** blocked, even if the tool name is in a safe list.

### Extended Match Syntax

Policy rules support enhanced `detail_conditions`:

```jsonc
// Exact match (existing)
"key": "value"

// Regex pattern -- matches event.details["command"] via re.search
"command_pattern": "rm\\s+-rf"

// List membership -- matches if event.details["tool_name"] is in the list
"tool_name_in": ["bash", "shell", "exec"]

// Numeric greater-than -- matches if event.details["payload_bytes"] > 1048576
"payload_bytes_gt": 1048576

// Burst detection -- triggers when event count exceeds threshold in window
"burst_window_seconds": 10,
"burst_threshold": 20
```

### Overriding / Extending Policies

1. Edit `angelnode/config/default_policy.json` directly (bind-mounted read-only in Docker)
2. Or push updated rules via AngelClaw Cloud -- the ANGELNODE polls every 60s
3. Rules are first-match-wins -- put more specific rules **before** generic catch-alls

---

## AI Assistant API

The Cloud API exposes three assistant endpoints under `/api/v1/assistant/`:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/assistant/incidents` | GET | Summarize recent incidents (by severity, classification, top agents) |
| `/api/v1/assistant/propose` | POST | Propose policy tightening rules based on recent high-severity events |
| `/api/v1/assistant/explain` | GET | Explain why a specific event was blocked/alerted/allowed |

All endpoints are **read-only** and accept `X-TENANT-ID` header for tenant scoping.

Example:

```bash
# Summarize last 24h of incidents
curl http://127.0.0.1:8500/api/v1/assistant/incidents

# Propose tightening for an agent group
curl -X POST http://127.0.0.1:8500/api/v1/assistant/propose \
  -H "Content-Type: application/json" \
  -d '{"agent_group_id": "production"}'

# Explain a specific event
curl "http://127.0.0.1:8500/api/v1/assistant/explain?event_id=<uuid>"
```

---

## Secret Protection

AngelClaw embraces AI usage -- but **absolutely refuses to leak secrets**.

Every layer in the stack scans for and redacts API keys, tokens, passwords,
SSH keys, JWTs, connection strings, and sensitive file paths. The secret
scanner (`shared/security/secret_scanner.py`) is used by:

| Layer | What it does |
|-------|-------------|
| **ANGELNODE AI Shield** | Scans tool-call arguments; blocks if secrets detected; redacts before logging |
| **Cloud AI Assistant** | Redacts event details and explanations in all API responses |
| **LLM Proxy** | Scrubs user prompt *before* LLM, scrubs LLM response *before* user |

**No raw secret ever leaves the system** -- not through the API, not through
the LLM, not through event explanations. This is the one rule that is never relaxed.

See [docs/architecture/overview.md](docs/architecture/overview.md) for the full
secret protection pipeline diagram.

---

## LLM Proxy -- Guardian Angel for LLMs

An optional LLM proxy endpoint at `/api/v1/llm/chat` forwards requests to an
Ollama (or OpenAI-compatible) backend with an enforced guardian-angel system prompt.

The LLM proxy is designed to make local AI **safe to use freely**:
- Mandatory security-analyst system prompt (cannot be overridden)
- All user prompts and context are scrubbed for secrets before reaching the LLM
- All LLM responses are scrubbed for secrets before reaching the user
- Prompt injection attempts that try to extract secrets are caught and redacted

**Disabled by default.** To enable:

1. Set `LLM_ENABLED=true` on the `cloud` service in `ops/docker-compose.yml`
2. Bring up the stack: `docker-compose up --build -d`
3. Pull a model: `docker-compose exec ollama ollama pull llama3`
4. Test: `curl -X POST http://127.0.0.1:8500/api/v1/llm/chat -H "Content-Type: application/json" -d '{"prompt":"hello"}'`

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_ENABLED` | `false` | Enable/disable the proxy |
| `LLM_BACKEND_URL` | `http://ollama:11434` | LLM service URL (internal Docker network) |
| `LLM_MODEL` | `llama3` | Model name for inference |
| `LLM_MAX_TOKENS` | `1024` | Max tokens per response |
| `LLM_TIMEOUT_SECONDS` | `60` | Request timeout |

**Security**: The Ollama service has **no host port** -- it's reachable only
from the Docker network at `http://ollama:11434`. Never expose it to the internet.

### Request schema

```jsonc
POST /api/v1/llm/chat
{
  "prompt": "Why was agent dev-01 blocked from writing to /etc?",  // required string
  "context": {                      // optional dict -- structured data for the LLM
    "agent_id": "dev-01",
    "recent_events": ["file_write blocked /etc/passwd"]
  },
  "options": {                      // optional dict -- model params forwarded to Ollama
    "temperature": 0.3
  }
}
```

### Example curls

```bash
# Simple question (prompt only)
curl -X POST http://127.0.0.1:8500/api/v1/llm/chat \
  -H "Content-Type: application/json" \
  -d '{"prompt": "What are the top 3 things I should check after a failed deploy?"}'

# Question with structured context + model options
curl -X POST http://127.0.0.1:8500/api/v1/llm/chat \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Summarize the security posture for agent dev-01",
    "context": {
      "agent_id": "dev-01",
      "blocked_events": 12,
      "top_categories": ["shell", "file", "network"]
    },
    "options": {"temperature": 0.2}
  }'
```

---

## CLI Usage

`ops/cli/angelclawctl` is a lightweight Python CLI for operators:

```bash
# Check AngelClaw Node and Cloud health
./ops/cli/angelclawctl status

# Show recent security events with threat matrix
./ops/cli/angelclawctl incidents

# Run AI tool evaluation tests (safe read, secret path, API key)
./ops/cli/angelclawctl test-ai-tool

# Explain a specific event decision
./ops/cli/angelclawctl explain <event-id>
```

Override endpoints via environment:
```bash
ANGELNODE_URL=http://10.0.0.5:8400 CLOUD_URL=http://10.0.0.5:8500 ./ops/cli/angelclawctl status
```

---

## Web Dashboard

The Guardian Angel dashboard is served at **`http://127.0.0.1:8500/ui`**.

It shows:
- **Fleet status** -- registered agents, health, tags, last sync
- **Network trust bar** -- % of agents in verified/conditional/untrusted state
- **Active alerts feed** -- real-time security events with severity icons
- **Threat landscape chart** -- events by category over the last 24h
- **AngelClaw AI chat** -- ask questions about incidents, policies, and security posture

No build step needed -- it's a single HTML file served by FastAPI.

---

## API Endpoints Summary

### ANGELNODE (127.0.0.1:8400)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Liveness probe |
| `/status` | GET | Agent status, counters, policy version |
| `/evaluate` | POST | Evaluate an event against active PolicySet |
| `/ai/openclaw/evaluate_tool` | POST | AI agent tool-call evaluation |

### Cloud API (127.0.0.1:8500)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Liveness probe |
| `/ui` | GET | Guardian Angel web dashboard |
| `/api/v1/agents/register` | POST | Register an ANGELNODE |
| `/api/v1/agents` | GET | List all registered agents |
| `/api/v1/agents/identity` | GET | Agent identity and behavioral fingerprint |
| `/api/v1/events/batch` | POST | Ingest event batch |
| `/api/v1/incidents/recent` | GET | Recent security events feed |
| `/api/v1/policies/current` | GET | Get current policy for an agent |
| `/api/v1/analytics/policy/evolution` | GET | Policy version history |
| `/api/v1/analytics/threat-matrix` | GET | Threat landscape by category |
| `/api/v1/analytics/ai-traffic` | GET | AI tool traffic inspection |
| `/api/v1/analytics/sessions` | GET | Session analytics by agent |
| `/api/v1/assistant/incidents` | GET | Incident summary |
| `/api/v1/assistant/propose` | POST | Policy tightening proposals |
| `/api/v1/assistant/explain` | GET | Event decision explanation |
| `/api/v1/llm/chat` | POST | LLM proxy (disabled by default) |
| `/api/v1/guardian/reports/recent` | GET | Guardian heartbeat reports |
| `/api/v1/guardian/alerts/recent` | GET | Critical pattern alerts |
| `/api/v1/guardian/chat` | POST | Unified guardian chat |
| `/api/v1/guardian/event_context` | GET | Event with history window and AI traffic |
| `/api/v1/guardian/changes` | GET | Policy/config change log |
| `/api/v1/analytics/agent/timeline` | GET | Agent activity timeline |
| `/api/v1/angelclaw/chat` | POST | AngelClaw AI brain (29 intents, context-aware) |
| `/api/v1/angelclaw/preferences` | GET/POST | Operator preferences (autonomy, scan frequency, reporting) |
| `/api/v1/angelclaw/reports/recent` | GET | Guardian reports (last 10) |
| `/api/v1/angelclaw/activity/recent` | GET | Daemon activity log (last 20) |
| `/api/v1/angelclaw/actions/history` | GET | Action audit trail |
| `/api/v1/angelclaw/daemon/status` | GET | Daemon health status |
| `/api/v1/angelclaw/shield/status` | GET | Shield configuration and statistics |
| `/api/v1/angelclaw/shield/assess` | POST | Run full threat assessment |
| `/api/v1/angelclaw/skills/status` | GET | Module integrity report |
| `/api/v1/auth/login` | POST | JWT authentication |
| `/api/v1/auth/logout` | POST | Session termination |
| `/api/v1/auth/change-password` | POST | Password change |

## Access from Any Device

AngelClaw Cloud is accessible from any device with a browser:

- **Linux server** -- Direct access at `http://127.0.0.1:8500/ui` or via SSH tunnel
- **macOS** -- Direct access at `http://127.0.0.1:8500/ui` after Docker install
- **Windows host** -- Install AngelClaw Node for local protection, access Cloud UI via browser
- **Tablets/mobile** (e.g., Xiaomi Pad) -- Access via browser at `http://YOUR-VPS-IP:8500/ui` (requires auth when exposed)
- **SSH + CLI** -- Use `angelclawctl` via SSH for command-line access from any device

To expose the dashboard securely for remote access:

```bash
# Option 1: SSH tunnel (recommended -- no auth bypass needed)
ssh -L 8500:127.0.0.1:8500 user@your-vps

# Option 2: Reverse proxy with HTTPS (nginx/caddy)
# Configure your reverse proxy to forward to 127.0.0.1:8500
# Ensure ANGELCLAW_AUTH_ENABLED=true (default)
```

## License

See [LICENSE](LICENSE).
