# ANGELGRID – Autonomous AI Defense Fabric

**Guardian angel, not gatekeeper.**

ANGELGRID is a security fabric that lets people use AI agents, local models,
cloud APIs, and automations **as freely as they want** — while quietly protecting
their systems, data, and infrastructure in the background.

We don't block AI. We embrace it. ANGELGRID only intervenes when AI is about to
do something genuinely dangerous: destructive shell commands, accessing secrets,
modifying critical files, or calling risky external endpoints. Everything else —
analysis, reading, summarizing, reasoning, creating — flows freely.

## Repository Structure

```
angelgrid/
├── angelnode/           # Local autonomous protection agent
│   ├── core/            #   Policy engine, evaluation API, structured logging
│   ├── ai_shield/       #   AI agent adapters (OpenClaw, MoltBot, Claude Code)
│   ├── sensors/         #   Future: process/file/network monitors
│   └── config/          #   Default policies and configuration
├── cloud/               # SaaS backend (ANGELGRID Cloud)
│   ├── api/             #   FastAPI REST endpoints + AI Assistant routes
│   ├── ai_assistant/    #   Security analysis (read-only, deterministic)
│   ├── llm_proxy/       #   Optional LLM proxy for Ollama / external models
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
│   ├── docker/          #   Dockerfiles and compose configurations
│   ├── wazuh/           #   Wazuh SIEM integration configs and rules
│   └── infra/           #   Future: Terraform/Pulumi modules
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

## Quick Start

```bash
# Docker Compose (recommended)
cd ops
docker compose up --build

# Or run locally:
pip install -e ".[dev,cloud]"
uvicorn angelnode.core.server:app --host 127.0.0.1 --port 8400
uvicorn cloud.api.server:app --host 127.0.0.1 --port 8500
```

## Core Concepts

- **Guardian Angel** – ANGELGRID protects quietly. Most operations pass through with zero friction — only genuinely dangerous actions get blocked.
- **AI-First** – We support any model (Ollama, Claude, OpenAI), any agent framework (OpenClaw, Claude Code, MoltBot), and any workflow. Use AI however you like.
- **ANGELNODE** – Lightweight agent that evaluates actions locally. Fast, autonomous, always-on.
- **AI Shield** – Mediator for AI agent tool calls. Safe tools flow freely; risky ones get flagged.
- **Fail-Closed** – If the engine is unreachable, actions are blocked. Safety net of last resort, not the normal mode.

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
| `allow-ai-tool-read-file` | AUDIT | `read_file`, `search`, `grep`, `glob`, `list_files` |
| `allow-ai-tool-analysis` | ALLOW | `summarize`, `explain`, `analyze`, `diff`, `status` |
| `alert-ai-tool-shell` | ALERT | `bash`, `shell`, `exec`, `terminal`, `run_command` |
| `block-ai-tool-secrets-access` | BLOCK | Any tool call flagged with `accesses_secrets: true` |
| `alert-ai-tool-write` | ALERT | `write_file`, `edit`, `patch`, `create_file` |
| `alert-ai-tool-burst` | ALERT | >30 AI tool calls within 10 seconds |
| *(no match)* | **BLOCK** | Category default: unknown AI tools are blocked |

### Extended Match Syntax

Policy rules support enhanced `detail_conditions`:

```jsonc
// Exact match (existing)
"key": "value"

// Regex pattern — matches event.details["command"] via re.search
"command_pattern": "rm\\s+-rf"

// List membership — matches if event.details["tool_name"] is in the list
"tool_name_in": ["bash", "shell", "exec"]

// Numeric greater-than — matches if event.details["payload_bytes"] > 1048576
"payload_bytes_gt": 1048576

// Burst detection — triggers when event count exceeds threshold in window
"burst_window_seconds": 10,
"burst_threshold": 20
```

### Overriding / Extending Policies

1. Edit `angelnode/config/default_policy.json` directly (bind-mounted read-only in Docker)
2. Or push updated rules via ANGELGRID Cloud → the ANGELNODE polls every 60s
3. Rules are first-match-wins — put more specific rules **before** generic catch-alls

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

ANGELGRID embraces AI usage — but **absolutely refuses to leak secrets**.

Every layer in the stack scans for and redacts API keys, tokens, passwords,
SSH keys, JWTs, connection strings, and sensitive file paths. The secret
scanner (`shared/security/secret_scanner.py`) is used by:

| Layer | What it does |
|-------|-------------|
| **ANGELNODE AI Shield** | Scans tool-call arguments; blocks if secrets detected; redacts before logging |
| **Cloud AI Assistant** | Redacts event details and explanations in all API responses |
| **LLM Proxy** | Scrubs user prompt *before* LLM, scrubs LLM response *before* user |

**No raw secret ever leaves the system** — not through the API, not through
the LLM, not through event explanations. This is the one rule that is never relaxed.

See [docs/architecture/overview.md](docs/architecture/overview.md) for the full
secret protection pipeline diagram.

---

## LLM Proxy — Guardian Angel for LLMs

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

**Security**: The Ollama service has **no host port** — it's reachable only
from the Docker network at `http://ollama:11434`. Never expose it to the internet.

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
| `/api/v1/agents/register` | POST | Register an ANGELNODE |
| `/api/v1/events/batch` | POST | Ingest event batch |
| `/api/v1/policies/current` | GET | Get current policy for an agent |
| `/api/v1/assistant/incidents` | GET | Incident summary |
| `/api/v1/assistant/propose` | POST | Policy tightening proposals |
| `/api/v1/assistant/explain` | GET | Event decision explanation |
| `/api/v1/llm/chat` | POST | LLM proxy (disabled by default) |

## License

See [LICENSE](LICENSE).
