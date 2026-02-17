# AngelClaw Release Notes

## V2.0.0 — Angel Legion (2026-02-17)

**Status**: Fully autonomous AGI security suite with 10-agent Angel Legion swarm architecture.

This release introduces the **Angel Legion** — a dynamic swarm of 10 specialized sub-agents
managed by the Seraph orchestrator via a registry-based architecture. Expands from 4 hardcoded
agents to 10 dynamically registered agents with fine-grained permissions and specialized detection.

### Angel Legion — 7 New Specialized Sentinels

| Code Name | Type | Detections |
|-----------|------|------------|
| **Net Warden** | Network | Suspicious ports, public exposure, DNS tunneling, port scans |
| **Glass Eye** | Browser | Suspicious URLs, page injection, extension threats, data abuse |
| **Tool Smith** | Toolchain | Tool bursts, version drift, blocked retries, output injection |
| **Chronicle** | Timeline | Coordinated activity, rapid succession, kill chains, time clustering |
| **Vault Keeper** | Secrets | Access bursts, brute force, exfiltration, secret-in-payload |
| **Drift Watcher** | Behavior | Peer volume/severity deviation, escalation, category novelty |
| **Vigil** | Sentinel | Core pattern matching, anomaly detection, correlation (V1) |

### Dynamic Agent Registry

- `AgentRegistry` class manages N agents without hardcoding
- Lookup by ID, by type, all sentinels, active agents
- Graceful shutdown, status aggregation, Legion summary
- `SENTINEL_TYPES` frozenset defines detection-role agents

### Orchestrator V2

- Refactored to use `AgentRegistry` instead of hardcoded agent references
- Backward-compatible `.sentinel`, `.response`, `.forensic`, `.audit` properties
- All API routes iterate agents dynamically from registry
- Prometheus metrics emit per-agent gauges with agent type labels

### New Permission Model

| Permission | Used By |
|-----------|---------|
| `READ_NETWORK` | NetworkSentinel |
| `READ_SECRETS` | SecretsSentinel |
| `READ_TOOLS` | ToolchainSentinel |
| `READ_BROWSER` | BrowserSentinel |
| `READ_TIMELINE` | TimelineSentinel |

### Serenity Scale (AngelClaw-themed Risk Levels)

| Level | Severity | Color |
|-------|----------|-------|
| Serene | info | Clear |
| Whisper | low | Green |
| Murmur | medium | Yellow |
| Disturbed | high | Orange |
| Storm | critical | Red |

### Base Agent Enhancements

- `SubAgent.execute()` wraps all tasks with timeout enforcement
- Automatic status tracking (idle → busy → idle)
- Error handling for timeouts, permission errors, and general exceptions
- Duration tracking in milliseconds

### Test Results

- **1130 tests passing** (103 new Angel Legion tests)
- All new sentinel modules at **94-100% coverage**
- Overall coverage: **84%**

### Documentation

- `docs/angelclaw_lexicon.md` — Canonical terminology reference for the Angel Legion

---

## V0.8.0 — AngelClaw AGI Guardian (2026-02-16)

**Status**: Enterprise-grade autonomous AI security suite with ClawSec-inspired threat detection.

This release transforms AngelClaw into a full AGI Guardian with unified security modules,
comprehensive threat detection inspired by ClawSec/OpenClaw/Moltbot research, and 304
automated tests covering advanced attack scenarios.

### ClawSec-Inspired Unified Security Module (`cloud/angelclaw/security.py`)

- **PromptDefense**: Wraps shield.py with scan-and-block workflow, risk classification, stats tracking
- **ToolGuard**: Tool call validation with blocklist (20 tools), allowlist (16 tools), burst detection (20/10s)
- **SkillIntegrity**: SHA256 runtime integrity verification with auto-restore, tamper-evident audit chain
- **WorkspaceIsolation**: Path traversal detection, sensitive read/write blocklists, cross-tenant detection
- **RiskScoring**: Unified 0-100 scoring combining injection (30), leakage (25), evil AGI (25), trifecta (15), attack chain (5)
- **AdvisoryMonitor**: In-memory advisory registry with built-in advisories and custom rule support

### Enhanced Daemon Security Checks

- ClawSec-aligned continuous security monitoring in the autonomous daemon loop
- Real-time prompt injection detection in AI tool events
- Suspicious tool usage pattern detection (>50 events, >15 unique tools in 30 min)
- Data exfiltration monitoring via shield's leakage detection
- Exposed service indicators check

### Advanced Security Test Suite (101 new tests)

- **TestPromptInjectionAdvanced**: 22 tests covering multi-layer injection, encoded payloads, indirect injection
- **TestSecretExfilAttempts**: 11 tests for social engineering, encoded secrets, multi-step exfiltration
- **TestSelfProtectionDisable**: 10 tests verifying AngelClaw cannot be tricked into disabling itself
- **TestSecretScannerComprehensive**: 38 tests covering 20+ secret formats and edge cases
- **TestShieldEvasionAttempts**: 20 tests for obfuscation, encoding, attack chains, evasion combos

### Documentation

- `docs/angelclaw_vs_clawsec.md` — Comprehensive capability mapping: ClawSec vs AngelClaw
- `docs/security_model.md` — Enhanced with hard-coded invariants, 11 agentic AI attack vectors,
  defense-in-depth architecture, prompt injection deep dive, expanded RBAC model (3 roles)

### Branding

- All user-facing docstrings updated from "ANGELGRID" to "AngelClaw"
- Internal package name (`angelgrid`) and env vars (`ANGELGRID_*`) preserved for compatibility
- Version 0.8.0 across server, pyproject.toml, health endpoint, and installers

### Test Results

- **304 tests passing** (39 shield + 101 advanced security + 164 existing)
- Zero failures

---

## V0.4.0 — AngelClaw V3 (2026-02-16)

**Status**: Production-ready with auth, RBAC, and secure-by-default binding.

This release rebrands the project from ANGELGRID to **AngelClaw**, adds real
authentication and authorization, introduces Guardian Scan for automated
exposure analysis, and wires webhook/SIEM integration for external alerting.

### Rebranding

- All user-facing text renamed from ANGELGRID to **AngelClaw**
- Python package name (`angelgrid`) preserved for internal compatibility
- Environment variable names (`ANGELGRID_*`) preserved for backward compatibility;
  new `ANGELCLAW_*` aliases added for auth, binding, and webhook configuration

### Authentication & RBAC

- JWT-based auth with HMAC-SHA256 signing (no external dependency)
- Two roles: **Viewer** (read-only) and **Operator** (full control)
- Login page in the dashboard with localStorage JWT persistence
- Bearer token support for service-to-service communication
- Auth enabled by default (`ANGELCLAW_AUTH_ENABLED=true`)
- New endpoints: `POST /api/v1/auth/login`, `GET /api/v1/auth/me`, `POST /api/v1/auth/logout`

### Secure-by-Default Binding

- Cloud API and Docker Compose now bind to `127.0.0.1` by default (was `0.0.0.0`)
- Public exposure requires explicit `ANGELCLAW_BIND_HOST=0.0.0.0` + auth enabled

### Guardian Scan

- New chat command: "scan", "audit", "check system", "harden"
- Runs 7 automated security checks: stale agents, secret access attempts,
  auth configuration, binding exposure, severity spikes, no agents, no webhook
- Returns structured risk assessments sorted by severity with hardening suggestions

### Webhook / SIEM Integration

- New `WebhookSink` service pushes critical/high alerts to any HTTP(S) endpoint
- HMAC-SHA256 payload signing via `X-AngelClaw-Signature` header
- Wired into the event bus — fires automatically on Guardian Alert creation
- Integration docs for Wazuh, Splunk HEC, and Elasticsearch/Kibana

### Event Bus — Critical Pattern Detection

- Detects repeated secret exfiltration (>=2 secret-access events in a batch)
- Detects high-severity burst (>=5 high/critical from one agent in a batch)
- Detects agent flapping (>=8 distinct event types from one agent)
- Creates `GuardianAlertRow` entries with full event correlation

### Dashboard Enhancements

- Login page with username/password form
- User badge in header showing username + role
- Logout button
- Auth-aware API calls (auto-redirect to login on 401)
- AngelClaw V3 branding throughout

### Documentation

- `docs/product_overview.md` — full product overview and architecture
- `docs/security_model.md` — threat model, secret protection pipeline, auth model
- `docs/integrations.md` — webhook config, HMAC verification, Wazuh/Splunk/Elastic guides
- All README files updated with AngelClaw branding

### New Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `ANGELCLAW_AUTH_ENABLED` | `true` | Enable/disable authentication |
| `ANGELCLAW_AUTH_MODE` | `local` | Auth mode: `local` or `bearer` |
| `ANGELCLAW_ADMIN_USER` | `admin` | Admin username |
| `ANGELCLAW_ADMIN_PASSWORD` | *(required)* | Admin password |
| `ANGELCLAW_VIEWER_USER` | `viewer` | Viewer username |
| `ANGELCLAW_VIEWER_PASSWORD` | *(optional)* | Viewer password |
| `ANGELCLAW_JWT_SECRET` | *(auto-generated)* | JWT signing key |
| `ANGELCLAW_BIND_HOST` | `127.0.0.1` | Server bind address |
| `ANGELCLAW_BIND_PORT` | `8500` | Server bind port |
| `ANGELCLAW_WEBHOOK_URL` | *(empty)* | Webhook endpoint for alerts |
| `ANGELCLAW_WEBHOOK_SECRET` | *(empty)* | HMAC signing secret |

---

## V0.3.0 — V1 Pilot Release (2026-02-16)

**Status**: Internal testing / pilot deployment on VPS.

This is the first feature-complete release of ANGELGRID, running on a
single Ubuntu VPS with Docker Compose. It is intended for internal
testing and iteration — not production deployment.

### Major Features

**Policy Engine (ANGELNODE)**
- 28-rule bootstrap policy with first-match-wins evaluation
- Extended match syntax: `_pattern` (regex), `_in` (list), `_gt` (numeric), burst detection
- Per-category default-deny (zero-trust) with 11 categories
- Cloud sync: auto-register on startup, poll for policy updates every 60s
- Fail-closed: if engine unreachable, all actions blocked

**AI Shield**
- AI agent tool-call evaluation via `/ai/openclaw/evaluate_tool`
- Comprehensive secret detection in tool arguments (API keys, tokens, passwords, paths)
- Secret-touching operations blocked FIRST (before tool-name allowlists)
- Arguments redacted before logging — secrets never written to disk

**Secret Protection (end-to-end)**
- `shared/security/secret_scanner.py`: 17 value patterns, 7 key patterns, 16 path patterns
- Layer 1 (ANGELNODE): detect + block + redact in tool calls
- Layer 2 (Cloud AI Assistant): redact event details + explanations in responses
- Layer 3 (LLM Proxy): scrub prompt before LLM, scrub response before user
- 53 automated tests, all passing

**Cloud API (v0.3.0)**
- Agent registration + policy distribution
- Event ingestion + incident management
- AI Assistant: incident summary, policy proposals, event explanation
- LLM Proxy: Ollama integration with guardian-angel system prompt (disabled by default)
- Analytics: fleet listing, threat matrix, policy evolution, AI traffic, sessions, agent identity
- Health endpoint at `/health`

**Web Dashboard**
- Guardian Angel dashboard at `/ui`
- Fleet status table, network trust bar, active alerts feed
- Threat landscape chart, ANGELGRID AI chat interface
- Single HTML file — no build step, no Node.js

**CLI Tool**
- `angelgridctl status` — health + fleet overview
- `angelgridctl incidents` — recent events + threat matrix
- `angelgridctl test-ai-tool` — 4 automated policy checks
- `angelgridctl explain <event-id>` — decision explanation

**Infrastructure**
- Docker Compose: ANGELNODE + Cloud + Ollama (internal-only)
- systemd service: auto-start on boot, graceful shutdown
- Health watchdog: checks every 2 minutes, auto-restarts if down
- All ports bound to 127.0.0.1 (loopback only)

### Known Limitations (V1 Pilot)

- Single-VPS deployment only (no multi-node yet)
- SQLite database (switch to PostgreSQL for production)
- LLM proxy disabled by default (requires `LLM_ENABLED=true` + model pull)
- No TLS/HTTPS on API endpoints (use reverse proxy for production)
- No JWT/OAuth2 auth (using X-TENANT-ID header for dev)
- Web dashboard is a skeleton — functional but minimal styling
- Sensors (process, file, network monitors) are stubs

### What's Next

- Linux and Windows installers for easy deployment
- Multi-node agent registration with remote Cloud
- TLS + auth middleware
- Production database (PostgreSQL)
- Richer web dashboard with historical charts
- Wazuh SIEM integration testing

---

*AngelClaw: Guardian angel, not gatekeeper.*
*We will iterate tomorrow.*
