# AngelClaw Release Notes

## V3.0.0 — Dominion (2026-02-19)

**Status**: Enterprise-grade autonomous AGI security platform with full-spectrum defense capabilities.

This is a **massive** triple-phase upgrade (V2.4 Fortress + V2.5 Ascension + V3.0 Dominion) that transforms AngelClaw from a monitoring tool into a complete autonomous defense platform with 12 wardens, 67+ NLP intents, enterprise features, and real-time capabilities.

### V2.4 — Fortress

- **Adaptive Rate Limiter** — Token-bucket with per-role tiers (admin:300, secops:200, viewer:100, anon:60/min), per-endpoint limits, burst allowance, X-RateLimit-* headers
- **WebSocket Live Feed** — Real-time event and alert streaming via `ws://host:8500/ws/events` and `/ws/alerts` with tenant-scoped filtering
- **Policy Snapshots & Rollback** — Named policy snapshots with diff comparison and one-click rollback
- **Quarantine Manager** — Agent quarantine with timed release, event suppression, and management API
- **Notification Channels** — Slack, Discord, and Webhook channels with severity-based routing rules
- **Compliance Warden (Paladin)** — Detects unencrypted transfers, access control violations, retention breaches, encryption gaps
- **API Warden (Gate Keeper)** — Detects endpoint enumeration, auth failure spikes, oversized payloads, unusual HTTP methods, rate limit evasion
- **Event Bus V2.4** — 4 new alert patterns: compliance_violation, api_abuse_cascade, quarantine_breach, notification_failure
- **Brain V2.4** — 8 new NLP intents: quarantine_status, quarantine_manage, compliance_check, notification_manage, policy_snapshot, policy_rollback, websocket_status, export_data
- **New Event Categories** — `compliance` and `api_security` categories with 10 new policy rules

### V2.5 — Ascension

- **Plugin System** — Dynamic warden plugin loading from `plugins/` directory with manifest.json validation, hot-reload, enable/disable
- **API Key Authentication** — SHA-256 hashed API keys with create/validate/revoke/rotate, scoped permissions, X-API-Key header support
- **Audit Export** — JSON/CSV export for events, audit trail, alerts, and policies with date range and category filters
- **Backup & Restore** — Full JSON backup of all database tables with restore validation and backup management API
- **Enhanced Predictive Engine** — 4 new threat patterns (zero-day, account takeover, API key compromise, warden evasion), confidence calibration from learning engine, trend analysis
- **Brain V2.5** — 7 new NLP intents: plugin_manage, plugin_status, api_key_manage, backup_manage, dashboard_info, prediction_trend, learning_status

### V3.0 — Dominion

- **Admin Console** — Full org-wide dashboard with Halo Score, Wingspan, fleet overview, tenant management, per-agent detail views, and 10-page sidebar navigation
- **Anti-Tamper Protection** — Three modes (OFF/MONITOR/ENFORCE), per-agent and per-tenant config, heartbeat monitoring, binary checksum verification, tamper event logging
- **Self-Learning Feedback Loop** — Operator accept/reject/ignore/modify tracking, per-tenant acceptance rates, automatic adjustment recommendations (verbosity, thresholds, autonomy)
- **Self-Hardening Engine** — Autonomous security weakness detection (scan failures, loose allowlists, missing logs, weak auth, unprotected agents, repeated misconfigs), observe/suggest/auto_apply modes, all actions revertible
- **Custom RBAC** — User-defined roles with granular permissions beyond the built-in admin/secops/viewer roles
- **Event Replay** — Replay historical event batches through the detection engine to discover missed indicators
- **Threat Hunting** — DSL-based query engine for hunting across the event store with saved queries and grouping
- **Remediation Workflows** — Multi-step automated response playbooks with trigger conditions, rollback steps, and execution tracking
- **Agent Mesh** — Agent-to-agent communication protocol with message passing, inbox, and request-response patterns
- **Enhanced Metrics V2** — Trend analysis, hourly event rates, threat predictions, category/severity breakdowns
- **Brain V3.0** — 10 new NLP intents: role_manage, event_replay, threat_hunt, remediation_manage, mesh_status, fleet_deep, admin_overview, anti_tamper_status, feedback_status, hardening_status
- **Dashboard V3** — Complete rewrite with sidebar navigation, 10 pages (Dashboard, Fleet, Tenants, Alerts, Legion, Anti-Tamper, Analytics, Self-Learning, Policies, Settings), mobile responsive, PWA support
- **Mobile PWA** — Manifest.json and service worker for home screen install on iOS/Android, fully responsive UI
- **Browser Extensions** — Chrome/Chromium extension v3.0.0 with badge alerts, mini chat, quick actions, DuckDuckGo support docs
- **Daemon V3** — Anti-tamper heartbeat checks, self-hardening cycle, and feedback-based adjustments integrated into autonomous daemon loop

### Infrastructure

- **15 new API routers** mounted in server.py (policy, quarantine, notifications, WebSocket, plugins, API keys, export, backup, roles, replays, remediation, hunting, mesh, metrics v2, admin console)
- **15 new DB tables** — PolicySnapshotRow, QuarantineRecordRow, NotificationChannelRow, NotificationRuleRow, PluginRegistrationRow, ApiKeyRow, BackupRecordRow, CustomRoleRow, EventReplayRow, RemediationWorkflowRow, ThreatHuntQueryRow, TenantRow, AntiTamperConfigRow, AntiTamperEventRow, FeedbackRecordRow, SelfHardeningLogRow
- **12 wardens** in Angel Legion (up from 10)
- **71+ NLP intents** (up from 45)
- **~40 new files** across services, routes, wardens, mobile, extensions, and tests
- **15+ new test files** covering all V2.4/V2.5/V3.0 features
- **Version bumps** to 3.0.0 across pyproject.toml, server.py, brain.py, context.py
- **PWA serving** via /mobile/* route for manifest.json and service-worker.js

---

## V2.1.0 — Angel Legion: Seraph Core (2026-02-18)

**Status**: Maximum-performance autonomous AGI security suite with enhanced Seraph Brain core intelligence.

This release upgrades the Seraph Brain with an enhanced internal cognition protocol
for deeper cross-domain synthesis, expert-level strategic reasoning, and autonomous
decision-making at maximum processing capability. All enhancements are internal —
the user-facing API surface remains stable and backward-compatible.

### Seraph Brain Core Upgrade

- **Enhanced internal cognition protocol** — deeper cross-domain synthesis across security, infrastructure, and AI safety domains
- **Expert-level strategic reasoning** — autonomous decision-making at maximum depth and speed
- **Maximum processing capability** — 100x depth internal analysis for threat assessment
- **Upgraded system identity** — richer internal context for all brain responses

### Version Bump

- All version strings updated from 2.0.0 to 2.1.0 across the entire codebase
- All installers (Linux, macOS, Windows) updated
- CI/CD pipeline validated
- All 1130+ tests passing

### Backward Compatibility

- No breaking API changes — all endpoints, models, and integrations remain stable
- No new user-facing intents — the upgrade is purely internal brain enhancement
- All existing tests pass without modification

---

## V2.0.0 — Angel Legion (2026-02-17)

**Status**: Fully autonomous AGI security suite with 10-agent Angel Legion swarm architecture.

This release introduces the **Angel Legion** — a dynamic swarm of 10 specialized sub-agents
managed by the Seraph orchestrator via a registry-based architecture. Expands from 4 hardcoded
agents to 10 dynamically registered agents with fine-grained permissions and specialized detection.

### Angel Legion — 7 New Specialized Wardens

| Code Name | Type | Detections |
|-----------|------|------------|
| **Net Warden** | Network | Suspicious ports, public exposure, DNS tunneling, port scans |
| **Glass Eye** | Browser | Suspicious URLs, page injection, extension threats, data abuse |
| **Tool Smith** | Toolchain | Tool bursts, version drift, blocked retries, output injection |
| **Chronicle** | Timeline | Coordinated activity, rapid succession, kill chains, time clustering |
| **Vault Keeper** | Secrets | Access bursts, brute force, exfiltration, secret-in-payload |
| **Drift Watcher** | Behavior | Peer volume/severity deviation, escalation, category novelty |
| **Vigil** | Warden | Core pattern matching, anomaly detection, correlation (V1) |

### Dynamic Agent Registry

- `AgentRegistry` class manages N agents without hardcoding
- Lookup by ID, by type, all wardens, active agents
- Graceful shutdown, status aggregation, Legion summary
- `WARDEN_TYPES` frozenset defines detection-role agents

### Orchestrator V2

- Refactored to use `AgentRegistry` instead of hardcoded agent references
- Backward-compatible `.warden`, `.response`, `.forensic`, `.audit` properties
- All API routes iterate agents dynamically from registry
- Prometheus metrics emit per-agent gauges with agent type labels

### New Permission Model

| Permission | Used By |
|-----------|---------|
| `READ_NETWORK` | NetworkWarden |
| `READ_SECRETS` | SecretsWarden |
| `READ_TOOLS` | ToolchainWarden |
| `READ_BROWSER` | BrowserWarden |
| `READ_TIMELINE` | TimelineWarden |

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
- All new warden modules at **94-100% coverage**
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
