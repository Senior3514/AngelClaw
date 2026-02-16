# AngelClaw Architecture Overview

## System Components

```
┌──────────────────────────────────────────────────────────────────┐
│                        AngelClaw Cloud                            │
│  ┌──────────┐  ┌──────────────┐  ┌────────────┐  ┌───────────┐ │
│  │ Agent    │  │ Policy       │  │ Event      │  │ Incident  │ │
│  │ Registry │  │ Distribution │  │ Ingestion  │  │ Mgmt      │ │
│  └──────────┘  └──────────────┘  └────────────┘  └───────────┘ │
│                        │                                         │
│  ┌──────────┐  ┌──────────────┐  ┌────────────┐  ┌───────────┐ │
│  │Analytics │  │ LLM Proxy    │  │ Web UI     │  │ AI Asst   │ │
│  │ Engine   │  │ (Ollama)     │  │ Dashboard  │  │ (r/o)     │ │
│  └──────────┘  └──────────────┘  └────────────┘  └───────────┘ │
│                   REST API (FastAPI)                              │
└───────────────────────┬──────────────────────────────────────────┘
                        │  HTTPS
        ┌───────────────┼───────────────┐
        │               │               │
┌───────▼──────┐ ┌──────▼───────┐ ┌─────▼────────┐
│  ANGELNODE   │ │  ANGELNODE   │ │  ANGELNODE   │
│  (Server A)  │ │  (AI Host B) │ │  (Laptop C)  │
│              │ │              │ │              │
│ ┌──────────┐ │ │ ┌──────────┐ │ │ ┌──────────┐ │
│ │ Policy   │ │ │ │ Policy   │ │ │ │ Policy   │ │
│ │ Engine   │ │ │ │ Engine   │ │ │ │ Engine   │ │
│ └────┬─────┘ │ │ └────┬─────┘ │ │ └────┬─────┘ │
│      │       │ │      │       │ │      │       │
│ ┌────▼─────┐ │ │ ┌────▼─────┐ │ │ ┌────▼─────┐ │
│ │ Sensors  │ │ │ │AI Shield │ │ │ │ Sensors  │ │
│ │ (future) │ │ │ │(OpenClaw)│ │ │ │ (future) │ │
│ └──────────┘ │ │ └──────────┘ │ │ └──────────┘ │
└──────────────┘ └──────────────┘ └──────────────┘
```

## Data Flow

1. **Event Generation**: Sensors or AI shield adapters detect activity and create Events.
2. **Local Evaluation**: The ANGELNODE Policy Engine evaluates each Event against the active PolicySet.
3. **Decision**: The engine returns allow/block/alert/audit and the caller enforces it.
4. **Logging**: Every decision is written to a structured JSON log file.
5. **Telemetry Upload**: Events are batched and sent to AngelClaw Cloud for correlation.
6. **Policy Sync**: ANGELNODEs periodically pull updated PolicySets from Cloud.
7. **SIEM Integration**: Log files are forwarded to Wazuh/SIEM via Filebeat.

## Key Design Principles

- **Guardian Angel, Not Gatekeeper**: AngelClaw enables AI adoption. Most AI operations (analysis, reading, summarizing, reasoning) flow freely. We only intervene for genuinely dangerous actions — destructive commands, secret access, risky external calls.
- **AI-First, Safety-Always**: We embrace AI agents, local models (Ollama), cloud models (Claude, OpenAI), and agent frameworks. AngelClaw focuses on safe orchestration, not restricting which tools people use.
- **Autonomous**: ANGELNODEs enforce policy locally even when Cloud is unreachable.
- **Zero Trust with Zero Friction**: Every action is verified against policy, but the vast majority pass through transparently. Users shouldn't notice AngelClaw until it saves them.
- **Fail-Closed**: If the policy engine is unreachable, actions are blocked. This is the safety net of last resort.
- **Structured Logging**: All decisions are machine-parseable JSON for forensics.
- **Minimal Footprint**: The agent is a single Python process with no heavy dependencies.
- **Secrets Never Leak**: Every layer actively scans and redacts secrets. API keys, tokens, passwords, SSH keys — none of them ever leave the system in raw form.

## Secret Protection Pipeline

AngelClaw **absolutely refuses** to leak secrets, passwords, API keys,
tokens, or credentials — no matter what prompt injection or bypass
technique is attempted. Secret protection is enforced at every layer:

```
                        SECRET PROTECTION LAYERS
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 1 — ANGELNODE (AI Shield)                                 │
│                                                                  │
│  AI agent tool call → secret_scanner.contains_secret()           │
│                     → secret_scanner.is_sensitive_path()          │
│                     → secret_scanner.is_sensitive_key()           │
│                                                                  │
│  If secrets detected:                                            │
│    • accesses_secrets=True → triggers block-ai-tool-secrets rule │
│    • Severity escalated to CRITICAL                              │
│    • Arguments redacted before logging (never written raw)       │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 2 — Cloud AI Assistant                                    │
│                                                                  │
│  GET /explain, GET /incidents, POST /propose                     │
│    • Event details → redact_dict() before response               │
│    • Explanations → redact_secrets() before response             │
│    • No raw secret ever reaches the API consumer                 │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 3 — LLM Proxy (Guardian Angel for LLMs)                   │
│                                                                  │
│  User prompt ──→ redact_secrets() ──→ inject system prompt       │
│                                         │                        │
│                                    Send to LLM                   │
│                                         │                        │
│  LLM response ──→ redact_secrets() ──→ return to user            │
│                                                                  │
│  At no point does a raw secret reach the LLM or the user.        │
└──────────────────────────────────────────────────────────────────┘
```

### What counts as a secret?

| Category | Patterns detected |
|----------|-------------------|
| API keys | `AKIA*`, `ghp_*`, `sk-*`, `sk-ant-*`, `sk_test_*`, `gho_*` |
| Tokens | JWTs (`eyJ...`), bearer tokens, Slack tokens (`xox*-*`) |
| Passwords | Any `password=`, `passwd=`, `pwd=` assignment |
| SSH keys | `-----BEGIN * PRIVATE KEY-----` |
| Cloud creds | AWS credentials, kube config, Docker config |
| Connection strings | `postgres://user:pass@host`, `redis://...` |
| Secret files | `.env`, `.aws/credentials`, `secrets.yml`, `*.pem`, `*.key` |
| Sensitive dict keys | `password`, `secret`, `api_key`, `token`, `credential` |

The scanner lives in `shared/security/secret_scanner.py` and is used by
every component in the stack.

## Analytics Engine

The Cloud API includes a read-only analytics layer (`cloud/api/analytics_routes.py`)
that computes insights from stored events and agent data:

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/agents` | Fleet listing — all registered ANGELNODEs |
| `GET /api/v1/agents/identity` | Agent behavioral fingerprint and risk profile |
| `GET /api/v1/incidents/recent` | Recent security events feed (filterable) |
| `GET /api/v1/analytics/policy/evolution` | Policy version history and rule counts |
| `GET /api/v1/analytics/threat-matrix` | Threat landscape by category and severity |
| `GET /api/v1/analytics/ai-traffic` | AI tool call traffic inspection |
| `GET /api/v1/analytics/sessions` | Session grouping and risk scoring |

All analytics are computed on-the-fly from existing tables (no additional
storage needed). All endpoints are tenant-scoped and read-only.

## V3 Autonomous Guardian

V3 adds autonomous monitoring, a unified chat interface, deeper analytics,
and transparent observability. All new features are **read-only/suggest-only**
— no auto-applying actions.

### Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    AngelClaw Cloud V3                                   │
│                                                                      │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────┐  ┌────────────┐ │
│  │  Guardian    │  │  Event Bus   │  │  Timeline  │  │ Predictive │ │
│  │  Heartbeat   │  │  (Alerts)    │  │  Builder   │  │  Engine    │ │
│  │  (5min loop) │  │  (on ingest) │  │            │  │            │ │
│  └──────┬──────┘  └──────┬──────┘  └─────┬──────┘  └─────┬──────┘ │
│         │                │               │                │         │
│         ▼                ▼               ▼                ▼         │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │              Guardian Chat Orchestrator                       │   │
│  │  (Deterministic + Optional LLM enrichment)                   │   │
│  └──────────────────────────────────────────────────────────────┘   │
│         │                                                           │
│  ┌──────▼──────────────────────────────────────────────────────┐   │
│  │  Guardian API (/api/v1/guardian/*)                            │   │
│  │  reports/recent | alerts/recent | chat | event_context |     │   │
│  │  changes                                                     │   │
│  └──────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

### Guardian Heartbeat Flow

1. Every 5 minutes, the heartbeat service computes fleet health
2. Counts agents by status, events by severity, detects anomalies
3. Stores a `GuardianReportRow` and emits a log line
4. Anomaly types: agents going offline, severity spikes, repeated patterns

### Event Bus (Alert Detection) Flow

1. `ingest_events()` inserts event batch into the database
2. Calls `check_for_alerts()` synchronously after insert
3. Detects patterns: repeated secret exfil, high-severity bursts, agent flapping
4. Creates `GuardianAlertRow` entries for critical patterns

### Guardian Chat Flow

1. User sends prompt via `/api/v1/guardian/chat`
2. Regex-based intent detection classifies the query
3. Deterministic handler gathers data (incidents, agents, threats, etc.)
4. If LLM is enabled, enriches with natural language via `/api/v1/llm/chat`
5. Action suggestions are always deterministic (never LLM-generated)
6. Returns structured response with answer, actions, and references

### New Endpoints (V3)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/guardian/reports/recent` | GET | Guardian heartbeat reports |
| `/api/v1/guardian/alerts/recent` | GET | Critical pattern alerts |
| `/api/v1/guardian/chat` | POST | Unified guardian chat |
| `/api/v1/guardian/event_context` | GET | Event with history window |
| `/api/v1/guardian/changes` | GET | Policy/config change log |
| `/api/v1/analytics/agent/timeline` | GET | Agent activity timeline |

### New DB Tables (V3)

| Table | Purpose |
|-------|---------|
| `guardian_reports` | Periodic heartbeat summaries (fleet health, anomalies, policy changes) |
| `guardian_alerts` | Event-driven critical notifications (secret exfil, severity spikes, flapping) |
| `guardian_changes` | Policy/config change records (immutable audit trail) |

### Deep Context for Decisions

The `event_context` endpoint provides a comprehensive decision bundle:
- **Policy evaluation**: re-evaluates the event against the bootstrap policy
  to show which rule fired, the action taken, and the risk level
- **Agent decision history**: the agent's last 20 events for behavioral context
- **History window**: events from the same agent within +/- 5 minutes
- **Related AI traffic**: AI tool calls in the same time window

### Agent Timeline

Each agent has a chronological timeline (`/api/v1/analytics/agent/timeline`)
that combines events, policy changes, session boundaries, and AI tool calls.
The Web UI shows this as a modal when clicking on an agent in Fleet Status.

### Predictive Threat Vectors

The threat matrix now includes predicted "next attack vectors" based on
deterministic pattern correlation:
- shell + network traffic → data exfiltration risk
- AI tool calls + secret access → lateral movement risk
- auth event spikes → privilege escalation risk
- file modifications + shell activity → persistence risk

Predictions are shown in the dashboard's threat landscape card and are
available via the Guardian Chat.

## Operator Experience

### Web Dashboard (`/ui`)

A two-panel web dashboard at `http://CLOUD:8500/ui` provides:

**Left panel (65%)**:
- Stats row (agents, events, blocked, rules, alerts)
- Guardian Alerts feed (critical pattern notifications)
- Fleet status table (agents, health, version, last seen)
- Threat landscape chart by category
- Recent events feed with severity icons

**Right panel (35%)**:
- Persistent Guardian Chat connected to `/api/v1/guardian/chat`
- Renders action suggestion cards and reference links
- Session history in JS array (in-memory, cleared on refresh)
- Responsive: stacks vertically on mobile

The dashboard is a lightweight HTML file with vanilla JS that calls
the Cloud REST API. No build step or Node.js required.

### CLI Tool (`ops/cli/angelgridctl`)

A Python CLI for operators that wraps the REST APIs:
- `angelgridctl status` — ANGELNODE + Cloud health
- `angelgridctl incidents` — recent events + threat matrix
- `angelgridctl test-ai-tool` — run AI tool evaluation checks
- `angelgridctl explain <event-id>` — explain a decision
