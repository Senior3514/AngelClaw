# ANGELGRID Architecture Overview

## System Components

```
┌──────────────────────────────────────────────────────────────────┐
│                        ANGELGRID Cloud                           │
│  ┌──────────┐  ┌──────────────┐  ┌────────────┐  ┌───────────┐ │
│  │ Agent    │  │ Policy       │  │ Event      │  │ Incident  │ │
│  │ Registry │  │ Distribution │  │ Ingestion  │  │ Mgmt      │ │
│  └──────────┘  └──────────────┘  └────────────┘  └───────────┘ │
│                        │                                         │
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
5. **Telemetry Upload**: Events are batched and sent to ANGELGRID Cloud for correlation.
6. **Policy Sync**: ANGELNODEs periodically pull updated PolicySets from Cloud.
7. **SIEM Integration**: Log files are forwarded to Wazuh/SIEM via Filebeat.

## Key Design Principles

- **Guardian Angel, Not Gatekeeper**: ANGELGRID enables AI adoption. Most AI operations (analysis, reading, summarizing, reasoning) flow freely. We only intervene for genuinely dangerous actions — destructive commands, secret access, risky external calls.
- **AI-First, Safety-Always**: We embrace AI agents, local models (Ollama), cloud models (Claude, OpenAI), and agent frameworks. ANGELGRID focuses on safe orchestration, not restricting which tools people use.
- **Autonomous**: ANGELNODEs enforce policy locally even when Cloud is unreachable.
- **Zero Trust with Zero Friction**: Every action is verified against policy, but the vast majority pass through transparently. Users shouldn't notice ANGELGRID until it saves them.
- **Fail-Closed**: If the policy engine is unreachable, actions are blocked. This is the safety net of last resort.
- **Structured Logging**: All decisions are machine-parseable JSON for forensics.
- **Minimal Footprint**: The agent is a single Python process with no heavy dependencies.
- **Secrets Never Leak**: Every layer actively scans and redacts secrets. API keys, tokens, passwords, SSH keys — none of them ever leave the system in raw form.

## Secret Protection Pipeline

ANGELGRID **absolutely refuses** to leak secrets, passwords, API keys,
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
