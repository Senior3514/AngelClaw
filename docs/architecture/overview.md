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
