# AngelClaw — Autonomous AI Defense Guardian

**Your AGI-era shield for safe AI adoption**

---

## Who Is AngelClaw For?

| Audience | Use Case |
|---|---|
| **DevOps Teams** | Protect production infrastructure from AI-initiated destructive commands, enforce change-management policies automatically |
| **Security Teams** | Monitor AI agent activity in real time, detect prompt injection and secret exfiltration, integrate alerts with existing SIEM pipelines |
| **AI Platform Operators** | Safely run Ollama, Claude, OpenAI, or any AI framework at scale without restricting productivity |

---

## Core Promise

> Let people use AI freely while quietly protecting systems and data.

AngelClaw sits between your AI agents and the resources they touch. It evaluates every action — shell commands, file access, network calls, database queries, tool invocations — against a policy engine and intervenes **only when genuinely dangerous behavior is detected**.

Reading, analyzing, summarizing, and reasoning are always free. No speed bumps, no unnecessary friction.

---

## Key Capabilities

| Capability | Description |
|---|---|
| **Policy Engine** | 28+ rules evaluated top-down (first match wins). Supports regex patterns, list membership, numeric thresholds, and sliding-window burst detection. Zero-trust default-deny for high-risk categories; explicit allowlists for known-safe operations. |
| **AI Shield** | Intercepts AI tool calls before execution. Blocks secret access, alerts on shell invocations, audits file writes — all without breaking the AI workflow. |
| **Guardian Chat** | Natural-language security assistant. Ask "why was this blocked?" or "summarize today's incidents" and get instant, context-aware answers with full event timelines. |
| **Predictive Threat Engine** | Detects anomaly patterns and burst activity before they escalate. Alerts on >20 shell execs in 10 seconds or >30 AI tool calls in 10 seconds. |
| **Webhook / SIEM Integration** | Push critical alerts to any webhook endpoint with HMAC-SHA256 signing. Native support for Wazuh, Splunk HEC, and Elastic. |
| **Auth and RBAC** | JWT-based authentication with Viewer (read-only) and Operator (full control) roles. Bearer token support for service-to-service communication. |
| **Secret Scanner** | 3-layer detection pipeline: value patterns (AWS keys, GitHub PATs, JWTs, SSH keys, etc.), sensitive key names, and sensitive file paths. Secrets are redacted at every output boundary — AngelClaw never leaks raw credentials. |

---

## Architecture Summary

```
+---------------------+         +------------------------+
|     ANGELNODE        |         |   AngelClaw Cloud      |
|  (Local Agent)       | <-----> |  (Central Management)  |
|                     |   sync   |                        |
|  - Policy Engine    |         |  - Event Store (SQL)   |
|  - AI Shield        |         |  - AI Assistant API    |
|  - Decision Logger  |         |  - Guardian Chat       |
|  - Burst Tracker    |         |  - Webhook Sink        |
|                     |         |  - Auth / RBAC         |
|  127.0.0.1:8400     |         |  127.0.0.1:8500        |
+---------------------+         +------------------------+
```

**ANGELNODE** runs on each host where AI agents operate. It intercepts actions locally, evaluates them against the loaded policy, and logs every decision. Latency-sensitive; designed for inline evaluation.

**AngelClaw Cloud** aggregates events from all nodes, provides the management dashboard, runs the AI assistant for incident analysis and policy proposals, and dispatches webhook alerts to external systems.

Both components bind to `127.0.0.1` by default. Public exposure requires explicit configuration and authentication.

---

## Philosophy

> **Guardian angel, not gatekeeper. Seatbelt, not speed bump.**

- We embrace AI usage. People should use AI agents, Ollama, Claude Code, any model, as much as they want.
- AngelClaw protects quietly in the background.
- Only intervene for genuinely dangerous actions: destructive commands, secret access, critical file modifications, risky external calls.
- Analysis, reading, summarizing, reasoning — always free, no restrictions.
- When something is blocked: explain why, suggest a safe alternative, help users configure targeted exceptions.
- Never suggest broad restrictions — prefer precise allowlist rules.

---

## Model-Agnostic by Design

AngelClaw does not care which AI model or framework you use. It focuses on **safe orchestration**, not model selection.

| Supported | Examples |
|---|---|
| Local models | Ollama, llama.cpp, vLLM |
| Cloud APIs | OpenAI, Anthropic Claude, Google Gemini |
| Agent frameworks | LangChain, CrewAI, AutoGPT, Claude Code |
| Custom tools | Any tool-calling agent that invokes shell, file, network, or DB operations |

The policy engine evaluates **actions**, not models. Swap your LLM backend anytime; your security posture stays the same.
