# ANGELGRID AI – Philosophy, UX & Safety Boundaries

## Our Philosophy: Guardian Angel, Not Gatekeeper

ANGELGRID exists to **enable** AI adoption — not restrict it.

Most "AI security" tools try to limit, block, or slow down AI usage.
ANGELGRID takes the opposite approach: we want people to use AI agents,
Claude Code, Ollama, web AI apps, and automations **as much as they like**.
ANGELGRID's job is to be the invisible safety net — the "guardian angel"
that protects systems, data, and infrastructure in the background, without
killing creativity or making AI adoption painful.

### Core Design Principles

1. **AI-first, safety-always.** We never try to "stop AI" in general.
   Analysis, reading, summarizing, reasoning, and creative work flow freely.
   ANGELGRID only intervenes when AI is about to do something genuinely
   dangerous: destructive shell commands, modifying critical system files,
   accessing secrets, or calling risky external endpoints.

2. **Human-friendly UX.** The ANGELGRID assistant is a friendly guide, not
   a wall of error messages. When something is blocked, it explains *why*
   in plain language and suggests a safe alternative. Users should never
   need deep security expertise to work with ANGELGRID.

3. **Embrace variety of models.** Local models (Ollama), cloud models
   (Claude, OpenAI-compatible), agent frameworks (OpenClaw, MoltBot,
   Claude Code) — ANGELGRID doesn't care which model you use. We focus
   on safe orchestration and control, not on picking winners.

4. **Quiet protection.** The best security is the kind you don't notice.
   ANGELGRID should feel like a seatbelt, not a speed bump. Most AI
   operations pass through with zero friction — only truly risky actions
   get flagged or blocked.

---

## The Guardian Angel UX

The ANGELGRID AI assistant acts as a friendly security companion in the
Cloud console:

```
┌─────────────────────────────────────────────────────┐
│  ANGELGRID AI                                  [?]  │
├─────────────────────────────────────────────────────┤
│                                                     │
│  User: "Why was my AI agent's file write blocked?"  │
│                                                     │
│  AI: "Your agent tried to write to /etc/passwd,     │
│   which is a system-critical file. ANGELGRID         │
│   blocked it to protect your system.                │
│                                                     │
│   To achieve your goal safely, you could:           │
│   • Write to a user-space path like ~/config/       │
│   • Add a policy rule to allow writes to a          │
│     specific /etc/ file if you really need it       │
│                                                     │
│   Want me to help set up a targeted rule?"          │
│                                                     │
│  User: "Yes, propose a rule for /etc/myapp.conf"    │
│                                                     │
│  AI: "Here's a proposed rule:                       │
│   • allow-file-write-myapp-conf                     │
│   • Allows writes only to /etc/myapp.conf           │
│   • All other /etc/ writes remain blocked           │
│                                                     │
│   ⚠ This is a proposal. Click 'Apply' to submit    │
│   for approval."                                    │
│                                                     │
│  [Apply Proposal]  [Dismiss]  [Export]              │
│                                                     │
└─────────────────────────────────────────────────────┘
```

Key UX principles:
- **Explain, don't just deny.** Every block comes with a human-readable reason.
- **Suggest alternatives.** Help the user achieve their goal safely.
- **Make policy changes easy.** Users shouldn't need to hand-edit JSON to
  configure ANGELGRID — the assistant guides them through it.

---

## Separation of Concerns: Analysis vs. Action

### Analysis (ANGELGRID AI does freely — no restrictions)

- Summarize incidents, events, and trends
- Explain policy rules and why decisions were made
- Identify gaps in policy coverage
- Correlate events across agents
- Generate risk assessments
- Propose policy changes as structured data
- Help users understand their security posture

### Action (requires explicit human approval)

- **Policy edits** — Any modification to a PolicySet (add/remove/modify rules)
- **Policy deployment** — Pushing a new PolicySet version to agents
- **Agent configuration changes** — Modifying agent settings or tags
- **Incident status changes** — Closing or reclassifying incidents

**There is no "auto-apply" mode.** Even if an admin requests it, the system
architecture enforces the approval step at the API layer.

---

## Approval Workflow

```
  ANGELGRID AI          Cloud API            Approver           Audit Log
       │                    │                    │                   │
       │  propose_changes() │                    │                   │
       │───────────────────>│                    │                   │
       │  ProposedChanges   │                    │                   │
       │<───────────────────│                    │                   │
       │                    │                    │                   │
       │         [User clicks "Apply"]           │                   │
       │                    │                    │                   │
       │                    │  approval_request  │                   │
       │                    │───────────────────>│                   │
       │                    │                    │                   │
       │                    │    approved/denied │                   │
       │                    │<───────────────────│                   │
       │                    │                    │                   │
       │                    │         log ChangeEvent               │
       │                    │──────────────────────────────────────>│
       │                    │                    │                   │
       │                    │  [if approved: apply policy]           │
       │                    │                    │                   │
```

## ChangeEvent Logging

Every policy or configuration change — whether proposed by ANGELGRID AI or
made manually — is logged as a **ChangeEvent** with:

| Field             | Description                                    |
|-------------------|------------------------------------------------|
| `change_type`     | `policy_edit`, `policy_deploy`, `config_change` |
| `proposed_by`     | `angelgrid_ai` or `user:<email>`                |
| `approved_by`     | `user:<email>` (required)                       |
| `timestamp`       | When the change was applied                     |
| `before_snapshot` | PolicySet version hash before the change        |
| `after_snapshot`  | PolicySet version hash after the change         |
| `diff`            | Structured diff of rules added/removed/modified |

ChangeEvents are immutable and cannot be deleted or modified.  They serve
as the audit trail for all policy mutations in the system.

---

## Safety Guarantees

1. **No direct database writes** from the assistant module — the code is
   architecturally read-only (queries only, no ORM mutations).

2. **Multi-backend LLM support** — the LLM proxy supports Ollama (local),
   Claude, and OpenAI-compatible APIs. When an LLM is used, it operates
   behind the same analysis-only boundary with an enforced system prompt.

3. **Tenant isolation** — all queries are scoped by tenant_id.  The
   assistant cannot access data from other tenants.

4. **No secret exposure** — secrets are actively scanned and redacted at
   every layer (ANGELNODE, AI Assistant, LLM Proxy). Even if raw secrets
   exist in logs or database, ANGELGRID redacts them before any response
   leaves the system. See the Secret Protection section below.

5. **LLM containment** — the LLM proxy scrubs both input (user prompt,
   context) and output (LLM response) for secrets. The system prompt is
   mandatory and cannot be overridden. The LLM backend (Ollama) has no
   host port and is reachable only from the Docker network.

---

## Secret Protection: The One Hard Line

ANGELGRID embraces AI usage. We let AI agents read, write, analyze, and
create freely. But there is **one absolute rule**: secrets never leak.

No matter what prompt injection, social engineering, or bypass technique
is attempted, ANGELGRID will **never** return raw secret values through
any API endpoint, LLM response, or event explanation.

### How it works

Every layer in the stack runs secrets through `shared/security/secret_scanner.py`:

1. **ANGELNODE AI Shield** — scans tool-call arguments for API keys, tokens,
   passwords, and sensitive file paths. If found, the tool call is blocked
   and severity is escalated to CRITICAL.

2. **Cloud AI Assistant** — redacts event details and explanations before
   returning them to API consumers. Even if the database contains raw
   secrets, they are scrubbed in the response.

3. **LLM Proxy** — scrubs the user's prompt and context *before* sending
   to the LLM, then scrubs the LLM's response *before* returning to the
   user. Secrets never reach the model, and even if the model hallucinates
   a secret-like string, it gets caught on the way back.

### What gets caught

API keys (`AKIA*`, `ghp_*`, `sk-*`), JWTs, passwords, SSH private keys,
database connection strings, bearer tokens, Slack tokens, Stripe keys,
sensitive file paths (`.env`, `.ssh/*`, `.aws/credentials`), and any dict
key named `password`, `secret`, `token`, `api_key`, or `credential`.

### The philosophy

This isn't about distrust — it's about making AI **safer to use freely**.
When developers know that ANGELGRID has their back on secrets, they can
give AI agents more freedom, not less.

---

## V2: Guardian Chat & Autonomous Reports

### Guardian Chat

The V2 dashboard features a persistent Guardian Chat panel that provides a
unified interface to all ANGELGRID analytics and insights.

**Intent Detection**: The chat uses regex-based intent detection to classify
user queries into categories:

| Intent | Example queries |
|--------|----------------|
| `incidents` | "What happened recently?" "Show me incidents" |
| `agent_status` | "How's my fleet?" "Which agents are offline?" |
| `threats` | "Any threat predictions?" "What risks do you see?" |
| `alerts` | "Any guardian alerts?" "Critical notifications?" |
| `changes` | "What changed recently?" "Policy updates?" |
| `propose` | "Suggest policy improvements" |
| `explain` | "Why was this event blocked?" |
| `help` | "What can you do?" |
| `about` | "Who are you?" |

**Dual Mode**:
- **Deterministic (default)**: Each intent triggers a handler that queries
  the database and formats a response using template strings.
- **LLM-backed (LLM_ENABLED=true)**: Same handlers gather factual data,
  then the LLM enriches the response with natural language. Falls back to
  deterministic mode if the LLM is unreachable.

**Action Suggestions**: The chat returns structured `ActionSuggestion` objects
that the UI renders as styled cards. These are **always deterministic** — never
generated by the LLM. Actions are suggestions only and are never auto-applied.

### Guardian Reports & Alerts

**Heartbeat Reports**: Every 5 minutes, a background task computes fleet
health (agents by status, incident counts, anomaly detection) and stores a
`GuardianReportRow`. Accessible via `GET /api/v1/guardian/reports/recent`.

**Event-Driven Alerts**: When events are ingested, the event bus scans for
critical patterns:
- Repeated secret exfiltration (>=2 in a batch)
- High-severity burst (>=5 from one agent)
- Agent flapping (>=8 distinct event types from one agent)

Alerts are stored as `GuardianAlertRow` entries and displayed in the
dashboard's Guardian Alerts feed.

### Predictive Threat Vectors

Deterministic pattern rules (no ML) correlate event categories to predict
attack vectors:
- shell + network → data exfiltration
- ai_tool + secrets → lateral movement
- auth spikes → privilege escalation
- file + shell → persistence

Predictions appear in the threat matrix and are available via the chat.

---

### Deep Context for Decisions

V2 enhances every decision with deep contextual understanding:

**Event Context Bundle** (`GET /api/v1/guardian/event_context`):
For any event, the system returns:
- The event itself with full details
- **Policy evaluation**: which rule fired, the action taken, risk level
- **History window**: events from the same agent within +/- 5 minutes
- **Agent decision history**: the agent's last 20 events (behavioral context)
- **Related AI traffic**: AI tool calls in the same time window

This bundle powers both the chat explanations and the dashboard's event
detail views.

**Chat Explain with Context**: When a user asks "Explain event <id>", the
chat extracts the event ID, re-evaluates it against the bootstrap policy,
and returns a rich explanation that includes the matched rule, surrounding
context, and the agent's recent behavioral pattern.

### Agent Timeline

Each agent has a chronological timeline accessible via:
- `GET /api/v1/analytics/agent/timeline?agentId=...&hours=24`
- Web UI: click any agent in Fleet Status to open the timeline modal

The timeline combines:
- Security events (with severity color-coding)
- Policy changes (version updates)
- Session boundaries (5-minute gaps)
- AI tool calls (highlighted separately)

The AI Assistant uses timelines to provide contextual explanations like:
"Over the last 24h this agent had X blocks, Y warnings, and a policy
update at T."

### Operator Experience: "What Have You Been Doing?"

When an operator asks the guardian "What have you been doing?", the chat
pulls from the stored guardian reports to show:
- Latest heartbeat summary (fleet health, event counts, anomalies)
- Number of reports generated
- Policy changes tracked since last report

This makes ANGELGRID's autonomous operation transparent — operators always
know what the system has been watching and detecting.

---

## What ANGELGRID is NOT

- **Not an AI blocker.** We don't restrict which models, tools, or frameworks
  users can use. Use Claude Code, Ollama, GPT, open-source agents — we
  protect them all equally.
- **Not a compliance checkbox.** We're a living safety fabric that adapts
  to real threats, not a static audit tool.
- **Not a productivity tax.** If ANGELGRID is slowing down legitimate work,
  the policies need tuning — not the user's workflow.
- **Not a secret exposer.** Under no circumstances will ANGELGRID return
  raw secrets in any API response, LLM output, or log entry. This is the
  one rule that is never relaxed.
