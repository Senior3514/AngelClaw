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

4. **No secret exposure** — the assistant never returns raw credentials,
   tokens, or connection strings.  It operates on metadata only.

---

## What ANGELGRID is NOT

- **Not an AI blocker.** We don't restrict which models, tools, or frameworks
  users can use. Use Claude Code, Ollama, GPT, open-source agents — we
  protect them all equally.
- **Not a compliance checkbox.** We're a living safety fabric that adapts
  to real threats, not a static audit tool.
- **Not a productivity tax.** If ANGELGRID is slowing down legitimate work,
  the policies need tuning — not the user's workflow.
