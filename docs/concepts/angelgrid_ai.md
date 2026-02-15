# ANGELGRID AI – UX, Safety Boundaries & Approval Workflow

## Overview

ANGELGRID AI is a security assistant embedded in the ANGELGRID Cloud console.
It provides a **chat-style UX** where analysts can ask questions about their
security posture, investigate incidents, and receive policy recommendations.

## UX Model

The console presents a chat panel where users can interact with ANGELGRID AI:

```
┌─────────────────────────────────────────────────────┐
│  ANGELGRID AI                                  [?]  │
├─────────────────────────────────────────────────────┤
│                                                     │
│  User: "What happened in the last 24 hours?"        │
│                                                     │
│  AI: "I found 12 incidents across 4 agents:         │
│   - 3 CRITICAL (prompt injection on ai-host-01)     │
│   - 5 HIGH (unauthorized shell access)              │
│   - 4 WARN (suspicious outbound network)            │
│                                                     │
│   Recommendation: Review AI tool policies for       │
│   ai-host-01. I can propose tighter rules if        │
│   you'd like."                                      │
│                                                     │
│  User: "Yes, propose rules for the ai-hosts group." │
│                                                     │
│  AI: "Here are 3 proposed rules:                    │
│   1. Block all shell tool calls from AI agents      │
│      unless explicitly allowlisted                  │
│   2. Alert on outbound HTTP from AI hosts           │
│   3. Block credential-file reads from AI agents     │
│                                                     │
│   ⚠ These are proposals only. Click 'Apply' to      │
│   submit for approval."                             │
│                                                     │
│  [Apply Proposals]  [Dismiss]  [Export]              │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## Separation of Concerns: Analysis vs. Action

This is the most important architectural boundary in ANGELGRID AI.

### Analysis (ANGELGRID AI can do freely)

- Summarize incidents, events, and trends
- Explain policy rules and their coverage
- Identify gaps in policy coverage
- Correlate events across agents
- Generate risk assessments
- Propose policy changes as structured data

### Action (requires explicit human approval)

- **Policy edits** — Any modification to a PolicySet (add/remove/modify rules)
- **Policy deployment** — Pushing a new PolicySet version to agents
- **Agent configuration changes** — Modifying agent settings or tags
- **Incident status changes** — Closing or reclassifying incidents

**There is no "auto-apply" mode.** Even if an admin requests it, the system
architecture enforces the approval step at the API layer.

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

## Safety Guarantees

1. **No direct database writes** from the assistant module — the code is
   architecturally read-only (queries only, no ORM mutations).

2. **No external LLM calls** in the current implementation — all analysis
   is deterministic and auditable.  When LLM integration is added, it will
   be sandboxed behind the same analysis-only boundary.

3. **Tenant isolation** — all queries are scoped by tenant_id.  The
   assistant cannot access data from other tenants.

4. **No secret exposure** — the assistant never returns raw credentials,
   tokens, or connection strings.  It operates on metadata only.
