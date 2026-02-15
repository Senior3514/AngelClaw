# ANGELGRID AI – Security Assistant

ANGELGRID AI is a built-in security assistant that helps analysts understand
events, incidents, and policies through a chat-style UX in the ANGELGRID Cloud
console.

## Design Principles

1. **Analysis only, never action.**  ANGELGRID AI can summarize incidents,
   explain policy gaps, and *propose* changes — but it **cannot** apply
   changes directly.  Every proposed change must go through explicit human
   approval and is logged as an auditable ChangeEvent.

2. **No external LLM dependency (yet).**  The current implementation uses
   structured queries against the Cloud database and deterministic logic.
   Future versions may integrate an LLM for natural-language interaction,
   but the safety boundary (analysis vs. action) will remain enforced at
   the API layer regardless of the backend.

3. **Tenant isolation.**  All queries are scoped by `tenant_id`.  The
   assistant never crosses tenant boundaries.

## Available Functions

- `summarize_recent_incidents(tenant_id)` — Returns a structured summary of
  recent incidents: counts by classification, severity distribution, top
  affected agents, and recommended focus areas.

- `propose_policy_tightening(agent_group_id)` — Analyzes recent block/alert
  events for an agent group and proposes new or tightened policy rules.
  Returns structured `ProposedPolicyChanges` — never applies them.

## Safety Boundaries

See [docs/concepts/angelgrid_ai.md](../../../docs/concepts/angelgrid_ai.md)
for the full UX and safety model.
