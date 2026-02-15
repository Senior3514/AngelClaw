# ANGELGRID Cloud – Centralized SaaS Backend

ANGELGRID Cloud provides centralized policy management, event ingestion, global learning,
and multi-tenant operations for all connected ANGELNODEs.

## Structure

- `api/` – FastAPI application with REST endpoints for agent registration, event ingestion, and policy distribution.
- `db/` – Database models (SQLAlchemy) and migration support.
- `services/` – Business logic for policy compilation, incident correlation, and threat intel.
- `ai_assistant/` – ANGELGRID AI security assistant (analysis-only, never applies changes directly).

## API Endpoints

- `POST /api/v1/agents/register` – Register an ANGELNODE, receive initial PolicySet.
- `POST /api/v1/events/batch` – Ingest a batch of events from agents.
- `GET  /api/v1/policies/current?agentId=...` – Retrieve current PolicySet for an agent.

## ANGELGRID AI Assistant

The `ai_assistant/` module provides structured security analysis functions:

- `summarize_recent_incidents(tenant_id)` – Aggregates incidents by classification and severity.
- `propose_policy_tightening(agent_group_id)` – Proposes new rules based on event patterns.

**Safety boundary:** The assistant is strictly read-only. It queries data and
returns proposals but **cannot** modify policies, agents, or incidents directly.
All changes require explicit human approval and are logged as ChangeEvents.

See [docs/concepts/angelgrid_ai.md](../docs/concepts/angelgrid_ai.md) for the
full UX and safety model.

## Running

```bash
pip install -e ".[cloud]"
uvicorn cloud.api.server:app --host 0.0.0.0 --port 8500
```
