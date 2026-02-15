# ANGELGRID Cloud – Centralized SaaS Backend

ANGELGRID Cloud provides centralized policy management, event ingestion, global learning,
and multi-tenant operations for all connected ANGELNODEs.

## Structure

- `api/` – FastAPI application with REST endpoints for agent registration, event ingestion, and policy distribution.
- `db/` – Database models (SQLAlchemy) and migration support.
- `services/` – Business logic for policy compilation, incident correlation, and threat intel.

## API Endpoints

- `POST /api/v1/agents/register` – Register an ANGELNODE, receive initial PolicySet.
- `POST /api/v1/events/batch` – Ingest a batch of events from agents.
- `GET  /api/v1/policies/current?agentId=...` – Retrieve current PolicySet for an agent.

## Running

```bash
cd cloud
pip install -e .
uvicorn api.server:app --host 0.0.0.0 --port 8500
```
