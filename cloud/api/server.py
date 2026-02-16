"""ANGELGRID Cloud – SaaS Backend API Server.

Central management plane for ANGELNODE fleet.  Handles agent registration,
event ingestion, policy distribution, AI-assisted analysis, analytics,
and the Guardian Angel web dashboard.
"""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from shared.models.agent_node import AgentNode, AgentRegistrationRequest, AgentStatus
from shared.models.event import Event, EventBatch
from shared.models.policy import PolicySet

from ..ai_assistant.assistant import propose_policy_tightening, summarize_recent_incidents
from ..ai_assistant.models import IncidentSummary, ProposedPolicyChanges
from ..db.models import AgentNodeRow, Base, EventRow, PolicySetRow
from ..db.session import engine, get_db

logger = logging.getLogger("angelgrid.cloud")

_UI_DIR = Path(__file__).resolve().parent.parent / "ui"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create database tables on startup."""
    Base.metadata.create_all(bind=engine)
    _ensure_default_policy_exists()
    logger.info("ANGELGRID Cloud API started — tables created")
    yield


app = FastAPI(
    title="ANGELGRID Cloud API",
    version="0.3.0",
    lifespan=lifespan,
)

# Mount the AI Assistant routes
from cloud.api.assistant_routes import router as assistant_router  # noqa: E402

app.include_router(assistant_router)

# Mount the LLM proxy routes
from cloud.llm_proxy.routes import router as llm_router  # noqa: E402

app.include_router(llm_router)

# Mount analytics and fleet routes
from cloud.api.analytics_routes import router as analytics_router  # noqa: E402

app.include_router(analytics_router)


# ---------------------------------------------------------------------------
# GET /health — liveness probe
# ---------------------------------------------------------------------------

@app.get("/health", tags=["System"])
def health_check():
    return {"status": "ok", "version": "0.3.0"}


# ---------------------------------------------------------------------------
# GET /ui — Guardian Angel Dashboard
# ---------------------------------------------------------------------------

@app.get("/ui", response_class=HTMLResponse, tags=["Dashboard"], include_in_schema=False)
def serve_dashboard():
    """Serve the Guardian Angel web dashboard."""
    index = _UI_DIR / "index.html"
    if index.exists():
        return HTMLResponse(content=index.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>Dashboard not found</h1><p>Place index.html in cloud/ui/</p>", status_code=404)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ensure_default_policy_exists():
    """Seed the database with the bootstrap policy if none exists."""
    from ..db.session import SessionLocal
    from pathlib import Path

    db = SessionLocal()
    try:
        existing = db.query(PolicySetRow).first()
        if existing:
            return
        # Load the default policy shipped with ANGELNODE
        default_path = (
            Path(__file__).resolve().parent.parent.parent
            / "angelnode" / "config" / "default_policy.json"
        )
        if not default_path.exists():
            logger.warning("Default policy file not found at %s", default_path)
            return
        data = json.loads(default_path.read_text(encoding="utf-8"))
        ps = PolicySet.model_validate(data)
        row = PolicySetRow(
            id=ps.id,
            name=ps.name,
            description=ps.description,
            rules_json=[r.model_dump(mode="json") for r in ps.rules],
            version_hash=ps.version,
        )
        db.add(row)
        db.commit()
        logger.info("Seeded default PolicySet (version=%s)", ps.version)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# POST /api/v1/agents/register
# ---------------------------------------------------------------------------

@app.post("/api/v1/agents/register")
def register_agent(
    req: AgentRegistrationRequest,
    db: Session = Depends(get_db),
):
    """Register a new ANGELNODE and return its initial PolicySet.

    If the agent hostname already exists, update its record instead
    of creating a duplicate.
    """
    # Check for existing registration by hostname
    existing = db.query(AgentNodeRow).filter_by(hostname=req.hostname).first()

    node = AgentNode(
        type=req.type,
        os=req.os,
        hostname=req.hostname,
        tags=req.tags,
        version=req.version,
        status=AgentStatus.ACTIVE,
    )

    if existing:
        existing.status = AgentStatus.ACTIVE.value
        existing.last_seen_at = datetime.now(timezone.utc)
        existing.version = req.version
        existing.tags = req.tags
        node.id = existing.id
    else:
        row = AgentNodeRow(
            id=node.id,
            type=node.type.value,
            os=node.os,
            hostname=node.hostname,
            tags=node.tags,
            version=node.version,
            status=node.status.value,
            registered_at=node.registered_at,
        )
        db.add(row)

    db.commit()

    # Return the current default PolicySet
    ps_row = db.query(PolicySetRow).first()
    policy_set = None
    if ps_row:
        policy_set = {
            "id": ps_row.id,
            "name": ps_row.name,
            "description": ps_row.description,
            "rules": ps_row.rules_json,
            "version": ps_row.version_hash,
        }

    return {
        "agent_id": node.id,
        "status": "registered",
        "policy_set": policy_set,
    }


# ---------------------------------------------------------------------------
# POST /api/v1/events/batch
# ---------------------------------------------------------------------------

@app.post("/api/v1/events/batch")
def ingest_events(
    batch: EventBatch,
    db: Session = Depends(get_db),
):
    """Ingest a batch of Events from an ANGELNODE.

    Events are stored for analysis, correlation, and incident creation.
    """
    # Update agent last-seen timestamp
    agent_row = db.query(AgentNodeRow).filter_by(id=batch.agent_id).first()
    if agent_row:
        agent_row.last_seen_at = datetime.now(timezone.utc)

    rows = []
    for event in batch.events:
        rows.append(EventRow(
            id=event.id,
            agent_id=event.agent_id,
            timestamp=event.timestamp,
            category=event.category.value,
            type=event.type,
            severity=event.severity.value,
            details=event.details,
            source=event.source,
        ))

    db.add_all(rows)
    db.commit()

    return {
        "accepted": len(rows),
        "agent_id": batch.agent_id,
    }


# ---------------------------------------------------------------------------
# GET /api/v1/policies/current
# ---------------------------------------------------------------------------

@app.get("/api/v1/policies/current")
def get_current_policy(
    agentId: str = Query(..., description="Agent ID to fetch policy for"),
    db: Session = Depends(get_db),
):
    """Return the current PolicySet for a given agent.

    For the MVP, all agents receive the same global policy.  Future versions
    will support per-agent and per-tag policy compilation.
    """
    agent_row = db.query(AgentNodeRow).filter_by(id=agentId).first()
    if not agent_row:
        raise HTTPException(status_code=404, detail="Agent not found")

    ps_row = db.query(PolicySetRow).first()
    if not ps_row:
        raise HTTPException(status_code=404, detail="No policy available")

    return {
        "id": ps_row.id,
        "name": ps_row.name,
        "description": ps_row.description,
        "rules": ps_row.rules_json,
        "version": ps_row.version_hash,
    }


# ---------------------------------------------------------------------------
# GET /api/v1/ai/summary/incidents
# ---------------------------------------------------------------------------

@app.get(
    "/api/v1/ai/summary/incidents",
    response_model=IncidentSummary,
    tags=["AI Assistant"],
)
def ai_summary_incidents(
    tenantId: str = Query(..., description="Tenant ID to scope the summary"),
    lookbackHours: int = Query(
        default=24,
        ge=1,
        le=720,
        description="How many hours back to look (1–720)",
    ),
    db: Session = Depends(get_db),
):
    """Summarize recent incidents for a tenant.

    Returns aggregated counts by classification and severity, the top
    affected agents, and deterministic recommendations.

    This endpoint is strictly read-only — it queries data but never
    modifies the database.
    """
    return summarize_recent_incidents(db, tenantId, lookback_hours=lookbackHours)


# ---------------------------------------------------------------------------
# GET /api/v1/ai/propose/policy
# ---------------------------------------------------------------------------

@app.get(
    "/api/v1/ai/propose/policy",
    response_model=ProposedPolicyChanges,
    tags=["AI Assistant"],
)
def ai_propose_policy(
    agentGroupId: str = Query(
        ..., description="Agent group tag to analyze (matches AgentNodeRow.tags)",
    ),
    lookbackHours: int = Query(
        default=24,
        ge=1,
        le=720,
        description="How many hours back to look (1–720)",
    ),
    db: Session = Depends(get_db),
):
    """Propose policy tightening for an agent group.

    Analyzes recent high-severity events, identifies recurring patterns,
    and returns structured rule proposals.  Proposals are never applied
    automatically — they require explicit human approval.

    This endpoint is strictly read-only — it queries data but never
    modifies the database.
    """
    return propose_policy_tightening(db, agentGroupId, lookback_hours=lookbackHours)
