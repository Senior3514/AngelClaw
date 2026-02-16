"""AngelClaw Cloud – SaaS Backend API Server (V3 Autonomous Guardian).

Central management plane for ANGELNODE fleet.  Handles agent registration,
event ingestion, policy distribution, AI-assisted analysis, analytics,
guardian heartbeat, event bus alerts, and the Guardian Angel web dashboard.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import os

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from shared.models.agent_node import AgentNode, AgentRegistrationRequest, AgentStatus
from shared.models.event import Event, EventBatch
from shared.models.policy import PolicySet

from ..ai_assistant.assistant import propose_policy_tightening, summarize_recent_incidents
from ..ai_assistant.models import IncidentSummary, ProposedPolicyChanges
from ..db.models import AgentNodeRow, Base, EventRow, GuardianChangeRow, PolicySetRow
from ..db.session import engine, get_db

logger = logging.getLogger("angelgrid.cloud")

_UI_DIR = Path(__file__).resolve().parent.parent / "ui"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create database tables on startup, start guardian heartbeat and orchestrator."""
    Base.metadata.create_all(bind=engine)
    _ensure_default_policy_exists()
    # Start guardian heartbeat background task
    from cloud.services.guardian_heartbeat import heartbeat_loop
    heartbeat_task = asyncio.create_task(heartbeat_loop())
    # Start ANGEL AGI Orchestrator
    from cloud.guardian.orchestrator import angel_orchestrator
    await angel_orchestrator.start()
    logger.info("AngelClaw Cloud API V3 started — tables created, heartbeat + orchestrator running")
    yield
    heartbeat_task.cancel()
    await angel_orchestrator.stop()


app = FastAPI(
    title="AngelClaw Cloud API",
    version="0.4.0",
    lifespan=lifespan,
)

# Mount auth routes (always available, even when auth is disabled)
from cloud.auth.routes import router as auth_router  # noqa: E402

app.include_router(auth_router)

# Mount the AI Assistant routes
from cloud.api.assistant_routes import router as assistant_router  # noqa: E402

app.include_router(assistant_router)

# Mount the LLM proxy routes
from cloud.llm_proxy.routes import router as llm_router  # noqa: E402

app.include_router(llm_router)

# Mount analytics and fleet routes
from cloud.api.analytics_routes import router as analytics_router  # noqa: E402

app.include_router(analytics_router)

# Mount Guardian V3 routes
from cloud.api.guardian_routes import router as guardian_router  # noqa: E402

app.include_router(guardian_router)

# Mount Orchestrator API routes (ANGEL AGI)
from cloud.api.orchestrator_routes import router as orchestrator_router  # noqa: E402

app.include_router(orchestrator_router)


# ---------------------------------------------------------------------------
# Auth middleware — protect /api/v1/* routes when auth is enabled
# ---------------------------------------------------------------------------

from cloud.auth.config import AUTH_ENABLED  # noqa: E402
from cloud.auth.service import verify_bearer, verify_jwt  # noqa: E402

# Paths that never require auth
_PUBLIC_PATHS = {"/health", "/ui", "/api/v1/auth/login", "/api/v1/auth/logout", "/docs", "/openapi.json", "/redoc"}


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """If auth is enabled, require a valid token for /api/v1/* routes."""
    if not AUTH_ENABLED:
        return await call_next(request)

    path = request.url.path

    # Public paths bypass auth
    if path in _PUBLIC_PATHS or not path.startswith("/api/"):
        return await call_next(request)

    # Extract token from header or cookie
    token = None
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    elif auth_header:
        token = auth_header

    if not token:
        token = request.cookies.get("angelclaw_token")

    if not token:
        return JSONResponse(status_code=401, content={"detail": "Authentication required"})

    user = verify_jwt(token)
    if not user:
        from cloud.auth.config import AUTH_MODE
        if AUTH_MODE == "bearer":
            user = verify_bearer(token)

    if not user:
        return JSONResponse(status_code=401, content={"detail": "Invalid or expired token"})

    # Viewer role check: block POST/PUT/DELETE on non-chat endpoints
    if user.role.value == "viewer" and request.method in ("POST", "PUT", "DELETE"):
        # Allow chat for viewers (read-only operation that returns analysis)
        if path not in ("/api/v1/guardian/chat", "/api/v1/auth/logout"):
            return JSONResponse(
                status_code=403,
                content={"detail": f"Viewers cannot {request.method} to {path}"},
            )

    # Attach user to request state for downstream use
    request.state.auth_user = user
    return await call_next(request)


# ---------------------------------------------------------------------------
# GET /health — liveness probe
# ---------------------------------------------------------------------------

@app.get("/health", tags=["System"])
def health_check():
    return {"status": "ok", "version": "0.4.0"}


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
        # Record this as a guardian change
        change = GuardianChangeRow(
            id=str(uuid.uuid4()),
            tenant_id="dev-tenant",
            change_type="policy_seed",
            description=f"Initial policy seeded: {ps.name} (v{ps.version[:8]})",
            after_snapshot=ps.version,
            changed_by="system",
            details={"policy_name": ps.name, "rule_count": len(ps.rules)},
        )
        db.add(change)
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
    """Register a new ANGELNODE and return its initial PolicySet."""
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
    """Ingest a batch of Events from an ANGELNODE."""
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

    # V2: Check for critical patterns via the event bus
    from cloud.services.event_bus import check_for_alerts
    alerts_created = []
    try:
        alerts_created = check_for_alerts(db, rows)
        if alerts_created:
            logger.info(
                "[EVENT INGEST] %d event(s) ingested from agent %s — %d alert(s) triggered",
                len(rows), batch.agent_id[:8], len(alerts_created),
            )
    except Exception:
        logger.exception("[EVENT INGEST] Event bus alert check failed (non-fatal)")

    # V3: Run events through ANGEL AGI Orchestrator (non-blocking)
    from cloud.guardian.orchestrator import angel_orchestrator
    indicators = []
    try:
        indicators = asyncio.get_event_loop().run_until_complete(
            angel_orchestrator.process_events(rows, db)
        ) if not asyncio.get_event_loop().is_running() else []
        # If we're inside an async context, schedule as task
        if asyncio.get_event_loop().is_running():
            asyncio.create_task(_run_orchestrator(rows, db))
    except RuntimeError:
        # No event loop — skip orchestrator (sync context)
        pass
    except Exception:
        logger.debug("[EVENT INGEST] Orchestrator analysis skipped", exc_info=True)

    return {
        "accepted": len(rows),
        "agent_id": batch.agent_id,
        "alerts": len(alerts_created),
        "indicators": len(indicators),
    }


async def _run_orchestrator(rows: list, db: Session) -> None:
    """Run orchestrator analysis as a background task."""
    from cloud.guardian.orchestrator import angel_orchestrator
    try:
        await angel_orchestrator.process_events(rows, db)
    except Exception:
        logger.debug("[ORCHESTRATOR] Background analysis failed", exc_info=True)


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


# ---------------------------------------------------------------------------
# Standalone runner with secure-by-default binding
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    bind_host = os.environ.get("ANGELCLAW_BIND_HOST", "127.0.0.1")
    bind_port = int(os.environ.get("ANGELCLAW_BIND_PORT", "8500"))
    uvicorn.run(app, host=bind_host, port=bind_port)
