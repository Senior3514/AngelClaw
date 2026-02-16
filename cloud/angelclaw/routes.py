"""AngelClaw AGI Guardian – API Routes.

All AngelClaw endpoints under /api/v1/angelclaw/*.
Tenant-scoped, auth-aware, secret-safe.

Endpoints:
  POST /chat              — Unified natural-language chat
  GET  /preferences       — Get operator preferences
  POST /preferences       — Update preferences
  GET  /reports/recent    — Recent guardian reports
  GET  /activity/recent   — Recent daemon activity
  GET  /actions/history   — Action audit trail
  GET  /daemon/status     — Daemon health
  GET  /shield/status     — ClawSec shield status
  POST /shield/assess     — Run shield threat assessment
  GET  /skills/status     — Skills integrity verification
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Header, Query
from sqlalchemy.orm import Session

from cloud.angelclaw.models import (
    ActivityEntry,
    AngelClawChatRequest,
    AngelClawChatResponse,
    DaemonStatus,
)
from cloud.db.models import GuardianReportRow
from cloud.db.session import get_db
from shared.security.secret_scanner import redact_secrets

logger = logging.getLogger("angelclaw.routes")

router = APIRouter(prefix="/api/v1/angelclaw", tags=["AngelClaw AGI Guardian"])


# ---------------------------------------------------------------------------
# Tenant dependency
# ---------------------------------------------------------------------------

async def _tenant(x_tenant_id: Optional[str] = Header(default=None)) -> str:
    return x_tenant_id or "dev-tenant"


# ---------------------------------------------------------------------------
# POST /api/v1/angelclaw/chat
# ---------------------------------------------------------------------------

@router.post("/chat", response_model=AngelClawChatResponse, summary="Unified AngelClaw chat")
async def angelclaw_chat(
    req: AngelClawChatRequest,
    db: Session = Depends(get_db),
) -> AngelClawChatResponse:
    """Main entry point — natural language interface to the autonomous guardian."""
    from cloud.angelclaw.brain import brain
    result = await brain.chat(
        db=db,
        tenant_id=req.tenant_id,
        prompt=req.prompt,
        mode=req.mode,
        preferences=req.preferences,
    )
    return AngelClawChatResponse(**result)


# ---------------------------------------------------------------------------
# GET /api/v1/angelclaw/preferences
# ---------------------------------------------------------------------------

@router.get("/preferences", summary="Get AngelClaw preferences")
def get_preferences_endpoint(
    tenantId: str = Query(default="dev-tenant"),
    tenant_id: str = Depends(_tenant),
    db: Session = Depends(get_db),
):
    from cloud.angelclaw.preferences import get_preferences
    effective = tenantId or tenant_id
    prefs = get_preferences(db, effective)
    return prefs.model_dump(mode="json")


# ---------------------------------------------------------------------------
# POST /api/v1/angelclaw/preferences
# ---------------------------------------------------------------------------

@router.post("/preferences", summary="Update AngelClaw preferences")
def update_preferences_endpoint(
    body: dict,
    tenantId: str = Query(default="dev-tenant"),
    tenant_id: str = Depends(_tenant),
    db: Session = Depends(get_db),
):
    from cloud.angelclaw.preferences import PreferencesUpdate, update_preferences
    effective = tenantId or tenant_id
    update = PreferencesUpdate(**{k: v for k, v in body.items() if k in PreferencesUpdate.model_fields})
    prefs = update_preferences(db, effective, update, updated_by="api")
    return prefs.model_dump(mode="json")


# ---------------------------------------------------------------------------
# GET /api/v1/angelclaw/reports/recent
# ---------------------------------------------------------------------------

@router.get("/reports/recent", summary="Recent guardian reports")
def recent_reports(
    tenantId: str = Query(default="dev-tenant"),
    limit: int = Query(default=10, ge=1, le=100),
    tenant_id: str = Depends(_tenant),
    db: Session = Depends(get_db),
):
    effective = tenantId or tenant_id
    rows = (
        db.query(GuardianReportRow)
        .filter(GuardianReportRow.tenant_id == effective)
        .order_by(GuardianReportRow.timestamp.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "agents_total": r.agents_total,
            "agents_active": r.agents_active,
            "agents_degraded": r.agents_degraded,
            "agents_offline": r.agents_offline,
            "incidents_total": r.incidents_total,
            "incidents_by_severity": r.incidents_by_severity or {},
            "anomalies": r.anomalies or [],
            "summary": r.summary or "",
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# GET /api/v1/angelclaw/activity/recent
# ---------------------------------------------------------------------------

@router.get("/activity/recent", response_model=list[ActivityEntry], summary="Recent daemon activity")
def recent_activity(
    limit: int = Query(default=20, ge=1, le=200),
):
    from cloud.angelclaw.daemon import get_recent_activity
    return [ActivityEntry(**a) for a in get_recent_activity(limit)]


# ---------------------------------------------------------------------------
# GET /api/v1/angelclaw/actions/history
# ---------------------------------------------------------------------------

@router.get("/actions/history", summary="Action audit trail")
def actions_history(
    tenantId: str = Query(default="dev-tenant"),
    limit: int = Query(default=50, ge=1, le=500),
    tenant_id: str = Depends(_tenant),
    db: Session = Depends(get_db),
):
    from cloud.angelclaw.actions import get_action_history
    effective = tenantId or tenant_id
    return get_action_history(db, effective, limit)


# ---------------------------------------------------------------------------
# GET /api/v1/angelclaw/daemon/status
# ---------------------------------------------------------------------------

@router.get("/daemon/status", response_model=DaemonStatus, summary="Daemon health")
def daemon_status():
    from cloud.angelclaw.daemon import get_daemon_status
    return DaemonStatus(**get_daemon_status())


# ---------------------------------------------------------------------------
# GET /api/v1/angelclaw/shield/status
# ---------------------------------------------------------------------------

@router.get("/shield/status", summary="ClawSec shield status")
def shield_status():
    from cloud.angelclaw.shield import shield as _shield
    return _shield.get_status()


# ---------------------------------------------------------------------------
# POST /api/v1/angelclaw/shield/assess
# ---------------------------------------------------------------------------

@router.post("/shield/assess", summary="Run shield threat assessment")
def shield_assess(
    tenantId: str = Query(default="dev-tenant"),
    tenant_id: str = Depends(_tenant),
    db: Session = Depends(get_db),
):
    from cloud.angelclaw.shield import shield as _shield
    from cloud.angelclaw.context import gather_context

    effective = tenantId or tenant_id
    ctx = gather_context(db, effective, lookback_hours=24, include_events=True)

    event_dicts = [
        {"category": e.get("category", ""), "type": e.get("type", ""),
         "details": e.get("details", {}), "severity": e.get("severity", "")}
        for e in ctx.recent_events[:200]
    ]
    report = _shield.assess_events(event_dicts)

    return {
        "overall_risk": report.overall_risk.value,
        "lethal_trifecta_score": report.lethal_trifecta_score,
        "checks_run": report.checks_run,
        "indicators": [
            {
                "category": ind.category.value,
                "severity": ind.severity.value,
                "title": ind.title,
                "description": ind.description,
                "evidence": ind.evidence[:3],
                "mitigations": ind.mitigations[:3],
            }
            for ind in report.indicators
        ],
        "skills_status": report.skills_status,
        "scanned_at": report.scanned_at,
    }


# ---------------------------------------------------------------------------
# GET /api/v1/angelclaw/skills/status
# ---------------------------------------------------------------------------

@router.get("/skills/status", summary="Skills integrity verification")
def skills_status():
    from cloud.angelclaw.shield import verify_all_skills
    return verify_all_skills()
