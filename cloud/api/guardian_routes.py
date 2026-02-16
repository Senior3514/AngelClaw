"""AngelClaw Cloud – Guardian API routes (V3).

Provides endpoints for guardian reports, alerts, chat, event context,
and change tracking. All endpoints are read-only except chat (which
generates responses but never auto-applies actions).

Router prefix: /api/v1/guardian
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.orm import Session

from cloud.api.guardian_models import (
    ChatRequest,
    ChatResponse,
    EvaluationResult,
    EventContext,
    GuardianAlert,
    GuardianChange,
    GuardianReport,
)
from cloud.db.models import EventRow, GuardianAlertRow, GuardianChangeRow, GuardianReportRow
from cloud.db.session import get_db
from cloud.services.guardian_chat import handle_chat
from shared.security.secret_scanner import redact_dict, redact_secrets

logger = logging.getLogger("angelgrid.cloud.guardian_api")

router = APIRouter(prefix="/api/v1/guardian", tags=["Guardian V2"])


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

async def _require_tenant(
    x_tenant_id: Optional[str] = Header(default=None),
) -> str:
    return x_tenant_id or "dev-tenant"


# ---------------------------------------------------------------------------
# GET /api/v1/guardian/reports/recent
# ---------------------------------------------------------------------------

@router.get(
    "/reports/recent",
    response_model=list[GuardianReport],
    summary="Recent guardian heartbeat reports",
)
def recent_reports(
    tenantId: str = Query(default="dev-tenant"),
    limit: int = Query(default=10, ge=1, le=100),
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> list[GuardianReport]:
    effective_tenant = tenantId or tenant_id
    rows = (
        db.query(GuardianReportRow)
        .filter(GuardianReportRow.tenant_id == effective_tenant)
        .order_by(GuardianReportRow.timestamp.desc())
        .limit(limit)
        .all()
    )
    return [
        GuardianReport(
            id=r.id,
            tenant_id=r.tenant_id,
            timestamp=r.timestamp,
            agents_total=r.agents_total,
            agents_active=r.agents_active,
            agents_degraded=r.agents_degraded,
            agents_offline=r.agents_offline,
            incidents_total=r.incidents_total,
            incidents_by_severity=r.incidents_by_severity or {},
            policy_changes_since_last=r.policy_changes_since_last or 0,
            anomalies=r.anomalies or [],
            summary=r.summary or "",
        )
        for r in rows
    ]


# ---------------------------------------------------------------------------
# GET /api/v1/guardian/alerts/recent
# ---------------------------------------------------------------------------

@router.get(
    "/alerts/recent",
    response_model=list[GuardianAlert],
    summary="Recent guardian critical alerts",
)
def recent_alerts(
    tenantId: str = Query(default="dev-tenant"),
    limit: int = Query(default=20, ge=1, le=200),
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> list[GuardianAlert]:
    effective_tenant = tenantId or tenant_id
    rows = (
        db.query(GuardianAlertRow)
        .filter(GuardianAlertRow.tenant_id == effective_tenant)
        .order_by(GuardianAlertRow.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        GuardianAlert(
            id=r.id,
            tenant_id=r.tenant_id,
            alert_type=r.alert_type,
            title=r.title,
            severity=r.severity,
            details=redact_dict(r.details) if r.details else {},
            related_event_ids=r.related_event_ids or [],
            related_agent_ids=r.related_agent_ids or [],
            created_at=r.created_at,
        )
        for r in rows
    ]


# ---------------------------------------------------------------------------
# POST /api/v1/guardian/chat
# ---------------------------------------------------------------------------

@router.post(
    "/chat",
    response_model=ChatResponse,
    summary="Unified guardian chat",
)
async def guardian_chat(
    req: ChatRequest,
    db: Session = Depends(get_db),
) -> ChatResponse:
    return await handle_chat(db, req)


# ---------------------------------------------------------------------------
# GET /api/v1/guardian/event_context
# ---------------------------------------------------------------------------

@router.get(
    "/event_context",
    response_model=EventContext,
    summary="Event context with history window",
)
def event_context(
    eventId: str = Query(..., description="Event ID to inspect"),
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> EventContext:
    event = db.query(EventRow).filter_by(id=eventId).first()
    if not event:
        raise HTTPException(status_code=404, detail=f"Event '{eventId}' not found")

    # Get history window: events from same agent within +/- 5 minutes
    window_start = event.timestamp - timedelta(minutes=5)
    window_end = event.timestamp + timedelta(minutes=5)
    history = (
        db.query(EventRow)
        .filter(
            EventRow.agent_id == event.agent_id,
            EventRow.timestamp >= window_start,
            EventRow.timestamp <= window_end,
            EventRow.id != event.id,
        )
        .order_by(EventRow.timestamp.asc())
        .limit(20)
        .all()
    )

    # Get related AI traffic
    ai_traffic = (
        db.query(EventRow)
        .filter(
            EventRow.agent_id == event.agent_id,
            EventRow.category == "ai_tool",
            EventRow.timestamp >= window_start,
            EventRow.timestamp <= window_end,
        )
        .order_by(EventRow.timestamp.asc())
        .limit(10)
        .all()
    )

    # Policy evaluation — re-evaluate against bootstrap policy to show which rule fired
    evaluation = None
    explanation = f"Event {event.category}/{event.type} with severity {event.severity}"
    if event.source:
        explanation += f" from {event.source}"
    explanation += f". Occurred at {event.timestamp.isoformat()}."

    try:
        from pathlib import Path as _Path
        from shared.models.event import Event as _Event, EventCategory, Severity
        from angelnode.core.engine import PolicyEngine

        ev = _Event(
            id=event.id,
            agent_id=event.agent_id,
            timestamp=event.timestamp,
            category=EventCategory(event.category),
            type=event.type,
            severity=Severity(event.severity),
            details=event.details or {},
            source=event.source,
        )
        policy_path = (
            _Path(__file__).resolve().parent.parent.parent
            / "angelnode" / "config" / "default_policy.json"
        )
        if policy_path.exists():
            eng = PolicyEngine.from_file(policy_path)
            decision = eng.evaluate(ev)
            evaluation = EvaluationResult(
                action=decision.action.value.upper(),
                reason=decision.reason,
                matched_rule_id=decision.matched_rule_id,
                risk_level=decision.risk_level.value,
            )
            explanation = (
                f"Action: {decision.action.value.upper()}. "
                f"Reason: {decision.reason}. "
                f"Risk level: {decision.risk_level.value}."
            )
    except Exception:
        logger.debug("Policy evaluation unavailable for event %s", eventId)

    # Agent's recent decision history (last 20 events from same agent, before this event)
    agent_history = (
        db.query(EventRow)
        .filter(
            EventRow.agent_id == event.agent_id,
            EventRow.timestamp <= event.timestamp,
            EventRow.id != event.id,
        )
        .order_by(EventRow.timestamp.desc())
        .limit(20)
        .all()
    )

    safe_details = redact_dict(event.details) if event.details else {}
    safe_explanation = redact_secrets(explanation)

    return EventContext(
        event_id=event.id,
        category=event.category,
        type=event.type,
        timestamp=event.timestamp,
        severity=event.severity,
        source=event.source,
        details=safe_details,
        explanation=safe_explanation,
        evaluation=evaluation,
        agent_decision_history=[
            {
                "id": h.id,
                "timestamp": h.timestamp.isoformat(),
                "category": h.category,
                "type": h.type,
                "severity": h.severity,
            }
            for h in agent_history
        ],
        history_window=[
            {
                "id": h.id,
                "timestamp": h.timestamp.isoformat(),
                "category": h.category,
                "type": h.type,
                "severity": h.severity,
            }
            for h in history
        ],
        related_ai_traffic=[
            {
                "id": t.id,
                "timestamp": t.timestamp.isoformat(),
                "type": t.type,
                "severity": t.severity,
                "tool_name": (t.details or {}).get("tool_name", "unknown"),
            }
            for t in ai_traffic
        ],
    )


# ---------------------------------------------------------------------------
# GET /api/v1/guardian/changes
# ---------------------------------------------------------------------------

@router.get(
    "/changes",
    response_model=list[GuardianChange],
    summary="Policy/config changes since timestamp",
)
def recent_changes(
    since: str = Query(..., description="ISO timestamp to filter from"),
    tenantId: str = Query(default="dev-tenant"),
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> list[GuardianChange]:
    effective_tenant = tenantId or tenant_id
    try:
        since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid 'since' timestamp format")

    rows = (
        db.query(GuardianChangeRow)
        .filter(
            GuardianChangeRow.tenant_id == effective_tenant,
            GuardianChangeRow.created_at >= since_dt,
        )
        .order_by(GuardianChangeRow.created_at.desc())
        .all()
    )
    return [
        GuardianChange(
            id=r.id,
            tenant_id=r.tenant_id,
            change_type=r.change_type,
            description=r.description or "",
            before_snapshot=r.before_snapshot,
            after_snapshot=r.after_snapshot,
            changed_by=r.changed_by or "system",
            details=r.details or {},
            created_at=r.created_at,
        )
        for r in rows
    ]
