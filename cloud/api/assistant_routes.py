"""AngelClaw Cloud – AI Assistant API routes.

Exposes the security assistant analysis functions as REST endpoints.
All endpoints are read-only and do not modify database state.

Auth: For local dev, a simple X-TENANT-ID header is used for tenant
scoping. This header-based approach is designed to be replaced by a
proper auth middleware (JWT, OAuth2) when deploying to production.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Header, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from cloud.ai_assistant.assistant import (
    propose_policy_tightening,
    summarize_recent_incidents,
)
from cloud.ai_assistant.models import IncidentSummary, ProposedPolicyChanges
from cloud.db.models import EventRow
from cloud.db.session import get_db
from shared.security.secret_scanner import redact_dict, redact_secrets

logger = logging.getLogger("angelgrid.cloud.assistant_api")

router = APIRouter(prefix="/api/v1/assistant", tags=["AI Assistant"])


# ---------------------------------------------------------------------------
# Auth dependency (pluggable)
# ---------------------------------------------------------------------------

async def _require_tenant(
    x_tenant_id: Optional[str] = Header(default=None),
) -> str:
    """Extract tenant ID from header. Returns a default for local dev.

    SECURITY NOTE: In production, replace this with JWT/OAuth2 middleware
    that validates the token and extracts tenant_id from claims.
    """
    if x_tenant_id:
        return x_tenant_id
    # Local dev fallback — always set a tenant for safety
    return "dev-tenant"


# ---------------------------------------------------------------------------
# Response models for /explain
# ---------------------------------------------------------------------------

class EventExplanation(BaseModel):
    """Explains why a specific event was blocked/alerted/allowed."""

    event_id: str
    category: str
    type: str
    timestamp: datetime
    severity: str
    source: Optional[str] = None
    details: dict = Field(default_factory=dict)
    matched_rule_id: Optional[str] = None
    explanation: str = Field(
        description="Human-readable explanation of the decision",
    )
    context_window: list[dict] = Field(
        default_factory=list,
        description="Surrounding events within +/- 5 minutes (when include_context=true)",
    )
    related_ai_traffic: list[dict] = Field(
        default_factory=list,
        description="AI tool call events from same agent in the window (when include_context=true)",
    )


# ---------------------------------------------------------------------------
# GET /api/v1/assistant/incidents
# ---------------------------------------------------------------------------

@router.get(
    "/incidents",
    response_model=IncidentSummary,
    summary="Summarize recent incidents",
    description=(
        "Returns a structured summary of recent incidents for the tenant, "
        "including breakdowns by classification and severity, top affected "
        "agents, and recommended focus areas. Read-only."
    ),
)
def get_incident_summary(
    lookback_hours: int = Query(
        default=24,
        ge=1,
        le=720,
        description="How many hours back to analyze (1–720)",
    ),
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> IncidentSummary:
    return summarize_recent_incidents(db, tenant_id, lookback_hours)


# ---------------------------------------------------------------------------
# POST /api/v1/assistant/propose
# ---------------------------------------------------------------------------

class ProposeRequest(BaseModel):
    """Request body for policy tightening proposals."""

    agent_group_id: str = Field(
        description="Agent group tag to analyze (matches AgentNode.tags)",
    )
    lookback_hours: int = Field(
        default=24,
        ge=1,
        le=720,
        description="How many hours back to analyze",
    )


@router.post(
    "/propose",
    response_model=ProposedPolicyChanges,
    summary="Propose policy tightening",
    description=(
        "Analyzes recent high-severity events for an agent group and "
        "proposes new policy rules to close gaps. Returns proposals only — "
        "changes are never applied automatically. Read-only."
    ),
)
def propose_tightening(
    req: ProposeRequest,
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> ProposedPolicyChanges:
    return propose_policy_tightening(db, req.agent_group_id, req.lookback_hours)


# ---------------------------------------------------------------------------
# GET /api/v1/assistant/explain
# ---------------------------------------------------------------------------

@router.get(
    "/explain",
    response_model=EventExplanation,
    summary="Explain an event decision",
    description=(
        "Given an event ID, returns a human-readable explanation of why "
        "the event was blocked, alerted, audited, or allowed, including "
        "the matched rule (if any). Read-only."
    ),
)
def explain_event(
    event_id: str = Query(..., description="The event ID to explain"),
    include_context: bool = Query(default=False, description="Include surrounding events and AI traffic"),
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> EventExplanation:
    event_row = db.query(EventRow).filter_by(id=event_id).first()
    if not event_row:
        raise HTTPException(status_code=404, detail=f"Event '{event_id}' not found")

    # Re-evaluate the event against the current default policy to produce
    # an explanation.  We import here to avoid circular imports at module level.
    import json
    from pathlib import Path

    from shared.models.event import Event, EventCategory, Severity
    from angelnode.core.engine import PolicyEngine

    # Reconstruct the Event from the stored row
    event = Event(
        id=event_row.id,
        agent_id=event_row.agent_id,
        timestamp=event_row.timestamp,
        category=EventCategory(event_row.category),
        type=event_row.type,
        severity=Severity(event_row.severity),
        details=event_row.details or {},
        source=event_row.source,
    )

    # Load the bootstrap policy for evaluation
    policy_path = Path(__file__).resolve().parent.parent.parent / "angelnode" / "config" / "default_policy.json"
    if policy_path.exists():
        engine = PolicyEngine.from_file(policy_path)
        decision = engine.evaluate(event)
        explanation = (
            f"Action: {decision.action.value.upper()}. "
            f"Reason: {decision.reason}. "
            f"Risk level: {decision.risk_level.value}."
        )
        if decision.matched_rule_id:
            explanation += f" Matched rule: '{decision.matched_rule_id}'."
        else:
            explanation += " No specific rule matched; category default was applied."
    else:
        explanation = (
            "Unable to re-evaluate — policy file not found. "
            "The event was processed by the ANGELNODE at ingest time."
        )
        decision = None

    # SECURITY: redact any secrets from event details before returning
    safe_details = redact_dict(event_row.details) if event_row.details else {}
    safe_explanation = redact_secrets(explanation)

    # Optional: include surrounding context
    context_window_data: list[dict] = []
    ai_traffic_data: list[dict] = []
    if include_context:
        from datetime import timedelta
        window_start = event_row.timestamp - timedelta(minutes=5)
        window_end = event_row.timestamp + timedelta(minutes=5)
        history = (
            db.query(EventRow)
            .filter(
                EventRow.agent_id == event_row.agent_id,
                EventRow.timestamp >= window_start,
                EventRow.timestamp <= window_end,
                EventRow.id != event_row.id,
            )
            .order_by(EventRow.timestamp.asc())
            .limit(20)
            .all()
        )
        context_window_data = [
            {
                "id": h.id,
                "timestamp": h.timestamp.isoformat(),
                "category": h.category,
                "type": h.type,
                "severity": h.severity,
            }
            for h in history
        ]
        ai_events = (
            db.query(EventRow)
            .filter(
                EventRow.agent_id == event_row.agent_id,
                EventRow.category == "ai_tool",
                EventRow.timestamp >= window_start,
                EventRow.timestamp <= window_end,
            )
            .order_by(EventRow.timestamp.asc())
            .limit(10)
            .all()
        )
        ai_traffic_data = [
            {
                "id": t.id,
                "timestamp": t.timestamp.isoformat(),
                "type": t.type,
                "severity": t.severity,
                "tool_name": (t.details or {}).get("tool_name", "unknown"),
            }
            for t in ai_events
        ]

    return EventExplanation(
        event_id=event_row.id,
        category=event_row.category,
        type=event_row.type,
        timestamp=event_row.timestamp,
        severity=event_row.severity,
        source=event_row.source,
        details=safe_details,
        matched_rule_id=decision.matched_rule_id if decision else None,
        explanation=safe_explanation,
        context_window=context_window_data,
        related_ai_traffic=ai_traffic_data,
    )
