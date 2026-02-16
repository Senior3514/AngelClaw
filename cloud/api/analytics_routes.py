"""ANGELGRID Cloud – Analytics & Fleet API routes.

Provides endpoints for:
  - Agent fleet listing and identity
  - Recent incidents/events feed
  - Policy evolution tracking
  - Threat matrix analytics
  - AI traffic inspection
  - Session analytics

All endpoints are read-only and return JSON. Tenant-scoped via
X-TENANT-ID header (local dev fallback: dev-tenant).
"""

from __future__ import annotations

import hashlib
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, Query
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from cloud.db.models import AgentNodeRow, EventRow, IncidentRow, PolicySetRow
from cloud.db.session import get_db
from shared.security.secret_scanner import redact_dict

logger = logging.getLogger("angelgrid.cloud.analytics")

router = APIRouter(tags=["Analytics & Fleet"])


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

async def _require_tenant(
    x_tenant_id: Optional[str] = Header(default=None),
) -> str:
    return x_tenant_id or "dev-tenant"


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class AgentSummary(BaseModel):
    agent_id: str
    hostname: str
    os: str
    type: str
    status: str
    version: str
    tags: list[str] = Field(default_factory=list)
    registered_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None


class RecentEvent(BaseModel):
    id: str
    agent_id: str
    timestamp: datetime
    category: str
    type: str
    severity: str
    source: Optional[str] = None
    details: dict[str, Any] = Field(default_factory=dict)


class PolicyEvolutionEntry(BaseModel):
    version_hash: str
    policy_name: str
    created_at: datetime
    rule_count: int


class ThreatMatrixEntry(BaseModel):
    category: str
    total_events: int
    by_severity: dict[str, int] = Field(default_factory=dict)
    top_types: list[dict[str, Any]] = Field(default_factory=list)


class AITrafficEntry(BaseModel):
    id: str
    agent_id: str
    timestamp: datetime
    tool_name: str
    action_taken: str
    risk_level: str
    accesses_secrets: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class AgentIdentity(BaseModel):
    agent_id: str
    hostname: str
    os: str
    type: str
    status: str
    tags: list[str] = Field(default_factory=list)
    behavioral_fingerprint: dict[str, Any] = Field(default_factory=dict)
    total_events: int = 0
    risk_profile: str = "unknown"


class SessionSummary(BaseModel):
    agent_id: str
    session_start: datetime
    session_end: datetime
    event_count: int
    categories: list[str] = Field(default_factory=list)
    max_severity: str = "info"
    risk_score: float = 0.0


# ---------------------------------------------------------------------------
# GET /api/v1/agents – Fleet listing
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/agents",
    response_model=list[AgentSummary],
    summary="List all registered agents",
)
def list_agents(
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> list[AgentSummary]:
    rows = db.query(AgentNodeRow).order_by(AgentNodeRow.registered_at.desc()).all()
    return [
        AgentSummary(
            agent_id=r.id,
            hostname=r.hostname,
            os=r.os,
            type=r.type,
            status=r.status,
            version=r.version or "unknown",
            tags=r.tags or [],
            registered_at=r.registered_at,
            last_seen_at=r.last_seen_at,
        )
        for r in rows
    ]


# ---------------------------------------------------------------------------
# GET /api/v1/incidents/recent – Recent events feed
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/incidents/recent",
    response_model=list[RecentEvent],
    summary="List recent security events",
)
def recent_events(
    limit: int = Query(default=50, ge=1, le=500),
    severity: Optional[str] = Query(default=None, description="Filter by severity"),
    category: Optional[str] = Query(default=None, description="Filter by category"),
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> list[RecentEvent]:
    q = db.query(EventRow).order_by(EventRow.timestamp.desc())
    if severity:
        q = q.filter(EventRow.severity == severity)
    if category:
        q = q.filter(EventRow.category == category)
    rows = q.limit(limit).all()
    return [
        RecentEvent(
            id=r.id,
            agent_id=r.agent_id,
            timestamp=r.timestamp,
            category=r.category,
            type=r.type,
            severity=r.severity,
            source=r.source,
            details=redact_dict(r.details) if r.details else {},
        )
        for r in rows
    ]


# ---------------------------------------------------------------------------
# GET /api/v1/analytics/policy/evolution
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/analytics/policy/evolution",
    response_model=list[PolicyEvolutionEntry],
    summary="Policy version history",
)
def policy_evolution(
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> list[PolicyEvolutionEntry]:
    rows = db.query(PolicySetRow).order_by(PolicySetRow.created_at.desc()).all()
    return [
        PolicyEvolutionEntry(
            version_hash=r.version_hash,
            policy_name=r.name,
            created_at=r.created_at,
            rule_count=len(r.rules_json) if r.rules_json else 0,
        )
        for r in rows
    ]


# ---------------------------------------------------------------------------
# GET /api/v1/analytics/threat-matrix
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/analytics/threat-matrix",
    response_model=list[ThreatMatrixEntry],
    summary="Threat landscape by category",
)
def threat_matrix(
    lookback_hours: int = Query(default=24, ge=1, le=720),
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> list[ThreatMatrixEntry]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    events = db.query(EventRow).filter(EventRow.timestamp >= cutoff).all()

    # Group by category
    by_cat: dict[str, list[EventRow]] = {}
    for ev in events:
        by_cat.setdefault(ev.category, []).append(ev)

    result = []
    for cat, cat_events in sorted(by_cat.items(), key=lambda x: -len(x[1])):
        sev_counter: Counter[str] = Counter(e.severity for e in cat_events)
        type_counter: Counter[str] = Counter(e.type for e in cat_events)
        result.append(ThreatMatrixEntry(
            category=cat,
            total_events=len(cat_events),
            by_severity=dict(sev_counter.most_common()),
            top_types=[
                {"type": t, "count": c}
                for t, c in type_counter.most_common(5)
            ],
        ))
    return result


# ---------------------------------------------------------------------------
# GET /api/v1/analytics/ai-traffic
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/analytics/ai-traffic",
    response_model=list[AITrafficEntry],
    summary="AI-to-AI and AI tool traffic",
)
def ai_traffic(
    limit: int = Query(default=50, ge=1, le=500),
    lookback_hours: int = Query(default=24, ge=1, le=720),
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> list[AITrafficEntry]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    events = (
        db.query(EventRow)
        .filter(EventRow.category == "ai_tool", EventRow.timestamp >= cutoff)
        .order_by(EventRow.timestamp.desc())
        .limit(limit)
        .all()
    )
    return [
        AITrafficEntry(
            id=e.id,
            agent_id=e.agent_id,
            timestamp=e.timestamp,
            tool_name=(e.details or {}).get("tool_name", "unknown"),
            action_taken=(e.details or {}).get("action", "unknown"),
            risk_level=e.severity,
            accesses_secrets=(e.details or {}).get("accesses_secrets", False),
            details=redact_dict(e.details) if e.details else {},
        )
        for e in events
    ]


# ---------------------------------------------------------------------------
# GET /api/v1/agents/identity
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/agents/identity",
    response_model=AgentIdentity,
    summary="Agent identity and behavioral fingerprint",
)
def agent_identity(
    agent_id: str = Query(..., description="Agent ID to inspect"),
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> AgentIdentity:
    agent = db.query(AgentNodeRow).filter_by(id=agent_id).first()
    if not agent:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")

    # Compute behavioral fingerprint from recent events
    cutoff = datetime.now(timezone.utc) - timedelta(hours=168)  # 7 days
    events = (
        db.query(EventRow)
        .filter(EventRow.agent_id == agent_id, EventRow.timestamp >= cutoff)
        .all()
    )

    cat_counter: Counter[str] = Counter(e.category for e in events)
    sev_counter: Counter[str] = Counter(e.severity for e in events)

    # Risk profile heuristic
    critical = sev_counter.get("critical", 0)
    high = sev_counter.get("high", 0)
    if critical > 0:
        risk = "critical"
    elif high > 3:
        risk = "high"
    elif high > 0:
        risk = "medium"
    elif len(events) > 0:
        risk = "low"
    else:
        risk = "none"

    return AgentIdentity(
        agent_id=agent.id,
        hostname=agent.hostname,
        os=agent.os,
        type=agent.type,
        status=agent.status,
        tags=agent.tags or [],
        behavioral_fingerprint={
            "event_categories": dict(cat_counter.most_common()),
            "severity_distribution": dict(sev_counter.most_common()),
            "lookback_hours": 168,
            "fingerprint_hash": hashlib.sha256(
                f"{agent_id}:{dict(cat_counter)}".encode()
            ).hexdigest()[:16],
        },
        total_events=len(events),
        risk_profile=risk,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/analytics/sessions
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/analytics/sessions",
    response_model=list[SessionSummary],
    summary="Session analytics by agent",
)
def session_analytics(
    agent_id: Optional[str] = Query(default=None, description="Filter by agent"),
    lookback_hours: int = Query(default=24, ge=1, le=720),
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> list[SessionSummary]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    q = db.query(EventRow).filter(EventRow.timestamp >= cutoff)
    if agent_id:
        q = q.filter(EventRow.agent_id == agent_id)
    events = q.order_by(EventRow.timestamp.asc()).all()

    if not events:
        return []

    # Group into sessions: 5-minute gap = new session
    SESSION_GAP = timedelta(minutes=5)
    SEVERITY_ORDER = {"info": 0, "low": 1, "warn": 2, "medium": 3, "high": 4, "critical": 5}

    sessions: list[SessionSummary] = []
    current: list[EventRow] = [events[0]]

    for ev in events[1:]:
        if (
            ev.agent_id != current[-1].agent_id
            or (ev.timestamp - current[-1].timestamp) > SESSION_GAP
        ):
            sessions.append(_build_session(current, SEVERITY_ORDER))
            current = [ev]
        else:
            current.append(ev)
    if current:
        sessions.append(_build_session(current, SEVERITY_ORDER))

    return sorted(sessions, key=lambda s: s.session_start, reverse=True)[:100]


def _build_session(
    events: list[EventRow],
    sev_order: dict[str, int],
) -> SessionSummary:
    categories = list({e.category for e in events})
    max_sev = max(events, key=lambda e: sev_order.get(e.severity, 0))
    risk = min(1.0, sum(sev_order.get(e.severity, 0) for e in events) / max(len(events) * 3, 1))
    return SessionSummary(
        agent_id=events[0].agent_id,
        session_start=events[0].timestamp,
        session_end=events[-1].timestamp,
        event_count=len(events),
        categories=categories,
        max_severity=max_sev.severity,
        risk_score=round(risk, 2),
    )
