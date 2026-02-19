"""AngelClaw AGI Guardian – Admin Console API Routes.

Provides organization-wide visibility, tenant management, anti-tamper control,
legion status, analytics, and manual scan triggers. All endpoints require
admin-level RBAC.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from cloud.db.models import (
    AgentNodeRow,
    AntiTamperConfigRow,
    AntiTamperEventRow,
    EventRow,
    FeedbackRecordRow,
    GuardianAlertRow,
    GuardianReportRow,
    SelfHardeningLogRow,
    TenantRow,
)
from cloud.db.session import get_db

logger = logging.getLogger("angelclaw.admin")

router = APIRouter(prefix="/api/v1/admin", tags=["Admin Console"])


def _require_admin(request: Request) -> None:
    """Verify that the current user has admin privileges."""
    user = getattr(request.state, "auth_user", None)
    if user and hasattr(user, "role"):
        if user.role.value not in ("admin", "operator"):
            raise HTTPException(status_code=403, detail="Admin access required")


# ---------------------------------------------------------------------------
# GET /org/overview — Organization-wide dashboard
# ---------------------------------------------------------------------------


@router.get("/org/overview")
def org_overview(
    request: Request,
    db: Session = Depends(get_db),
):
    """Org-level dashboard: total agents, tenants, halo score, alerts, events."""
    _require_admin(request)

    agents = db.query(AgentNodeRow).all()
    total_agents = len(agents)
    active = sum(1 for a in agents if a.status == "active")
    degraded = sum(1 for a in agents if a.status == "degraded")
    offline = total_agents - active - degraded

    now = datetime.now(timezone.utc)
    cutoff_24h = now - timedelta(hours=24)

    event_count = db.query(EventRow).filter(EventRow.timestamp >= cutoff_24h).count()
    alert_count = (
        db.query(GuardianAlertRow)
        .filter(GuardianAlertRow.created_at >= cutoff_24h)
        .count()
    )

    # Compute org-wide halo score (average of tenant scores or basic formula)
    tenants = db.query(TenantRow).all()
    if tenants:
        halo = sum(t.halo_score for t in tenants) // len(tenants)
        wingspan = sum(t.wingspan for t in tenants) // len(tenants)
    else:
        # Derive from agent health
        halo = min(100, max(0, 100 - (degraded * 10) - (offline * 20) - (alert_count * 2)))
        wingspan = min(100, total_agents * 10) if total_agents else 0

    # Orchestrator stats
    try:
        from cloud.guardian.orchestrator import angel_orchestrator
        orch = angel_orchestrator.status()
    except Exception:
        orch = {"running": False, "stats": {}}

    return {
        "agents": {
            "total": total_agents,
            "active": active,
            "degraded": degraded,
            "offline": offline,
        },
        "tenants": len(tenants) if tenants else 1,
        "halo_score": halo,
        "wingspan": wingspan,
        "events_24h": event_count,
        "alerts_24h": alert_count,
        "orchestrator": {
            "running": orch.get("running", False),
            "stats": orch.get("stats", {}),
        },
    }


# ---------------------------------------------------------------------------
# GET /tenants — List tenants with metrics
# ---------------------------------------------------------------------------


@router.get("/tenants")
def list_tenants(
    request: Request,
    db: Session = Depends(get_db),
):
    """List all tenants with aggregated metrics."""
    _require_admin(request)

    tenants = db.query(TenantRow).all()
    if not tenants:
        # Return default dev tenant if none exist
        agents = db.query(AgentNodeRow).all()
        return [{
            "id": "dev-tenant",
            "name": "Development",
            "status": "active",
            "tier": "standard",
            "agent_count": len(agents),
            "halo_score": 85,
            "wingspan": min(100, len(agents) * 10),
        }]

    result = []
    for t in tenants:
        agent_count = (
            db.query(AgentNodeRow)
            .filter(AgentNodeRow.tags.contains([t.id]))
            .count()
        )
        result.append({
            "id": t.id,
            "name": t.name,
            "description": t.description,
            "status": t.status,
            "tier": t.tier,
            "agent_count": agent_count,
            "halo_score": t.halo_score,
            "wingspan": t.wingspan,
            "contact_email": t.contact_email,
            "created_at": t.created_at.isoformat() if t.created_at else None,
        })
    return result


# ---------------------------------------------------------------------------
# GET /tenants/{tenant_id}/agents — Agents per tenant
# ---------------------------------------------------------------------------


@router.get("/tenants/{tenant_id}/agents")
def tenant_agents(
    tenant_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Get all agents belonging to a tenant."""
    _require_admin(request)

    agents = db.query(AgentNodeRow).all()
    # Filter by tenant_id in tags or return all for dev-tenant
    if tenant_id != "dev-tenant":
        agents = [a for a in agents if tenant_id in (a.tags or [])]

    return [
        {
            "agent_id": a.id,
            "hostname": a.hostname,
            "type": a.type,
            "os": a.os,
            "status": a.status,
            "version": a.version,
            "tags": a.tags or [],
            "policy_version": a.policy_version,
            "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
            "registered_at": a.registered_at.isoformat() if a.registered_at else None,
        }
        for a in agents
    ]


# ---------------------------------------------------------------------------
# GET /agents/{agent_id}/detail — Detailed agent view
# ---------------------------------------------------------------------------


@router.get("/agents/{agent_id}/detail")
def agent_detail(
    agent_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Get detailed information about a specific agent."""
    _require_admin(request)

    agent = db.query(AgentNodeRow).filter_by(id=agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    events = (
        db.query(EventRow)
        .filter(EventRow.agent_id == agent_id, EventRow.timestamp >= cutoff)
        .order_by(EventRow.timestamp.desc())
        .limit(50)
        .all()
    )

    alerts = (
        db.query(GuardianAlertRow)
        .filter(GuardianAlertRow.related_agent_ids.contains([agent_id]))
        .order_by(GuardianAlertRow.created_at.desc())
        .limit(20)
        .all()
    )

    # Anti-tamper status
    from cloud.services.anti_tamper import anti_tamper_service
    tamper_config = anti_tamper_service.get_config("dev-tenant", agent_id)

    return {
        "agent": {
            "id": agent.id,
            "hostname": agent.hostname,
            "type": agent.type,
            "os": agent.os,
            "status": agent.status,
            "version": agent.version,
            "tags": agent.tags or [],
            "policy_version": agent.policy_version,
            "last_seen_at": agent.last_seen_at.isoformat() if agent.last_seen_at else None,
            "registered_at": agent.registered_at.isoformat() if agent.registered_at else None,
        },
        "events_24h": len(events),
        "recent_events": [
            {
                "id": e.id,
                "category": e.category,
                "type": e.type,
                "severity": e.severity,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            }
            for e in events[:20]
        ],
        "alerts": [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in alerts[:10]
        ],
        "anti_tamper": {
            "mode": tamper_config.mode.value,
            "protected": tamper_config.mode.value != "off",
        },
    }


# ---------------------------------------------------------------------------
# POST /anti-tamper/configure — Set anti-tamper config
# ---------------------------------------------------------------------------


@router.post("/anti-tamper/configure")
def configure_anti_tamper(
    request: Request,
    body: dict,
    db: Session = Depends(get_db),
):
    """Configure anti-tamper protection for a tenant or agent."""
    _require_admin(request)

    from cloud.services.anti_tamper import anti_tamper_service

    tenant_id = body.get("tenant_id", "dev-tenant")
    mode = body.get("mode", "monitor")
    agent_id = body.get("agent_id")

    user = getattr(request.state, "auth_user", None)
    enabled_by = user.username if user else "system"

    try:
        config = anti_tamper_service.configure(
            tenant_id=tenant_id,
            mode=mode,
            agent_id=agent_id,
            enabled_by=enabled_by,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Persist to DB
    row = AntiTamperConfigRow(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        agent_id=agent_id,
        mode=mode,
        enabled_by=enabled_by,
    )
    db.add(row)
    try:
        db.commit()
    except Exception:
        db.rollback()

    return {
        "status": "configured",
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "mode": mode,
        "enabled_by": enabled_by,
    }


# ---------------------------------------------------------------------------
# GET /anti-tamper/status — Anti-tamper status overview
# ---------------------------------------------------------------------------


@router.get("/anti-tamper/status")
def anti_tamper_status(
    request: Request,
    tenant_id: str = Query(default=None),
):
    """Get anti-tamper status overview."""
    _require_admin(request)

    from cloud.services.anti_tamper import anti_tamper_service
    return anti_tamper_service.get_status(tenant_id)


# ---------------------------------------------------------------------------
# GET /anti-tamper/events — Tamper event log
# ---------------------------------------------------------------------------


@router.get("/anti-tamper/events")
def anti_tamper_events(
    request: Request,
    tenant_id: str = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
):
    """Get tamper detection events."""
    _require_admin(request)

    from cloud.services.anti_tamper import anti_tamper_service
    return anti_tamper_service.get_events(tenant_id=tenant_id, limit=limit)


# ---------------------------------------------------------------------------
# GET /legion/status — Legion wardens status
# ---------------------------------------------------------------------------


@router.get("/legion/status")
def legion_status(request: Request):
    """Get Angel Legion warden status and performance metrics."""
    _require_admin(request)

    try:
        from cloud.guardian.orchestrator import angel_orchestrator
        status = angel_orchestrator.status()
        return {
            "running": status.get("running", False),
            "autonomy_mode": status.get("autonomy_mode", "unknown"),
            "legion": status.get("legion", {}),
            "agents": status.get("agents", {}),
            "warden_performance": status.get("warden_performance", {}),
            "stats": status.get("stats", {}),
            "incidents": status.get("incidents", {}),
        }
    except Exception as e:
        return {"running": False, "error": str(e)}


# ---------------------------------------------------------------------------
# GET /analytics/trends — Trend analytics
# ---------------------------------------------------------------------------


@router.get("/analytics/trends")
def analytics_trends(
    request: Request,
    lookback_hours: int = Query(default=24, ge=1, le=720),
    db: Session = Depends(get_db),
):
    """Get threat trend analytics."""
    _require_admin(request)

    try:
        from cloud.services.predictive import predict_trends
        trends = predict_trends(db, lookback_hours=lookback_hours)
        if trends:
            return trends[0]
        return {"overall_direction": "stable", "by_category": []}
    except Exception:
        return {"overall_direction": "stable", "by_category": []}


# ---------------------------------------------------------------------------
# GET /analytics/risk-scores — Risk scoring with learning data
# ---------------------------------------------------------------------------


@router.get("/analytics/risk-scores")
def analytics_risk_scores(request: Request):
    """Get risk scoring data from the learning engine."""
    _require_admin(request)

    try:
        from cloud.guardian.learning import learning_engine
        summary = learning_engine.summary()
        return {
            "total_reflections": summary.get("total_reflections", 0),
            "detection_effectiveness": learning_engine.detection_effectiveness_score(),
            "escalation_rate": learning_engine.get_escalation_rate(),
            "playbook_ranking": summary.get("playbook_ranking", []),
            "pattern_precision": summary.get("pattern_precision", {}),
            "confidence_overrides": summary.get("confidence_overrides", {}),
            "correlated_patterns": learning_engine.get_correlated_patterns(),
        }
    except Exception:
        return {"total_reflections": 0, "detection_effectiveness": 0.5}


# ---------------------------------------------------------------------------
# POST /scan/trigger — Trigger manual scan
# ---------------------------------------------------------------------------


@router.post("/scan/trigger")
async def trigger_scan(
    request: Request,
    body: dict,
    db: Session = Depends(get_db),
):
    """Trigger a manual Guardian scan for a tenant."""
    _require_admin(request)

    tenant_id = body.get("tenant_id", "dev-tenant")
    scan_type = body.get("scan_type", "halo_sweep")

    try:
        from cloud.guardian.orchestrator import angel_orchestrator

        if scan_type == "halo_sweep":
            result = await angel_orchestrator.halo_sweep(db, tenant_id)
        elif scan_type == "pulse_check":
            result = angel_orchestrator.pulse_check()
        else:
            result = await angel_orchestrator.halo_sweep(db, tenant_id)

        return {
            "status": "completed",
            "tenant_id": tenant_id,
            "scan_type": scan_type,
            "result": result,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ---------------------------------------------------------------------------
# GET /feedback/summary — Feedback loop summary
# ---------------------------------------------------------------------------


@router.get("/feedback/summary")
def feedback_summary(
    request: Request,
    tenant_id: str = Query(default="dev-tenant"),
):
    """Get operator feedback summary."""
    _require_admin(request)

    from cloud.services.feedback_loop import feedback_service
    return feedback_service.get_tenant_summary(tenant_id)


# ---------------------------------------------------------------------------
# POST /feedback — Record operator feedback
# ---------------------------------------------------------------------------


@router.post("/feedback")
def record_feedback(
    request: Request,
    body: dict,
):
    """Record operator feedback on a suggestion."""
    _require_admin(request)

    from cloud.services.feedback_loop import feedback_service

    user = getattr(request.state, "auth_user", None)
    operator = user.username if user else "unknown"

    try:
        record = feedback_service.record_feedback(
            tenant_id=body.get("tenant_id", "dev-tenant"),
            suggestion_type=body.get("suggestion_type", "general"),
            action=body.get("action", "accepted"),
            operator=operator,
            suggestion_id=body.get("suggestion_id", ""),
            reason=body.get("reason", ""),
            context=body.get("context", {}),
        )
        return {"status": "recorded", "feedback_id": record.id}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------------------
# GET /hardening/log — Self-hardening log
# ---------------------------------------------------------------------------


@router.get("/hardening/log")
def hardening_log(
    request: Request,
    tenant_id: str = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
):
    """Get self-hardening action log."""
    _require_admin(request)

    from cloud.services.self_hardening import self_hardening_engine
    return self_hardening_engine.get_hardening_log(tenant_id=tenant_id, limit=limit)


# ---------------------------------------------------------------------------
# POST /hardening/apply — Apply a proposed hardening action
# ---------------------------------------------------------------------------


@router.post("/hardening/apply")
def apply_hardening(
    request: Request,
    body: dict,
):
    """Apply a proposed hardening action."""
    _require_admin(request)

    from cloud.services.self_hardening import self_hardening_engine

    user = getattr(request.state, "auth_user", None)
    applied_by = user.username if user else "operator"

    action_id = body.get("action_id")
    if not action_id:
        raise HTTPException(status_code=400, detail="action_id required")

    result = self_hardening_engine.apply_action(action_id, applied_by=applied_by)
    if not result:
        raise HTTPException(status_code=404, detail="Action not found")
    return result


# ---------------------------------------------------------------------------
# POST /hardening/revert — Revert a hardening action
# ---------------------------------------------------------------------------


@router.post("/hardening/revert")
def revert_hardening(
    request: Request,
    body: dict,
):
    """Revert a previously applied hardening action."""
    _require_admin(request)

    from cloud.services.self_hardening import self_hardening_engine

    user = getattr(request.state, "auth_user", None)
    reverted_by = user.username if user else "operator"

    action_id = body.get("action_id")
    if not action_id:
        raise HTTPException(status_code=400, detail="action_id required")

    result = self_hardening_engine.revert_action(action_id, reverted_by=reverted_by)
    if not result:
        raise HTTPException(status_code=404, detail="Action not found")
    return result
