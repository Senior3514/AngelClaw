"""AngelClaw Cloud – Metrics & Readiness Routes.

Provides:
  GET /ready   — deep readiness probe (DB, orchestrator, sub-agents)
  GET /metrics — Prometheus-compatible text exposition
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from cloud.db.models import AgentNodeRow, EventRow, GuardianAlertRow, IncidentRow
from cloud.db.session import get_db
from cloud.guardian.orchestrator import angel_orchestrator

router = APIRouter(tags=["Observability"])

_START_TIME = time.monotonic()


# ---------------------------------------------------------------------------
# GET /ready — deep readiness check
# ---------------------------------------------------------------------------


@router.get("/ready")
def readiness_check(db: Session = Depends(get_db)):
    """Deep readiness probe: DB, orchestrator, and sub-agent health."""
    checks: dict[str, dict] = {}

    # 1. Database connectivity
    try:
        db.execute(
            db.bind.dialect.do_ping(db.connection())
            if False
            else __import__("sqlalchemy").text("SELECT 1")
        )
        checks["database"] = {"status": "ok"}
    except Exception as exc:
        checks["database"] = {"status": "fail", "error": str(exc)[:200]}

    # 2. Orchestrator running
    orch_status = angel_orchestrator.status()
    checks["orchestrator"] = {
        "status": "ok" if orch_status["running"] else "degraded",
        "events_processed": orch_status["stats"]["events_processed"],
    }

    # 3. Sub-agents (iterate all agents from registry)
    for agent_id, info in orch_status["agents"].items():
        agent_type = info.get("agent_type", "unknown")
        checks[f"agent_{agent_type}_{agent_id[:8]}"] = {
            "status": info["status"],
            "tasks_completed": info["tasks_completed"],
            "tasks_failed": info["tasks_failed"],
        }

    # Overall verdict
    all_ok = all(c.get("status") in ("ok", "idle") for c in checks.values())
    status_code = 200 if all_ok else 503

    return {
        "ready": all_ok,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    } | ({"_status_code": status_code} if not all_ok else {})


# ---------------------------------------------------------------------------
# GET /metrics — Prometheus text exposition
# ---------------------------------------------------------------------------


@router.get("/metrics", response_class=PlainTextResponse)
def prometheus_metrics(db: Session = Depends(get_db)):
    """Prometheus-compatible metrics endpoint."""
    lines: list[str] = []

    def _gauge(name: str, help_text: str, value: float, labels: str = "") -> None:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} gauge")
        label_str = f"{{{labels}}}" if labels else ""
        lines.append(f"{name}{label_str} {value}")

    def _counter(name: str, help_text: str, value: float, labels: str = "") -> None:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} counter")
        label_str = f"{{{labels}}}" if labels else ""
        lines.append(f"{name}{label_str} {value}")

    # --- Uptime ---
    uptime = time.monotonic() - _START_TIME
    _gauge("angelclaw_uptime_seconds", "Process uptime in seconds", round(uptime, 1))

    # --- Fleet metrics (from DB) ---
    try:
        total_agents = db.query(AgentNodeRow).count()
        active_agents = db.query(AgentNodeRow).filter_by(status="active").count()
        _gauge("angelclaw_agents_total", "Total registered agents", total_agents)
        _gauge("angelclaw_agents_active", "Active agents", active_agents)
    except Exception:
        pass

    try:
        total_events = db.query(EventRow).count()
        _counter("angelclaw_events_ingested_total", "Total events ingested", total_events)
    except Exception:
        pass

    try:
        total_alerts = db.query(GuardianAlertRow).count()
        _counter("angelclaw_alerts_total", "Total guardian alerts", total_alerts)

        for sev in ("critical", "high", "warn", "info"):
            count = db.query(GuardianAlertRow).filter_by(severity=sev).count()
            if count:
                lines.append(f'angelclaw_alerts_by_severity{{severity="{sev}"}} {count}')
    except Exception:
        pass

    try:
        total_incidents = db.query(IncidentRow).count()
        _counter("angelclaw_incidents_total", "Total incidents", total_incidents)

        for status in ("open", "resolved", "escalated"):
            count = db.query(IncidentRow).filter_by(status=status).count()
            if count:
                lines.append(f'angelclaw_incidents_by_status{{status="{status}"}} {count}')
    except Exception:
        pass

    # --- Orchestrator stats ---
    orch = angel_orchestrator.status()
    stats = orch.get("stats", {})
    _counter(
        "angelclaw_orchestrator_events_processed_total",
        "Events processed by orchestrator",
        stats.get("events_processed", 0),
    )
    _counter(
        "angelclaw_orchestrator_indicators_total",
        "Threat indicators detected",
        stats.get("indicators_found", 0),
    )
    _counter(
        "angelclaw_orchestrator_incidents_total",
        "Incidents created by orchestrator",
        stats.get("incidents_created", 0),
    )
    _counter(
        "angelclaw_orchestrator_responses_total",
        "Responses executed",
        stats.get("responses_executed", 0),
    )

    _gauge(
        "angelclaw_orchestrator_running",
        "Whether orchestrator is running (1=yes, 0=no)",
        1 if orch.get("running") else 0,
    )
    _gauge(
        "angelclaw_orchestrator_pending_approvals",
        "Incidents pending operator approval",
        orch.get("incidents", {}).get("pending_approval", 0),
    )

    # --- Sub-agent health (all agents in registry) ---
    lines.append("# HELP angelclaw_agent_healthy Sub-agent health (1=healthy)")
    lines.append("# TYPE angelclaw_agent_healthy gauge")
    for agent_id, info in orch["agents"].items():
        agent_type = info.get("agent_type", "unknown")
        healthy = 1 if info["status"] in ("ok", "idle") else 0
        lines.append(
            f'angelclaw_agent_healthy{{agent="{agent_type}",'
            f'id="{agent_id[:8]}"}} {healthy}'
        )
        lines.append(
            f'angelclaw_agent_tasks_completed{{agent="{agent_type}",id="{agent_id[:8]}"}} '
            f'{info["tasks_completed"]}'
        )
        lines.append(
            f'angelclaw_agent_tasks_failed{{agent="{agent_type}",id="{agent_id[:8]}"}} '
            f'{info["tasks_failed"]}'
        )

    # --- Playbooks ---
    playbooks = orch.get("playbooks", [])
    _gauge("angelclaw_playbooks_loaded", "Number of loaded playbooks", len(playbooks))

    lines.append("")
    return "\n".join(lines)
