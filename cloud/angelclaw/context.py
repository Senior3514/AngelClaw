"""AngelClaw AGI Guardian – Deep Context Engine.

Gathers comprehensive system context for the brain to use when answering
questions, making decisions, or proposing actions. This is what gives
AngelClaw its "awareness" of the environment it lives in.
"""

from __future__ import annotations

import logging
import os
import platform
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from cloud.db.models import (
    AgentNodeRow,
    EventRow,
    GuardianAlertRow,
    GuardianChangeRow,
    PolicySetRow,
)

logger = logging.getLogger("angelclaw.context")

_BOOT_TIME = time.monotonic()


# ---------------------------------------------------------------------------
# Context Snapshot
# ---------------------------------------------------------------------------


class EnvironmentContext:
    """A snapshot of everything AngelClaw knows about its environment."""

    def __init__(self) -> None:
        self.host: dict[str, Any] = {}
        self.agents: list[dict] = []
        self.agent_summary: dict[str, int] = {}
        self.recent_events: list[dict] = []
        self.event_summary: dict[str, int] = {}
        self.recent_alerts: list[dict] = []
        self.recent_incidents: list[dict] = []
        self.policy: dict[str, Any] = {}
        self.recent_changes: list[dict] = []
        self.orchestrator_status: dict[str, Any] = {}
        self.self_audit_summary: str = ""
        self.learning_summary: dict[str, Any] = {}
        self.preferences: dict[str, Any] = {}
        self.recent_activity: list[dict] = []
        self.timestamp: datetime = datetime.now(timezone.utc)

    def to_prompt_context(self) -> str:
        """Format as a text block the brain can reason over."""
        lines = [
            "=== ANGELCLAW ENVIRONMENT CONTEXT ===",
            f"Timestamp: {self.timestamp.isoformat()}",
            "",
            "--- HOST ---",
        ]
        for k, v in self.host.items():
            lines.append(f"  {k}: {v}")

        lines.append("")
        lines.append(f"--- FLEET ({self.agent_summary.get('total', 0)} agents) ---")
        for k, v in self.agent_summary.items():
            lines.append(f"  {k}: {v}")
        if self.agents:
            lines.append("  Recent agents:")
            for a in self.agents[:5]:
                lines.append(
                    f"    - {a.get('hostname', '?')} ({a.get('status', '?')}, {a.get('type', '?')})"
                )

        lines.append("")
        lines.append("--- EVENTS (last 24h) ---")
        for k, v in self.event_summary.items():
            lines.append(f"  {k}: {v}")

        if self.recent_alerts:
            lines.append("")
            lines.append(f"--- ALERTS ({len(self.recent_alerts)} recent) ---")
            for a in self.recent_alerts[:5]:
                lines.append(f"  [{a.get('severity', '?')}] {a.get('title', '?')}")

        if self.recent_incidents:
            lines.append("")
            lines.append(f"--- INCIDENTS ({len(self.recent_incidents)} active) ---")
            for inc in self.recent_incidents[:5]:
                lines.append(
                    f"  [{inc.get('severity', '?')}]"
                    f" {inc.get('title', '?')}"
                    f" — {inc.get('state', '?')}"
                )

        lines.append("")
        lines.append("--- POLICY ---")
        lines.append(f"  Name: {self.policy.get('name', 'unknown')}")
        lines.append(f"  Rules: {self.policy.get('rule_count', 0)}")
        lines.append(f"  Version: {self.policy.get('version', 'unknown')}")

        if self.recent_changes:
            lines.append("")
            lines.append(f"--- RECENT CHANGES ({len(self.recent_changes)}) ---")
            for c in self.recent_changes[:5]:
                lines.append(f"  [{c.get('change_type', '?')}] {c.get('description', '?')}")

        lines.append("")
        lines.append("--- ORCHESTRATOR ---")
        orch = self.orchestrator_status
        lines.append(f"  Running: {orch.get('running', False)}")
        stats = orch.get("stats", {})
        for k, v in stats.items():
            lines.append(f"  {k}: {v}")

        if self.self_audit_summary:
            lines.append("")
            lines.append("--- SELF-AUDIT ---")
            lines.append(f"  {self.self_audit_summary}")

        lines.append("")
        lines.append("--- PREFERENCES ---")
        for k, v in self.preferences.items():
            lines.append(f"  {k}: {v}")

        if self.recent_activity:
            lines.append("")
            lines.append(f"--- RECENT ACTIVITY ({len(self.recent_activity)} entries) ---")
            for act in self.recent_activity[:5]:
                lines.append(f"  [{act.get('timestamp', '?')}] {act.get('summary', '?')}")

        lines.append("")
        lines.append("=== END CONTEXT ===")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Context Gatherer
# ---------------------------------------------------------------------------


def gather_context(
    db: Session,
    tenant_id: str = "dev-tenant",
    lookback_hours: int = 24,
    include_events: bool = True,
) -> EnvironmentContext:
    """Build a comprehensive environment context snapshot."""
    ctx = EnvironmentContext()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

    # Host info
    ctx.host = _gather_host_info()

    # Agents
    agents = db.query(AgentNodeRow).all()
    ctx.agents = [
        {
            "id": a.id,
            "hostname": a.hostname,
            "type": a.type,
            "os": a.os,
            "status": a.status,
            "version": a.version,
            "tags": a.tags or [],
            "policy_version": a.policy_version,
            "last_seen": a.last_seen_at.isoformat() if a.last_seen_at else None,
        }
        for a in agents
    ]
    ctx.agent_summary = {
        "total": len(agents),
        "active": sum(1 for a in agents if a.status == "active"),
        "degraded": sum(1 for a in agents if a.status == "degraded"),
        "offline": sum(1 for a in agents if a.status == "offline"),
    }

    # Events
    if include_events:
        events = (
            db.query(EventRow)
            .filter(EventRow.timestamp >= cutoff)
            .order_by(EventRow.timestamp.desc())
            .limit(200)
            .all()
        )
        ctx.recent_events = [
            {
                "id": e.id,
                "agent_id": e.agent_id,
                "category": e.category,
                "type": e.type,
                "severity": e.severity,
                "source": e.source,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            }
            for e in events[:20]
        ]
        by_severity = {}
        by_category = {}
        for e in events:
            by_severity[e.severity] = by_severity.get(e.severity, 0) + 1
            by_category[e.category] = by_category.get(e.category, 0) + 1
        ctx.event_summary = {
            "total": len(events),
            "by_severity": by_severity,
            "by_category": by_category,
        }

    # Alerts
    alerts = (
        db.query(GuardianAlertRow)
        .filter(GuardianAlertRow.created_at >= cutoff)
        .order_by(GuardianAlertRow.created_at.desc())
        .limit(20)
        .all()
    )
    ctx.recent_alerts = [
        {
            "id": a.id,
            "alert_type": a.alert_type,
            "title": a.title,
            "severity": a.severity,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in alerts
    ]

    # Policy
    ps = db.query(PolicySetRow).first()
    if ps:
        ctx.policy = {
            "name": ps.name,
            "rule_count": len(ps.rules_json) if ps.rules_json else 0,
            "version": ps.version_hash,
            "description": ps.description,
        }

    # Changes
    changes = (
        db.query(GuardianChangeRow)
        .filter(GuardianChangeRow.created_at >= cutoff)
        .order_by(GuardianChangeRow.created_at.desc())
        .limit(10)
        .all()
    )
    ctx.recent_changes = [
        {
            "change_type": c.change_type,
            "description": c.description,
            "changed_by": c.changed_by,
            "created_at": c.created_at.isoformat() if c.created_at else None,
        }
        for c in changes
    ]

    # Orchestrator
    try:
        from cloud.guardian.orchestrator import angel_orchestrator

        ctx.orchestrator_status = angel_orchestrator.status()

        incidents = angel_orchestrator.list_incidents(limit=10)
        ctx.recent_incidents = [
            {
                "incident_id": inc.incident_id,
                "state": inc.state.value,
                "severity": inc.severity,
                "title": inc.title,
                "playbook": inc.playbook_name,
                "created_at": inc.created_at.isoformat() if inc.created_at else None,
            }
            for inc in incidents
        ]
    except Exception:
        ctx.orchestrator_status = {"running": False, "error": "unavailable"}

    # Self-audit summary
    try:
        import asyncio

        from cloud.guardian.self_audit import run_self_audit

        loop = asyncio.get_event_loop()
        if loop.is_running():
            ctx.self_audit_summary = "(audit available on demand)"
        else:
            report = loop.run_until_complete(run_self_audit(db))
            ctx.self_audit_summary = report.summary
    except Exception:
        ctx.self_audit_summary = "(audit unavailable)"

    # Learning
    try:
        from cloud.guardian.learning import learning_engine

        ctx.learning_summary = learning_engine.summary()
    except Exception:
        ctx.learning_summary = {}

    # Preferences
    try:
        from cloud.angelclaw.preferences import get_preferences

        prefs = get_preferences(db, tenant_id)
        ctx.preferences = prefs.model_dump(mode="json")
    except Exception:
        ctx.preferences = {}

    # Recent daemon activity
    try:
        from cloud.angelclaw.daemon import get_recent_activity

        ctx.recent_activity = get_recent_activity(limit=10)
    except Exception:
        ctx.recent_activity = []

    return ctx


def _gather_host_info() -> dict[str, Any]:
    """Collect information about the host machine."""
    uptime_seconds = time.monotonic() - _BOOT_TIME
    hours, remainder = divmod(int(uptime_seconds), 3600)
    minutes, _ = divmod(remainder, 60)

    return {
        "hostname": platform.node() or os.environ.get("HOSTNAME", "unknown"),
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "architecture": platform.machine(),
        "angelclaw_version": "3.0.0",
        "process_uptime": f"{hours}h {minutes}m",
        "pid": os.getpid(),
    }
