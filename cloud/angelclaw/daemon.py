"""AngelClaw V5 – Autonomous Daemon.

Always-on background loop that makes AngelClaw a living guardian:
  - Periodic scans (configurable frequency)
  - Guardian report generation
  - Drift detection (policy, agent health, anomalies)
  - Activity logging with human-friendly summaries
  - Respects operator preferences (frequency, reporting level, autonomy)

Lightweight: runs as an asyncio task inside the Cloud process.
No external dependencies. No separate process needed.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any

from cloud.db.models import GuardianReportRow
from cloud.db.session import SessionLocal

logger = logging.getLogger("angelclaw.daemon")

# In-memory activity log (capped ring buffer — zero DB overhead for activity)
_MAX_ACTIVITY = 200
_activity_log: deque[dict[str, Any]] = deque(maxlen=_MAX_ACTIVITY)

# Daemon state
_running = False
_task: asyncio.Task | None = None
_cycles_completed = 0
_last_scan_summary = ""


def get_recent_activity(limit: int = 20) -> list[dict]:
    """Return recent daemon activity entries (newest first)."""
    items = list(_activity_log)
    items.reverse()
    return items[:limit]


def get_daemon_status() -> dict:
    return {
        "running": _running,
        "cycles_completed": _cycles_completed,
        "last_scan_summary": _last_scan_summary,
        "activity_count": len(_activity_log),
    }


def _log_activity(summary: str, category: str = "scan", details: dict | None = None) -> None:
    """Append to in-memory activity log."""
    entry = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "category": category,
        "summary": summary,
        "details": details or {},
    }
    _activity_log.append(entry)
    logger.info("[ANGELCLAW] %s", summary)


# ---------------------------------------------------------------------------
# Main daemon loop
# ---------------------------------------------------------------------------

async def daemon_loop(tenant_id: str = "dev-tenant") -> None:
    """Main autonomous loop. Runs until cancelled."""
    global _running, _cycles_completed, _last_scan_summary

    _running = True
    _log_activity("AngelClaw daemon started — autonomous guardian active", "lifecycle")
    logger.info("[DAEMON] AngelClaw V5 daemon started for tenant=%s", tenant_id)

    # Initial short delay to let other services start
    await asyncio.sleep(5)

    while _running:
        db = None
        try:
            db = SessionLocal()

            # Get current preferences for scan frequency
            from cloud.angelclaw.preferences import get_preferences, ReportingLevel
            prefs = get_preferences(db, tenant_id)
            interval = max(60, prefs.scan_frequency_minutes * 60)  # min 1 minute
            reporting = prefs.reporting_level

            # ---- CYCLE START ----
            _cycles_completed += 1
            cycle_start = datetime.now(timezone.utc)

            # 1. Lightweight guardian scan
            scan_summary = await _run_scan(db, tenant_id, reporting)
            _last_scan_summary = scan_summary

            # 2. Generate guardian report
            _generate_report(db, tenant_id)

            # 3. Check for drift and anomalies
            drift_findings = _check_drift(db, tenant_id)

            # 4. Check agent health
            health_issues = _check_agent_health(db)

            # 5. Log cycle summary
            elapsed = (datetime.now(timezone.utc) - cycle_start).total_seconds()
            cycle_summary = (
                f"Cycle #{_cycles_completed} complete ({elapsed:.1f}s) — "
                f"{scan_summary}"
            )
            if drift_findings:
                cycle_summary += f", {len(drift_findings)} drift finding(s)"
            if health_issues:
                cycle_summary += f", {len(health_issues)} health issue(s)"

            if reporting != ReportingLevel.QUIET or drift_findings or health_issues:
                _log_activity(cycle_summary, "cycle")

            db.close()
            db = None

            # Sleep until next cycle
            await asyncio.sleep(interval)

        except asyncio.CancelledError:
            break
        except Exception:
            logger.exception("[DAEMON] Cycle error (will retry)")
            _log_activity("Daemon cycle error — will retry", "error")
            if db:
                try:
                    db.close()
                except Exception:
                    pass
            await asyncio.sleep(30)  # Back off on error

    _running = False
    _log_activity("AngelClaw daemon stopped", "lifecycle")


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

async def _run_scan(db, tenant_id: str, reporting) -> str:
    """Run lightweight guardian scan."""
    try:
        from cloud.services.guardian_scan import run_guardian_scan
        result = await run_guardian_scan(db, tenant_id)

        critical = sum(1 for r in result.top_risks if r.severity == "critical")
        high = sum(1 for r in result.top_risks if r.severity == "high")
        medium = sum(1 for r in result.top_risks if r.severity == "medium")

        summary = f"{result.total_checks} checks, {len(result.top_risks)} risks ({critical}C/{high}H/{medium}M)"

        if critical > 0:
            _log_activity(f"CRITICAL: {critical} critical exposure(s) found", "alert",
                          {"risks": [r.title for r in result.top_risks if r.severity == "critical"]})
        elif high > 0 and str(reporting) != "quiet":
            _log_activity(f"Scan: {high} high-severity exposure(s)", "scan")

        return summary
    except Exception as e:
        logger.debug("[DAEMON] Scan failed: %s", e)
        return "scan skipped"


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def _generate_report(db, tenant_id: str) -> None:
    """Generate a guardian report (same format as heartbeat)."""
    try:
        from cloud.db.models import AgentNodeRow, EventRow, GuardianChangeRow
        from collections import Counter

        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=10)

        agents = db.query(AgentNodeRow).all()
        total = len(agents)
        active = sum(1 for a in agents if a.status == "active")
        degraded = sum(1 for a in agents if a.status == "degraded")
        offline = total - active - degraded

        events = db.query(EventRow).filter(EventRow.timestamp >= cutoff).all()
        sev_counter = Counter(e.severity for e in events)

        # Check for anomalies
        anomalies = []
        stale_cutoff = now - timedelta(minutes=10)
        for a in agents:
            if a.status == "active" and a.last_seen_at and a.last_seen_at < stale_cutoff:
                anomalies.append(f"Agent {a.hostname} may be offline")

        if sev_counter.get("critical", 0) >= 3:
            anomalies.append(f"Severity spike: {sev_counter['critical']} critical events")

        # Policy changes
        last_report = (
            db.query(GuardianReportRow)
            .filter(GuardianReportRow.tenant_id == tenant_id)
            .order_by(GuardianReportRow.timestamp.desc())
            .first()
        )
        changes_cutoff = last_report.timestamp if last_report else cutoff
        from cloud.db.models import GuardianChangeRow
        policy_changes = (
            db.query(GuardianChangeRow)
            .filter(GuardianChangeRow.tenant_id == tenant_id, GuardianChangeRow.created_at >= changes_cutoff)
            .count()
        )

        summary = (
            f"{total} agents ({active} active, {degraded} degraded, {offline} offline), "
            f"{len(events)} events, {len(anomalies)} anomalies"
        )

        row = GuardianReportRow(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            timestamp=now,
            agents_total=total,
            agents_active=active,
            agents_degraded=degraded,
            agents_offline=offline,
            incidents_total=len(events),
            incidents_by_severity=dict(sev_counter),
            policy_changes_since_last=policy_changes,
            anomalies=anomalies,
            summary=summary,
        )
        db.add(row)
        db.commit()
    except Exception:
        logger.debug("[DAEMON] Report generation failed", exc_info=True)
        try:
            db.rollback()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------

def _check_drift(db, tenant_id: str) -> list[str]:
    """Check for policy drift between recommended and actual."""
    findings = []
    try:
        from cloud.db.models import AgentNodeRow, PolicySetRow
        ps = db.query(PolicySetRow).first()
        if not ps:
            return findings

        agents = db.query(AgentNodeRow).filter(AgentNodeRow.status == "active").all()
        drifted = [a for a in agents if a.policy_version != ps.version_hash and a.policy_version != "0"]
        if drifted:
            msg = f"Policy drift: {len(drifted)} agent(s) on old policy version"
            findings.append(msg)
            _log_activity(msg, "drift", {"agents": [a.hostname for a in drifted[:5]]})
    except Exception:
        pass
    return findings


# ---------------------------------------------------------------------------
# Agent health
# ---------------------------------------------------------------------------

def _check_agent_health(db) -> list[str]:
    """Check for unhealthy agents."""
    issues = []
    try:
        from cloud.db.models import AgentNodeRow
        now = datetime.now(timezone.utc)
        stale_cutoff = now - timedelta(minutes=15)
        agents = db.query(AgentNodeRow).filter(AgentNodeRow.status == "active").all()

        for a in agents:
            if a.last_seen_at and a.last_seen_at < stale_cutoff:
                msg = f"Agent {a.hostname} unresponsive (last seen {a.last_seen_at.strftime('%H:%M')})"
                issues.append(msg)
    except Exception:
        pass
    return issues


# ---------------------------------------------------------------------------
# Start / stop helpers
# ---------------------------------------------------------------------------

async def start_daemon(tenant_id: str = "dev-tenant") -> None:
    """Start the daemon as a background task."""
    global _task, _running
    if _running:
        return
    _task = asyncio.create_task(daemon_loop(tenant_id))


async def stop_daemon() -> None:
    """Stop the daemon gracefully."""
    global _running, _task
    _running = False
    if _task:
        _task.cancel()
        try:
            await _task
        except asyncio.CancelledError:
            pass
        _task = None
