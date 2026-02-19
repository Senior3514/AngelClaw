"""AngelClaw Cloud – Guardian Heartbeat Service.

Background async loop that runs every 5 minutes, computes fleet health,
incident counts, anomaly detection, and stores a GuardianReportRow.

Uses SessionLocal directly (not request-scoped).
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone

from cloud.db.models import AgentNodeRow, EventRow, GuardianChangeRow, GuardianReportRow
from cloud.db.session import SessionLocal

logger = logging.getLogger("angelgrid.cloud.heartbeat")

HEARTBEAT_INTERVAL_SECONDS = 300  # 5 minutes
LOOKBACK_MINUTES = 5


async def heartbeat_loop(tenant_id: str = "dev-tenant") -> None:
    """Run the guardian heartbeat every 5 minutes. Call via asyncio.create_task."""
    logger.info("Guardian heartbeat started (interval=%ds)", HEARTBEAT_INTERVAL_SECONDS)
    while True:
        try:
            _run_heartbeat(tenant_id)
        except Exception:
            logger.exception("Guardian heartbeat failed")
        await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)


def _run_heartbeat(tenant_id: str) -> GuardianReportRow:
    """Compute fleet health and store a report row."""
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        cutoff = now - timedelta(minutes=LOOKBACK_MINUTES)

        # Fleet health
        agents = db.query(AgentNodeRow).all()
        total = len(agents)
        active = sum(1 for a in agents if a.status == "active")
        degraded = sum(1 for a in agents if a.status == "degraded")
        offline = total - active - degraded

        # Incident counts by severity in the lookback window
        events = db.query(EventRow).filter(EventRow.timestamp >= cutoff).all()
        sev_counter: Counter[str] = Counter(e.severity for e in events)

        # Anomaly detection
        anomalies: list[str] = []

        # Check for agents that went offline (last_seen > 10 min ago but status=active)
        stale_cutoff = now - timedelta(minutes=10)
        for a in agents:
            if a.status == "active" and a.last_seen_at and a.last_seen_at < stale_cutoff:
                anomalies.append(
                    f"Agent {a.hostname} ({a.id[:8]})"
                    f" may be offline"
                    f" — last seen {a.last_seen_at.isoformat()}"
                )

        # Check for severity spikes
        critical_count = sev_counter.get("critical", 0)
        high_count = sev_counter.get("high", 0)
        if critical_count >= 3:
            anomalies.append(
                f"Severity spike: {critical_count} critical events in last {LOOKBACK_MINUTES}min"
            )
        if high_count >= 10:
            anomalies.append(
                f"Severity spike: {high_count} high-severity events in last {LOOKBACK_MINUTES}min"
            )

        # Check for repeated patterns
        type_counter: Counter[str] = Counter(e.type for e in events)
        for ev_type, count in type_counter.most_common(3):
            if count >= 10:
                anomalies.append(
                    f"Repeated pattern: {ev_type} occurred {count}x in last {LOOKBACK_MINUTES}min"
                )

        # Policy changes since last report
        last_report = (
            db.query(GuardianReportRow)
            .filter(GuardianReportRow.tenant_id == tenant_id)
            .order_by(GuardianReportRow.timestamp.desc())
            .first()
        )
        changes_cutoff = last_report.timestamp if last_report else cutoff
        policy_changes = (
            db.query(GuardianChangeRow)
            .filter(
                GuardianChangeRow.tenant_id == tenant_id,
                GuardianChangeRow.created_at >= changes_cutoff,
            )
            .count()
        )
        if policy_changes > 0:
            anomalies.append(f"Policy/config: {policy_changes} change(s) since last report")

        summary = (
            f"{total} agents ({active} healthy, {degraded} degraded, {offline} offline), "
            f"{len(events)} events in last {LOOKBACK_MINUTES}min, "
            f"{policy_changes} policy change(s), "
            f"{len(anomalies)} anomalies"
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

        # Human-friendly summary lines
        logger.info("[GUARDIAN REPORT] %s", summary)
        if anomalies:
            for a in anomalies:
                logger.warning("[GUARDIAN ANOMALY] %s", a)
        if offline > 0:
            logger.warning(
                "[GUARDIAN FLEET] %d agent(s) offline — investigate connectivity", offline
            )
        return row
    finally:
        db.close()
