"""ANGELGRID Cloud – Event Bus (Critical Pattern Detection).

Called synchronously from ingest_events() after batch insert.
Detects dangerous patterns and creates GuardianAlertRow entries.

Patterns detected:
  - Repeated secret exfiltration (>=2 secret-access events in a batch)
  - High-severity burst (>=5 high/critical from one agent in a batch)
  - Agent flapping (agent re-registering frequently)
"""

from __future__ import annotations

import logging
import uuid
from collections import Counter
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from cloud.db.models import EventRow, GuardianAlertRow

logger = logging.getLogger("angelgrid.cloud.event_bus")


def check_for_alerts(db: Session, events: list[EventRow], tenant_id: str = "dev-tenant") -> list[GuardianAlertRow]:
    """Analyze a batch of ingested events for critical patterns.

    Called synchronously inside ingest_events(). Creates GuardianAlertRow
    entries for any patterns found and commits them.
    """
    alerts: list[GuardianAlertRow] = []

    if not events:
        return alerts

    # Pattern 1: Repeated secret exfiltration
    secret_events = [
        e for e in events
        if (e.details or {}).get("accesses_secrets") is True
    ]
    if len(secret_events) >= 2:
        agent_ids = list({e.agent_id for e in secret_events})
        alert = GuardianAlertRow(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            alert_type="repeated_secret_exfil",
            title=f"Repeated secret access detected: {len(secret_events)} events in batch",
            severity="critical",
            details={
                "secret_event_count": len(secret_events),
                "event_types": list({e.type for e in secret_events}),
            },
            related_event_ids=[e.id for e in secret_events],
            related_agent_ids=agent_ids,
        )
        alerts.append(alert)
        logger.warning(
            "Guardian Alert [repeated_secret_exfil]: %s — %d related events from %d agents",
            alert.title, len(secret_events), len(agent_ids),
        )

    # Pattern 2: High-severity burst from one agent (>=5)
    agent_high_sev: Counter[str] = Counter()
    high_sev_events: dict[str, list[EventRow]] = {}
    for e in events:
        if e.severity in ("high", "critical"):
            agent_high_sev[e.agent_id] += 1
            high_sev_events.setdefault(e.agent_id, []).append(e)

    for agent_id, count in agent_high_sev.items():
        if count >= 5:
            evts = high_sev_events[agent_id]
            alert = GuardianAlertRow(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                alert_type="high_severity_burst",
                title=f"High-severity burst: {count} events from agent {agent_id[:8]}",
                severity="high",
                details={
                    "agent_id": agent_id,
                    "event_count": count,
                    "severities": dict(Counter(e.severity for e in evts)),
                },
                related_event_ids=[e.id for e in evts],
                related_agent_ids=[agent_id],
            )
            alerts.append(alert)
            logger.warning(
                "Guardian Alert [high_severity_burst]: %s — %d related events from 1 agent",
                alert.title, count,
            )

    # Pattern 3: Agent flapping (multiple different types from same agent in short burst)
    agent_types: dict[str, set[str]] = {}
    for e in events:
        agent_types.setdefault(e.agent_id, set()).add(e.type)
    for agent_id, types in agent_types.items():
        if len(types) >= 8:
            alert = GuardianAlertRow(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                alert_type="agent_flapping",
                title=f"Agent flapping: {len(types)} distinct event types from {agent_id[:8]}",
                severity="warn",
                details={
                    "agent_id": agent_id,
                    "distinct_types": len(types),
                    "types": sorted(types),
                },
                related_event_ids=[e.id for e in events if e.agent_id == agent_id],
                related_agent_ids=[agent_id],
            )
            alerts.append(alert)
            logger.warning(
                "Guardian Alert [agent_flapping]: %s — %d event types",
                alert.title, len(types),
            )

    if alerts:
        db.add_all(alerts)
        db.commit()
        for a in alerts:
            logger.warning(
                "[GUARDIAN ALERT] %s | severity=%s | %s | agents=%s",
                a.alert_type, a.severity, a.title,
                ",".join(a.related_agent_ids[:3]) if a.related_agent_ids else "none",
            )

    return alerts
