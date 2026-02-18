"""AngelClaw Cloud – Event Bus (Critical Pattern Detection).

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

from sqlalchemy.orm import Session

from cloud.db.models import EventRow, GuardianAlertRow

logger = logging.getLogger("angelgrid.cloud.event_bus")


def check_for_alerts(
    db: Session, events: list[EventRow], tenant_id: str = "dev-tenant"
) -> list[GuardianAlertRow]:
    """Analyze a batch of ingested events for critical patterns.

    Called synchronously inside ingest_events(). Creates GuardianAlertRow
    entries for any patterns found and commits them.
    """
    alerts: list[GuardianAlertRow] = []

    if not events:
        return alerts

    # Pattern 1: Repeated secret exfiltration
    secret_events = [e for e in events if (e.details or {}).get("accesses_secrets") is True]
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
            alert.title,
            len(secret_events),
            len(agent_ids),
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
                alert.title,
                count,
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
                alert.title,
                len(types),
            )

    # V2.1 — Pattern 4: Privilege escalation cascade
    priv_keywords = {"sudo", "chmod", "setuid", "escalat", "root", "admin", "privilege"}
    priv_events = [
        e for e in events
        if any(k in ((e.details or {}).get("command", "") or (e.type or "")).lower()
               for k in priv_keywords)
        and e.severity in ("high", "critical")
    ]
    if len(priv_events) >= 3:
        priv_agents = list({e.agent_id for e in priv_events})
        alert = GuardianAlertRow(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            alert_type="privilege_escalation_cascade",
            title=f"Privilege escalation cascade: {len(priv_events)} events across {len(priv_agents)} agent(s)",
            severity="critical",
            details={
                "event_count": len(priv_events),
                "agents": priv_agents[:10],
            },
            related_event_ids=[e.id for e in priv_events],
            related_agent_ids=priv_agents,
        )
        alerts.append(alert)
        logger.warning(
            "Guardian Alert [privilege_escalation_cascade]: %s", alert.title
        )

    # V2.1 — Pattern 5: Lateral movement detection
    lateral_keywords = {"ssh", "rdp", "psexec", "wmi", "lateral", "pivot", "remote_exec"}
    lateral_events = [
        e for e in events
        if any(k in ((e.details or {}).get("command", "") or (e.type or "")).lower()
               for k in lateral_keywords)
    ]
    lateral_agents = {e.agent_id for e in lateral_events}
    if len(lateral_agents) >= 2 and len(lateral_events) >= 3:
        alert = GuardianAlertRow(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            alert_type="lateral_movement",
            title=f"Lateral movement: {len(lateral_events)} events across {len(lateral_agents)} agents",
            severity="critical",
            details={
                "event_count": len(lateral_events),
                "agents": sorted(lateral_agents)[:10],
            },
            related_event_ids=[e.id for e in lateral_events],
            related_agent_ids=sorted(lateral_agents),
        )
        alerts.append(alert)
        logger.warning("Guardian Alert [lateral_movement]: %s", alert.title)

    # V2.1 — Pattern 6: Data staging (compress/encode before exfil)
    staging_keywords = {"base64", "gzip", "tar ", "zip ", "compress", "encode", "encrypt"}
    staging_events = [
        e for e in events
        if any(k in ((e.details or {}).get("command", "") or "").lower()
               for k in staging_keywords)
    ]
    if len(staging_events) >= 2:
        staging_agents = list({e.agent_id for e in staging_events})
        alert = GuardianAlertRow(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            alert_type="data_staging",
            title=f"Data staging detected: {len(staging_events)} encoding/compression events",
            severity="high",
            details={
                "event_count": len(staging_events),
                "agents": staging_agents[:10],
            },
            related_event_ids=[e.id for e in staging_events],
            related_agent_ids=staging_agents,
        )
        alerts.append(alert)
        logger.warning("Guardian Alert [data_staging]: %s", alert.title)

    # V2.1 — Pattern 7: Credential spray (multiple agents with failed auth)
    auth_fail_agents: dict[str, int] = {}
    auth_fail_events: dict[str, list[EventRow]] = {}
    for e in events:
        if e.type and "auth" in e.type.lower() and e.severity in ("high", "critical"):
            auth_fail_agents[e.agent_id] = auth_fail_agents.get(e.agent_id, 0) + 1
            auth_fail_events.setdefault(e.agent_id, []).append(e)
    spray_agents = [aid for aid, cnt in auth_fail_agents.items() if cnt >= 2]
    if len(spray_agents) >= 2:
        all_spray_events = []
        for aid in spray_agents:
            all_spray_events.extend(auth_fail_events.get(aid, []))
        alert = GuardianAlertRow(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            alert_type="credential_spray",
            title=f"Credential spray: auth failures across {len(spray_agents)} agents",
            severity="critical",
            details={
                "agents": spray_agents[:10],
                "total_failures": sum(auth_fail_agents[a] for a in spray_agents),
            },
            related_event_ids=[e.id for e in all_spray_events],
            related_agent_ids=spray_agents,
        )
        alerts.append(alert)
        logger.warning("Guardian Alert [credential_spray]: %s", alert.title)

    if alerts:
        db.add_all(alerts)
        db.commit()
        for a in alerts:
            logger.warning(
                "[GUARDIAN ALERT] %s | severity=%s | %s | agents=%s",
                a.alert_type,
                a.severity,
                a.title,
                ",".join(a.related_agent_ids[:3]) if a.related_agent_ids else "none",
            )

        # Fire webhooks for critical/high alerts (non-blocking)
        _fire_webhooks(alerts, tenant_id)

    return alerts


def _fire_webhooks(alerts: list[GuardianAlertRow], tenant_id: str) -> None:
    """Send webhook notifications for critical alerts (best-effort)."""
    try:
        import asyncio

        from cloud.services.webhook import webhook_sink

        if not webhook_sink.enabled:
            return

        for a in alerts:
            if a.severity in ("critical", "high"):
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        loop.create_task(
                            webhook_sink.send_alert(
                                alert_type=a.alert_type,
                                title=a.title,
                                severity=a.severity,
                                details=a.details,
                                tenant_id=tenant_id,
                                related_event_ids=a.related_event_ids,
                            )
                        )
                    else:
                        asyncio.run(
                            webhook_sink.send_alert(
                                alert_type=a.alert_type,
                                title=a.title,
                                severity=a.severity,
                                details=a.details,
                                tenant_id=tenant_id,
                                related_event_ids=a.related_event_ids,
                            )
                        )
                except Exception:
                    logger.debug("Webhook fire failed for alert %s", a.id, exc_info=True)
    except Exception:
        logger.debug("Webhook module unavailable", exc_info=True)
