"""AngelClaw Cloud – Wazuh Alert Ingestion Service.

Background task that periodically polls Wazuh alerts and converts them
into AngelClaw EventRow entries for unified analysis by the guardian
orchestrator.

Runs alongside the heartbeat loop in the Cloud API lifespan.
Gracefully degrades to no-op if Wazuh is not configured.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone

from cloud.db.models import EventRow
from cloud.db.session import SessionLocal
from cloud.integrations.wazuh_client import wazuh_client

logger = logging.getLogger("angelgrid.cloud.integrations.wazuh_ingest")

# Configurable poll interval (seconds)
POLL_INTERVAL = int(os.environ.get("ANGELCLAW_WAZUH_POLL_INTERVAL", "60"))

# Track last-seen alert timestamp to avoid duplicates
_last_poll_ts: str = ""


def _wazuh_level_to_severity(level: int) -> str:
    """Map Wazuh rule level (1-15) to AngelClaw severity."""
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 5:
        return "warn"
    return "info"


def _wazuh_rule_to_category(rule_groups: list[str]) -> str:
    """Map Wazuh rule groups to AngelClaw event category."""
    groups_lower = {g.lower() for g in rule_groups}

    if groups_lower & {"authentication_failed", "authentication_success", "pam"}:
        return "auth"
    if groups_lower & {"syscheck", "fim"}:
        return "file_system"
    if groups_lower & {"firewall", "iptables", "ids"}:
        return "network"
    if groups_lower & {"rootkit", "malware", "trojan"}:
        return "process"
    if groups_lower & {"sshd", "ssh"}:
        return "network"
    return "system"


async def wazuh_ingest_loop(tenant_id: str = "dev-tenant") -> None:
    """Poll Wazuh alerts periodically and ingest into AngelClaw.

    Call via asyncio.create_task() from the server lifespan.
    """
    global _last_poll_ts

    if not wazuh_client.enabled:
        logger.info("[WAZUH INGEST] Wazuh not configured — ingest loop disabled")
        return

    logger.info(
        "[WAZUH INGEST] Started (interval=%ds, url=%s)",
        POLL_INTERVAL,
        wazuh_client.base_url,
    )

    while True:
        try:
            alerts = await wazuh_client.get_alerts(limit=100, severity=5)

            if not alerts:
                await asyncio.sleep(POLL_INTERVAL)
                continue

            # Deduplicate: skip alerts we've already seen
            new_alerts = []
            newest_ts = _last_poll_ts
            for alert in alerts:
                ts = alert.get("timestamp", "")
                if ts and ts > _last_poll_ts:
                    new_alerts.append(alert)
                    if ts > newest_ts:
                        newest_ts = ts

            if new_alerts:
                _last_poll_ts = newest_ts
                ingested = _ingest_alerts(new_alerts, tenant_id)
                logger.info(
                    "[WAZUH INGEST] Ingested %d/%d new Wazuh alerts",
                    ingested,
                    len(new_alerts),
                )

        except asyncio.CancelledError:
            logger.info("[WAZUH INGEST] Shutting down")
            break
        except Exception:
            logger.exception("[WAZUH INGEST] Poll cycle failed")

        await asyncio.sleep(POLL_INTERVAL)


def _ingest_alerts(alerts: list[dict], tenant_id: str) -> int:
    """Convert Wazuh alerts to EventRows and persist them."""
    db = SessionLocal()
    try:
        rows: list[EventRow] = []
        for alert in alerts:
            rule = alert.get("rule", {})
            agent_info = alert.get("agent", {})

            # Parse timestamp
            ts_str = alert.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                ts = datetime.now(timezone.utc)

            row = EventRow(
                id=str(uuid.uuid4()),
                agent_id=agent_info.get("id", f"wazuh-{agent_info.get('name', 'unknown')}"),
                timestamp=ts,
                category=_wazuh_rule_to_category(rule.get("groups", [])),
                type=f"wazuh.{rule.get('id', 'unknown')}",
                severity=_wazuh_level_to_severity(rule.get("level", 3)),
                details={
                    "source": "wazuh",
                    "wazuh_rule_id": rule.get("id"),
                    "wazuh_rule_description": rule.get("description", ""),
                    "wazuh_rule_level": rule.get("level"),
                    "wazuh_rule_groups": rule.get("groups", []),
                    "wazuh_agent_name": agent_info.get("name"),
                    "wazuh_agent_ip": agent_info.get("ip"),
                    "full_log": alert.get("full_log", "")[:2000],
                },
                source=f"wazuh:{agent_info.get('name', 'unknown')}",
            )
            rows.append(row)

        if rows:
            db.add_all(rows)
            db.commit()

        return len(rows)
    except Exception:
        db.rollback()
        logger.exception("[WAZUH INGEST] Failed to persist alerts")
        return 0
    finally:
        db.close()
