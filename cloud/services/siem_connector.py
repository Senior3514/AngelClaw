"""AngelClaw V4.2 — Nexus: Universal SIEM Connector Service.

Manages bidirectional SIEM integrations (Splunk, Elastic, QRadar, ArcSight,
Sentinel, Wazuh) with configurable sync directions and event filters.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.siem_connector")

SUPPORTED_SIEMS = {"splunk", "elastic", "qradar", "arcsight", "sentinel", "wazuh"}


class SIEMConnector(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    name: str
    siem_type: str
    connection_config: dict[str, Any] = {}
    sync_direction: str = "push"  # push, pull, bidirectional
    event_filter: dict[str, Any] = {}
    enabled: bool = True
    last_sync_at: datetime | None = None
    events_synced: int = 0
    error: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SIEMConnectorService:
    """Universal SIEM connector management."""

    def __init__(self) -> None:
        self._connectors: dict[str, SIEMConnector] = {}
        self._tenant_connectors: dict[str, list[str]] = defaultdict(list)
        self._sync_log: list[dict] = []

    def create_connector(
        self,
        tenant_id: str,
        name: str,
        siem_type: str,
        connection_config: dict | None = None,
        sync_direction: str = "push",
        event_filter: dict | None = None,
    ) -> dict:
        if siem_type not in SUPPORTED_SIEMS:
            return {"error": f"Unsupported SIEM type. Supported: {', '.join(sorted(SUPPORTED_SIEMS))}"}
        connector = SIEMConnector(
            tenant_id=tenant_id, name=name, siem_type=siem_type,
            connection_config=connection_config or {},
            sync_direction=sync_direction, event_filter=event_filter or {},
        )
        self._connectors[connector.id] = connector
        self._tenant_connectors[tenant_id].append(connector.id)
        logger.info("[SIEM] Created %s connector '%s' for %s", siem_type, name, tenant_id)
        return connector.model_dump(mode="json")

    def list_connectors(self, tenant_id: str) -> list[dict]:
        return [
            self._connectors[cid].model_dump(mode="json")
            for cid in self._tenant_connectors.get(tenant_id, [])
            if cid in self._connectors
        ]

    def get_connector(self, connector_id: str) -> dict | None:
        c = self._connectors.get(connector_id)
        return c.model_dump(mode="json") if c else None

    def toggle_connector(self, connector_id: str, enabled: bool) -> dict | None:
        c = self._connectors.get(connector_id)
        if not c:
            return None
        c.enabled = enabled
        return c.model_dump(mode="json")

    def delete_connector(self, connector_id: str) -> bool:
        c = self._connectors.pop(connector_id, None)
        if not c:
            return False
        self._tenant_connectors[c.tenant_id] = [
            x for x in self._tenant_connectors[c.tenant_id] if x != connector_id
        ]
        return True

    def sync_events(self, connector_id: str, events: list[dict]) -> dict:
        c = self._connectors.get(connector_id)
        if not c:
            return {"error": "Connector not found"}
        if not c.enabled:
            return {"error": "Connector is disabled"}

        # Apply event filter
        filtered = self._apply_filter(events, c.event_filter)

        # Simulate sync
        c.events_synced += len(filtered)
        c.last_sync_at = datetime.now(timezone.utc)
        c.error = None

        self._sync_log.append({
            "connector_id": connector_id,
            "siem_type": c.siem_type,
            "events_synced": len(filtered),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        logger.info("[SIEM] Synced %d events via %s connector '%s'", len(filtered), c.siem_type, c.name)
        return {"synced": len(filtered), "filtered_out": len(events) - len(filtered)}

    def test_connection(self, connector_id: str) -> dict:
        c = self._connectors.get(connector_id)
        if not c:
            return {"error": "Connector not found"}
        # Simulate connection test
        return {
            "connector_id": connector_id,
            "siem_type": c.siem_type,
            "status": "connected",
            "latency_ms": 45,
        }

    def get_sync_log(self, tenant_id: str, limit: int = 50) -> list[dict]:
        tenant_connectors = set(self._tenant_connectors.get(tenant_id, []))
        results = [
            entry for entry in reversed(self._sync_log)
            if entry.get("connector_id") in tenant_connectors
        ]
        return results[:limit]

    def get_stats(self, tenant_id: str) -> dict:
        connectors = [
            self._connectors[c] for c in self._tenant_connectors.get(tenant_id, [])
            if c in self._connectors
        ]
        by_type: dict[str, int] = defaultdict(int)
        total_synced = 0
        for c in connectors:
            by_type[c.siem_type] += 1
            total_synced += c.events_synced
        return {
            "total_connectors": len(connectors),
            "enabled": sum(1 for c in connectors if c.enabled),
            "by_type": dict(by_type),
            "total_events_synced": total_synced,
        }

    def _apply_filter(self, events: list[dict], filter_config: dict) -> list[dict]:
        if not filter_config:
            return events
        filtered = []
        categories = filter_config.get("categories")
        min_severity = filter_config.get("min_severity")
        sev_order = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
        min_sev_val = sev_order.get(min_severity, 0) if min_severity else 0
        for e in events:
            if categories and e.get("category") not in categories:
                continue
            if min_sev_val and sev_order.get(e.get("severity", "info"), 0) < min_sev_val:
                continue
            filtered.append(e)
        return filtered


# Module-level singleton
siem_connector_service = SIEMConnectorService()
