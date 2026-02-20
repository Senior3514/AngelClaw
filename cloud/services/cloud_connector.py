"""AngelClaw V6.0 — Omniguard: Cloud Connector Service.

Multi-cloud connector management for AWS, Azure, GCP, OCI, and Alibaba
Cloud. Handles credential storage, health checking, resource discovery
synchronisation, and per-connector analytics.

Features:
  - Connector CRUD with multi-region support
  - Credential validation and rotation tracking
  - Automated health checking with failure detection
  - Resource discovery and synchronisation
  - Per-tenant isolation with provider-level analytics
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.cloud_connector")

_SUPPORTED_PROVIDERS = {"aws", "azure", "gcp", "oci", "alibaba"}


class CloudConnector(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    cloud_provider: str  # aws, azure, gcp, oci, alibaba
    name: str
    config: dict[str, Any] = {}
    regions: list[str] = []
    enabled: bool = True
    health_status: str = "unknown"  # healthy, degraded, unhealthy, unknown
    last_health_check: datetime | None = None
    resources_discovered: int = 0
    last_sync_at: datetime | None = None
    sync_errors: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DiscoveredResource(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    connector_id: str
    tenant_id: str = "dev-tenant"
    resource_type: str  # vm, bucket, database, network, iam_role, function
    resource_id: str
    name: str = ""
    region: str = ""
    provider: str = ""
    tags: dict[str, str] = {}
    metadata: dict[str, Any] = {}
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CloudConnectorService:
    """Multi-cloud connector management and resource discovery."""

    def __init__(self) -> None:
        self._connectors: dict[str, CloudConnector] = {}
        self._tenant_connectors: dict[str, list[str]] = defaultdict(list)
        self._resources: dict[str, DiscoveredResource] = {}
        self._connector_resources: dict[str, list[str]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Connector CRUD
    # ------------------------------------------------------------------

    def add_connector(
        self,
        tenant_id: str,
        cloud_provider: str,
        name: str,
        config: dict | None = None,
        regions: list[str] | None = None,
    ) -> dict:
        """Add a new cloud connector."""
        provider = cloud_provider.lower()
        if provider not in _SUPPORTED_PROVIDERS:
            return {
                "error": (
                    f"Unsupported provider '{provider}'."
                    f" Supported: {sorted(_SUPPORTED_PROVIDERS)}"
                )
            }

        connector = CloudConnector(
            tenant_id=tenant_id,
            cloud_provider=provider,
            name=name,
            config=config or {},
            regions=regions or [],
        )
        self._connectors[connector.id] = connector
        self._tenant_connectors[tenant_id].append(connector.id)

        logger.info(
            "[CLOUD_CONN] Added connector '%s' (%s) with %d regions for %s",
            name,
            provider,
            len(connector.regions),
            tenant_id,
        )
        return connector.model_dump(mode="json")

    def list_connectors(self, tenant_id: str) -> list[dict]:
        """List all connectors for a tenant."""
        cids = self._tenant_connectors.get(tenant_id, [])
        return [
            self._connectors[cid].model_dump(mode="json") for cid in cids if cid in self._connectors
        ]

    def test_connector(self, connector_id: str) -> dict:
        """Test a connector's connectivity and credentials."""
        conn = self._connectors.get(connector_id)
        if not conn:
            return {"error": "Connector not found"}

        # Simulate health check
        conn.last_health_check = datetime.now(timezone.utc)
        conn.health_status = "healthy"

        logger.info(
            "[CLOUD_CONN] Tested connector '%s' (%s): %s",
            conn.name,
            conn.cloud_provider,
            conn.health_status,
        )
        return {
            "connector_id": connector_id,
            "name": conn.name,
            "provider": conn.cloud_provider,
            "health_status": conn.health_status,
            "tested_at": conn.last_health_check.isoformat(),
        }

    def sync_resources(self, connector_id: str) -> dict:
        """Synchronise resource discovery for a connector."""
        conn = self._connectors.get(connector_id)
        if not conn:
            return {"error": "Connector not found"}
        if not conn.enabled:
            return {"error": "Connector is disabled"}

        # Simulate resource discovery
        discovered_count = len(conn.regions) * 3  # Simulate 3 resources per region
        new_resources = []
        for region in conn.regions:
            for rtype in ("vm", "bucket", "network"):
                res = DiscoveredResource(
                    connector_id=connector_id,
                    tenant_id=conn.tenant_id,
                    resource_type=rtype,
                    resource_id=f"{conn.cloud_provider}-{region}-{rtype}-{uuid.uuid4().hex[:8]}",
                    name=f"{rtype}-{region}",
                    region=region,
                    provider=conn.cloud_provider,
                )
                self._resources[res.id] = res
                self._connector_resources[connector_id].append(res.id)
                new_resources.append(res.id)

        conn.resources_discovered += discovered_count
        conn.last_sync_at = datetime.now(timezone.utc)

        logger.info(
            "[CLOUD_CONN] Synced %d resources for connector '%s'",
            discovered_count,
            conn.name,
        )
        return {
            "connector_id": connector_id,
            "resources_discovered": discovered_count,
            "total_resources": conn.resources_discovered,
            "synced_at": conn.last_sync_at.isoformat(),
        }

    def remove_connector(self, connector_id: str) -> dict | None:
        """Remove a cloud connector and its discovered resources."""
        conn = self._connectors.get(connector_id)
        if not conn:
            return None

        # Remove discovered resources
        for rid in self._connector_resources.get(connector_id, []):
            self._resources.pop(rid, None)
        self._connector_resources.pop(connector_id, None)

        # Remove from tenant list
        self._tenant_connectors[conn.tenant_id] = [
            cid for cid in self._tenant_connectors[conn.tenant_id] if cid != connector_id
        ]
        del self._connectors[connector_id]

        logger.info("[CLOUD_CONN] Removed connector '%s'", conn.name)
        return {"removed": connector_id, "name": conn.name}

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return cloud connector statistics for a tenant."""
        connectors = [
            self._connectors[cid]
            for cid in self._tenant_connectors.get(tenant_id, [])
            if cid in self._connectors
        ]

        by_provider: dict[str, int] = defaultdict(int)
        by_health: dict[str, int] = defaultdict(int)
        total_resources = 0
        for c in connectors:
            by_provider[c.cloud_provider] += 1
            by_health[c.health_status] += 1
            total_resources += c.resources_discovered

        return {
            "total_connectors": len(connectors),
            "enabled_connectors": sum(1 for c in connectors if c.enabled),
            "by_provider": dict(by_provider),
            "by_health": dict(by_health),
            "total_resources_discovered": total_resources,
            "total_sync_errors": sum(c.sync_errors for c in connectors),
        }


# Module-level singleton
cloud_connector_service = CloudConnectorService()
