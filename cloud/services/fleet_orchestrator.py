"""AngelClaw V5.5 — Convergence: Fleet Orchestrator.

Fleet-wide ANGELNODE management including registration, health tracking,
OS distribution analytics, version compliance checking, and batch command
dispatch to managed endpoints.

Features:
  - Node registration with OS/version/tag metadata
  - Per-node health percentage and metric tracking
  - Fleet-level health aggregation and status
  - OS distribution analytics
  - Batch command dispatch with result tracking
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.fleet_orchestrator")

# Health percentage thresholds
_HEALTH_CRITICAL = 25
_HEALTH_DEGRADED = 60
_HEALTH_HEALTHY = 80


class FleetNode(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    hostname: str
    os_type: str  # windows, linux, macos, freebsd
    version: str = ""
    tags: list[str] = []
    health_pct: float = 100.0
    status: str = "online"  # online, degraded, critical, offline
    metrics: dict[str, Any] = {}
    last_seen_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FleetCommand(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    command: str
    params: dict[str, Any] = {}
    target_node_ids: list[str] = []
    status: str = "pending"  # pending, dispatched, completed, failed
    results: dict[str, dict[str, Any]] = {}  # node_id -> result
    dispatched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None


class FleetOrchestrator:
    """Fleet-wide node management and batch command dispatch."""

    def __init__(self) -> None:
        self._nodes: dict[str, FleetNode] = {}
        self._tenant_nodes: dict[str, list[str]] = defaultdict(list)
        self._commands: dict[str, FleetCommand] = {}
        self._tenant_commands: dict[str, list[str]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Node Registration & Health
    # ------------------------------------------------------------------

    def register_node(
        self,
        tenant_id: str,
        hostname: str,
        os_type: str,
        version: str = "",
        tags: list[str] | None = None,
    ) -> dict:
        """Register a new ANGELNODE in the fleet."""
        node = FleetNode(
            tenant_id=tenant_id,
            hostname=hostname,
            os_type=os_type.lower(),
            version=version,
            tags=tags or [],
        )
        self._nodes[node.id] = node
        self._tenant_nodes[tenant_id].append(node.id)

        logger.info(
            "[FLEET] Registered node '%s' (%s %s) for %s",
            hostname,
            os_type,
            version,
            tenant_id,
        )
        return node.model_dump(mode="json")

    def update_node_health(
        self,
        tenant_id: str,
        node_id: str,
        health_pct: float,
        metrics: dict | None = None,
    ) -> dict | None:
        """Update a node's health percentage and optional metrics."""
        node = self._nodes.get(node_id)
        if not node or node.tenant_id != tenant_id:
            return None

        node.health_pct = max(0.0, min(100.0, health_pct))
        node.last_seen_at = datetime.now(timezone.utc)
        if metrics:
            node.metrics.update(metrics)

        # Derive status from health percentage
        if health_pct < _HEALTH_CRITICAL:
            node.status = "critical"
        elif health_pct < _HEALTH_DEGRADED:
            node.status = "degraded"
        else:
            node.status = "online"

        logger.debug(
            "[FLEET] Updated node '%s' health=%.0f%% status=%s",
            node.hostname,
            health_pct,
            node.status,
        )
        return node.model_dump(mode="json")

    def remove_node(self, tenant_id: str, node_id: str) -> bool:
        """Remove a node from the fleet."""
        node = self._nodes.get(node_id)
        if not node or node.tenant_id != tenant_id:
            return False
        del self._nodes[node_id]
        self._tenant_nodes[tenant_id] = [
            nid for nid in self._tenant_nodes[tenant_id] if nid != node_id
        ]
        logger.info("[FLEET] Removed node '%s' from %s", node.hostname, tenant_id)
        return True

    # ------------------------------------------------------------------
    # Fleet Status & Analytics
    # ------------------------------------------------------------------

    def get_fleet_status(self, tenant_id: str) -> dict:
        """Return aggregate fleet status for a tenant."""
        nodes = self._get_tenant_nodes(tenant_id)
        if not nodes:
            return {
                "tenant_id": tenant_id,
                "total_nodes": 0,
                "online": 0,
                "degraded": 0,
                "critical": 0,
                "offline": 0,
                "avg_health_pct": 0.0,
            }

        status_counts: dict[str, int] = defaultdict(int)
        health_sum = 0.0
        for n in nodes:
            status_counts[n.status] += 1
            health_sum += n.health_pct

        return {
            "tenant_id": tenant_id,
            "total_nodes": len(nodes),
            "online": status_counts.get("online", 0),
            "degraded": status_counts.get("degraded", 0),
            "critical": status_counts.get("critical", 0),
            "offline": status_counts.get("offline", 0),
            "avg_health_pct": round(health_sum / len(nodes), 1),
        }

    def get_os_distribution(self, tenant_id: str) -> dict:
        """Return OS type distribution across the fleet."""
        nodes = self._get_tenant_nodes(tenant_id)
        by_os: dict[str, int] = defaultdict(int)
        by_version: dict[str, int] = defaultdict(int)
        for n in nodes:
            by_os[n.os_type] += 1
            if n.version:
                by_version[f"{n.os_type}/{n.version}"] += 1

        return {
            "tenant_id": tenant_id,
            "total_nodes": len(nodes),
            "by_os": dict(by_os),
            "by_version": dict(
                sorted(by_version.items(), key=lambda x: x[1], reverse=True),
            ),
        }

    # ------------------------------------------------------------------
    # Batch Command Dispatch
    # ------------------------------------------------------------------

    def dispatch_command(
        self,
        tenant_id: str,
        node_ids: list[str],
        command: str,
        params: dict | None = None,
    ) -> dict:
        """Dispatch a command to one or more fleet nodes."""
        # Validate node IDs belong to tenant
        valid_ids = []
        for nid in node_ids:
            node = self._nodes.get(nid)
            if node and node.tenant_id == tenant_id:
                valid_ids.append(nid)

        if not valid_ids:
            return {"error": "No valid target nodes found"}

        cmd = FleetCommand(
            tenant_id=tenant_id,
            command=command,
            params=params or {},
            target_node_ids=valid_ids,
            status="dispatched",
        )

        # Simulate dispatch — in production this would push to a message queue
        for nid in valid_ids:
            node = self._nodes.get(nid)
            cmd.results[nid] = {
                "hostname": node.hostname if node else "unknown",
                "status": "dispatched",
                "dispatched_at": datetime.now(timezone.utc).isoformat(),
            }

        self._commands[cmd.id] = cmd
        self._tenant_commands[tenant_id].append(cmd.id)

        # Cap command history
        if len(self._tenant_commands[tenant_id]) > 5000:
            self._tenant_commands[tenant_id] = self._tenant_commands[tenant_id][-5000:]

        logger.info(
            "[FLEET] Dispatched command '%s' to %d nodes for %s",
            command,
            len(valid_ids),
            tenant_id,
        )
        return cmd.model_dump(mode="json")

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return fleet orchestrator statistics for a tenant."""
        nodes = self._get_tenant_nodes(tenant_id)
        commands = [
            self._commands[cid]
            for cid in self._tenant_commands.get(tenant_id, [])
            if cid in self._commands
        ]

        by_os: dict[str, int] = defaultdict(int)
        by_status: dict[str, int] = defaultdict(int)
        for n in nodes:
            by_os[n.os_type] += 1
            by_status[n.status] += 1

        return {
            "total_nodes": len(nodes),
            "by_os": dict(by_os),
            "by_status": dict(by_status),
            "avg_health_pct": round(
                sum(n.health_pct for n in nodes) / max(len(nodes), 1),
                1,
            ),
            "total_commands": len(commands),
            "commands_completed": sum(1 for c in commands if c.status == "completed"),
            "commands_failed": sum(1 for c in commands if c.status == "failed"),
        }

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _get_tenant_nodes(self, tenant_id: str) -> list[FleetNode]:
        """Return all nodes belonging to a tenant."""
        return [
            self._nodes[nid] for nid in self._tenant_nodes.get(tenant_id, []) if nid in self._nodes
        ]


# Module-level singleton
fleet_orchestrator_service = FleetOrchestrator()
