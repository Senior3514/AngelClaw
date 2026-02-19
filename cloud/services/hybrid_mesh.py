"""AngelClaw V6.0 — Omniguard: Hybrid Mesh Service.

Hybrid deployment orchestration for on-prem, cloud, and edge
environments. Manages cross-environment federation, policy
synchronisation, and latency-aware routing between mesh nodes.

Features:
  - Environment registration (on-prem, cloud, edge)
  - Cross-environment policy synchronisation
  - Latency map computation between environments
  - Node federation across environments
  - Per-tenant isolation with mesh analytics
"""

from __future__ import annotations

import logging
import random
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.hybrid_mesh")

_ENV_TYPES = {"on_prem", "cloud", "edge", "colocation", "branch"}


class MeshEnvironment(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    env_name: str
    env_type: str  # on_prem, cloud, edge, colocation, branch
    endpoint: str = ""
    config: dict[str, Any] = {}
    status: str = "active"  # active, degraded, offline, syncing
    node_count: int = 0
    policies_synced: int = 0
    last_sync_at: datetime | None = None
    federated_with: list[str] = []  # list of environment IDs
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PolicySync(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    source_env: str
    target_env: str
    policies_count: int = 0
    status: str = "pending"  # pending, syncing, completed, failed
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    error: str | None = None


class HybridMeshService:
    """Hybrid deployment orchestration and cross-environment federation."""

    def __init__(self) -> None:
        self._environments: dict[str, MeshEnvironment] = {}
        self._tenant_envs: dict[str, list[str]] = defaultdict(list)
        self._syncs: dict[str, PolicySync] = {}
        self._tenant_syncs: dict[str, list[str]] = defaultdict(list)
        self._latency_cache: dict[str, dict[str, float]] = {}  # env_pair -> latency_ms

    # ------------------------------------------------------------------
    # Environment Management
    # ------------------------------------------------------------------

    def register_environment(
        self,
        tenant_id: str,
        env_name: str,
        env_type: str,
        endpoint: str = "",
        config: dict | None = None,
    ) -> dict:
        """Register a new environment in the hybrid mesh."""
        etype = env_type.lower() if env_type.lower() in _ENV_TYPES else "cloud"

        env = MeshEnvironment(
            tenant_id=tenant_id,
            env_name=env_name,
            env_type=etype,
            endpoint=endpoint,
            config=config or {},
        )
        self._environments[env.id] = env
        self._tenant_envs[tenant_id].append(env.id)

        logger.info(
            "[HYBRID_MESH] Registered environment '%s' (%s) for %s",
            env_name, etype, tenant_id,
        )
        return env.model_dump(mode="json")

    def list_environments(self, tenant_id: str) -> list[dict]:
        """List all environments for a tenant."""
        return [
            self._environments[eid].model_dump(mode="json")
            for eid in self._tenant_envs.get(tenant_id, [])
            if eid in self._environments
        ]

    def remove_environment(self, tenant_id: str, env_id: str) -> bool:
        """Remove an environment from the mesh."""
        env = self._environments.get(env_id)
        if not env or env.tenant_id != tenant_id:
            return False

        # Remove from federation links
        for eid in env.federated_with:
            other = self._environments.get(eid)
            if other and env_id in other.federated_with:
                other.federated_with.remove(env_id)

        self._tenant_envs[tenant_id] = [
            e for e in self._tenant_envs[tenant_id] if e != env_id
        ]
        del self._environments[env_id]
        logger.info("[HYBRID_MESH] Removed environment '%s'", env.env_name)
        return True

    # ------------------------------------------------------------------
    # Policy Synchronisation
    # ------------------------------------------------------------------

    def sync_policies(
        self,
        tenant_id: str,
        source_env: str,
        target_env: str,
    ) -> dict:
        """Synchronise policies from source environment to target."""
        src = self._environments.get(source_env)
        tgt = self._environments.get(target_env)

        if not src or src.tenant_id != tenant_id:
            return {"error": "Source environment not found"}
        if not tgt or tgt.tenant_id != tenant_id:
            return {"error": "Target environment not found"}

        sync = PolicySync(
            tenant_id=tenant_id,
            source_env=source_env,
            target_env=target_env,
            status="syncing",
        )

        # Simulate policy sync
        policies_count = random.randint(5, 30)
        sync.policies_count = policies_count
        sync.status = "completed"
        sync.completed_at = datetime.now(timezone.utc)

        tgt.policies_synced += policies_count
        tgt.last_sync_at = datetime.now(timezone.utc)

        self._syncs[sync.id] = sync
        self._tenant_syncs[tenant_id].append(sync.id)

        logger.info(
            "[HYBRID_MESH] Synced %d policies from '%s' to '%s'",
            policies_count, src.env_name, tgt.env_name,
        )
        return sync.model_dump(mode="json")

    # ------------------------------------------------------------------
    # Mesh Status & Latency
    # ------------------------------------------------------------------

    def get_mesh_status(self, tenant_id: str) -> dict:
        """Return overall mesh status for a tenant."""
        envs = self._get_tenant_envs(tenant_id)

        by_type: dict[str, int] = defaultdict(int)
        by_status: dict[str, int] = defaultdict(int)
        total_nodes = 0
        for e in envs:
            by_type[e.env_type] += 1
            by_status[e.status] += 1
            total_nodes += e.node_count

        # Count federation links
        federation_links = sum(len(e.federated_with) for e in envs) // 2

        return {
            "tenant_id": tenant_id,
            "total_environments": len(envs),
            "by_type": dict(by_type),
            "by_status": dict(by_status),
            "total_nodes": total_nodes,
            "federation_links": federation_links,
            "total_syncs": len(self._tenant_syncs.get(tenant_id, [])),
        }

    def get_latency_map(self, tenant_id: str) -> dict:
        """Compute a latency map between all environment pairs."""
        envs = self._get_tenant_envs(tenant_id)
        latency_map: dict[str, dict[str, float]] = {}

        for i, env_a in enumerate(envs):
            latency_map[env_a.env_name] = {}
            for j, env_b in enumerate(envs):
                if i == j:
                    latency_map[env_a.env_name][env_b.env_name] = 0.0
                    continue

                pair_key = f"{env_a.id}:{env_b.id}"
                if pair_key not in self._latency_cache:
                    # Simulate latency based on environment types
                    base = self._estimate_latency(env_a.env_type, env_b.env_type)
                    self._latency_cache[pair_key] = base

                latency_map[env_a.env_name][env_b.env_name] = (
                    self._latency_cache[pair_key]
                )

        return {
            "tenant_id": tenant_id,
            "environment_count": len(envs),
            "latency_map": latency_map,
        }

    # ------------------------------------------------------------------
    # Federation
    # ------------------------------------------------------------------

    def federate_nodes(
        self,
        tenant_id: str,
        env_ids: list[str],
    ) -> dict:
        """Federate nodes across multiple environments."""
        envs = []
        for eid in env_ids:
            env = self._environments.get(eid)
            if env and env.tenant_id == tenant_id:
                envs.append(env)

        if len(envs) < 2:
            return {"error": "At least two valid environments required for federation"}

        # Create federation links between all pairs
        links_created = 0
        for i, env_a in enumerate(envs):
            for env_b in envs[i + 1:]:
                if env_b.id not in env_a.federated_with:
                    env_a.federated_with.append(env_b.id)
                    env_b.federated_with.append(env_a.id)
                    links_created += 1

        logger.info(
            "[HYBRID_MESH] Federated %d environments with %d new links for %s",
            len(envs), links_created, tenant_id,
        )
        return {
            "federated_environments": len(envs),
            "new_links": links_created,
            "environments": [e.env_name for e in envs],
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return hybrid mesh statistics for a tenant."""
        envs = self._get_tenant_envs(tenant_id)
        syncs = [
            self._syncs[sid]
            for sid in self._tenant_syncs.get(tenant_id, [])
            if sid in self._syncs
        ]

        return {
            "total_environments": len(envs),
            "active_environments": sum(1 for e in envs if e.status == "active"),
            "total_federation_links": sum(len(e.federated_with) for e in envs) // 2,
            "total_policy_syncs": len(syncs),
            "successful_syncs": sum(1 for s in syncs if s.status == "completed"),
            "failed_syncs": sum(1 for s in syncs if s.status == "failed"),
            "total_policies_synced": sum(e.policies_synced for e in envs),
        }

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _get_tenant_envs(self, tenant_id: str) -> list[MeshEnvironment]:
        """Return all environments belonging to a tenant."""
        return [
            self._environments[eid]
            for eid in self._tenant_envs.get(tenant_id, [])
            if eid in self._environments
        ]

    @staticmethod
    def _estimate_latency(type_a: str, type_b: str) -> float:
        """Estimate latency between two environment types in milliseconds."""
        # Same type has low latency
        if type_a == type_b:
            return round(random.uniform(1.0, 10.0), 1)
        # Edge to anything has higher latency
        if "edge" in (type_a, type_b):
            return round(random.uniform(20.0, 80.0), 1)
        # Cloud to on-prem
        if {"cloud", "on_prem"} == {type_a, type_b}:
            return round(random.uniform(10.0, 50.0), 1)
        return round(random.uniform(5.0, 30.0), 1)


# Module-level singleton
hybrid_mesh_service = HybridMeshService()
