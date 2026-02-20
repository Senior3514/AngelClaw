"""AngelClaw V4.0 — Omniscience: Topology Map Service.

Manages network topology links between assets, builds dependency graphs,
and identifies critical paths and exposure points.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("angelclaw.topology")


class TopologyLink:
    def __init__(
        self,
        tenant_id: str,
        source_asset_id: str,
        target_asset_id: str,
        link_type: str = "network",
        protocol: str | None = None,
        port: int | None = None,
        direction: str = "bidirectional",
        risk_score: int = 0,
    ) -> None:
        self.id = str(uuid.uuid4())
        self.tenant_id = tenant_id
        self.source_asset_id = source_asset_id
        self.target_asset_id = target_asset_id
        self.link_type = link_type
        self.protocol = protocol
        self.port = port
        self.direction = direction
        self.risk_score = risk_score
        self.discovered_at = datetime.now(timezone.utc)
        self.last_seen_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "source_asset_id": self.source_asset_id,
            "target_asset_id": self.target_asset_id,
            "link_type": self.link_type,
            "protocol": self.protocol,
            "port": self.port,
            "direction": self.direction,
            "risk_score": self.risk_score,
            "discovered_at": self.discovered_at.isoformat(),
            "last_seen_at": self.last_seen_at.isoformat(),
        }


class TopologyService:
    """Network topology map with graph analysis."""

    def __init__(self) -> None:
        self._links: dict[str, TopologyLink] = {}
        self._adjacency: dict[str, set[str]] = defaultdict(set)  # asset_id -> linked asset_ids

    def add_link(
        self,
        tenant_id: str,
        source_asset_id: str,
        target_asset_id: str,
        link_type: str = "network",
        protocol: str | None = None,
        port: int | None = None,
        direction: str = "bidirectional",
    ) -> dict:
        link = TopologyLink(
            tenant_id=tenant_id,
            source_asset_id=source_asset_id,
            target_asset_id=target_asset_id,
            link_type=link_type,
            protocol=protocol,
            port=port,
            direction=direction,
        )
        self._links[link.id] = link
        self._adjacency[source_asset_id].add(target_asset_id)
        if direction == "bidirectional":
            self._adjacency[target_asset_id].add(source_asset_id)
        logger.info(
            "[TOPOLOGY] Added link %s -> %s (%s)",
            source_asset_id[:8],
            target_asset_id[:8],
            link_type,
        )
        return link.to_dict()

    def remove_link(self, link_id: str) -> bool:
        link = self._links.pop(link_id, None)
        if not link:
            return False
        self._adjacency[link.source_asset_id].discard(link.target_asset_id)
        if link.direction == "bidirectional":
            self._adjacency[link.target_asset_id].discard(link.source_asset_id)
        return True

    def get_links(self, tenant_id: str, asset_id: str | None = None) -> list[dict]:
        results = []
        for link in self._links.values():
            if link.tenant_id != tenant_id:
                continue
            if asset_id and asset_id not in (link.source_asset_id, link.target_asset_id):
                continue
            results.append(link.to_dict())
        return results

    def get_neighbors(self, asset_id: str) -> list[str]:
        return list(self._adjacency.get(asset_id, set()))

    def get_graph(self, tenant_id: str) -> dict:
        """Return full topology graph data (nodes + edges)."""
        nodes: set[str] = set()
        edges = []
        for link in self._links.values():
            if link.tenant_id != tenant_id:
                continue
            nodes.add(link.source_asset_id)
            nodes.add(link.target_asset_id)
            edges.append(
                {
                    "source": link.source_asset_id,
                    "target": link.target_asset_id,
                    "type": link.link_type,
                    "protocol": link.protocol,
                    "port": link.port,
                }
            )
        return {
            "nodes": list(nodes),
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
        }

    def find_path(self, source_id: str, target_id: str, max_depth: int = 10) -> list[str] | None:
        """BFS shortest path between two assets."""
        if source_id == target_id:
            return [source_id]
        visited = {source_id}
        queue: list[list[str]] = [[source_id]]
        while queue:
            path = queue.pop(0)
            if len(path) > max_depth:
                break
            current = path[-1]
            for neighbor in self._adjacency.get(current, set()):
                if neighbor == target_id:
                    return path + [neighbor]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(path + [neighbor])
        return None

    def find_critical_nodes(self, tenant_id: str) -> list[dict]:
        """Find nodes with highest connectivity (potential single points of failure)."""
        connectivity: dict[str, int] = defaultdict(int)
        for link in self._links.values():
            if link.tenant_id != tenant_id:
                continue
            connectivity[link.source_asset_id] += 1
            connectivity[link.target_asset_id] += 1
        sorted_nodes = sorted(connectivity.items(), key=lambda x: x[1], reverse=True)
        return [{"asset_id": nid, "connections": count} for nid, count in sorted_nodes[:20]]

    def get_stats(self, tenant_id: str) -> dict:
        tenant_links = [link for link in self._links.values() if link.tenant_id == tenant_id]
        by_type: dict[str, int] = defaultdict(int)
        for link in tenant_links:
            by_type[link.link_type] += 1
        nodes = set()
        for link in tenant_links:
            nodes.add(link.source_asset_id)
            nodes.add(link.target_asset_id)
        return {
            "total_links": len(tenant_links),
            "total_nodes": len(nodes),
            "by_type": dict(by_type),
        }


# Module-level singleton
topology_service = TopologyService()
