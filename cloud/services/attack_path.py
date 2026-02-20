"""AngelClaw V4.1 — Prophecy: Attack Path Analysis Engine.

Computes potential attack paths between assets using topology and
vulnerability data. Maps to MITRE ATT&CK techniques and provides
risk-ranked paths with mitigation recommendations.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("angelclaw.attack_path")

# MITRE ATT&CK technique mapping (simplified)
_TECHNIQUE_MAP = {
    "ssh": ["T1021.004 - SSH", "T1078 - Valid Accounts"],
    "http": ["T1190 - Exploit Public-Facing App", "T1071.001 - Web Protocols"],
    "https": ["T1190 - Exploit Public-Facing App", "T1573 - Encrypted Channel"],
    "smb": ["T1021.002 - SMB/Windows Admin Shares", "T1570 - Lateral Tool Transfer"],
    "rdp": ["T1021.001 - Remote Desktop Protocol"],
    "dns": ["T1071.004 - DNS", "T1568 - Dynamic Resolution"],
    "tcp": ["T1095 - Non-Application Layer Protocol"],
}


class AttackPath:
    def __init__(
        self,
        tenant_id: str,
        name: str,
        source_asset_id: str,
        target_asset_id: str,
        path_nodes: list[str],
        attack_techniques: list[str] | None = None,
        risk_score: int = 0,
        likelihood: float = 0.5,
        mitigations: list[str] | None = None,
    ) -> None:
        self.id = str(uuid.uuid4())
        self.tenant_id = tenant_id
        self.name = name
        self.source_asset_id = source_asset_id
        self.target_asset_id = target_asset_id
        self.path_nodes = path_nodes
        self.attack_techniques = attack_techniques or []
        self.risk_score = risk_score
        self.likelihood = likelihood
        self.mitigations = mitigations or []
        self.status = "active"
        self.computed_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "source_asset_id": self.source_asset_id,
            "target_asset_id": self.target_asset_id,
            "path_nodes": self.path_nodes,
            "path_length": len(self.path_nodes),
            "attack_techniques": self.attack_techniques,
            "risk_score": self.risk_score,
            "likelihood": self.likelihood,
            "mitigations": self.mitigations,
            "status": self.status,
            "computed_at": self.computed_at.isoformat(),
        }


class AttackPathEngine:
    """Attack path analysis with MITRE ATT&CK mapping."""

    def __init__(self) -> None:
        self._paths: dict[str, AttackPath] = {}
        self._tenant_paths: dict[str, list[str]] = defaultdict(list)

    def compute_paths(
        self,
        tenant_id: str,
        topology_links: list[dict],
        asset_risks: dict[str, int] | None = None,
        critical_assets: list[str] | None = None,
    ) -> list[dict]:
        """Compute attack paths through the topology."""
        asset_risks = asset_risks or {}
        critical_assets = critical_assets or []

        # Build adjacency from topology
        adjacency: dict[str, list[dict]] = defaultdict(list)
        for link in topology_links:
            adjacency[link.get("source_asset_id", "")].append(link)
            if link.get("direction") == "bidirectional":
                reverse = dict(link)
                reverse["source_asset_id"] = link.get("target_asset_id", "")
                reverse["target_asset_id"] = link.get("source_asset_id", "")
                adjacency[reverse["source_asset_id"]].append(reverse)

        # Find paths to critical assets using BFS
        new_paths = []
        for target in critical_assets:
            for source in adjacency:
                if source == target:
                    continue
                path = self._bfs_path(adjacency, source, target)
                if path and len(path) <= 6:
                    techniques = self._map_techniques(adjacency, path)
                    risk = self._compute_risk(path, asset_risks, techniques)
                    likelihood = min(1.0, 0.3 + (1.0 / len(path)) * 0.5)

                    ap = AttackPath(
                        tenant_id=tenant_id,
                        name=f"Path: {source[:8]} -> {target[:8]}",
                        source_asset_id=source,
                        target_asset_id=target,
                        path_nodes=path,
                        attack_techniques=techniques,
                        risk_score=risk,
                        likelihood=round(likelihood, 2),
                        mitigations=self._suggest_mitigations(techniques),
                    )
                    self._paths[ap.id] = ap
                    self._tenant_paths[tenant_id].append(ap.id)
                    new_paths.append(ap.to_dict())

        # Sort by risk
        new_paths.sort(key=lambda p: p["risk_score"], reverse=True)
        logger.info("[ATTACK_PATH] Computed %d attack paths for %s", len(new_paths), tenant_id)
        return new_paths[:50]  # Top 50

    def get_paths(self, tenant_id: str, min_risk: int = 0) -> list[dict]:
        results = []
        for pid in self._tenant_paths.get(tenant_id, []):
            path = self._paths.get(pid)
            if path and path.risk_score >= min_risk:
                results.append(path.to_dict())
        results.sort(key=lambda p: p["risk_score"], reverse=True)
        return results

    def get_path(self, path_id: str) -> dict | None:
        path = self._paths.get(path_id)
        return path.to_dict() if path else None

    def mitigate_path(self, path_id: str) -> dict | None:
        path = self._paths.get(path_id)
        if not path:
            return None
        path.status = "mitigated"
        return path.to_dict()

    def get_stats(self, tenant_id: str) -> dict:
        paths = [self._paths[p] for p in self._tenant_paths.get(tenant_id, []) if p in self._paths]
        return {
            "total_paths": len(paths),
            "active": sum(1 for p in paths if p.status == "active"),
            "mitigated": sum(1 for p in paths if p.status == "mitigated"),
            "avg_risk": round(sum(p.risk_score for p in paths) / max(len(paths), 1), 1),
            "critical_paths": sum(1 for p in paths if p.risk_score >= 80),
        }

    def _bfs_path(self, adjacency: dict, source: str, target: str) -> list[str] | None:
        visited = {source}
        queue: list[list[str]] = [[source]]
        while queue:
            path = queue.pop(0)
            if len(path) > 6:
                break
            current = path[-1]
            for link in adjacency.get(current, []):
                neighbor = link.get("target_asset_id", "")
                if neighbor == target:
                    return path + [neighbor]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(path + [neighbor])
        return None

    def _map_techniques(self, adjacency: dict, path: list[str]) -> list[str]:
        techniques = []
        for i in range(len(path) - 1):
            for link in adjacency.get(path[i], []):
                if link.get("target_asset_id") == path[i + 1]:
                    protocol = link.get("protocol", "tcp")
                    techniques.extend(_TECHNIQUE_MAP.get(protocol, []))
        return list(set(techniques))

    def _compute_risk(
        self, path: list[str], asset_risks: dict[str, int], techniques: list[str]
    ) -> int:
        path_risk = max((asset_risks.get(n, 0) for n in path), default=0)
        technique_bonus = min(30, len(techniques) * 5)
        hop_penalty = max(0, 5 - len(path)) * 5  # shorter paths = higher risk
        return min(100, path_risk + technique_bonus + hop_penalty)

    def _suggest_mitigations(self, techniques: list[str]) -> list[str]:
        mitigations = []
        tech_str = " ".join(techniques).lower()
        if "ssh" in tech_str:
            mitigations.append("Enforce key-based SSH authentication; disable password auth")
        if "rdp" in tech_str:
            mitigations.append("Restrict RDP access via network segmentation and MFA")
        if "smb" in tech_str:
            mitigations.append("Disable SMBv1; restrict admin shares")
        if "exploit" in tech_str:
            mitigations.append("Patch public-facing applications; deploy WAF")
        if not mitigations:
            mitigations.append("Review network segmentation between path nodes")
        return mitigations


# Module-level singleton
attack_path_engine = AttackPathEngine()
