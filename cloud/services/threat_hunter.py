"""AngelClaw V6.5 — Prometheus: Threat Hunter Service.

Autonomous threat hunting engine with hypothesis-driven hunts, automated
execution, IOC correlation, and hunt playbook management. Enables
proactive security by continuously searching for hidden threats.

Features:
  - Hunt creation with hypothesis and configuration
  - Automated hunt execution with result tracking
  - Hunt playbook management (reusable hunt templates)
  - IOC correlation during hunt execution
  - Per-tenant isolation with hunt analytics
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.threat_hunter")

_HUNT_TYPES = {"hypothesis", "ioc_sweep", "behavioral", "anomaly", "network", "endpoint"}
_HUNT_STATUSES = {"created", "running", "completed", "failed", "cancelled"}


class ThreatHunt(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    name: str
    hypothesis: str = ""
    hunt_type: str = "hypothesis"
    config: dict[str, Any] = {}
    status: str = "created"  # created, running, completed, failed, cancelled
    findings_count: int = 0
    iocs_matched: int = 0
    events_analysed: int = 0
    results: list[dict[str, Any]] = []
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = "system"


class HuntPlaybook(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    name: str
    description: str = ""
    steps: list[dict[str, Any]] = []
    hunt_type: str = "hypothesis"
    tags: list[str] = []
    times_executed: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = "system"


class ThreatHunterService:
    """Autonomous threat hunting with hypothesis-driven execution."""

    def __init__(self) -> None:
        self._hunts: dict[str, ThreatHunt] = {}
        self._tenant_hunts: dict[str, list[str]] = defaultdict(list)
        self._playbooks: dict[str, HuntPlaybook] = {}
        self._tenant_playbooks: dict[str, list[str]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Hunt Management
    # ------------------------------------------------------------------

    def create_hunt(
        self,
        tenant_id: str,
        name: str,
        hypothesis: str = "",
        hunt_type: str = "hypothesis",
        config: dict | None = None,
        created_by: str = "system",
    ) -> dict:
        """Create a new threat hunt."""
        htype = hunt_type if hunt_type in _HUNT_TYPES else "hypothesis"

        hunt = ThreatHunt(
            tenant_id=tenant_id,
            name=name,
            hypothesis=hypothesis,
            hunt_type=htype,
            config=config or {},
            created_by=created_by,
        )
        self._hunts[hunt.id] = hunt
        self._tenant_hunts[tenant_id].append(hunt.id)

        logger.info(
            "[THREAT_HUNT] Created hunt '%s' (%s) for %s — hypothesis: %s",
            name, htype, tenant_id, hypothesis[:80] if hypothesis else "none",
        )
        return hunt.model_dump(mode="json")

    def execute_hunt(self, hunt_id: str) -> dict:
        """Execute a threat hunt and gather results."""
        hunt = self._hunts.get(hunt_id)
        if not hunt:
            return {"error": "Hunt not found"}
        if hunt.status == "running":
            return {"error": "Hunt is already running"}

        hunt.status = "running"
        hunt.started_at = datetime.now(timezone.utc)

        try:
            results = self._run_hunt_logic(hunt)
            hunt.results = results
            hunt.findings_count = sum(1 for r in results if r.get("finding"))
            hunt.iocs_matched = sum(1 for r in results if r.get("ioc_match"))
            hunt.events_analysed = sum(r.get("events_scanned", 0) for r in results)
            hunt.status = "completed"
        except Exception as exc:
            hunt.status = "failed"
            hunt.results = [{"error": str(exc)}]
            logger.error("[THREAT_HUNT] Hunt '%s' failed: %s", hunt.name, exc)

        hunt.completed_at = datetime.now(timezone.utc)

        logger.info(
            "[THREAT_HUNT] Hunt '%s' %s — %d findings, %d IOC matches",
            hunt.name, hunt.status, hunt.findings_count, hunt.iocs_matched,
        )
        return hunt.model_dump(mode="json")

    def list_hunts(
        self,
        tenant_id: str,
        status: str | None = None,
    ) -> list[dict]:
        """List hunts for a tenant with optional status filter."""
        results = []
        for hid in self._tenant_hunts.get(tenant_id, []):
            hunt = self._hunts.get(hid)
            if not hunt:
                continue
            if status and hunt.status != status:
                continue
            results.append(hunt.model_dump(mode="json"))
        results.sort(key=lambda h: h.get("created_at", ""), reverse=True)
        return results

    def get_hunt_results(self, hunt_id: str) -> dict | None:
        """Get detailed results for a completed hunt."""
        hunt = self._hunts.get(hunt_id)
        if not hunt:
            return None
        return {
            "hunt_id": hunt.id,
            "name": hunt.name,
            "status": hunt.status,
            "hypothesis": hunt.hypothesis,
            "findings_count": hunt.findings_count,
            "iocs_matched": hunt.iocs_matched,
            "events_analysed": hunt.events_analysed,
            "results": hunt.results,
            "started_at": hunt.started_at.isoformat() if hunt.started_at else None,
            "completed_at": hunt.completed_at.isoformat() if hunt.completed_at else None,
        }

    # ------------------------------------------------------------------
    # Hunt Playbooks
    # ------------------------------------------------------------------

    def create_playbook(
        self,
        tenant_id: str,
        name: str,
        steps: list[dict] | None = None,
        description: str = "",
        hunt_type: str = "hypothesis",
        tags: list[str] | None = None,
        created_by: str = "system",
    ) -> dict:
        """Create a reusable hunt playbook."""
        pb = HuntPlaybook(
            tenant_id=tenant_id,
            name=name,
            description=description,
            steps=steps or [],
            hunt_type=hunt_type if hunt_type in _HUNT_TYPES else "hypothesis",
            tags=tags or [],
            created_by=created_by,
        )
        self._playbooks[pb.id] = pb
        self._tenant_playbooks[tenant_id].append(pb.id)

        logger.info(
            "[THREAT_HUNT] Created playbook '%s' with %d steps for %s",
            name, len(pb.steps), tenant_id,
        )
        return pb.model_dump(mode="json")

    def list_playbooks(self, tenant_id: str) -> list[dict]:
        """List all hunt playbooks for a tenant."""
        return [
            self._playbooks[pid].model_dump(mode="json")
            for pid in self._tenant_playbooks.get(tenant_id, [])
            if pid in self._playbooks
        ]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return threat hunter statistics for a tenant."""
        hunts = [
            self._hunts[hid]
            for hid in self._tenant_hunts.get(tenant_id, [])
            if hid in self._hunts
        ]
        playbooks = [
            self._playbooks[pid]
            for pid in self._tenant_playbooks.get(tenant_id, [])
            if pid in self._playbooks
        ]

        by_status: dict[str, int] = defaultdict(int)
        by_type: dict[str, int] = defaultdict(int)
        total_findings = 0
        total_iocs = 0
        for h in hunts:
            by_status[h.status] += 1
            by_type[h.hunt_type] += 1
            total_findings += h.findings_count
            total_iocs += h.iocs_matched

        return {
            "total_hunts": len(hunts),
            "by_status": dict(by_status),
            "by_type": dict(by_type),
            "total_findings": total_findings,
            "total_iocs_matched": total_iocs,
            "total_playbooks": len(playbooks),
            "avg_findings_per_hunt": round(
                total_findings / max(len(hunts), 1), 1,
            ),
        }

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _run_hunt_logic(self, hunt: ThreatHunt) -> list[dict]:
        """Execute hunt logic based on hunt type.

        In production, this would integrate with log sources, SIEM, and
        endpoint telemetry. For the orchestration layer, we simulate results.
        """
        results = []
        if hunt.hunt_type == "ioc_sweep":
            results.append({
                "step": "ioc_sweep",
                "events_scanned": 5000,
                "ioc_match": True,
                "finding": True,
                "details": "Matched 3 known-bad IPs in network logs",
            })
        elif hunt.hunt_type == "behavioral":
            results.append({
                "step": "behavioral_analysis",
                "events_scanned": 8000,
                "ioc_match": False,
                "finding": True,
                "details": "Detected lateral movement pattern",
            })
        elif hunt.hunt_type == "anomaly":
            results.append({
                "step": "anomaly_detection",
                "events_scanned": 12000,
                "ioc_match": False,
                "finding": False,
                "details": "No significant anomalies detected",
            })
        else:
            results.append({
                "step": "hypothesis_test",
                "events_scanned": 3000,
                "ioc_match": False,
                "finding": False,
                "details": f"Tested hypothesis: {hunt.hypothesis}",
            })

        return results


# Module-level singleton
threat_hunter_service = ThreatHunterService()
