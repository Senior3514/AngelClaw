"""AngelClaw V5.0 — Transcendence: AI Incident Commander.

Orchestrates major-incident lifecycle from declaration through post-mortem.
Each incident is assigned an AI commander identity, maintains a structured
timeline of updates, and automatically computes mean-time-to-resolve (MTTR).

Features:
  - Major incident declaration with severity and related-incident linking
  - Automatic AI commander assignment
  - Structured timeline with status transitions
  - MTTR computation on resolution
  - Per-tenant analytics (by status, severity, avg MTTR)
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("angelclaw.incident_commander")

# Pool of AI commander identities for automatic assignment
_COMMANDER_POOL = [
    "sentinel-alpha",
    "sentinel-bravo",
    "sentinel-charlie",
    "sentinel-delta",
    "sentinel-echo",
]


class MajorIncident:
    def __init__(
        self,
        tenant_id: str,
        title: str,
        severity: str,
        description: str = "",
        commander_ai: str = "",
        related_incident_ids: list[str] | None = None,
    ) -> None:
        self.id = str(uuid.uuid4())
        self.tenant_id = tenant_id
        self.title = title
        self.severity = severity              # critical, high, medium, low
        self.description = description
        self.status = "declared"              # declared, investigating, mitigating, resolved, postmortem
        self.commander_ai = commander_ai
        self.timeline: list[dict[str, Any]] = []
        self.related_incident_ids: list[str] = related_incident_ids or []
        self.declared_at = datetime.now(timezone.utc)
        self.resolved_at: datetime | None = None
        self.mttr_seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "status": self.status,
            "commander_ai": self.commander_ai,
            "timeline": self.timeline,
            "related_incident_ids": self.related_incident_ids,
            "declared_at": self.declared_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "mttr_seconds": self.mttr_seconds,
        }


class IncidentCommanderService:
    """AI-driven major-incident lifecycle management."""

    def __init__(self) -> None:
        self._incidents: dict[str, MajorIncident] = {}
        self._tenant_incidents: dict[str, list[str]] = defaultdict(list)
        self._commander_idx = 0               # round-robin index

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def declare_incident(
        self,
        tenant_id: str,
        title: str,
        severity: str,
        description: str = "",
        related_ids: list[str] | None = None,
    ) -> dict:
        """Declare a new major incident and auto-assign an AI commander."""
        commander = self._next_commander()
        incident = MajorIncident(
            tenant_id=tenant_id,
            title=title,
            severity=severity,
            description=description,
            commander_ai=commander,
            related_incident_ids=related_ids,
        )
        # Seed the timeline with the declaration event
        incident.timeline.append({
            "timestamp": incident.declared_at.isoformat(),
            "status": "declared",
            "update": f"Incident declared — commander {commander} assigned.",
        })

        self._incidents[incident.id] = incident
        self._tenant_incidents[tenant_id].append(incident.id)
        logger.info(
            "[INCIDENT_CMD] Declared incident '%s' severity=%s commander=%s for %s",
            title, severity, commander, tenant_id,
        )
        return incident.to_dict()

    def add_update(
        self,
        incident_id: str,
        update_text: str,
        status: str | None = None,
    ) -> dict | None:
        """Append an update to the incident timeline.

        If *status* is provided the incident status is transitioned.
        When the new status is ``resolved`` the resolved_at timestamp
        and mttr_seconds are computed automatically.
        """
        incident = self._incidents.get(incident_id)
        if not incident:
            return None

        now = datetime.now(timezone.utc)
        entry: dict[str, Any] = {
            "timestamp": now.isoformat(),
            "update": update_text,
        }

        if status:
            entry["status"] = status
            incident.status = status

            # Compute MTTR on resolution
            if status == "resolved" and incident.resolved_at is None:
                incident.resolved_at = now
                delta = (incident.resolved_at - incident.declared_at).total_seconds()
                incident.mttr_seconds = round(delta, 2)
                entry["mttr_seconds"] = incident.mttr_seconds

        incident.timeline.append(entry)
        logger.info(
            "[INCIDENT_CMD] Update on %s — status=%s",
            incident_id[:8], status or incident.status,
        )
        return incident.to_dict()

    def list_incidents(self, tenant_id: str) -> list[dict]:
        """List all major incidents for a tenant."""
        results = []
        for iid in self._tenant_incidents.get(tenant_id, []):
            incident = self._incidents.get(iid)
            if incident:
                results.append(incident.to_dict())
        return results

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return incident-commander statistics for a tenant."""
        incidents = [
            self._incidents[iid]
            for iid in self._tenant_incidents.get(tenant_id, [])
            if iid in self._incidents
        ]
        by_status: dict[str, int] = defaultdict(int)
        by_severity: dict[str, int] = defaultdict(int)
        mttr_values: list[float] = []
        for inc in incidents:
            by_status[inc.status] += 1
            by_severity[inc.severity] += 1
            if inc.mttr_seconds is not None:
                mttr_values.append(inc.mttr_seconds)
        return {
            "total": len(incidents),
            "by_status": dict(by_status),
            "by_severity": dict(by_severity),
            "avg_mttr_seconds": round(
                sum(mttr_values) / max(len(mttr_values), 1), 2,
            ) if mttr_values else None,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _next_commander(self) -> str:
        """Round-robin assignment from the commander pool."""
        commander = _COMMANDER_POOL[self._commander_idx % len(_COMMANDER_POOL)]
        self._commander_idx += 1
        return commander


# Module-level singleton
incident_commander_service = IncidentCommanderService()
