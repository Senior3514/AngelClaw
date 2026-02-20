"""AngelClaw V4.0 — Omniscience: Incident Timeline Service.

Builds rich timeline visualizations for incidents with events, actions,
comments, escalations, and resolution milestones.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("angelclaw.incident_timeline")


class TimelineEntry:
    def __init__(
        self,
        tenant_id: str,
        incident_id: str,
        entry_type: str,
        title: str,
        description: str = "",
        actor: str = "system",
        details: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> None:
        self.id = str(uuid.uuid4())
        self.tenant_id = tenant_id
        self.incident_id = incident_id
        self.entry_type = entry_type  # event, action, comment, escalation, resolution
        self.timestamp = timestamp or datetime.now(timezone.utc)
        self.title = title
        self.description = description
        self.actor = actor
        self.details = details or {}
        self.created_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "incident_id": self.incident_id,
            "entry_type": self.entry_type,
            "timestamp": self.timestamp.isoformat(),
            "title": self.title,
            "description": self.description,
            "actor": self.actor,
            "details": self.details,
            "created_at": self.created_at.isoformat(),
        }


class IncidentTimelineService:
    """Incident timeline management for visualization and audit."""

    def __init__(self) -> None:
        self._entries: dict[str, TimelineEntry] = {}
        self._incident_entries: dict[str, list[str]] = defaultdict(list)

    def add_entry(
        self,
        tenant_id: str,
        incident_id: str,
        entry_type: str,
        title: str,
        description: str = "",
        actor: str = "system",
        details: dict | None = None,
        timestamp: datetime | None = None,
    ) -> dict:
        entry = TimelineEntry(
            tenant_id=tenant_id,
            incident_id=incident_id,
            entry_type=entry_type,
            title=title,
            description=description,
            actor=actor,
            details=details,
            timestamp=timestamp,
        )
        self._entries[entry.id] = entry
        self._incident_entries[incident_id].append(entry.id)
        return entry.to_dict()

    def get_timeline(self, incident_id: str, entry_type: str | None = None) -> list[dict]:
        """Get ordered timeline for an incident."""
        entries = []
        for eid in self._incident_entries.get(incident_id, []):
            entry = self._entries.get(eid)
            if not entry:
                continue
            if entry_type and entry.entry_type != entry_type:
                continue
            entries.append(entry.to_dict())
        entries.sort(key=lambda e: e["timestamp"])
        return entries

    def add_comment(
        self, tenant_id: str, incident_id: str, comment: str, actor: str = "operator"
    ) -> dict:
        return self.add_entry(tenant_id, incident_id, "comment", "Comment added", comment, actor)

    def add_escalation(
        self, tenant_id: str, incident_id: str, escalated_to: str, reason: str = ""
    ) -> dict:
        return self.add_entry(
            tenant_id,
            incident_id,
            "escalation",
            f"Escalated to {escalated_to}",
            reason,
            "system",
            details={"escalated_to": escalated_to},
        )

    def add_resolution(
        self, tenant_id: str, incident_id: str, resolution: str, actor: str = "operator"
    ) -> dict:
        return self.add_entry(
            tenant_id, incident_id, "resolution", "Incident resolved", resolution, actor
        )

    def get_stats(self, tenant_id: str) -> dict:
        tenant_entries = [e for e in self._entries.values() if e.tenant_id == tenant_id]
        by_type: dict[str, int] = defaultdict(int)
        for e in tenant_entries:
            by_type[e.entry_type] += 1
        return {
            "total_entries": len(tenant_entries),
            "incidents_tracked": len(set(e.incident_id for e in tenant_entries)),
            "by_type": dict(by_type),
        }


# Module-level singleton
incident_timeline_service = IncidentTimelineService()
