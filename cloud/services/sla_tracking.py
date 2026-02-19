"""AngelClaw V4.0 — Omniscience: SLA Tracking Service.

Tracks incident response SLA compliance, monitors breach conditions,
and escalates when response/resolution times are exceeded.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.sla_tracking")


class SLAConfig(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    name: str
    severity: str  # critical, high, medium, low
    response_time_minutes: int
    resolution_time_minutes: int
    escalation_contacts: list[str] = []
    enabled: bool = True
    breaches_total: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SLATracker:
    """Track incident SLA status and detect breaches."""

    def __init__(self) -> None:
        self.id = str(uuid.uuid4())
        self.incident_id: str = ""
        self.tenant_id: str = "dev-tenant"
        self.severity: str = "medium"
        self.sla_config_id: str | None = None
        self.created_at: datetime = datetime.now(timezone.utc)
        self.first_response_at: datetime | None = None
        self.resolved_at: datetime | None = None
        self.response_breached: bool = False
        self.resolution_breached: bool = False
        self.escalated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "tenant_id": self.tenant_id,
            "severity": self.severity,
            "sla_config_id": self.sla_config_id,
            "created_at": self.created_at.isoformat(),
            "first_response_at": self.first_response_at.isoformat() if self.first_response_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "response_breached": self.response_breached,
            "resolution_breached": self.resolution_breached,
            "escalated": self.escalated,
        }


class SLATrackingService:
    """SLA configuration and compliance monitoring."""

    def __init__(self) -> None:
        self._configs: dict[str, SLAConfig] = {}
        self._tenant_configs: dict[str, list[str]] = defaultdict(list)
        self._trackers: dict[str, SLATracker] = {}  # incident_id -> tracker

    # -- Config CRUD --

    def create_config(
        self,
        tenant_id: str,
        name: str,
        severity: str,
        response_time_minutes: int,
        resolution_time_minutes: int,
        escalation_contacts: list[str] | None = None,
    ) -> dict:
        config = SLAConfig(
            tenant_id=tenant_id,
            name=name,
            severity=severity,
            response_time_minutes=response_time_minutes,
            resolution_time_minutes=resolution_time_minutes,
            escalation_contacts=escalation_contacts or [],
        )
        self._configs[config.id] = config
        self._tenant_configs[tenant_id].append(config.id)
        logger.info("[SLA] Created config '%s' for severity=%s", name, severity)
        return config.model_dump(mode="json")

    def list_configs(self, tenant_id: str) -> list[dict]:
        return [
            self._configs[cid].model_dump(mode="json")
            for cid in self._tenant_configs.get(tenant_id, [])
            if cid in self._configs
        ]

    def get_config_for_severity(self, tenant_id: str, severity: str) -> SLAConfig | None:
        for cid in self._tenant_configs.get(tenant_id, []):
            config = self._configs.get(cid)
            if config and config.severity == severity and config.enabled:
                return config
        return None

    # -- Tracking --

    def start_tracking(self, tenant_id: str, incident_id: str, severity: str) -> dict:
        config = self.get_config_for_severity(tenant_id, severity)
        tracker = SLATracker()
        tracker.incident_id = incident_id
        tracker.tenant_id = tenant_id
        tracker.severity = severity
        tracker.sla_config_id = config.id if config else None
        self._trackers[incident_id] = tracker
        return tracker.to_dict()

    def record_response(self, incident_id: str) -> dict | None:
        tracker = self._trackers.get(incident_id)
        if not tracker:
            return None
        tracker.first_response_at = datetime.now(timezone.utc)
        return tracker.to_dict()

    def record_resolution(self, incident_id: str) -> dict | None:
        tracker = self._trackers.get(incident_id)
        if not tracker:
            return None
        tracker.resolved_at = datetime.now(timezone.utc)
        return tracker.to_dict()

    def check_breaches(self, tenant_id: str) -> list[dict]:
        """Check all active trackers for SLA breaches."""
        now = datetime.now(timezone.utc)
        breaches = []
        for tracker in self._trackers.values():
            if tracker.tenant_id != tenant_id:
                continue
            if tracker.resolved_at:
                continue  # Already resolved

            config = self._configs.get(tracker.sla_config_id or "") if tracker.sla_config_id else None
            if not config:
                continue

            # Check response SLA
            if not tracker.first_response_at:
                deadline = tracker.created_at + timedelta(minutes=config.response_time_minutes)
                if now > deadline and not tracker.response_breached:
                    tracker.response_breached = True
                    config.breaches_total += 1
                    breaches.append({
                        "incident_id": tracker.incident_id,
                        "breach_type": "response",
                        "severity": tracker.severity,
                        "deadline": deadline.isoformat(),
                        "overdue_minutes": int((now - deadline).total_seconds() / 60),
                    })

            # Check resolution SLA
            resolution_deadline = tracker.created_at + timedelta(minutes=config.resolution_time_minutes)
            if now > resolution_deadline and not tracker.resolution_breached:
                tracker.resolution_breached = True
                config.breaches_total += 1
                breaches.append({
                    "incident_id": tracker.incident_id,
                    "breach_type": "resolution",
                    "severity": tracker.severity,
                    "deadline": resolution_deadline.isoformat(),
                    "overdue_minutes": int((now - resolution_deadline).total_seconds() / 60),
                })

        if breaches:
            logger.warning("[SLA] %d breach(es) detected for %s", len(breaches), tenant_id)
        return breaches

    def get_compliance_report(self, tenant_id: str) -> dict:
        trackers = [t for t in self._trackers.values() if t.tenant_id == tenant_id]
        total = len(trackers)
        response_ok = sum(1 for t in trackers if not t.response_breached)
        resolution_ok = sum(1 for t in trackers if not t.resolution_breached)
        return {
            "total_incidents_tracked": total,
            "response_sla_compliance": round(response_ok / max(total, 1) * 100, 1),
            "resolution_sla_compliance": round(resolution_ok / max(total, 1) * 100, 1),
            "total_breaches": sum(1 for t in trackers if t.response_breached or t.resolution_breached),
            "active_trackers": sum(1 for t in trackers if not t.resolved_at),
        }


# Module-level singleton
sla_tracking_service = SLATrackingService()
