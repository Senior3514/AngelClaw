"""AngelClaw V5.5 — Convergence: Dashboard Aggregator.

Aggregates data from all AngelClaw subsystems into unified dashboard
payloads consumed by the Command Center UI. Provides single-call
access to halo score, wingspan, threat landscape, compliance status,
and predictive analytics.

Features:
  - Command Center payload aggregation
  - Wingspan statistics (node coverage, agent deployment)
  - Threat landscape overview
  - Predictive analytics summary
  - Per-tenant isolation with caching
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.dashboard_aggregator")


class DashboardSnapshot(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    section: str  # command_center, wingspan, threat_landscape, predictive
    data: dict[str, Any] = {}
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class WidgetConfig(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    widget_name: str
    position: int = 0
    visible: bool = True
    config: dict[str, Any] = {}


class DashboardAggregator:
    """Aggregates subsystem data into unified dashboard payloads."""

    def __init__(self) -> None:
        self._snapshots: dict[str, list[DashboardSnapshot]] = defaultdict(list)
        self._widgets: dict[str, list[WidgetConfig]] = defaultdict(list)
        # Subsystem data stores (populated by service integrations)
        self._halo_scores: dict[str, float] = defaultdict(float)
        self._wingspan_data: dict[str, dict[str, Any]] = defaultdict(dict)
        self._threat_data: dict[str, dict[str, Any]] = defaultdict(dict)
        self._compliance_data: dict[str, dict[str, Any]] = defaultdict(dict)
        self._event_data: dict[str, list[dict[str, Any]]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Data Ingestion (called by other services)
    # ------------------------------------------------------------------

    def update_halo_score(self, tenant_id: str, score: float) -> None:
        """Update cached halo score for a tenant."""
        self._halo_scores[tenant_id] = max(0.0, min(100.0, score))

    def update_wingspan(self, tenant_id: str, data: dict) -> None:
        """Update cached wingspan data for a tenant."""
        self._wingspan_data[tenant_id] = data

    def update_threat_data(self, tenant_id: str, data: dict) -> None:
        """Update cached threat landscape data for a tenant."""
        self._threat_data[tenant_id] = data

    def update_compliance(self, tenant_id: str, data: dict) -> None:
        """Update cached compliance data for a tenant."""
        self._compliance_data[tenant_id] = data

    def push_event(self, tenant_id: str, event: dict) -> None:
        """Push a recent event for dashboard display."""
        self._event_data[tenant_id].append({
            **event,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        # Keep only the most recent 200 events
        if len(self._event_data[tenant_id]) > 200:
            self._event_data[tenant_id] = self._event_data[tenant_id][-200:]

    # ------------------------------------------------------------------
    # Dashboard Payloads
    # ------------------------------------------------------------------

    def get_command_center(self, tenant_id: str) -> dict:
        """Aggregate the full Command Center dashboard payload."""
        wingspan = self._wingspan_data.get(tenant_id, {})
        threats = self._threat_data.get(tenant_id, {})
        compliance = self._compliance_data.get(tenant_id, {})
        recent_events = self._event_data.get(tenant_id, [])[-20:]

        payload = {
            "tenant_id": tenant_id,
            "halo_score": self._halo_scores.get(tenant_id, 0.0),
            "wingspan": {
                "total_nodes": wingspan.get("total_nodes", 0),
                "online_nodes": wingspan.get("online_nodes", 0),
                "coverage_pct": wingspan.get("coverage_pct", 0.0),
            },
            "threat_count": threats.get("total_threats", 0),
            "alert_count": threats.get("total_alerts", 0),
            "active_wardens": wingspan.get("active_wardens", 0),
            "top_threats": threats.get("top_threats", [])[:5],
            "compliance_status": {
                "overall_pct": compliance.get("overall_pct", 0.0),
                "frameworks": compliance.get("frameworks", []),
            },
            "recent_events": recent_events,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        self._record_snapshot(tenant_id, "command_center", payload)
        logger.debug("[DASHBOARD] Generated command center payload for %s", tenant_id)
        return payload

    def get_wingspan_stats(self, tenant_id: str) -> dict:
        """Return detailed wingspan statistics."""
        wingspan = self._wingspan_data.get(tenant_id, {})

        payload = {
            "tenant_id": tenant_id,
            "total_nodes": wingspan.get("total_nodes", 0),
            "online_nodes": wingspan.get("online_nodes", 0),
            "offline_nodes": wingspan.get("offline_nodes", 0),
            "degraded_nodes": wingspan.get("degraded_nodes", 0),
            "coverage_pct": wingspan.get("coverage_pct", 0.0),
            "active_wardens": wingspan.get("active_wardens", 0),
            "os_distribution": wingspan.get("os_distribution", {}),
            "version_compliance": wingspan.get("version_compliance", {}),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        self._record_snapshot(tenant_id, "wingspan", payload)
        return payload

    def get_threat_landscape(self, tenant_id: str) -> dict:
        """Return threat landscape overview."""
        threats = self._threat_data.get(tenant_id, {})

        payload = {
            "tenant_id": tenant_id,
            "total_threats": threats.get("total_threats", 0),
            "total_alerts": threats.get("total_alerts", 0),
            "by_severity": threats.get("by_severity", {}),
            "by_category": threats.get("by_category", {}),
            "top_threats": threats.get("top_threats", [])[:10],
            "active_incidents": threats.get("active_incidents", 0),
            "mean_time_to_detect": threats.get("mttd_minutes", 0),
            "mean_time_to_respond": threats.get("mttr_minutes", 0),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        self._record_snapshot(tenant_id, "threat_landscape", payload)
        return payload

    def get_predictive_stats(self, tenant_id: str) -> dict:
        """Return predictive analytics summary."""
        threats = self._threat_data.get(tenant_id, {})
        wingspan = self._wingspan_data.get(tenant_id, {})

        # Derive predictive indicators from available data
        threat_trend = threats.get("threat_trend", "stable")
        risk_forecast = threats.get("risk_forecast", "moderate")
        predicted_incidents_24h = threats.get("predicted_incidents_24h", 0)

        payload = {
            "tenant_id": tenant_id,
            "threat_trend": threat_trend,
            "risk_forecast": risk_forecast,
            "predicted_incidents_24h": predicted_incidents_24h,
            "halo_score_trend": self._compute_score_trend(tenant_id),
            "fleet_health_trend": wingspan.get("health_trend", "stable"),
            "recommended_actions": threats.get("recommended_actions", []),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        self._record_snapshot(tenant_id, "predictive", payload)
        return payload

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return dashboard aggregator statistics for a tenant."""
        snapshots = self._snapshots.get(tenant_id, [])
        by_section: dict[str, int] = defaultdict(int)
        for snap in snapshots:
            by_section[snap.section] += 1

        return {
            "total_snapshots": len(snapshots),
            "by_section": dict(by_section),
            "cached_halo_score": self._halo_scores.get(tenant_id, 0.0),
            "recent_events_count": len(self._event_data.get(tenant_id, [])),
            "widgets_configured": len(self._widgets.get(tenant_id, [])),
        }

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _record_snapshot(
        self, tenant_id: str, section: str, data: dict,
    ) -> None:
        """Record a dashboard snapshot for history."""
        snap = DashboardSnapshot(
            tenant_id=tenant_id, section=section, data=data,
        )
        self._snapshots[tenant_id].append(snap)
        # Cap snapshots per tenant
        if len(self._snapshots[tenant_id]) > 2000:
            self._snapshots[tenant_id] = self._snapshots[tenant_id][-2000:]

    def _compute_score_trend(self, tenant_id: str) -> str:
        """Derive halo score trend from recent snapshots."""
        recent = [
            s for s in self._snapshots.get(tenant_id, [])
            if s.section == "command_center"
        ][-10:]

        if len(recent) < 2:
            return "stable"

        scores = [s.data.get("halo_score", 0.0) for s in recent]
        delta = scores[-1] - scores[0]
        if delta > 3:
            return "improving"
        elif delta < -3:
            return "declining"
        return "stable"


# Module-level singleton
dashboard_aggregator_service = DashboardAggregator()
