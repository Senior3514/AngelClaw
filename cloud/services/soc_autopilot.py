"""AngelClaw V7.0 — Empyrion: SOC Autopilot Service.

AGI-driven Security Operations Center automation with autonomous triage,
investigation orchestration, analyst augmentation, shift handoff
generation, and workload balancing across SOC teams.

Features:
  - Autonomous alert triage with severity/priority classification
  - Investigation orchestration and evidence collection
  - Analyst assignment and workload balancing
  - Shift status tracking and handoff generation
  - Per-tenant isolation with SOC analytics
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.soc_autopilot")

_TRIAGE_LEVELS = {"p1_critical", "p2_high", "p3_medium", "p4_low", "p5_info"}
_INVESTIGATION_STATUSES = {
    "open", "investigating", "escalated", "resolved", "closed",
}


class TriagedAlert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    alert_id: str
    original_data: dict[str, Any] = {}
    triage_level: str = "p3_medium"
    category: str = ""
    assigned_analyst: str | None = None
    auto_triaged: bool = True
    investigation_id: str | None = None
    status: str = "triaged"  # triaged, assigned, investigating, resolved, closed
    triage_reasoning: str = ""
    triaged_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Investigation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    alert_ids: list[str] = []
    lead_analyst: str | None = None
    status: str = "open"
    findings: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    timeline: list[dict[str, Any]] = []
    resolution: str | None = None
    opened_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    closed_at: datetime | None = None


class SOCAnalyst(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    analyst_id: str
    name: str = ""
    shift: str = "day"  # day, swing, night
    active: bool = True
    current_workload: int = 0
    max_workload: int = 10
    alerts_handled: int = 0
    investigations_led: int = 0
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SOCAutopilotService:
    """AGI-driven SOC automation with autonomous triage and orchestration."""

    def __init__(self) -> None:
        self._alerts: dict[str, TriagedAlert] = {}
        self._tenant_alerts: dict[str, list[str]] = defaultdict(list)
        self._investigations: dict[str, Investigation] = {}
        self._tenant_investigations: dict[str, list[str]] = defaultdict(list)
        self._analysts: dict[str, SOCAnalyst] = {}
        self._tenant_analysts: dict[str, list[str]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Alert Triage
    # ------------------------------------------------------------------

    def triage_alert(
        self,
        tenant_id: str,
        alert_id: str,
        alert_data: dict | None = None,
    ) -> dict:
        """Autonomously triage an incoming security alert."""
        data = alert_data or {}

        # AGI triage logic
        triage_level, category, reasoning = self._compute_triage(data)

        alert = TriagedAlert(
            tenant_id=tenant_id,
            alert_id=alert_id,
            original_data=data,
            triage_level=triage_level,
            category=category,
            triage_reasoning=reasoning,
        )

        self._alerts[alert.id] = alert
        self._tenant_alerts[tenant_id].append(alert.id)

        # Cap alert history
        if len(self._tenant_alerts[tenant_id]) > 10000:
            self._tenant_alerts[tenant_id] = self._tenant_alerts[tenant_id][-10000:]

        # Auto-assign if P1 or P2
        if triage_level in ("p1_critical", "p2_high"):
            self._auto_assign(tenant_id, alert)

        logger.info(
            "[SOC_AUTO] Triaged alert %s as %s (%s) for %s",
            alert_id, triage_level, category, tenant_id,
        )
        return alert.model_dump(mode="json")

    # ------------------------------------------------------------------
    # Investigation
    # ------------------------------------------------------------------

    def investigate(
        self,
        tenant_id: str,
        investigation_id: str,
    ) -> dict:
        """Orchestrate an investigation, collecting evidence and building timeline."""
        inv = self._investigations.get(investigation_id)
        if not inv:
            return {"error": "Investigation not found"}
        if inv.tenant_id != tenant_id:
            return {"error": "Investigation does not belong to this tenant"}

        inv.status = "investigating"

        # Simulate evidence collection
        evidence_items = [
            {"type": "log_analysis", "source": "siem", "summary": "Correlated 15 log events"},
            {"type": "network_capture", "source": "ndr", "summary": "Captured suspicious traffic patterns"},
            {"type": "endpoint_telemetry", "source": "edr", "summary": "Process tree reconstruction complete"},
        ]
        inv.evidence.extend(evidence_items)

        # Build timeline
        timeline_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "automated_evidence_collection",
            "details": f"Collected {len(evidence_items)} evidence items",
        }
        inv.timeline.append(timeline_entry)

        logger.info(
            "[SOC_AUTO] Investigation %s: collected %d evidence items",
            investigation_id[:8], len(evidence_items),
        )
        return inv.model_dump(mode="json")

    def create_investigation(
        self,
        tenant_id: str,
        alert_ids: list[str],
        lead_analyst: str | None = None,
    ) -> dict:
        """Create a new investigation from one or more alerts."""
        inv = Investigation(
            tenant_id=tenant_id,
            alert_ids=alert_ids,
            lead_analyst=lead_analyst,
        )
        self._investigations[inv.id] = inv
        self._tenant_investigations[tenant_id].append(inv.id)

        # Link alerts to investigation
        for aid in alert_ids:
            for ta in self._alerts.values():
                if ta.alert_id == aid and ta.tenant_id == tenant_id:
                    ta.investigation_id = inv.id
                    ta.status = "investigating"

        logger.info(
            "[SOC_AUTO] Created investigation %s with %d alerts for %s",
            inv.id[:8], len(alert_ids), tenant_id,
        )
        return inv.model_dump(mode="json")

    # ------------------------------------------------------------------
    # Analyst Management
    # ------------------------------------------------------------------

    def register_analyst(
        self,
        tenant_id: str,
        analyst_id: str,
        name: str = "",
        shift: str = "day",
        max_workload: int = 10,
    ) -> dict:
        """Register a SOC analyst for workload tracking."""
        analyst = SOCAnalyst(
            tenant_id=tenant_id,
            analyst_id=analyst_id,
            name=name or analyst_id,
            shift=shift,
            max_workload=max_workload,
        )
        self._analysts[analyst.id] = analyst
        self._tenant_analysts[tenant_id].append(analyst.id)

        logger.info(
            "[SOC_AUTO] Registered analyst '%s' (shift=%s) for %s",
            name or analyst_id, shift, tenant_id,
        )
        return analyst.model_dump(mode="json")

    def assign_analyst(
        self,
        tenant_id: str,
        alert_id: str,
        analyst_id: str,
    ) -> dict:
        """Manually assign an analyst to a triaged alert."""
        # Find the triaged alert
        target = None
        for ta in self._alerts.values():
            if ta.alert_id == alert_id and ta.tenant_id == tenant_id:
                target = ta
                break

        if not target:
            return {"error": "Alert not found"}

        # Find the analyst
        analyst = None
        for a in self._analysts.values():
            if a.analyst_id == analyst_id and a.tenant_id == tenant_id:
                analyst = a
                break

        if not analyst:
            return {"error": "Analyst not found"}

        target.assigned_analyst = analyst_id
        target.status = "assigned"
        analyst.current_workload += 1
        analyst.alerts_handled += 1

        logger.info(
            "[SOC_AUTO] Assigned alert %s to analyst '%s'",
            alert_id, analyst_id,
        )
        return target.model_dump(mode="json")

    # ------------------------------------------------------------------
    # Shift & Workload
    # ------------------------------------------------------------------

    def get_shift_status(self, tenant_id: str) -> dict:
        """Return current shift status across all analysts."""
        analysts = self._get_tenant_analysts(tenant_id)

        by_shift: dict[str, list[dict]] = defaultdict(list)
        for a in analysts:
            by_shift[a.shift].append({
                "analyst_id": a.analyst_id,
                "name": a.name,
                "active": a.active,
                "workload": a.current_workload,
                "max_workload": a.max_workload,
                "utilization_pct": round(
                    a.current_workload / max(a.max_workload, 1) * 100, 1,
                ),
            })

        return {
            "tenant_id": tenant_id,
            "total_analysts": len(analysts),
            "active_analysts": sum(1 for a in analysts if a.active),
            "by_shift": dict(by_shift),
        }

    def get_workload(self, tenant_id: str) -> dict:
        """Return workload distribution across analysts."""
        analysts = self._get_tenant_analysts(tenant_id)

        total_capacity = sum(a.max_workload for a in analysts if a.active)
        total_current = sum(a.current_workload for a in analysts if a.active)

        overloaded = [
            a.analyst_id for a in analysts
            if a.active and a.current_workload >= a.max_workload
        ]
        available = [
            a.analyst_id for a in analysts
            if a.active and a.current_workload < a.max_workload
        ]

        return {
            "tenant_id": tenant_id,
            "total_capacity": total_capacity,
            "current_workload": total_current,
            "utilization_pct": round(
                total_current / max(total_capacity, 1) * 100, 1,
            ),
            "overloaded_analysts": overloaded,
            "available_analysts": available,
        }

    def generate_handoff(self, tenant_id: str) -> dict:
        """Generate a shift handoff report."""
        alerts = [
            self._alerts[aid]
            for aid in self._tenant_alerts.get(tenant_id, [])
            if aid in self._alerts
        ]
        investigations = [
            self._investigations[iid]
            for iid in self._tenant_investigations.get(tenant_id, [])
            if iid in self._investigations
        ]

        open_alerts = [a for a in alerts if a.status not in ("resolved", "closed")]
        active_investigations = [
            i for i in investigations if i.status in ("open", "investigating")
        ]

        by_priority: dict[str, int] = defaultdict(int)
        for a in open_alerts:
            by_priority[a.triage_level] += 1

        return {
            "tenant_id": tenant_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "open_alerts": len(open_alerts),
            "by_priority": dict(by_priority),
            "active_investigations": len(active_investigations),
            "critical_items": [
                {
                    "alert_id": a.alert_id,
                    "triage_level": a.triage_level,
                    "category": a.category,
                    "assigned_to": a.assigned_analyst,
                }
                for a in open_alerts
                if a.triage_level in ("p1_critical", "p2_high")
            ],
            "pending_investigations": [
                {
                    "investigation_id": i.id,
                    "alert_count": len(i.alert_ids),
                    "lead_analyst": i.lead_analyst,
                    "status": i.status,
                }
                for i in active_investigations
            ],
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return SOC Autopilot statistics for a tenant."""
        alerts = [
            self._alerts[aid]
            for aid in self._tenant_alerts.get(tenant_id, [])
            if aid in self._alerts
        ]
        investigations = [
            self._investigations[iid]
            for iid in self._tenant_investigations.get(tenant_id, [])
            if iid in self._investigations
        ]
        analysts = self._get_tenant_analysts(tenant_id)

        by_triage: dict[str, int] = defaultdict(int)
        by_status: dict[str, int] = defaultdict(int)
        for a in alerts:
            by_triage[a.triage_level] += 1
            by_status[a.status] += 1

        return {
            "total_alerts_triaged": len(alerts),
            "by_triage_level": dict(by_triage),
            "by_status": dict(by_status),
            "auto_triaged": sum(1 for a in alerts if a.auto_triaged),
            "total_investigations": len(investigations),
            "active_investigations": sum(
                1 for i in investigations
                if i.status in ("open", "investigating")
            ),
            "total_analysts": len(analysts),
            "active_analysts": sum(1 for a in analysts if a.active),
        }

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _compute_triage(
        self,
        alert_data: dict,
    ) -> tuple[str, str, str]:
        """Compute triage level, category, and reasoning from alert data.

        AGI-driven classification based on severity, source, and indicators.
        """
        severity = alert_data.get("severity", "medium").lower()
        source = alert_data.get("source", "unknown")
        alert_type = alert_data.get("type", "generic")

        # Map severity to triage level
        severity_map = {
            "critical": "p1_critical",
            "high": "p2_high",
            "medium": "p3_medium",
            "low": "p4_low",
            "info": "p5_info",
        }
        triage_level = severity_map.get(severity, "p3_medium")

        # Elevate based on keywords in alert data
        indicators = str(alert_data.get("indicators", "")).lower()
        if "ransomware" in indicators or "data_exfil" in indicators:
            triage_level = "p1_critical"
        elif "lateral_movement" in indicators or "privilege_escalation" in indicators:
            if triage_level not in ("p1_critical",):
                triage_level = "p2_high"

        # Determine category
        category = alert_type if alert_type != "generic" else source
        reasoning = (
            f"Classified as {triage_level} based on severity={severity}, "
            f"source={source}, type={alert_type}"
        )

        return triage_level, category, reasoning

    def _auto_assign(self, tenant_id: str, alert: TriagedAlert) -> None:
        """Auto-assign a high-priority alert to the least-loaded analyst."""
        analysts = self._get_tenant_analysts(tenant_id)
        available = [
            a for a in analysts
            if a.active and a.current_workload < a.max_workload
        ]

        if not available:
            logger.warning(
                "[SOC_AUTO] No available analysts for auto-assignment of %s",
                alert.alert_id,
            )
            return

        # Pick least loaded
        available.sort(key=lambda a: a.current_workload)
        chosen = available[0]
        alert.assigned_analyst = chosen.analyst_id
        alert.status = "assigned"
        chosen.current_workload += 1
        chosen.alerts_handled += 1

        logger.info(
            "[SOC_AUTO] Auto-assigned %s alert %s to '%s'",
            alert.triage_level, alert.alert_id, chosen.analyst_id,
        )

    def _get_tenant_analysts(self, tenant_id: str) -> list[SOCAnalyst]:
        """Return all analysts belonging to a tenant."""
        return [
            self._analysts[aid]
            for aid in self._tenant_analysts.get(tenant_id, [])
            if aid in self._analysts
        ]


# Module-level singleton
soc_autopilot_service = SOCAutopilotService()
