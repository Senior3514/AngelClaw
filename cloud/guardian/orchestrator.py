"""AngelClaw – ANGEL AGI Orchestrator.

The central brain of the guardian system.  Receives events, dispatches
them to sub-agents (Sentinel → Response → Forensic → Audit), manages
incident lifecycle, and coordinates all autonomous behavior.

Runs as a singleton background service inside the Cloud process.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from cloud.db.models import EventRow, GuardianAlertRow
from cloud.guardian.models import (
    AgentTask,
    AgentType,
    Incident,
    IncidentState,
    ThreatIndicator,
)
from cloud.guardian.sentinel_agent import SentinelAgent
from cloud.guardian.response_agent import ResponseAgent
from cloud.guardian.forensic_agent import ForensicAgent
from cloud.guardian.audit_agent import AuditAgent

logger = logging.getLogger("angelgrid.cloud.guardian.orchestrator")


class AngelOrchestrator:
    """Central guardian orchestrator — the brain of ANGEL AGI."""

    def __init__(self) -> None:
        # Sub-agent registry
        self.sentinel = SentinelAgent()
        self.response = ResponseAgent()
        self.forensic = ForensicAgent()
        self.audit = AuditAgent()

        # Incident tracking
        self._incidents: dict[str, Incident] = {}
        self._pending_approvals: dict[str, Incident] = {}

        # Stats
        self._events_processed: int = 0
        self._indicators_found: int = 0
        self._incidents_created: int = 0
        self._responses_executed: int = 0

        # Background task handle
        self._audit_task: asyncio.Task | None = None
        self._running: bool = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the orchestrator background loops."""
        self._running = True
        self._audit_task = asyncio.create_task(self._audit_loop())
        logger.info(
            "[ORCHESTRATOR] Started — agents: sentinel=%s, response=%s, "
            "forensic=%s, audit=%s",
            self.sentinel.agent_id, self.response.agent_id,
            self.forensic.agent_id, self.audit.agent_id,
        )

    async def stop(self) -> None:
        """Graceful shutdown."""
        self._running = False
        if self._audit_task:
            self._audit_task.cancel()
            try:
                await self._audit_task
            except asyncio.CancelledError:
                pass

        await self.sentinel.shutdown()
        await self.response.shutdown()
        await self.forensic.shutdown()
        await self.audit.shutdown()

        logger.info(
            "[ORCHESTRATOR] Stopped — events=%d, indicators=%d, "
            "incidents=%d, responses=%d",
            self._events_processed, self._indicators_found,
            self._incidents_created, self._responses_executed,
        )

    # ------------------------------------------------------------------
    # Main event processing pipeline
    # ------------------------------------------------------------------

    async def process_events(
        self,
        events: list[EventRow],
        db: Session,
        tenant_id: str = "dev-tenant",
    ) -> list[ThreatIndicator]:
        """Main entry point: analyze events through the full pipeline.

        Called from the event ingestion path (server.py / event_bus.py).

        Pipeline: Events → Sentinel → Indicators → Incidents → Response
        """
        if not events:
            return []

        self._events_processed += len(events)

        # Step 1: Dispatch to Sentinel for detection
        indicators = await self._run_detection(events)
        self._indicators_found += len(indicators)

        if not indicators:
            return []

        # Step 2: Create incidents from indicators
        new_incidents = self._create_incidents(indicators, tenant_id)
        self._incidents_created += len(new_incidents)

        # Step 3: Persist alerts to database
        self._persist_alerts(db, indicators, tenant_id)

        # Step 4: Attempt automatic response for each incident
        for incident in new_incidents:
            await self._handle_incident(incident, db, tenant_id)

        return indicators

    # ------------------------------------------------------------------
    # Detection (Sentinel)
    # ------------------------------------------------------------------

    async def _run_detection(
        self, events: list[EventRow],
    ) -> list[ThreatIndicator]:
        """Send events to the Sentinel for analysis."""
        task = AgentTask(
            correlation_id=str(uuid.uuid4()),
            task_type="detect",
            priority=1,
            payload={
                "events": [
                    {
                        "id": e.id,
                        "tenant_id": e.tenant_id,
                        "agent_id": e.agent_id,
                        "type": e.type,
                        "severity": e.severity,
                        "details": e.details or {},
                        "source": e.source or "",
                        "timestamp": e.timestamp.isoformat() if e.timestamp else "",
                    }
                    for e in events
                ],
                "window_seconds": 300,
            },
        )

        result = await self.sentinel.execute(task)

        if not result.success:
            logger.error("[ORCHESTRATOR] Sentinel failed: %s", result.error)
            return []

        indicator_dicts = result.result_data.get("indicators", [])
        indicators = [ThreatIndicator(**d) for d in indicator_dicts]

        if indicators:
            logger.info(
                "[ORCHESTRATOR] Sentinel found %d indicators from %d events",
                len(indicators), len(events),
            )

        return indicators

    # ------------------------------------------------------------------
    # Incident management
    # ------------------------------------------------------------------

    def _create_incidents(
        self,
        indicators: list[ThreatIndicator],
        tenant_id: str,
    ) -> list[Incident]:
        """Create tracked incidents from threat indicators."""
        incidents: list[Incident] = []

        for ind in indicators:
            # Only create incidents for high/critical
            if ind.severity not in ("high", "critical"):
                continue

            incident = Incident(
                correlation_id=str(uuid.uuid4()),
                state=IncidentState.NEW,
                severity=ind.severity,
                title=ind.description,
                description=(
                    f"Detected by {ind.indicator_type}: {ind.pattern_name}. "
                    f"Confidence: {ind.confidence:.0%}."
                ),
                trigger_indicator_id=ind.indicator_id,
                related_event_ids=ind.related_event_ids,
                related_agent_ids=ind.related_agent_ids,
                playbook_name=ind.suggested_playbook,
                mitre_tactics=[ind.mitre_tactic] if ind.mitre_tactic else [],
            )

            self._incidents[incident.incident_id] = incident
            incidents.append(incident)

            logger.warning(
                "[INCIDENT] %s | %s | severity=%s | playbook=%s | agents=%s",
                incident.incident_id[:8], incident.title[:60],
                incident.severity, incident.playbook_name,
                ",".join(a[:8] for a in incident.related_agent_ids[:3]),
            )

        return incidents

    async def _handle_incident(
        self,
        incident: Incident,
        db: Session,
        tenant_id: str,
    ) -> None:
        """Handle a single incident: triage → respond → investigate."""
        incident.state = IncidentState.TRIAGING
        incident.updated_at = datetime.now(timezone.utc)

        if not incident.playbook_name:
            incident.state = IncidentState.ESCALATED
            logger.info(
                "[ORCHESTRATOR] No playbook for incident %s — escalated",
                incident.incident_id[:8],
            )
            return

        playbook = self.response.get_playbook(incident.playbook_name)
        if not playbook:
            incident.state = IncidentState.ESCALATED
            logger.warning(
                "[ORCHESTRATOR] Playbook %s not found — escalated",
                incident.playbook_name,
            )
            return

        # Check if auto-respond is allowed
        if not playbook.auto_respond:
            incident.requires_approval = True
            incident.state = IncidentState.TRIAGING
            self._pending_approvals[incident.incident_id] = incident
            logger.info(
                "[ORCHESTRATOR] Incident %s awaiting approval for playbook %s",
                incident.incident_id[:8], playbook.name,
            )
            return

        # Execute playbook
        await self._execute_response(incident, db, tenant_id, approved=True)

    async def _execute_response(
        self,
        incident: Incident,
        db: Session,
        tenant_id: str,
        approved: bool = False,
        dry_run: bool = False,
    ) -> bool:
        """Execute the response playbook for an incident."""
        incident.state = IncidentState.RESPONDING
        incident.updated_at = datetime.now(timezone.utc)

        task = AgentTask(
            correlation_id=incident.correlation_id,
            task_type="respond",
            priority=1,
            payload={
                "playbook_name": incident.playbook_name,
                "incident": {
                    "incident_id": incident.incident_id,
                    "agent_id": incident.related_agent_ids[0] if incident.related_agent_ids else "",
                    "severity": incident.severity,
                    "title": incident.title,
                    "tenant_id": tenant_id,
                },
                "dry_run": dry_run,
                "approved": approved,
            },
        )

        result = await self.response.execute(task)
        self._responses_executed += 1

        if result.success:
            incident.state = IncidentState.INVESTIGATING
            incident.updated_at = datetime.now(timezone.utc)
            logger.info(
                "[ORCHESTRATOR] Response executed for incident %s",
                incident.incident_id[:8],
            )

            # Dispatch forensic investigation
            if incident.related_agent_ids:
                await self._investigate(incident, db)
        else:
            incident.state = IncidentState.ESCALATED
            incident.notes.append(f"Response failed: {result.error}")
            logger.error(
                "[ORCHESTRATOR] Response failed for incident %s: %s",
                incident.incident_id[:8], result.error,
            )

        return result.success

    # ------------------------------------------------------------------
    # Forensic investigation
    # ------------------------------------------------------------------

    async def _investigate(
        self, incident: Incident, db: Session,
    ) -> None:
        """Dispatch a forensic investigation for an incident."""
        task = AgentTask(
            correlation_id=incident.correlation_id,
            task_type="investigate",
            priority=3,
            payload={
                "incident_id": incident.incident_id,
                "agent_id": incident.related_agent_ids[0] if incident.related_agent_ids else "",
                "related_event_ids": incident.related_event_ids[:50],
                "lookback_minutes": 60,
                "_db": db,
            },
        )

        result = await self.forensic.execute(task)

        if result.success:
            report = result.result_data.get("report", {})
            incident.notes.append(
                f"Forensic report: {report.get('root_cause', 'unknown')}"
            )
            logger.info(
                "[ORCHESTRATOR] Forensic report for incident %s: %s",
                incident.incident_id[:8],
                report.get("root_cause", "unknown")[:80],
            )

    # ------------------------------------------------------------------
    # Periodic audit loop
    # ------------------------------------------------------------------

    async def _audit_loop(self) -> None:
        """Run self-audit every 30 minutes."""
        while self._running:
            try:
                await asyncio.sleep(1800)  # 30 minutes
                if not self._running:
                    break

                # Audit requires a DB session — we'll get one from the session factory
                try:
                    from cloud.db.session import SessionLocal
                    db = SessionLocal()
                    try:
                        task = AgentTask(
                            correlation_id=str(uuid.uuid4()),
                            task_type="audit",
                            priority=5,
                            payload={"period_minutes": 30, "_db": db},
                        )
                        result = await self.audit.execute(task)
                        if result.success:
                            report = result.result_data.get("report", {})
                            if not report.get("clean", True):
                                logger.warning(
                                    "[ORCHESTRATOR] Audit found discrepancies: %s",
                                    report.get("summary", "")[:120],
                                )
                    finally:
                        db.close()
                except Exception:
                    logger.debug("Audit cycle skipped (DB unavailable)", exc_info=True)

            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("[ORCHESTRATOR] Audit loop error")

    # ------------------------------------------------------------------
    # Approval workflow
    # ------------------------------------------------------------------

    async def approve_incident(
        self,
        incident_id: str,
        approved_by: str,
        db: Session,
        tenant_id: str = "dev-tenant",
    ) -> dict:
        """Operator approves a pending incident response."""
        incident = self._pending_approvals.pop(incident_id, None)
        if not incident:
            incident = self._incidents.get(incident_id)

        if not incident:
            return {"error": f"Incident {incident_id} not found"}

        if incident.state not in (IncidentState.NEW, IncidentState.TRIAGING):
            return {"error": f"Incident {incident_id} is {incident.state.value}, cannot approve"}

        incident.approved_by = approved_by
        incident.requires_approval = False

        success = await self._execute_response(
            incident, db, tenant_id, approved=True,
        )

        return {
            "incident_id": incident_id,
            "approved_by": approved_by,
            "response_executed": success,
            "state": incident.state.value,
        }

    # ------------------------------------------------------------------
    # Alert persistence
    # ------------------------------------------------------------------

    def _persist_alerts(
        self,
        db: Session,
        indicators: list[ThreatIndicator],
        tenant_id: str,
    ) -> None:
        """Save threat indicators as GuardianAlertRow entries."""
        alerts = []
        for ind in indicators:
            if ind.severity not in ("high", "critical"):
                continue
            alert = GuardianAlertRow(
                id=ind.indicator_id,
                tenant_id=tenant_id,
                alert_type=ind.pattern_name or ind.indicator_type,
                title=ind.description[:200],
                severity=ind.severity,
                details={
                    "indicator_type": ind.indicator_type,
                    "confidence": ind.confidence,
                    "suggested_playbook": ind.suggested_playbook,
                    "mitre_tactic": ind.mitre_tactic,
                    **(ind.metadata or {}),
                },
                related_event_ids=ind.related_event_ids[:20],
                related_agent_ids=ind.related_agent_ids[:10],
            )
            alerts.append(alert)

        if alerts:
            db.add_all(alerts)
            try:
                db.commit()
            except Exception:
                db.rollback()
                logger.exception("Failed to persist guardian alerts")

    # ------------------------------------------------------------------
    # Status / info
    # ------------------------------------------------------------------

    def status(self) -> dict:
        """Return orchestrator status for dashboards and APIs."""
        return {
            "running": self._running,
            "stats": {
                "events_processed": self._events_processed,
                "indicators_found": self._indicators_found,
                "incidents_created": self._incidents_created,
                "responses_executed": self._responses_executed,
            },
            "agents": {
                "sentinel": self.sentinel.info(),
                "response": self.response.info(),
                "forensic": self.forensic.info(),
                "audit": self.audit.info(),
            },
            "incidents": {
                "total": len(self._incidents),
                "pending_approval": len(self._pending_approvals),
                "by_state": self._incidents_by_state(),
            },
            "playbooks": self.response.list_playbooks(),
        }

    def _incidents_by_state(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for inc in self._incidents.values():
            counts[inc.state.value] = counts.get(inc.state.value, 0) + 1
        return counts

    def get_incident(self, incident_id: str) -> Incident | None:
        return self._incidents.get(incident_id)

    def list_incidents(
        self, limit: int = 20, state: str | None = None,
    ) -> list[Incident]:
        incidents = sorted(
            self._incidents.values(),
            key=lambda i: i.created_at,
            reverse=True,
        )
        if state:
            incidents = [i for i in incidents if i.state.value == state]
        return incidents[:limit]


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
angel_orchestrator = AngelOrchestrator()
