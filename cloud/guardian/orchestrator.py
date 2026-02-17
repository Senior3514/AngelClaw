"""AngelClaw – Seraph AGI Orchestrator (V2.0).

The central brain of the Angel Legion.  Receives events, dispatches
them to ALL sentinels in parallel (fan-out), manages incident lifecycle,
and coordinates autonomous behavior.

V2 upgrades:
  - Dynamic AgentRegistry replaces hard-coded agent attributes
  - Multi-sentinel fan-out via asyncio.gather
  - Autonomy modes: observe / suggest / auto_apply
  - Halo Sweep, Wing Scan, Pulse Check scan types
  - Circuit breaker for failing sentinels
  - Backward-compatible .sentinel/.response/.forensic/.audit properties

Runs as a singleton background service inside the Cloud process.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from cloud.db.models import EventRow, GuardianAlertRow
from cloud.guardian.audit_agent import AuditAgent
from cloud.guardian.behavior_sentinel import BehaviorSentinel
from cloud.guardian.browser_sentinel import BrowserSentinel
from cloud.guardian.forensic_agent import ForensicAgent
from cloud.guardian.models import (
    AgentTask,
    AgentType,
    Incident,
    IncidentState,
    ThreatIndicator,
)
from cloud.guardian.network_sentinel import NetworkSentinel
from cloud.guardian.registry import AgentRegistry
from cloud.guardian.response_agent import ResponseAgent
from cloud.guardian.secrets_sentinel import SecretsSentinel
from cloud.guardian.sentinel_agent import SentinelAgent
from cloud.guardian.timeline_sentinel import TimelineSentinel
from cloud.guardian.toolchain_sentinel import ToolchainSentinel

logger = logging.getLogger("angelgrid.cloud.guardian.orchestrator")

# Circuit breaker: skip a sentinel after this many consecutive failures
_CIRCUIT_BREAKER_THRESHOLD = 3


class AngelOrchestrator:
    """Seraph — the central guardian orchestrator of the Angel Legion."""

    def __init__(self) -> None:
        # Dynamic agent registry
        self.registry = AgentRegistry()

        # Create and register V1 core agents
        self._sentinel = SentinelAgent()
        self._response = ResponseAgent()
        self._forensic = ForensicAgent()
        self._audit = AuditAgent()
        for agent in [self._sentinel, self._response, self._forensic, self._audit]:
            self.registry.register(agent)

        # Create and register V2 Angel Legion sentinels
        self._network = NetworkSentinel()
        self._secrets = SecretsSentinel()
        self._toolchain = ToolchainSentinel()
        self._behavior = BehaviorSentinel()
        self._timeline = TimelineSentinel()
        self._browser = BrowserSentinel()
        for agent in [
            self._network, self._secrets, self._toolchain,
            self._behavior, self._timeline, self._browser,
        ]:
            self.registry.register(agent)

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

        # Autonomy mode: observe | suggest | auto_apply
        self._autonomy_mode: str = "suggest"

        # Circuit breaker state: agent_id -> consecutive failures
        self._sentinel_failures: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Backward-compatible properties
    # ------------------------------------------------------------------

    @property
    def sentinel(self) -> SentinelAgent:
        return self._sentinel

    @property
    def response(self) -> ResponseAgent:
        return self._response

    @property
    def forensic(self) -> ForensicAgent:
        return self._forensic

    @property
    def audit(self) -> AuditAgent:
        return self._audit

    # ------------------------------------------------------------------
    # Autonomy mode
    # ------------------------------------------------------------------

    @property
    def autonomy_mode(self) -> str:
        return self._autonomy_mode

    def set_autonomy_mode(self, mode: str) -> str:
        """Set autonomy mode. Returns the new mode."""
        valid = {"observe", "suggest", "auto_apply"}
        if mode not in valid:
            raise ValueError(f"Invalid autonomy mode: {mode!r}. Must be one of {valid}")
        old = self._autonomy_mode
        self._autonomy_mode = mode
        logger.info("[SERAPH] Autonomy mode changed: %s → %s", old, mode)
        return mode

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the orchestrator background loops."""
        self._running = True
        self._audit_task = asyncio.create_task(self._audit_loop())
        logger.info(
            "[SERAPH] Started — Angel Legion: %d agents (%d sentinels), mode=%s",
            self.registry.count,
            len(self.registry.all_sentinels()),
            self._autonomy_mode,
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

        await self.registry.shutdown_all()

        logger.info(
            "[SERAPH] Stopped — events=%d, indicators=%d, incidents=%d, responses=%d",
            self._events_processed,
            self._indicators_found,
            self._incidents_created,
            self._responses_executed,
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

        Pipeline: Events → All Sentinels (fan-out) → Indicators → Incidents → Response
        """
        if not events:
            return []

        self._events_processed += len(events)

        # Step 1: Fan-out to ALL sentinels for detection
        indicators = await self._run_detection(events)
        self._indicators_found += len(indicators)

        if not indicators:
            return []

        # In observe mode, stop here — log only
        if self._autonomy_mode == "observe":
            logger.info(
                "[SERAPH] Observe mode — %d indicators logged, no action taken",
                len(indicators),
            )
            return indicators

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
    # Detection — Multi-Sentinel Fan-Out
    # ------------------------------------------------------------------

    async def _run_detection(
        self,
        events: list[EventRow],
    ) -> list[ThreatIndicator]:
        """Fan out events to ALL sentinels, aggregate and deduplicate indicators."""
        serialized = [
            {
                "id": e.id,
                "tenant_id": getattr(e, "tenant_id", "dev-tenant"),
                "agent_id": e.agent_id,
                "type": e.type,
                "severity": e.severity,
                "details": e.details or {},
                "source": e.source or "",
                "timestamp": e.timestamp.isoformat() if e.timestamp else "",
            }
            for e in events
        ]

        sentinels = self.registry.all_sentinels()

        # Filter out circuit-broken sentinels
        active_sentinels = [
            s for s in sentinels
            if self._sentinel_failures.get(s.agent_id, 0) < _CIRCUIT_BREAKER_THRESHOLD
        ]

        if not active_sentinels:
            logger.warning("[SERAPH] All sentinels circuit-broken! Resetting.")
            self._sentinel_failures.clear()
            active_sentinels = sentinels

        # Create tasks for all active sentinels
        coroutines = []
        for sentinel in active_sentinels:
            task = AgentTask(
                correlation_id=str(uuid.uuid4()),
                task_type="detect",
                priority=1,
                payload={"events": serialized, "window_seconds": 300},
            )
            coroutines.append(sentinel.execute(task))

        # Fan-out: run all sentinels in parallel
        results = await asyncio.gather(*coroutines, return_exceptions=True)

        # Aggregate indicators from all sentinels
        all_indicators: list[ThreatIndicator] = []
        for sentinel, result in zip(active_sentinels, results):
            if isinstance(result, Exception):
                self._sentinel_failures[sentinel.agent_id] = (
                    self._sentinel_failures.get(sentinel.agent_id, 0) + 1
                )
                logger.error(
                    "[SERAPH] %s (%s) raised exception: %s",
                    sentinel.agent_id, sentinel.agent_type.value, result,
                )
                continue

            if not result.success:
                self._sentinel_failures[sentinel.agent_id] = (
                    self._sentinel_failures.get(sentinel.agent_id, 0) + 1
                )
                logger.error(
                    "[SERAPH] %s (%s) failed: %s",
                    sentinel.agent_id, sentinel.agent_type.value, result.error,
                )
                continue

            # Success — reset circuit breaker
            self._sentinel_failures.pop(sentinel.agent_id, None)

            indicator_dicts = result.result_data.get("indicators", [])
            for d in indicator_dicts:
                try:
                    all_indicators.append(ThreatIndicator(**d))
                except Exception:
                    logger.debug("Failed to parse indicator from %s", sentinel.agent_id)

        # Deduplicate by pattern_name + agent combo
        seen: set[tuple] = set()
        unique: list[ThreatIndicator] = []
        for ind in all_indicators:
            key = (ind.pattern_name, tuple(sorted(ind.related_agent_ids)))
            if key not in seen:
                seen.add(key)
                unique.append(ind)

        if unique:
            logger.info(
                "[SERAPH] %d sentinels → %d raw indicators → %d unique (from %d events)",
                len(active_sentinels),
                len(all_indicators),
                len(unique),
                len(events),
            )

        return unique

    # ------------------------------------------------------------------
    # Scan types (Halo Sweep, Wing Scan, Pulse Check)
    # ------------------------------------------------------------------

    async def halo_sweep(self, db: Session, tenant_id: str = "dev-tenant") -> dict:
        """Halo Sweep — full system scan. All sentinels fire."""
        # Gather recent events from DB for scanning
        recent_events = (
            db.query(EventRow)
            .order_by(EventRow.timestamp.desc())
            .limit(500)
            .all()
        )

        indicators = await self._run_detection(recent_events)

        return {
            "scan_type": "halo_sweep",
            "events_scanned": len(recent_events),
            "sentinels_active": len(self.registry.all_sentinels()),
            "indicators_found": len(indicators),
            "indicators": [ind.model_dump(mode="json") for ind in indicators[:50]],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def wing_scan(
        self,
        db: Session,
        domain: str,
        tenant_id: str = "dev-tenant",
    ) -> dict:
        """Wing Scan — targeted scan for a single sentinel domain."""
        domain_map: dict[str, AgentType] = {
            "network": AgentType.NETWORK,
            "secrets": AgentType.SECRETS,
            "toolchain": AgentType.TOOLCHAIN,
            "behavior": AgentType.BEHAVIOR,
            "timeline": AgentType.TIMELINE,
            "browser": AgentType.BROWSER,
            "sentinel": AgentType.SENTINEL,
        }

        agent_type = domain_map.get(domain.lower())
        if not agent_type:
            return {"error": f"Unknown domain: {domain}. Valid: {list(domain_map.keys())}"}

        sentinel = self.registry.get_first(agent_type)
        if not sentinel:
            return {"error": f"No sentinel for domain: {domain}"}

        recent_events = (
            db.query(EventRow)
            .order_by(EventRow.timestamp.desc())
            .limit(200)
            .all()
        )

        serialized = [
            {
                "id": e.id,
                "tenant_id": getattr(e, "tenant_id", "dev-tenant"),
                "agent_id": e.agent_id,
                "type": e.type,
                "severity": e.severity,
                "details": e.details or {},
                "source": e.source or "",
                "timestamp": e.timestamp.isoformat() if e.timestamp else "",
            }
            for e in recent_events
        ]

        task = AgentTask(
            correlation_id=str(uuid.uuid4()),
            task_type="detect",
            priority=1,
            payload={"events": serialized, "window_seconds": 300},
        )

        result = await sentinel.execute(task)
        indicators = []
        if result.success:
            for d in result.result_data.get("indicators", []):
                try:
                    indicators.append(ThreatIndicator(**d))
                except Exception:
                    pass

        return {
            "scan_type": "wing_scan",
            "domain": domain,
            "sentinel": sentinel.info(),
            "events_scanned": len(recent_events),
            "indicators_found": len(indicators),
            "indicators": [ind.model_dump(mode="json") for ind in indicators[:30]],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def pulse_check(self) -> dict:
        """Pulse Check — quick health of all agents."""
        agents = self.registry.all_agents()
        healthy = [a for a in agents if a.status.value in ("idle", "busy")]
        degraded = [a for a in agents if a.status.value == "error"]
        offline = [a for a in agents if a.status.value == "stopped"]

        return {
            "scan_type": "pulse_check",
            "total_agents": len(agents),
            "healthy": len(healthy),
            "degraded": len(degraded),
            "offline": len(offline),
            "agents": [a.info() for a in agents],
            "circuit_breakers": dict(self._sentinel_failures),
            "autonomy_mode": self._autonomy_mode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

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
                incident.incident_id[:8],
                incident.title[:60],
                incident.severity,
                incident.playbook_name,
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

        # No playbook → escalate regardless of mode
        if not incident.playbook_name:
            incident.state = IncidentState.ESCALATED
            logger.info(
                "[SERAPH] No playbook for incident %s — escalated",
                incident.incident_id[:8],
            )
            return

        playbook = self.response.get_playbook(incident.playbook_name)
        if not playbook:
            incident.state = IncidentState.ESCALATED
            logger.warning(
                "[SERAPH] Playbook %s not found — escalated",
                incident.playbook_name,
            )
            return

        # In suggest mode, always require approval (even if playbook is auto_respond)
        if self._autonomy_mode == "suggest":
            incident.requires_approval = True
            self._pending_approvals[incident.incident_id] = incident
            logger.info(
                "[SERAPH] Suggest mode — incident %s proposed for approval",
                incident.incident_id[:8],
            )
            return

        # auto_apply mode — check if auto-respond is allowed
        if not playbook.auto_respond:
            incident.requires_approval = True
            incident.state = IncidentState.TRIAGING
            self._pending_approvals[incident.incident_id] = incident
            logger.info(
                "[SERAPH] Incident %s awaiting approval for playbook %s",
                incident.incident_id[:8],
                playbook.name,
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
                "[SERAPH] Response executed for incident %s",
                incident.incident_id[:8],
            )

            # Dispatch forensic investigation
            if incident.related_agent_ids:
                await self._investigate(incident, db)
        else:
            incident.state = IncidentState.ESCALATED
            incident.notes.append(f"Response failed: {result.error}")
            logger.error(
                "[SERAPH] Response failed for incident %s: %s",
                incident.incident_id[:8],
                result.error,
            )

        return result.success

    # ------------------------------------------------------------------
    # Forensic investigation
    # ------------------------------------------------------------------

    async def _investigate(
        self,
        incident: Incident,
        db: Session,
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
            incident.notes.append(f"Forensic report: {report.get('root_cause', 'unknown')}")
            logger.info(
                "[SERAPH] Forensic report for incident %s: %s",
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
                                    "[SERAPH] Audit found discrepancies: %s",
                                    report.get("summary", "")[:120],
                                )
                    finally:
                        db.close()
                except Exception:
                    logger.debug("Audit cycle skipped (DB unavailable)", exc_info=True)

            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("[SERAPH] Audit loop error")

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
            incident,
            db,
            tenant_id,
            approved=True,
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
            "autonomy_mode": self._autonomy_mode,
            "stats": {
                "events_processed": self._events_processed,
                "indicators_found": self._indicators_found,
                "incidents_created": self._incidents_created,
                "responses_executed": self._responses_executed,
            },
            "legion": self.registry.summary(),
            "agents": self.registry.info_all(),
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
        self,
        limit: int = 20,
        state: str | None = None,
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
