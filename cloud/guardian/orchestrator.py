"""AngelClaw – Seraph AGI Orchestrator (V2.0).

The central brain of the Angel Legion.  Receives events, dispatches
them to ALL wardens in parallel (fan-out), manages incident lifecycle,
and coordinates autonomous behavior.

V2 upgrades:
  - Dynamic AgentRegistry replaces hard-coded agent attributes
  - Multi-warden fan-out via asyncio.gather
  - Autonomy modes: observe / suggest / auto_apply
  - Halo Sweep, Wing Scan, Pulse Check scan types
  - Circuit breaker for failing wardens
  - Backward-compatible .warden/.response/.forensic/.audit properties

Runs as a singleton background service inside the Cloud process.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from cloud.db.models import EventRow, GuardianAlertRow
from cloud.guardian.api_warden import ApiWarden
from cloud.guardian.audit_agent import AuditAgent
from cloud.guardian.base_agent import SubAgent
from cloud.guardian.behavior_warden import BehaviorWarden
from cloud.guardian.browser_warden import BrowserWarden
from cloud.guardian.compliance_warden import ComplianceWarden
from cloud.guardian.forensic_agent import ForensicAgent
from cloud.guardian.models import (
    AgentTask,
    AgentType,
    Incident,
    IncidentState,
    ThreatIndicator,
)
from cloud.guardian.network_warden import NetworkWarden
from cloud.guardian.registry import AgentRegistry
from cloud.guardian.response_agent import ResponseAgent
from cloud.guardian.secrets_warden import SecretsWarden
from cloud.guardian.timeline_warden import TimelineWarden
from cloud.guardian.toolchain_warden import ToolchainWarden
from cloud.guardian.warden_agent import WardenAgent

logger = logging.getLogger("angelgrid.cloud.guardian.orchestrator")

# Circuit breaker: skip a warden after this many consecutive failures
_CIRCUIT_BREAKER_THRESHOLD = 3


class AngelOrchestrator:
    """Seraph — the central guardian orchestrator of the Angel Legion."""

    def __init__(self) -> None:
        # Dynamic agent registry
        self.registry = AgentRegistry()

        # Create and register V1 core agents
        self._warden = WardenAgent()
        self._response = ResponseAgent()
        self._forensic = ForensicAgent()
        self._audit = AuditAgent()
        for agent in [self._warden, self._response, self._forensic, self._audit]:
            self.registry.register(agent)

        # Create and register V2 Angel Legion wardens
        self._network = NetworkWarden()
        self._secrets = SecretsWarden()
        self._toolchain = ToolchainWarden()
        self._behavior = BehaviorWarden()
        self._timeline = TimelineWarden()
        self._browser = BrowserWarden()
        for agent in [
            self._network, self._secrets, self._toolchain,
            self._behavior, self._timeline, self._browser,
        ]:
            self.registry.register(agent)

        # V2.4 — Fortress wardens
        self._compliance = ComplianceWarden()
        self._api_security = ApiWarden()
        for agent in [self._compliance, self._api_security]:
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
        self._warden_failures: dict[str, int] = {}

        # V2.2 — Per-warden performance metrics
        self._warden_latency: dict[str, list[float]] = {}   # agent_id -> recent latencies (ms)
        self._warden_indicator_counts: dict[str, int] = {}  # agent_id -> total indicators found
        self._total_detection_ms: float = 0.0

    # ------------------------------------------------------------------
    # Backward-compatible properties
    # ------------------------------------------------------------------

    @property
    def warden(self) -> WardenAgent:
        return self._warden

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
            "[SERAPH] Started — Angel Legion: %d agents (%d wardens), mode=%s",
            self.registry.count,
            len(self.registry.all_wardens()),
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

        Pipeline: Events → All Wardens (fan-out) → Indicators → Incidents → Response
        """
        if not events:
            return []

        self._events_processed += len(events)

        # Step 1: Fan-out to ALL wardens for detection
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
    # Detection — Multi-Warden Fan-Out
    # ------------------------------------------------------------------

    async def _run_detection(
        self,
        events: list[EventRow],
    ) -> list[ThreatIndicator]:
        """Fan out events to ALL wardens, aggregate and deduplicate indicators."""
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

        wardens = self.registry.all_wardens()

        # Filter out circuit-broken wardens
        active_wardens = [
            s for s in wardens
            if self._warden_failures.get(s.agent_id, 0) < _CIRCUIT_BREAKER_THRESHOLD
        ]

        if not active_wardens:
            logger.warning("[SERAPH] All wardens circuit-broken! Resetting.")
            self._warden_failures.clear()
            active_wardens = wardens

        # Create tasks for all active wardens
        coroutines = []
        for warden in active_wardens:
            task = AgentTask(
                correlation_id=str(uuid.uuid4()),
                task_type="detect",
                priority=1,
                payload={"events": serialized, "window_seconds": 300},
            )
            coroutines.append(warden.execute(task))

        # Fan-out: run all wardens in parallel (with timing)
        import time as _time
        _t0 = _time.monotonic()
        results = await asyncio.gather(*coroutines, return_exceptions=True)
        _elapsed_ms = (_time.monotonic() - _t0) * 1000
        self._total_detection_ms += _elapsed_ms

        # Aggregate indicators from all wardens
        all_indicators: list[ThreatIndicator] = []
        for warden, result in zip(active_wardens, results, strict=False):
            if isinstance(result, Exception):
                self._warden_failures[warden.agent_id] = (
                    self._warden_failures.get(warden.agent_id, 0) + 1
                )
                logger.error(
                    "[SERAPH] %s (%s) raised exception: %s",
                    warden.agent_id, warden.agent_type.value, result,
                )
                continue

            if not result.success:
                self._warden_failures[warden.agent_id] = (
                    self._warden_failures.get(warden.agent_id, 0) + 1
                )
                logger.error(
                    "[SERAPH] %s (%s) failed: %s",
                    warden.agent_id, warden.agent_type.value, result.error,
                )
                continue

            # Success — reset circuit breaker and track metrics
            self._warden_failures.pop(warden.agent_id, None)
            latency = result.duration_ms if hasattr(result, 'duration_ms') else 0.0
            if warden.agent_id not in self._warden_latency:
                self._warden_latency[warden.agent_id] = []
            self._warden_latency[warden.agent_id].append(latency)
            # Keep only last 50 latency samples
            if len(self._warden_latency[warden.agent_id]) > 50:
                self._warden_latency[warden.agent_id] = self._warden_latency[warden.agent_id][-50:]

            indicator_dicts = result.result_data.get("indicators", [])
            warden_ind_count = 0
            for d in indicator_dicts:
                try:
                    all_indicators.append(ThreatIndicator(**d))
                    warden_ind_count += 1
                except Exception:
                    logger.debug("Failed to parse indicator from %s", warden.agent_id)

            # V2.2 — Track per-warden indicator counts
            self._warden_indicator_counts[warden.agent_id] = (
                self._warden_indicator_counts.get(warden.agent_id, 0) + warden_ind_count
            )

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
                "[SERAPH] %d wardens → %d raw indicators → %d unique (from %d events)",
                len(active_wardens),
                len(all_indicators),
                len(unique),
                len(events),
            )

        return unique

    # ------------------------------------------------------------------
    # Scan types (Halo Sweep, Wing Scan, Pulse Check)
    # ------------------------------------------------------------------

    async def halo_sweep(self, db: Session, tenant_id: str = "dev-tenant") -> dict:
        """Halo Sweep — full system scan. All wardens fire."""
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
            "wardens_active": len(self.registry.all_wardens()),
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
        """Wing Scan — targeted scan for a single warden domain."""
        domain_map: dict[str, AgentType] = {
            "network": AgentType.NETWORK,
            "secrets": AgentType.SECRETS,
            "toolchain": AgentType.TOOLCHAIN,
            "behavior": AgentType.BEHAVIOR,
            "timeline": AgentType.TIMELINE,
            "browser": AgentType.BROWSER,
            "warden": AgentType.WARDEN,
            # V2.4 — Fortress wardens
            "compliance": AgentType.COMPLIANCE,
            "api": AgentType.API_SECURITY,
        }

        agent_type = domain_map.get(domain.lower())
        if not agent_type:
            return {"error": f"Unknown domain: {domain}. Valid: {list(domain_map.keys())}"}

        warden = self.registry.get_first(agent_type)
        if not warden:
            return {"error": f"No warden for domain: {domain}"}

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

        result = await warden.execute(task)
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
            "warden": warden.info(),
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
            "circuit_breakers": dict(self._warden_failures),
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
    # V2.2 — Containment workflow
    # ------------------------------------------------------------------

    async def contain_incident(
        self,
        incident_id: str,
        contained_by: str,
        db: Session,
        tenant_id: str = "dev-tenant",
    ) -> dict:
        """Mark an incident as contained — threat is controlled but not resolved."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return {"error": f"Incident {incident_id} not found"}

        if incident.state in (IncidentState.RESOLVED, IncidentState.CONTAINED):
            return {"error": f"Incident {incident_id} is already {incident.state.value}"}

        incident.state = IncidentState.CONTAINED
        incident.updated_at = datetime.now(timezone.utc)
        incident.notes.append(f"Contained by {contained_by}")

        logger.info(
            "[SERAPH] Incident %s contained by %s",
            incident.incident_id[:8],
            contained_by,
        )

        return {
            "incident_id": incident_id,
            "contained_by": contained_by,
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
        # V2.2 — compute per-warden performance metrics
        warden_perf = {}
        for wid, latencies in self._warden_latency.items():
            if latencies:
                warden_perf[wid] = {
                    "avg_latency_ms": round(sum(latencies) / len(latencies), 1),
                    "max_latency_ms": round(max(latencies), 1),
                    "samples": len(latencies),
                    "indicators_found": self._warden_indicator_counts.get(wid, 0),
                }

        return {
            "running": self._running,
            "autonomy_mode": self._autonomy_mode,
            "stats": {
                "events_processed": self._events_processed,
                "indicators_found": self._indicators_found,
                "incidents_created": self._incidents_created,
                "responses_executed": self._responses_executed,
                "total_detection_ms": round(self._total_detection_ms, 1),
            },
            "legion": self.registry.summary(),
            "agents": self.registry.info_all(),
            "warden_performance": warden_perf,
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


    # ------------------------------------------------------------------
    # V2.5 — Plugin warden registration
    # ------------------------------------------------------------------

    def register_external_warden(self, agent: SubAgent) -> dict:
        """Register an external warden (plugin) into the Legion."""
        self.registry.register(agent)
        logger.info(
            "[SERAPH] External warden registered: %s (%s)",
            agent.agent_id,
            agent.agent_type.value,
        )
        return {"agent_id": agent.agent_id, "agent_type": agent.agent_type.value}

    def deregister_external_warden(self, agent_id: str) -> bool:
        """Remove an external warden from the Legion."""
        result = self.registry.deregister(agent_id)
        if result:
            logger.info("[SERAPH] External warden deregistered: %s", agent_id)
        return result


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
angel_orchestrator = AngelOrchestrator()
