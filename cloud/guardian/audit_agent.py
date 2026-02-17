"""AngelClaw – Audit Agent.

Verifies that sub-agents behave as expected.  Compares intended actions
(from playbooks and policies) against actual outcomes (DB state changes,
logged events).  Reports discrepancies.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from cloud.db.models import EventRow, GuardianAlertRow
from cloud.guardian.base_agent import SubAgent
from cloud.guardian.models import (
    AgentResult,
    AgentTask,
    AgentType,
    AuditDiscrepancy,
    AuditReport,
    Permission,
)

logger = logging.getLogger("angelgrid.cloud.guardian.audit")


class AuditAgent(SubAgent):
    """Self-audit agent: verifies agent behavior matches expectations."""

    def __init__(self) -> None:
        super().__init__(
            agent_type=AgentType.AUDIT,
            permissions={
                Permission.READ_EVENTS,
                Permission.READ_AGENTS,
                Permission.READ_POLICIES,
                Permission.READ_LOGS,
            },
        )

    async def handle_task(self, task: AgentTask) -> AgentResult:
        """Run an audit cycle.

        Expected payload:
            period_minutes: int (default 60)
            db: Session (injected by orchestrator)
        """
        self.require_permission(Permission.READ_EVENTS)

        period_minutes = task.payload.get("period_minutes", 60)
        db: Session | None = task.payload.get("_db")

        if not db:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type.value,
                success=False,
                error="Database session not provided",
            )

        report = await self._run_audit(db, period_minutes)

        logger.info(
            "[AUDIT] Report %s: audited=%d agents, discrepancies=%d, clean=%s",
            report.report_id[:8],
            report.agents_audited,
            len(report.discrepancies),
            report.clean,
        )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            agent_type=self.agent_type.value,
            result_data={"report": report.model_dump(mode="json")},
        )

    async def _run_audit(
        self,
        db: Session,
        period_minutes: int,
    ) -> AuditReport:
        """Execute all audit checks."""
        now = datetime.now(timezone.utc)
        period_start = now - timedelta(minutes=period_minutes)
        discrepancies: list[AuditDiscrepancy] = []

        # Fetch events in the audit period
        events = (
            db.query(EventRow)
            .filter(EventRow.timestamp >= period_start)
            .order_by(EventRow.timestamp)
            .all()
        )

        agents_seen = {e.agent_id for e in events}

        # Check 1: Events that should have been blocked but weren't
        disc_1 = self._check_policy_enforcement(events)
        discrepancies.extend(disc_1)

        # Check 2: Alerts without corresponding response
        disc_2 = self._check_alert_response(db, period_start)
        discrepancies.extend(disc_2)

        # Check 3: Agent activity after quarantine
        disc_3 = self._check_quarantine_compliance(db, events, period_start)
        discrepancies.extend(disc_3)

        clean = len(discrepancies) == 0
        summary_parts = [
            f"Audit period: {period_minutes}min.",
            f"Events reviewed: {len(events)}.",
            f"Agents seen: {len(agents_seen)}.",
        ]
        if discrepancies:
            summary_parts.append(
                f"Found {len(discrepancies)} discrepancy(ies): "
                + ", ".join(d.description[:40] for d in discrepancies[:3])
            )
        else:
            summary_parts.append("All checks passed — clean audit.")

        return AuditReport(
            period_start=period_start,
            period_end=now,
            agents_audited=len(agents_seen),
            discrepancies=discrepancies,
            clean=clean,
            summary=" ".join(summary_parts),
        )

    # ------------------------------------------------------------------
    # Audit checks
    # ------------------------------------------------------------------

    def _check_policy_enforcement(
        self,
        events: list[EventRow],
    ) -> list[AuditDiscrepancy]:
        """Verify that secret-access events were blocked."""
        discrepancies: list[AuditDiscrepancy] = []

        for e in events:
            details = e.details or {}
            if details.get("accesses_secrets") is True:
                # This event should have been blocked by policy
                action = details.get("action", details.get("decision", ""))
                if action and action.lower() not in ("block", "blocked"):
                    discrepancies.append(
                        AuditDiscrepancy(
                            agent_id=e.agent_id,
                            expected_action="block",
                            actual_action=str(action),
                            event_id=e.id,
                            severity="critical",
                            description=(
                                f"Secret-access event {e.id[:8]} from agent "
                                f"{e.agent_id[:8]} was not blocked (action={action})"
                            ),
                        )
                    )

        return discrepancies

    def _check_alert_response(
        self,
        db: Session,
        period_start: datetime,
    ) -> list[AuditDiscrepancy]:
        """Check that critical alerts received a response."""
        critical_alerts = (
            db.query(GuardianAlertRow)
            .filter(
                GuardianAlertRow.created_at >= period_start,
                GuardianAlertRow.severity.in_(["critical"]),
            )
            .all()
        )

        discrepancies: list[AuditDiscrepancy] = []
        for alert in critical_alerts:
            # Check if there's a corresponding response in the alert details
            responded = (alert.details or {}).get("response_executed", False)
            if not responded:
                agents = alert.related_agent_ids or []
                discrepancies.append(
                    AuditDiscrepancy(
                        agent_id=agents[0] if agents else "system",
                        expected_action="auto_response",
                        actual_action="no_response",
                        event_id=alert.id,
                        severity="high",
                        description=(
                            f"Critical alert {alert.id[:8]} ({alert.alert_type}) "
                            f"has no recorded response"
                        ),
                    )
                )

        return discrepancies

    def _check_quarantine_compliance(
        self,
        db: Session,
        events: list[EventRow],
        period_start: datetime,
    ) -> list[AuditDiscrepancy]:
        """Check that quarantined agents aren't still submitting events."""
        from cloud.db.models import AgentNodeRow

        quarantined = db.query(AgentNodeRow).filter(AgentNodeRow.status == "quarantined").all()
        quarantined_ids = {a.agent_id for a in quarantined}
        if not quarantined_ids:
            return []

        discrepancies: list[AuditDiscrepancy] = []
        for e in events:
            if e.agent_id in quarantined_ids:
                discrepancies.append(
                    AuditDiscrepancy(
                        agent_id=e.agent_id,
                        expected_action="no_events (quarantined)",
                        actual_action=f"submitted event {e.type}",
                        event_id=e.id,
                        severity="high",
                        description=(
                            f"Quarantined agent {e.agent_id[:8]} submitted "
                            f"event {e.id[:8]} ({e.type})"
                        ),
                    )
                )

        return discrepancies
