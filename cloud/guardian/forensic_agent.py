"""AngelClaw – Forensic Agent.

Deep-dives into incidents: reconstructs timelines, collects evidence,
and produces structured ForensicReports for the Orchestrator.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from cloud.db.models import AgentNodeRow, EventRow
from cloud.guardian.base_agent import SubAgent
from cloud.guardian.models import (
    AgentResult,
    AgentTask,
    AgentType,
    ForensicEvidence,
    ForensicReport,
    Permission,
)

logger = logging.getLogger("angelgrid.cloud.guardian.forensic")

# Map event characteristics to kill-chain stages
_KILL_CHAIN_MAP: dict[str, str] = {
    "auth": "initial_access",
    "login": "initial_access",
    "scan": "reconnaissance",
    "shell": "execution",
    "exec": "execution",
    "command": "execution",
    "file": "persistence",
    "write": "persistence",
    "chmod": "privilege_escalation",
    "sudo": "privilege_escalation",
    "secret": "credential_access",
    "token": "credential_access",
    "network": "exfiltration",
    "upload": "exfiltration",
    "delete": "impact",
    "drop": "impact",
    # V2.1 — expanded kill chain mapping
    "enumerate": "reconnaissance",
    "discover": "reconnaissance",
    "exploit": "execution",
    "inject": "execution",
    "crontab": "persistence",
    "registry": "persistence",
    "escalat": "privilege_escalation",
    "setuid": "privilege_escalation",
    "dump": "credential_access",
    "crack": "credential_access",
    "lateral": "lateral_movement",
    "pivot": "lateral_movement",
    "encrypt": "impact",
    "ransom": "impact",
    "exfil": "exfiltration",
    "tunnel": "exfiltration",
}


class ForensicAgent(SubAgent):
    """Investigates incidents and produces forensic reports."""

    def __init__(self) -> None:
        super().__init__(
            agent_type=AgentType.FORENSIC,
            permissions={
                Permission.READ_EVENTS,
                Permission.READ_AGENTS,
                Permission.READ_LOGS,
            },
        )

    async def handle_task(self, task: AgentTask) -> AgentResult:
        """Investigate an incident.

        Expected payload:
            incident_id: str
            agent_id: str  — primary suspect agent
            related_event_ids: list[str]
            lookback_minutes: int (default 60)
            db: Session (injected by orchestrator)
        """
        self.require_permission(Permission.READ_EVENTS)

        incident_id = task.payload.get("incident_id", "")
        agent_id = task.payload.get("agent_id", "")
        related_ids = task.payload.get("related_event_ids", [])
        lookback = task.payload.get("lookback_minutes", 60)
        db: Session | None = task.payload.get("_db")

        if not db:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type.value,
                success=False,
                error="Database session not provided",
            )

        report = await self._investigate(
            db,
            incident_id,
            agent_id,
            related_ids,
            lookback,
        )

        logger.info(
            "[FORENSIC] Report %s for incident %s: %d evidence items, kill_chain=%s, root_cause=%s",
            report.report_id[:8],
            incident_id[:8],
            len(report.timeline),
            report.kill_chain,
            report.root_cause[:50] if report.root_cause else "unknown",
        )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            agent_type=self.agent_type.value,
            result_data={"report": report.model_dump(mode="json")},
        )

    async def _investigate(
        self,
        db: Session,
        incident_id: str,
        agent_id: str,
        related_ids: list[str],
        lookback_minutes: int,
    ) -> ForensicReport:
        """Build a forensic report by querying the database."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=lookback_minutes)
        evidence: list[ForensicEvidence] = []
        kill_chain: list[str] = []

        # 1. Gather directly related events
        if related_ids:
            related_events = (
                db.query(EventRow)
                .filter(EventRow.id.in_(related_ids))
                .order_by(EventRow.timestamp)
                .all()
            )
            for e in related_events:
                evidence.append(
                    ForensicEvidence(
                        evidence_type="event",
                        timestamp=e.timestamp,
                        data={
                            "event_id": e.id,
                            "type": e.type,
                            "severity": e.severity,
                            "agent_id": e.agent_id,
                            "details": _safe_details(e.details),
                        },
                        source="related_events",
                    )
                )

        # 2. Gather agent's full history in the lookback window
        if agent_id:
            agent_history = (
                db.query(EventRow)
                .filter(
                    EventRow.agent_id == agent_id,
                    EventRow.timestamp >= cutoff,
                )
                .order_by(EventRow.timestamp)
                .limit(200)
                .all()
            )
            for e in agent_history:
                if e.id not in related_ids:
                    evidence.append(
                        ForensicEvidence(
                            evidence_type="event",
                            timestamp=e.timestamp,
                            data={
                                "event_id": e.id,
                                "type": e.type,
                                "severity": e.severity,
                                "details": _safe_details(e.details),
                            },
                            source="agent_history",
                        )
                    )

            # 3. Agent registration info
            agent_row = db.query(AgentNodeRow).filter(AgentNodeRow.agent_id == agent_id).first()
            if agent_row:
                evidence.append(
                    ForensicEvidence(
                        evidence_type="state_snapshot",
                        timestamp=agent_row.last_seen_at or now,
                        data={
                            "agent_id": agent_row.agent_id,
                            "hostname": agent_row.hostname,
                            "status": agent_row.status,
                            "version": agent_row.version,
                            "registered_at": str(agent_row.registered_at),
                        },
                        source="agent_registry",
                    )
                )

        # Sort evidence chronologically
        evidence.sort(key=lambda e: e.timestamp)

        # 4. Build kill chain from evidence
        for ev in evidence:
            if ev.evidence_type == "event":
                event_type = (ev.data.get("type") or "").lower()
                for hint, stage in _KILL_CHAIN_MAP.items():
                    if hint in event_type:
                        if not kill_chain or kill_chain[-1] != stage:
                            kill_chain.append(stage)
                        break

        # 5. Determine root cause
        root_cause = self._determine_root_cause(evidence, kill_chain)

        # 6. Generate recommendations
        recommendations = self._generate_recommendations(kill_chain, evidence)

        # 7. Impact assessment
        sev_counts: dict[str, int] = {}
        for ev in evidence:
            if ev.evidence_type == "event":
                sev = ev.data.get("severity", "low")
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

        # V2.1 — IOC extraction and evidence scoring
        iocs = self._extract_iocs(evidence)
        evidence_score = self._score_evidence(evidence)

        impact = (
            f"{len(evidence)} evidence items collected. "
            f"Severity breakdown: {sev_counts}. "
            f"Kill chain depth: {len(kill_chain)} stages. "
            f"Evidence severity score: {evidence_score:.2f}. "
            f"IOCs extracted: {sum(len(v) for v in iocs.values())}."
        )

        return ForensicReport(
            incident_id=incident_id,
            agent_id=agent_id,
            timeline=evidence,
            kill_chain=kill_chain,
            root_cause=root_cause,
            impact_assessment=impact,
            recommendations=recommendations,
        )

    @staticmethod
    def _determine_root_cause(
        evidence: list[ForensicEvidence],
        kill_chain: list[str],
    ) -> str:
        """Infer a root cause from the evidence and kill chain."""
        if not evidence:
            return "Insufficient evidence to determine root cause."

        first_event = next(
            (e for e in evidence if e.evidence_type == "event"),
            None,
        )
        if not first_event:
            return "No event evidence found."

        event_type = first_event.data.get("type", "unknown")
        severity = first_event.data.get("severity", "unknown")

        if "secret" in (event_type or "").lower():
            return f"Initial trigger: secret access attempt ({event_type}, severity={severity})"
        if "auth" in (event_type or "").lower():
            return f"Initial trigger: authentication anomaly ({event_type}, severity={severity})"
        if kill_chain:
            return f"Attack chain starting with {kill_chain[0]} ({event_type}, severity={severity})"

        return f"First anomalous event: {event_type} (severity={severity})"

    @staticmethod
    def _generate_recommendations(
        kill_chain: list[str],
        evidence: list[ForensicEvidence],
    ) -> list[str]:
        """Generate actionable recommendations based on findings."""
        recs: list[str] = []

        if "credential_access" in kill_chain:
            recs.append("Rotate all secrets and API keys accessed by the suspect agent.")
        if "exfiltration" in kill_chain:
            recs.append("Audit outbound network connections and review data transfer logs.")
        if "privilege_escalation" in kill_chain:
            recs.append("Review and tighten permission policies for affected agents.")
        if "persistence" in kill_chain:
            recs.append("Scan for unauthorized file modifications and backdoors.")
        # V2.1 — expanded recommendations
        if "lateral_movement" in kill_chain:
            recs.append("Isolate affected agents and scan peer nodes for compromise indicators.")
        if "reconnaissance" in kill_chain:
            recs.append("Review agent permissions — restrict information gathering capabilities.")
        if "impact" in kill_chain:
            recs.append("Initiate disaster recovery procedures and verify backup integrity.")

        secret_events = [
            e
            for e in evidence
            if e.evidence_type == "event" and "secret" in (e.data.get("type") or "").lower()
        ]
        if secret_events:
            recs.append(
                f"Review {len(secret_events)} secret access event(s) and "
                "verify no credentials were leaked."
            )

        if not recs:
            recs.append("Continue monitoring the affected agent for further anomalies.")

        return recs

    # ------------------------------------------------------------------
    # V2.1 — IOC extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_iocs(evidence: list[ForensicEvidence]) -> dict:
        """Extract Indicators of Compromise from evidence.

        Returns a dict of IOC categories → list of values.
        """
        import re

        iocs: dict[str, set[str]] = {
            "ip_addresses": set(),
            "domains": set(),
            "file_hashes": set(),
            "file_paths": set(),
            "commands": set(),
            "user_agents": set(),
        }

        ip_re = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
        hash_re = re.compile(r"\b[0-9a-f]{32,64}\b")
        domain_re = re.compile(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b")

        for ev in evidence:
            if ev.evidence_type != "event":
                continue
            details = ev.data.get("details", {})
            if isinstance(details, dict):
                # Extract IPs
                for key in ("source_ip", "dst_ip", "ip", "remote_addr"):
                    val = details.get(key, "")
                    if val and ip_re.match(str(val)):
                        iocs["ip_addresses"].add(str(val))

                # Extract domains
                for key in ("domain", "dns_query", "hostname", "url"):
                    val = str(details.get(key, ""))
                    for match in domain_re.findall(val):
                        iocs["domains"].add(match)

                # Extract file paths
                for key in ("path", "file_path", "target_path"):
                    val = details.get(key, "")
                    if val:
                        iocs["file_paths"].add(str(val))

                # Extract commands
                cmd = details.get("command", "")
                if cmd:
                    iocs["commands"].add(str(cmd)[:200])

                # Extract hashes
                for key in ("hash", "sha256", "md5", "sha1"):
                    val = details.get(key, "")
                    if val and hash_re.match(str(val)):
                        iocs["file_hashes"].add(str(val))

        return {k: sorted(v)[:50] for k, v in iocs.items() if v}

    # ------------------------------------------------------------------
    # V2.1 — Evidence scoring
    # ------------------------------------------------------------------

    @staticmethod
    def _score_evidence(evidence: list[ForensicEvidence]) -> float:
        """Score the overall severity of collected evidence (0.0 - 1.0)."""
        if not evidence:
            return 0.0

        sev_weights = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.1, "info": 0.0}
        total_weight = 0.0
        count = 0

        for ev in evidence:
            if ev.evidence_type == "event":
                sev = ev.data.get("severity", "low")
                total_weight += sev_weights.get(sev, 0.0)
                count += 1

        if count == 0:
            return 0.0

        # Base score from severity
        avg_sev = total_weight / count
        # Volume bonus (more evidence = more concerning)
        volume_bonus = min(0.2, count * 0.01)

        return round(min(1.0, avg_sev + volume_bonus), 3)


def _safe_details(details: dict | None) -> dict:
    """Redact sensitive fields from event details."""
    if not details:
        return {}
    from shared.security.secret_scanner import redact_dict

    return redact_dict(details)
