"""Tests for incident lifecycle, model validation, and orchestrator incident management."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cloud.guardian.models import (
    AgentResult,
    AgentTask,
    AuditDiscrepancy,
    AuditReport,
    CorrelationChain,
    ForensicEvidence,
    ForensicReport,
    Incident,
    IncidentState,
    Playbook,
    PlaybookStep,
    ResponseResult,
    ThreatIndicator,
)
from cloud.guardian.orchestrator import AngelOrchestrator

# ---------------------------------------------------------------------------
# Incident model
# ---------------------------------------------------------------------------


class TestIncidentModel:
    def test_default_state(self):
        """New incident defaults to NEW state."""
        inc = Incident(title="Test incident")
        assert inc.state == IncidentState.NEW
        assert inc.incident_id
        assert inc.correlation_id
        assert inc.created_at is not None

    def test_state_values(self):
        """All incident states are valid."""
        for state in IncidentState:
            inc = Incident(state=state, title=f"State: {state.value}")
            assert inc.state == state

    def test_incident_with_full_data(self):
        """Incident can be created with all fields."""
        inc = Incident(
            state=IncidentState.RESPONDING,
            severity="critical",
            title="Critical: secret exfiltration",
            description="Multiple secret accesses detected",
            related_event_ids=["e1", "e2", "e3"],
            related_agent_ids=["agent-1"],
            playbook_name="quarantine_agent",
            mitre_tactics=["exfiltration", "credential_access"],
            requires_approval=True,
        )
        assert inc.severity == "critical"
        assert len(inc.related_event_ids) == 3
        assert inc.requires_approval is True

    def test_incident_serialization(self):
        """Incident serializes to JSON without errors."""
        inc = Incident(title="Serialization test", severity="high")
        data = inc.model_dump(mode="json")
        assert data["title"] == "Serialization test"
        assert data["state"] == "new"


# ---------------------------------------------------------------------------
# ThreatIndicator model
# ---------------------------------------------------------------------------


class TestThreatIndicator:
    def test_basic_creation(self):
        """ThreatIndicator with required fields."""
        ind = ThreatIndicator(
            indicator_type="pattern_match",
            severity="critical",
            confidence=0.95,
            description="Repeated secret exfiltration detected",
        )
        assert ind.indicator_id
        assert ind.confidence == 0.95

    def test_confidence_bounds(self):
        """Confidence must be between 0 and 1."""
        with pytest.raises(Exception):  # ValidationError
            ThreatIndicator(
                indicator_type="test",
                severity="low",
                confidence=1.5,
                description="Invalid",
            )

    def test_with_mitre_tactic(self):
        """ThreatIndicator with MITRE ATT&CK tactic."""
        ind = ThreatIndicator(
            indicator_type="correlation",
            severity="high",
            confidence=0.8,
            description="Kill chain detected",
            mitre_tactic="lateral_movement",
            related_event_ids=["e1", "e2"],
        )
        assert ind.mitre_tactic == "lateral_movement"


# ---------------------------------------------------------------------------
# Playbook & PlaybookStep models
# ---------------------------------------------------------------------------


class TestPlaybookModels:
    def test_playbook_step(self):
        """PlaybookStep with all fields."""
        step = PlaybookStep(
            action="pause_agent",
            target="agent-001",
            description="Pause the compromised agent",
            reversible=True,
            timeout_seconds=60,
            params={"reason": "suspected compromise"},
        )
        assert step.action == "pause_agent"
        assert step.reversible is True

    def test_playbook_creation(self):
        """Playbook with steps."""
        pb = Playbook(
            name="test_playbook",
            description="Test playbook",
            trigger_patterns=["repeated_secret_exfil"],
            severity_threshold="high",
            auto_respond=False,
            steps=[
                PlaybookStep(action="pause_agent"),
                PlaybookStep(action="revoke_token"),
            ],
        )
        assert pb.name == "test_playbook"
        assert len(pb.steps) == 2
        assert pb.auto_respond is False

    def test_response_result(self):
        """ResponseResult tracks action outcomes."""
        result = ResponseResult(
            action="pause_agent",
            target="agent-001",
            success=True,
            message="Agent paused successfully",
            dry_run=False,
        )
        assert result.success is True
        assert result.rolled_back is False


# ---------------------------------------------------------------------------
# Forensic & Audit models
# ---------------------------------------------------------------------------


class TestForensicAuditModels:
    def test_forensic_evidence(self):
        """ForensicEvidence stores evidence data."""
        ev = ForensicEvidence(
            evidence_type="event",
            timestamp=datetime.now(timezone.utc),
            data={"event_id": "e1", "details": {"command": "rm -rf /"}},
            source="event_log",
        )
        assert ev.evidence_type == "event"

    def test_forensic_report(self):
        """ForensicReport assembles investigation results."""
        report = ForensicReport(
            incident_id="inc-1",
            agent_id="agent-1",
            timeline=[
                ForensicEvidence(
                    evidence_type="event",
                    timestamp=datetime.now(timezone.utc),
                ),
            ],
            kill_chain=["initial_access", "execution", "exfiltration"],
            root_cause="Compromised API key",
            impact_assessment="3 secrets exposed",
            recommendations=["Rotate all API keys", "Enable MFA"],
        )
        assert report.incident_id == "inc-1"
        assert len(report.kill_chain) == 3
        assert len(report.recommendations) == 2

    def test_audit_discrepancy(self):
        """AuditDiscrepancy captures policy enforcement gaps."""
        disc = AuditDiscrepancy(
            agent_id="agent-1",
            expected_action="block",
            actual_action="allow",
            event_id="e1",
            severity="high",
            description="Agent allowed a blocked action",
        )
        assert disc.expected_action == "block"
        assert disc.actual_action == "allow"

    def test_audit_report(self):
        """AuditReport summarizes audit findings."""
        report = AuditReport(
            period_start=datetime.now(timezone.utc),
            period_end=datetime.now(timezone.utc),
            agents_audited=5,
            discrepancies=[],
            clean=True,
            summary="All agents compliant",
        )
        assert report.clean is True
        assert report.agents_audited == 5


# ---------------------------------------------------------------------------
# AgentTask & AgentResult models
# ---------------------------------------------------------------------------


class TestTaskResultModels:
    def test_agent_task_defaults(self):
        """AgentTask has sensible defaults."""
        task = AgentTask(task_type="detect")
        assert task.task_id
        assert task.priority == 5
        assert task.timeout_seconds == 300
        assert task.payload == {}

    def test_agent_result(self):
        """AgentResult captures task outcome."""
        result = AgentResult(
            task_id="t1",
            agent_id="sentinel-abc",
            agent_type="sentinel",
            success=True,
            result_data={"indicators_found": 3},
            duration_ms=42.5,
        )
        assert result.success is True
        assert result.duration_ms == 42.5


# ---------------------------------------------------------------------------
# Orchestrator incident management
# ---------------------------------------------------------------------------


class TestOrchestratorIncidents:
    def test_list_incidents_empty(self):
        """Fresh orchestrator has no incidents."""
        orch = AngelOrchestrator()
        assert orch.list_incidents() == []

    def test_get_nonexistent_incident(self):
        """Getting a missing incident returns None."""
        orch = AngelOrchestrator()
        assert orch.get_incident("fake-id") is None

    def test_status_structure(self):
        """Orchestrator status has required keys."""
        orch = AngelOrchestrator()
        status = orch.status()
        assert "running" in status
        assert "stats" in status
        assert "agents" in status
        assert "incidents" in status
        assert "playbooks" in status

    def test_status_agents(self):
        """All 10 sub-agents appear in status (Angel Legion)."""
        orch = AngelOrchestrator()
        agents = orch.status()["agents"]
        agent_types = {info["agent_type"] for info in agents.values()}
        for expected in ("sentinel", "response", "forensic", "audit",
                         "network", "secrets", "toolchain", "behavior",
                         "timeline", "browser"):
            assert expected in agent_types, f"Missing agent type: {expected}"

    @pytest.mark.asyncio
    async def test_approve_nonexistent(self):
        """Approving a nonexistent incident returns error."""
        orch = AngelOrchestrator()
        result = await orch.approve_incident("fake-id", "operator", db=None)
        assert "error" in result


# ---------------------------------------------------------------------------
# CorrelationChain model
# ---------------------------------------------------------------------------


class TestCorrelationChain:
    def test_chain_creation(self):
        """CorrelationChain captures kill chain sequence."""
        chain = CorrelationChain(
            event_ids=["e1", "e2", "e3"],
            agent_ids=["agent-1"],
            tactics=["reconnaissance", "execution", "exfiltration"],
            severity="critical",
            confidence=0.9,
            description="Multi-stage attack detected",
            time_span_seconds=120.0,
        )
        assert len(chain.tactics) == 3
        assert chain.severity == "critical"
        assert chain.time_span_seconds == 120.0
