"""Tests for V2.2 coverage push.

Targets biggest coverage gaps across brain, daemon,
analytics, context, patterns, and learning modules.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cloud.angelclaw.context import EnvironmentContext

NOW = datetime.now(timezone.utc)
TENANT = "test-tenant"

def _uid():
    return str(uuid.uuid4())

def _make_ctx(**overrides):
    """Build an EnvironmentContext with sensible defaults."""
    ctx = EnvironmentContext()
    ctx.host = overrides.get("host", {
        "hostname": "test-host",
        "os": "Linux 6.x",
        "angelclaw_version": "2.2.0",
    })
    ctx.agent_summary = overrides.get("agent_summary", {
        "total": 3,
        "active": 2,
        "degraded": 1,
        "offline": 0,
    })
    ctx.agents = overrides.get("agents", [])
    ctx.recent_events = overrides.get("recent_events", [])
    ctx.recent_alerts = overrides.get("recent_alerts", [])
    ctx.recent_incidents = overrides.get("recent_incidents", [])
    ctx.recent_changes = overrides.get("recent_changes", [])
    ctx.recent_activity = overrides.get("recent_activity", [])
    ctx.event_summary = overrides.get("event_summary", {"total": 0})
    ctx.preferences = overrides.get("preferences", {
        "scan_frequency_minutes": 10,
        "autonomy_level": "suggest_only",
        "reporting_level": "normal"
    })
    ctx.orchestrator_status = overrides.get("orchestrator_status", {
        "running": True,
        "stats": {"events_processed": 100, "incidents_created": 2, "indicators_found": 5}
    })
    ctx.self_audit_summary = overrides.get("self_audit_summary", "")
    ctx.learning_summary = overrides.get("learning_summary", {})
    ctx.policy = overrides.get("policy", {})
    return ctx


# =========================================================================
# Class 1: Brain handlers that only need EnvironmentContext
# =========================================================================

class TestBrainHandlersContext:
    """Test brain handlers that only require an EnvironmentContext."""

    @pytest.fixture(autouse=True)
    def _brain(self):
        from cloud.angelclaw.brain import brain
        self.brain = brain

    # -- _handle_alerts ---------------------------------------------------

    def test_alerts_no_alerts(self):
        ctx = _make_ctx(recent_alerts=[])
        result = self.brain._handle_alerts(ctx)
        assert "No guardian alerts" in result["answer"]

    def test_alerts_with_data(self):
        alerts = [
            {"severity": "critical", "title": "Secret exfiltration attempt"},
            {"severity": "high", "title": "Agent flapping detected"},
            {"severity": "low", "title": "Minor config drift"},
        ]
        ctx = _make_ctx(recent_alerts=alerts)
        result = self.brain._handle_alerts(ctx)
        assert "3" in result["answer"]
        assert "Secret exfiltration attempt" in result["answer"]
        assert "CRITICAL" in result["answer"]

    # -- _handle_agents ---------------------------------------------------

    def test_agents_no_agents(self):
        ctx = _make_ctx(agent_summary={"total": 0, "active": 0, "degraded": 0, "offline": 0})
        result = self.brain._handle_agents(ctx)
        assert "No agents" in result["answer"]

    def test_agents_with_fleet(self):
        ctx = _make_ctx(agent_summary={"total": 3, "active": 2, "degraded": 1, "offline": 0})
        result = self.brain._handle_agents(ctx)
        assert "3" in result["answer"]
        assert "Active: 2" in result["answer"]
        assert "Degraded: 1" in result["answer"]

    def test_agents_degraded_listed(self):
        ctx = _make_ctx(
            agent_summary={"total": 3, "active": 2, "degraded": 1, "offline": 0},
            agents=[{"status": "degraded", "hostname": "web-01"}],
        )
        result = self.brain._handle_agents(ctx)
        assert "web-01" in result["answer"]

    # -- _handle_changes --------------------------------------------------

    def test_changes_no_changes(self):
        ctx = _make_ctx(recent_changes=[])
        result = self.brain._handle_changes(ctx)
        assert "No policy" in result["answer"]

    def test_changes_with_data(self):
        changes = [
            {
                "change_type": "policy_update",
                "description": "Tightened allowlist",
                "changed_by": "admin",
            },
            {
                "change_type": "config_change",
                "description": "Increased scan freq",
                "changed_by": "system",
            },
        ]
        ctx = _make_ctx(recent_changes=changes)
        result = self.brain._handle_changes(ctx)
        assert "2" in result["answer"]
        assert "Tightened allowlist" in result["answer"]
        assert "Increased scan freq" in result["answer"]

    # -- _handle_activity -------------------------------------------------

    def test_activity_no_activity(self):
        ctx = _make_ctx(
            recent_activity=[],
            preferences={},
            orchestrator_status={"running": False},
        )
        result = self.brain._handle_activity(ctx)
        assert "No recent daemon activity" in result["answer"]

    def test_activity_with_entries(self):
        activity = [
            {"timestamp": "2026-02-18T10:00:00Z", "summary": "Ran security scan"},
            {"timestamp": "2026-02-18T10:05:00Z", "summary": "Updated policy"},
        ]
        ctx = _make_ctx(
            recent_activity=activity,
            preferences={
                "scan_frequency_minutes": 10,
                "autonomy_level": "suggest_only",
                "reporting_level": "normal",
            },
            orchestrator_status={
                "running": True,
                "stats": {
                    "events_processed": 50,
                    "incidents_created": 1,
                    "indicators_found": 3,
                },
            },
        )
        result = self.brain._handle_activity(ctx)
        assert "Ran security scan" in result["answer"]
        assert "Updated policy" in result["answer"]
        assert "scan every" in result["answer"]

    def test_activity_orchestrator_stats(self):
        ctx = _make_ctx(
            recent_activity=[],
            preferences={},
            orchestrator_status={
                "running": True,
                "stats": {"events_processed": 200, "incidents_created": 5, "indicators_found": 12},
            },
        )
        result = self.brain._handle_activity(ctx)
        assert "200" in result["answer"]
        assert "5" in result["answer"]
        assert "12" in result["answer"]

    # -- _handle_worried --------------------------------------------------

    def test_worried_no_concerns(self):
        ctx = _make_ctx(
            agent_summary={"total": 3, "active": 3, "degraded": 0, "offline": 0},
            recent_alerts=[],
            recent_incidents=[],
        )
        result = self.brain._handle_worried(ctx)
        assert "Everything looks good" in result["answer"]

    def test_worried_degraded(self):
        ctx = _make_ctx(
            agent_summary={"total": 4, "active": 2, "degraded": 2, "offline": 0},
            recent_alerts=[],
            recent_incidents=[],
        )
        result = self.brain._handle_worried(ctx)
        assert "2 degraded" in result["answer"]

    def test_worried_critical_alerts(self):
        ctx = _make_ctx(
            agent_summary={"total": 1, "active": 1, "degraded": 0, "offline": 0},
            recent_alerts=[{"severity": "critical", "title": "Bad thing"}],
            recent_incidents=[],
        )
        result = self.brain._handle_worried(ctx)
        assert "critical alert" in result["answer"]

    def test_worried_open_incidents(self):
        ctx = _make_ctx(
            agent_summary={"total": 1, "active": 1, "degraded": 0, "offline": 0},
            recent_alerts=[],
            recent_incidents=[{"state": "new", "title": "Injection detected on web-02"}],
        )
        result = self.brain._handle_worried(ctx)
        assert "open incident" in result["answer"]

    # -- _handle_backup_help ----------------------------------------------

    def test_backup_linux(self):
        ctx = _make_ctx(host={
            "hostname": "prod-1",
            "os": "Linux 6.x",
            "angelclaw_version": "2.2.0",
        })
        result = self.brain._handle_backup_help(ctx)
        assert "bash" in result["answer"]

    def test_backup_windows(self):
        ctx = _make_ctx(host={
            "hostname": "win-srv",
            "os": "Windows 11",
            "angelclaw_version": "2.2.0",
        })
        result = self.brain._handle_backup_help(ctx)
        assert "powershell" in result["answer"].lower() or "PowerShell" in result["answer"]

    # -- _handle_network_check --------------------------------------------

    def test_network_no_events(self):
        ctx = _make_ctx(recent_events=[])
        result = self.brain._handle_network_check(ctx)
        assert "Network Security Check" in result["answer"]

    def test_network_with_events(self):
        events = [
            {"category": "network", "severity": "low", "type": "outbound_connection"},
            {"category": "network", "severity": "medium", "type": "http_post"},
            {"category": "file_system", "severity": "info", "type": "file_read"},
        ]
        ctx = _make_ctx(recent_events=events)
        result = self.brain._handle_network_check(ctx)
        assert "2" in result["answer"]

    # -- _handle_compliance -----------------------------------------------

    def test_compliance_no_changes(self):
        ctx = _make_ctx(recent_changes=[])
        result = self.brain._handle_compliance(ctx)
        assert "Compliance" in result["answer"]
        assert "Recent auditable" not in result["answer"]

    def test_compliance_with_changes(self):
        changes = [
            {
                "change_type": "policy_update",
                "description": "Added new rule",
                "changed_by": "admin",
            },
        ]
        ctx = _make_ctx(recent_changes=changes)
        result = self.brain._handle_compliance(ctx)
        assert "Recent auditable" in result["answer"]

    # -- _handle_general --------------------------------------------------

    def test_general_host_question(self):
        ctx = _make_ctx()
        result = self.brain._handle_general(ctx, "what is the docker version")
        assert "About this host" in result["answer"]

    def test_general_non_host(self):
        ctx = _make_ctx()
        result = self.brain._handle_general(ctx, "what is XSS")
        assert "guardian" in result["answer"].lower()

    # -- _handle_serenity -------------------------------------------------

    def test_serenity_serene(self):
        ctx = _make_ctx(
            recent_alerts=[],
            recent_incidents=[],
            agent_summary={"total": 2, "active": 2, "degraded": 0, "offline": 0},
        )
        result = self.brain._handle_serenity(ctx)
        assert "SERENE" in result["answer"]

    def test_serenity_whisper(self):
        ctx = _make_ctx(
            recent_alerts=[],
            recent_incidents=[],
            agent_summary={"total": 3, "active": 2, "degraded": 1, "offline": 0},
        )
        result = self.brain._handle_serenity(ctx)
        assert "WHISPER" in result["answer"]

    def test_serenity_murmur(self):
        ctx = _make_ctx(
            recent_alerts=[{"severity": "low", "title": "Minor issue"}],
            recent_incidents=[],
            agent_summary={"total": 2, "active": 2, "degraded": 0, "offline": 0},
        )
        result = self.brain._handle_serenity(ctx)
        assert "MURMUR" in result["answer"]

    def test_serenity_disturbed(self):
        ctx = _make_ctx(
            recent_alerts=[{"severity": "high", "title": "Active threat"}],
            recent_incidents=[],
            agent_summary={"total": 2, "active": 2, "degraded": 0, "offline": 0},
        )
        result = self.brain._handle_serenity(ctx)
        assert "DISTURBED" in result["answer"]

    def test_serenity_storm(self):
        ctx = _make_ctx(
            recent_alerts=[{"severity": "critical", "title": "Breach in progress"}],
            recent_incidents=[],
            agent_summary={"total": 2, "active": 2, "degraded": 0, "offline": 0},
        )
        result = self.brain._handle_serenity(ctx)
        assert "STORM" in result["answer"]


# =========================================================================
# Class 2: Brain handlers needing mocked external services
# =========================================================================

class TestBrainHandlersMocked:
    """Test handlers that require mocked external services."""

    @pytest.fixture(autouse=True)
    def _brain(self):
        from cloud.angelclaw.brain import brain
        self.brain = brain

    # -- _handle_shield ---------------------------------------------------

    @patch("cloud.angelclaw.shield.shield")
    def test_shield_clean(self, mock_shield_obj):
        # Build mock report
        report = MagicMock()
        report.checks_run = 42
        report.overall_risk.value = "low"
        report.lethal_trifecta_score = 0.0
        report.indicators = []
        report.skills_status = {"total": 5, "verified": 5, "drifted": 0, "missing": 0}

        mock_shield_obj.assess_events.return_value = report
        mock_shield_obj.get_status.return_value = {
            "injection_patterns": 20,
            "leakage_patterns": 15,
            "evil_agi_patterns": 18,
            "attack_stages": 6,
        }

        ctx = _make_ctx(recent_events=[])
        result = self.brain._handle_shield(MagicMock(), ctx)

        assert "ClawSec Shield Assessment" in result["answer"]
        assert "42 checks" in result["answer"]
        assert "LOW" in result["answer"]
        assert "No threat indicators" in result["answer"]

    @patch("cloud.angelclaw.shield.shield")
    def test_shield_with_indicators(self, mock_shield_obj):
        indicator1 = MagicMock()
        indicator1.severity.value = "high"
        indicator1.title = "Prompt injection detected"
        indicator1.description = "Pattern matched in input"
        indicator1.mitigations = ["Block input", "Review agent"]

        indicator2 = MagicMock()
        indicator2.severity.value = "medium"
        indicator2.title = "Data leakage risk"
        indicator2.description = "Exfiltration pattern found"
        indicator2.mitigations = ["Block transfer"]

        report = MagicMock()
        report.checks_run = 50
        report.overall_risk.value = "high"
        report.lethal_trifecta_score = 0.33
        report.indicators = [indicator1, indicator2]
        report.skills_status = {"total": 5, "verified": 5, "drifted": 0, "missing": 0}

        mock_shield_obj.assess_events.return_value = report
        mock_shield_obj.get_status.return_value = {
            "injection_patterns": 20,
            "leakage_patterns": 15,
            "evil_agi_patterns": 18,
            "attack_stages": 6,
        }

        ctx = _make_ctx(recent_events=[{
            "category": "network",
            "type": "http_post",
            "details": {},
            "severity": "medium",
        }])
        result = self.brain._handle_shield(MagicMock(), ctx)

        assert "HIGH" in result["answer"]
        assert "Prompt injection detected" in result["answer"]
        assert "Data leakage risk" in result["answer"]
        assert "Threat indicators (2)" in result["answer"]

    # -- _handle_skills ---------------------------------------------------

    @patch("cloud.angelclaw.shield.verify_all_skills")
    def test_skills_all_verified(self, mock_verify):
        mock_verify.return_value = {
            "total": 5,
            "verified": 5,
            "drifted": 0,
            "missing": 0,
            "skills": {
                "mod1": {"verified": True, "drift": False, "hash": "abc123"},
            },
        }
        result = self.brain._handle_skills()
        assert "Skills Integrity Report" in result["answer"]
        assert "Verified: **5**" in result["answer"]
        assert "All modules verified" in result["answer"]
        assert "OK" in result["answer"]

    @patch("cloud.angelclaw.shield.verify_all_skills")
    def test_skills_with_drift(self, mock_verify):
        mock_verify.return_value = {
            "total": 5,
            "verified": 4,
            "drifted": 1,
            "missing": 0,
            "skills": {
                "mod1": {"verified": True, "drift": False, "hash": "abc123"},
                "mod2": {"verified": False, "drift": True, "hash": "def456"},
            },
        }
        result = self.brain._handle_skills()
        assert "WARNING" in result["answer"]
        assert "Drifted: **1**" in result["answer"]
        assert "DRIFT" in result["answer"]

    # -- _handle_legion_status --------------------------------------------

    @patch("cloud.guardian.orchestrator.angel_orchestrator")
    def test_legion_status(self, mock_orch):
        mock_orch.pulse_check.return_value = {
            "total_agents": 3,
            "healthy": 2,
            "degraded": 1,
            "offline": 0,
            "agents": [
                {
                    "status": "idle",
                    "name": "PatternWarden",
                    "type": "pattern_detection",
                    "tasks_completed": 10,
                },
                {
                    "status": "busy",
                    "name": "AnomalyWarden",
                    "type": "anomaly_detection",
                    "tasks_completed": 7,
                },
                {
                    "status": "error",
                    "name": "CorrelatorWarden",
                    "type": "correlation",
                    "tasks_completed": 3,
                },
            ],
            "circuit_breakers": {},
        }
        mock_orch.autonomy_mode = "supervised"

        result = self.brain._handle_legion_status()
        assert "Angel Legion Status" in result["answer"]
        assert "3 agents" in result["answer"] or "3" in result["answer"]
        assert "Healthy: **2**" in result["answer"]
        assert "PatternWarden" in result["answer"]
        assert "supervised" in result["answer"]

    # -- _handle_quarantine -----------------------------------------------

    def test_quarantine_no_uuid(self):
        result = self.brain._handle_quarantine("quarantine the agent")
        assert "need its agent ID" in result["answer"]

    def test_quarantine_with_uuid(self):
        result = self.brain._handle_quarantine(
            "quarantine agent a1b2c3d4-e5f6-7890-a123-b456c789d000"
        )
        assert "isolate_agent" in str(result.get("actions", []))


# =========================================================================
# Class 3: Brain handlers that create their own SessionLocal internally
# =========================================================================

class TestBrainHandlersDB:
    """Test handlers that create their own DB sessions internally."""

    @pytest.fixture(autouse=True)
    def _brain(self):
        from cloud.angelclaw.brain import brain
        self.brain = brain

    # -- _handle_incidents ------------------------------------------------

    @patch("cloud.ai_assistant.assistant.summarize_recent_incidents")
    @patch("cloud.db.session.SessionLocal")
    def test_incidents_with_data(self, mock_session_cls, mock_summarize):
        mock_db = MagicMock()
        mock_session_cls.return_value = mock_db

        sev_entry = MagicMock()
        sev_entry.severity = "critical"
        sev_entry.count = 2

        class_entry = MagicMock()
        class_entry.classification = "injection"
        class_entry.count = 3

        summary = MagicMock()
        summary.total_incidents = 5
        summary.by_severity = [sev_entry]
        summary.by_classification = [class_entry]
        summary.recommended_focus = ["Focus on critical"]
        mock_summarize.return_value = summary

        ctx = _make_ctx()
        result = self.brain._handle_incidents(ctx)

        assert "5" in result["answer"]
        assert "critical: 2" in result["answer"]
        assert "injection: 3" in result["answer"]
        assert "Focus on critical" in result["answer"]
        mock_db.close.assert_called_once()

    @patch("cloud.ai_assistant.assistant.summarize_recent_incidents")
    @patch("cloud.db.session.SessionLocal")
    def test_incidents_empty(self, mock_session_cls, mock_summarize):
        mock_db = MagicMock()
        mock_session_cls.return_value = mock_db

        summary = MagicMock()
        summary.total_incidents = 0
        summary.by_severity = []
        summary.by_classification = []
        summary.recommended_focus = []
        mock_summarize.return_value = summary

        ctx = _make_ctx()
        result = self.brain._handle_incidents(ctx)

        assert "0" in result["answer"]
        mock_db.close.assert_called_once()

    # -- _handle_threats --------------------------------------------------

    @patch("cloud.services.predictive.predict_threat_vectors")
    @patch("cloud.db.session.SessionLocal")
    def test_threats_none(self, mock_session_cls, mock_predict):
        mock_db = MagicMock()
        mock_session_cls.return_value = mock_db
        mock_predict.return_value = []

        result = self.brain._handle_threats(MagicMock())

        assert "No threat vectors" in result["answer"]
        mock_db.close.assert_called_once()

    @patch("cloud.services.predictive.predict_threat_vectors")
    @patch("cloud.db.session.SessionLocal")
    def test_threats_with_data(self, mock_session_cls, mock_predict):
        mock_db = MagicMock()
        mock_session_cls.return_value = mock_db

        pred1 = MagicMock()
        pred1.vector_name = "SQL Injection Spike"
        pred1.confidence = 0.85
        pred1.rationale = "Increase in SQLi attempts from 3 sources"

        pred2 = MagicMock()
        pred2.vector_name = "Credential Stuffing"
        pred2.confidence = 0.62
        pred2.rationale = "Brute force patterns detected"

        mock_predict.return_value = [pred1, pred2]

        result = self.brain._handle_threats(MagicMock())

        assert "SQL Injection Spike" in result["answer"]
        assert "85%" in result["answer"]
        assert "Credential Stuffing" in result["answer"]
        assert "62%" in result["answer"]
        mock_db.close.assert_called_once()

    # -- _handle_propose --------------------------------------------------

    @patch("cloud.ai_assistant.assistant.propose_policy_tightening")
    @patch("cloud.db.session.SessionLocal")
    def test_propose(self, mock_session_cls, mock_propose):
        mock_db = MagicMock()
        mock_session_cls.return_value = mock_db

        rule1 = MagicMock()
        rule1.description = "Block outbound to known C2"
        rule1.action = "deny"
        rule1.risk_level = "high"

        proposals = MagicMock()
        proposals.analysis_summary = "Analysis of 24h event data"
        proposals.proposed_rules = [rule1]
        mock_propose.return_value = proposals

        result = self.brain._handle_propose(MagicMock(), TENANT)

        assert "Analysis of 24h event data" in result["answer"]
        assert "Block outbound to known C2" in result["answer"]
        assert "deny" in result["answer"]
        mock_db.close.assert_called_once()

    # -- _handle_explain --------------------------------------------------

    @patch("cloud.ai_assistant.assistant.explain_event_with_context")
    def test_explain_no_id(self, mock_explain):
        result = self.brain._handle_explain(MagicMock(), "explain this event please")
        assert "need an event ID" in result["answer"]
        mock_explain.assert_not_called()

    @patch("cloud.ai_assistant.assistant.explain_event_with_context")
    def test_explain_not_found(self, mock_explain):
        mock_explain.return_value = {"error": "not found"}
        event_id = "a1b2c3d4-e5f6-7890-a123-b456c789d000"
        result = self.brain._handle_explain(MagicMock(), f"explain event {event_id}")
        assert "not found" in result["answer"]

    @patch("cloud.ai_assistant.assistant.explain_event_with_context")
    def test_explain_found(self, mock_explain):
        mock_explain.return_value = {
            "category": "network",
            "type": "outbound_connection",
            "severity": "high",
            "explanation": "Blocked due to suspicious destination IP",
        }
        event_id = "a1b2c3d4-e5f6-7890-a123-b456c789d000"
        result = self.brain._handle_explain(MagicMock(), f"explain event {event_id}")
        assert "network" in result["answer"]
        assert "outbound_connection" in result["answer"]
        assert "high" in result["answer"]
        assert "Blocked due to suspicious destination IP" in result["answer"]

    # -- _handle_action_history -------------------------------------------

    @patch("cloud.angelclaw.brain.get_action_history")
    def test_history_empty(self, mock_history):
        mock_history.return_value = []
        result = self.brain._handle_action_history(MagicMock(), TENANT)
        assert "No actions recorded" in result["answer"]

    @patch("cloud.angelclaw.brain.get_action_history")
    def test_history_with_data(self, mock_history):
        mock_history.return_value = [
            {
                "status": "applied",
                "action_type": "tighten_policy_rule",
                "description": "Blocked outbound to 1.2.3.4",
                "triggered_by": "chat",
                "created_at": "2026-02-18T10:00:00Z",
                "error": None,
            },
            {
                "status": "failed",
                "action_type": "isolate_agent",
                "description": "Isolate agent abc123",
                "triggered_by": "auto",
                "created_at": "2026-02-18T09:30:00Z",
                "error": "Agent unreachable",
            },
        ]
        result = self.brain._handle_action_history(MagicMock(), TENANT)
        assert "Action History" in result["answer"]
        assert "tighten_policy_rule" in result["answer"]
        assert "Blocked outbound" in result["answer"]
        assert "FAILED" in result["answer"]
        assert "Agent unreachable" in result["answer"]


# =========================================================================
# Class 4: TestBrainPreferences
# =========================================================================


class TestBrainPreferences:
    """Test preference handlers on the brain singleton."""

    def _mock_prefs(self, autonomy="suggest_only", reporting="normal", freq=10):
        """Build a mock Preferences object with the given values."""
        p = MagicMock()
        p.scan_frequency_minutes = freq
        p.reporting_level = MagicMock(value=reporting)
        p.autonomy_level = MagicMock(value=autonomy)
        p.updated_at = NOW
        p.updated_by = "chat"
        return p

    # --- _handle_pref_autonomy ---

    @patch("cloud.angelclaw.brain.update_preferences")
    def test_autonomy_observe(self, mock_update, db):
        from cloud.angelclaw.brain import brain

        mock_update.return_value = self._mock_prefs(autonomy="observe_only")
        result = brain._handle_pref_autonomy(db, TENANT, "set to observe only")
        assert "observe_only" in result["answer"]

    @patch("cloud.angelclaw.brain.update_preferences")
    def test_autonomy_suggest(self, mock_update, db):
        from cloud.angelclaw.brain import brain

        mock_update.return_value = self._mock_prefs(autonomy="suggest_only")
        result = brain._handle_pref_autonomy(db, TENANT, "suggest mode")
        assert "suggest_only" in result["answer"]

    @patch("cloud.angelclaw.brain.update_preferences")
    def test_autonomy_assist(self, mock_update, db):
        from cloud.angelclaw.brain import brain

        mock_update.return_value = self._mock_prefs(autonomy="assist")
        result = brain._handle_pref_autonomy(db, TENANT, "assist me")
        assert "assist" in result["answer"]

    @patch("cloud.angelclaw.brain.update_preferences")
    def test_autonomy_auto(self, mock_update, db):
        from cloud.angelclaw.brain import brain

        mock_update.return_value = self._mock_prefs(autonomy="autonomous_apply")
        result = brain._handle_pref_autonomy(db, TENANT, "go autonomous")
        assert "autonomous" in result["answer"]

    def test_autonomy_unknown(self, db):
        from cloud.angelclaw.brain import brain

        result = brain._handle_pref_autonomy(db, TENANT, "be nice")
        assert "Which autonomy level?" in result["answer"]

    # --- _handle_pref_reporting ---

    @patch("cloud.angelclaw.brain.update_preferences")
    def test_reporting_quiet(self, mock_update, db):
        from cloud.angelclaw.brain import brain

        mock_update.return_value = self._mock_prefs(reporting="quiet")
        result = brain._handle_pref_reporting(db, TENANT, "be quiet")
        assert "quiet" in result["answer"]

    @patch("cloud.angelclaw.brain.update_preferences")
    def test_reporting_verbose(self, mock_update, db):
        from cloud.angelclaw.brain import brain

        mock_update.return_value = self._mock_prefs(reporting="verbose")
        result = brain._handle_pref_reporting(db, TENANT, "verbose please")
        assert "verbose" in result["answer"]

    @patch("cloud.angelclaw.brain.update_preferences")
    def test_reporting_default(self, mock_update, db):
        from cloud.angelclaw.brain import brain

        mock_update.return_value = self._mock_prefs(reporting="normal")
        result = brain._handle_pref_reporting(db, TENANT, "normal")
        assert "normal" in result["answer"]

    # --- _handle_pref_show ---

    @patch("cloud.angelclaw.brain.get_preferences")
    def test_pref_show(self, mock_get, db):
        from cloud.angelclaw.brain import brain

        mock_get.return_value = self._mock_prefs(autonomy="assist", reporting="verbose", freq=5)
        result = brain._handle_pref_show(db, TENANT)
        assert "assist" in result["answer"]
        assert "verbose" in result["answer"]
        assert "5 minutes" in result["answer"]

    # --- _handle_pref_scan_freq ---

    @patch("cloud.angelclaw.brain.update_preferences")
    def test_scan_freq_valid(self, mock_update, db):
        from cloud.angelclaw.brain import brain

        mock_update.return_value = self._mock_prefs(freq=5)
        result = brain._handle_pref_scan_freq(db, TENANT, "scan every 5 minutes")
        assert "5 minutes" in result["answer"]

    def test_scan_freq_no_number(self, db):
        from cloud.angelclaw.brain import brain

        result = brain._handle_pref_scan_freq(db, TENANT, "scan more often")
        assert "How often" in result["answer"]

    @patch("cloud.angelclaw.brain.update_preferences")
    def test_scan_freq_clamped(self, mock_update, db):
        from cloud.angelclaw.brain import brain

        mock_update.return_value = self._mock_prefs(freq=1440)
        result = brain._handle_pref_scan_freq(db, TENANT, "scan every 9999 minutes")
        assert "1440" in result["answer"]


# =========================================================================
# Class 5: TestBrainAsyncHandlers
# =========================================================================


class TestBrainAsyncHandlers:
    """Test async brain handlers: apply_actions, diagnostics, LLM enrichment."""

    # --- _handle_apply_actions ---

    @pytest.mark.asyncio
    async def test_apply_no_pending(self, db):
        from cloud.angelclaw.brain import brain

        brain._pending_actions.pop(TENANT, None)
        result = await brain._handle_apply_actions(db, TENANT, "apply all")
        assert "No pending actions" in result["answer"]

    @pytest.mark.asyncio
    async def test_apply_all(self, db):
        from cloud.angelclaw.brain import brain

        mock_action1 = MagicMock()
        mock_action1.id = "act-1"
        mock_action1.action_type = MagicMock(value="update_policy")
        mock_action1.description = "test action 1"
        mock_action1.dry_run = True

        mock_action2 = MagicMock()
        mock_action2.id = "act-2"
        mock_action2.action_type = MagicMock(value="update_policy")
        mock_action2.description = "test action 2"
        mock_action2.dry_run = True

        brain._pending_actions[TENANT] = [mock_action1, mock_action2]

        exec_result = MagicMock(
            success=True,
            message="done",
            before_state={},
            after_state={},
        )
        original_executor = brain._executor
        brain._executor = MagicMock()
        brain._executor.execute = AsyncMock(return_value=exec_result)

        try:
            result = await brain._handle_apply_actions(db, TENANT, "apply all")
            assert "Applied **2**" in result["answer"]
        finally:
            brain._executor = original_executor

    # --- _handle_diagnostics ---

    @pytest.mark.asyncio
    @patch("cloud.guardian.orchestrator.angel_orchestrator")
    async def test_diagnostics(self, mock_orch, db):
        from cloud.angelclaw.brain import brain

        mock_orch.status.return_value = {
            "running": True,
            "stats": {
                "events_processed": 100,
                "indicators_found": 5,
                "incidents_created": 2,
                "responses_executed": 1,
            },
            "legion": {"total": 10, "wardens": 7},
            "incidents": {
                "total": 5,
                "pending_approval": 1,
                "by_state": {"new": 2, "resolved": 3},
            },
        }

        ctx = _make_ctx(
            agent_summary={"total": 3, "active": 2, "degraded": 1, "offline": 0},
            event_summary={"total": 50, "by_severity": {"high": 5}},
        )
        result = await brain._handle_diagnostics(db, TENANT, ctx)
        assert "Deep System Diagnostics" in result["answer"]
        assert "100" in result["answer"]  # events_processed
        assert "10" in result["answer"]   # legion total

    # --- _try_llm_enrich ---

    @pytest.mark.asyncio
    async def test_llm_disabled(self):
        from cloud.angelclaw.brain import brain

        ctx = _make_ctx()
        # Patch the import to raise ImportError (simulating no LLM config)
        with patch.dict("sys.modules", {"cloud.llm_proxy.config": None}):
            result = await brain._try_llm_enrich("test prompt", "base answer", "general", ctx)
        assert result is None


# =========================================================================
# Class 6: TestDaemonFunctions
# =========================================================================


class TestDaemonFunctions:
    """Test daemon internal functions from cloud.angelclaw.daemon."""

    # --- get_next_scan_time ---

    def test_not_running(self):
        import cloud.angelclaw.daemon as daemon_mod

        original_running = daemon_mod._running
        original_cycles = daemon_mod._cycles_completed
        try:
            daemon_mod._running = False
            daemon_mod._cycles_completed = 0
            result = daemon_mod.get_next_scan_time()
            assert result is None
        finally:
            daemon_mod._running = original_running
            daemon_mod._cycles_completed = original_cycles

    # --- _run_scan ---

    @pytest.mark.asyncio
    async def test_run_scan_success(self, db):
        from cloud.angelclaw.daemon import _run_scan

        scan_result = MagicMock()
        scan_result.total_checks = 10
        scan_result.top_risks = []
        scan_result.hardening_suggestions = []

        with patch(
            "cloud.services.guardian_scan.run_guardian_scan",
            new_callable=AsyncMock,
            return_value=scan_result,
        ):
            summary = await _run_scan(db, TENANT, "normal")
        assert "10 checks" in summary

    @pytest.mark.asyncio
    async def test_run_scan_exception(self, db):
        from cloud.angelclaw.daemon import _run_scan

        with patch(
            "cloud.services.guardian_scan.run_guardian_scan",
            new_callable=AsyncMock,
            side_effect=Exception("scan failed"),
        ):
            summary = await _run_scan(db, TENANT, "normal")
        assert "skipped" in summary

    # --- _check_drift ---

    def test_no_policy(self, db):
        from cloud.angelclaw.daemon import _check_drift
        from cloud.db.models import PolicySetRow

        db.query(PolicySetRow).delete()
        db.commit()

        findings = _check_drift(db, TENANT)
        assert findings == []

    def test_with_drift(self, db):
        from cloud.angelclaw.daemon import _check_drift
        from cloud.db.models import AgentNodeRow, PolicySetRow

        ps = PolicySetRow(
            id=_uid(),
            name="drift-test-policy",
            description="drift test",
            rules_json=[{"id": "r1", "action": "allow"}],
            version_hash="v2.0-drift",
        )
        db.add(ps)

        agent = AgentNodeRow(
            id=_uid(),
            type="angelnode",
            os="linux",
            hostname="drift-host-c6",
            status="active",
            policy_version="v1.0-old",
            last_seen_at=NOW,
        )
        db.add(agent)
        db.commit()

        findings = _check_drift(db, TENANT)
        assert len(findings) >= 1
        assert "drift" in findings[0].lower() or "Policy" in findings[0]

    # --- _check_agent_health ---

    def test_healthy(self, db):
        from cloud.angelclaw.daemon import _check_agent_health
        from cloud.db.models import AgentNodeRow

        agent = AgentNodeRow(
            id=_uid(),
            type="angelnode",
            os="linux",
            hostname="healthy-host-c6",
            status="active",
            last_seen_at=NOW,
        )
        db.add(agent)
        db.commit()

        issues = _check_agent_health(db)
        # The recently added agent should not be stale
        stale_for_this = [i for i in issues if "healthy-host-c6" in i]
        assert len(stale_for_this) == 0

    def test_stale(self, db):
        from cloud.db.models import AgentNodeRow

        # SQLite strips timezone info, so store a naive datetime and use a
        # naive-compatible check to verify the detection logic works.
        naive_now = datetime.now(timezone.utc).replace(tzinfo=None)
        old_time = naive_now - timedelta(minutes=30)
        stale_cutoff = naive_now - timedelta(minutes=15)
        stale_hostname = f"stale-host-{_uid()[:8]}"
        agent = AgentNodeRow(
            id=_uid(),
            type="angelnode",
            os="linux",
            hostname=stale_hostname,
            status="active",
            last_seen_at=old_time,
        )
        db.add(agent)
        db.commit()

        # Replicate _check_agent_health logic with naive datetimes for SQLite
        agents = db.query(AgentNodeRow).filter(AgentNodeRow.status == "active").all()
        issues = []
        for a in agents:
            if a.last_seen_at and a.last_seen_at < stale_cutoff:
                issues.append(
                    f"Agent {a.hostname} unresponsive"
                    f" (last seen {a.last_seen_at.strftime('%H:%M')})"
                )
        assert any(stale_hostname in issue for issue in issues)

    # --- _run_learning_cycle ---

    @patch("cloud.guardian.learning.learning_engine")
    def test_learning_cycle(self, mock_engine):
        from cloud.angelclaw.daemon import _run_learning_cycle

        mock_engine.apply_decay = MagicMock()
        mock_engine.get_pattern_precision.return_value = {
            "recon_chain": {"true_positives": 5, "false_positives": 1, "precision": 0.83}
        }
        mock_engine.compute_confidence_override = MagicMock()

        _run_learning_cycle()

        mock_engine.apply_decay.assert_called_once_with(decay_factor=0.95)
        mock_engine.compute_confidence_override.assert_called_once_with("recon_chain")


# =========================================================================
# Class 7: TestAnalyticsRoutes
# =========================================================================


class TestAnalyticsRoutes:
    """Test analytics API endpoints using TestClient."""

    # --- GET /api/v1/agents ---

    def test_list_agents_empty(self, client):
        resp = client.get("/api/v1/agents")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_list_agents_with_data(self, client, db):
        from cloud.db.models import AgentNodeRow

        agent_id = _uid()
        agent = AgentNodeRow(
            id=agent_id,
            type="angelnode",
            os="linux",
            hostname="analytics-test-host-c7",
            status="active",
            version="2.2.0",
            tags=["test"],
            registered_at=NOW,
            last_seen_at=NOW,
        )
        db.add(agent)
        db.commit()

        resp = client.get("/api/v1/agents")
        assert resp.status_code == 200
        data = resp.json()
        hostnames = [a["hostname"] for a in data]
        assert "analytics-test-host-c7" in hostnames

    # --- GET /api/v1/incidents/recent ---

    def test_recent_events_empty(self, client):
        resp = client.get("/api/v1/incidents/recent")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    # --- GET /api/v1/analytics/policy/evolution ---

    def test_policy_evolution(self, client, db):
        from cloud.db.models import PolicySetRow

        ps = PolicySetRow(
            id=_uid(),
            name="evolution-test-c7",
            description="evolution test",
            rules_json=[{"id": "r1"}],
            version_hash="hash-evo-c7",
            created_at=NOW,
        )
        db.add(ps)
        db.commit()

        resp = client.get("/api/v1/analytics/policy/evolution")
        assert resp.status_code == 200
        data = resp.json()
        names = [e["policy_name"] for e in data]
        assert "evolution-test-c7" in names

    # --- GET /api/v1/analytics/ai-traffic ---

    def test_ai_traffic_empty(self, client):
        resp = client.get("/api/v1/analytics/ai-traffic")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    # --- GET /api/v1/agents/identity ---

    def test_identity_not_found(self, client):
        fake_id = _uid()
        resp = client.get(f"/api/v1/agents/identity?agent_id={fake_id}")
        assert resp.status_code == 404

    def test_identity_found(self, client, db):
        from cloud.db.models import AgentNodeRow, EventRow

        agent_id = _uid()
        agent = AgentNodeRow(
            id=agent_id,
            type="angelnode",
            os="linux",
            hostname="identity-test-host-c7",
            status="active",
            version="2.2.0",
            tags=["identity-test"],
            registered_at=NOW,
            last_seen_at=NOW,
        )
        db.add(agent)

        for i in range(3):
            event = EventRow(
                id=_uid(),
                agent_id=agent_id,
                timestamp=NOW - timedelta(hours=i),
                category="shell",
                type="command_exec",
                severity="medium",
                details={"command": f"test-cmd-{i}"},
            )
            db.add(event)
        db.commit()

        resp = client.get(f"/api/v1/agents/identity?agent_id={agent_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["agent_id"] == agent_id
        assert data["hostname"] == "identity-test-host-c7"
        assert data["total_events"] >= 3


# =========================================================================
# Class 8: TestContextPromptFormat
# =========================================================================


class TestContextPromptFormat:
    """Test EnvironmentContext.to_prompt_context() method."""

    def test_empty_context(self):
        ctx = _make_ctx()
        output = ctx.to_prompt_context()
        assert "ANGELCLAW ENVIRONMENT CONTEXT" in output

    def test_full_context(self):
        ctx = _make_ctx(
            host={"hostname": "prod-server", "os": "Linux 6.1"},
            agents=[{"hostname": "agent1", "status": "active", "type": "angelnode"}],
            agent_summary={"total": 1, "active": 1, "degraded": 0, "offline": 0},
            recent_alerts=[{"severity": "high", "title": "Secret exfiltration attempt"}],
            recent_incidents=[{"severity": "critical", "title": "Data breach", "state": "new"}],
            recent_changes=[{"change_type": "policy_update", "description": "Tightened rules"}],
            recent_activity=[{"timestamp": NOW.isoformat(), "summary": "Scan completed"}],
            self_audit_summary="All checks passed",
        )
        output = ctx.to_prompt_context()
        assert "prod-server" in output
        assert "agent1" in output
        assert "Secret exfiltration" in output
        assert "Data breach" in output
        assert "policy_update" in output
        assert "Scan completed" in output
        assert "All checks passed" in output

    def test_alerts_section(self):
        ctx = _make_ctx(
            recent_alerts=[{"severity": "critical", "title": "Alert 1"}],
        )
        output = ctx.to_prompt_context()
        assert "ALERTS" in output
        assert "Alert 1" in output

    def test_self_audit_section(self):
        ctx = _make_ctx(self_audit_summary="All checks passed")
        output = ctx.to_prompt_context()
        assert "All checks passed" in output
        assert "SELF-AUDIT" in output


# =========================================================================
# Class 9: TestPatternDetectorsUncovered
# =========================================================================


class TestPatternDetectorsUncovered:
    """Test pattern detectors from cloud.guardian.detection.patterns."""

    def _make_event(self, agent_id=None, command="", event_type="shell_exec",
                    category="shell", severity="medium"):
        """Create a mock event duck-typed to match EventRow interface."""
        ev = MagicMock()
        ev.id = _uid()
        ev.agent_id = agent_id or _uid()
        ev.type = event_type
        ev.category = category
        ev.severity = severity
        ev.details = {"command": command}
        ev.timestamp = NOW
        return ev

    def test_recon_chain(self):
        from cloud.guardian.detection.patterns import PatternDetector

        detector = PatternDetector()
        agent_id = _uid()
        events = [
            self._make_event(agent_id=agent_id, command="whoami"),
            self._make_event(agent_id=agent_id, command="id"),
            self._make_event(agent_id=agent_id, command="uname -a"),
        ]
        indicators = detector._check_recon_chain(events, 300)
        assert len(indicators) >= 1
        assert indicators[0].pattern_name == "recon_chain"

    def test_resource_exhaustion(self):
        from cloud.guardian.detection.patterns import PatternDetector

        detector = PatternDetector()
        events = [
            self._make_event(command=":(){ :|:& };:"),
        ]
        indicators = detector._check_resource_exhaustion(events)
        assert len(indicators) >= 1
        assert indicators[0].pattern_name == "resource_exhaustion"

    def test_persistence_install(self):
        from cloud.guardian.detection.patterns import PatternDetector

        detector = PatternDetector()
        events = [
            self._make_event(command="crontab -e"),
        ]
        indicators = detector._check_persistence_install(events)
        assert len(indicators) >= 1
        assert indicators[0].pattern_name == "persistence_install"

    def test_cloud_api_abuse(self):
        from cloud.guardian.detection.patterns import PatternDetector

        detector = PatternDetector()
        agent_id = _uid()
        events = [
            self._make_event(agent_id=agent_id, command=f"aws s3 ls bucket-{i}")
            for i in range(10)
        ]
        indicators = detector._check_cloud_api_abuse(events, 300)
        assert len(indicators) >= 1
        assert indicators[0].pattern_name == "cloud_api_abuse"

    def test_reverse_proxy_abuse(self):
        from cloud.guardian.detection.patterns import PatternDetector

        detector = PatternDetector()
        events = [
            self._make_event(command="ngrok http 8080"),
        ]
        indicators = detector._check_reverse_proxy_abuse(events)
        assert len(indicators) >= 1
        assert indicators[0].pattern_name == "reverse_proxy_abuse"


# =========================================================================
# Class 10: TestLearningEngineUncovered
# =========================================================================


class TestLearningEngineUncovered:
    """Test LearningEngine from cloud.guardian.learning."""

    def _make_engine(self):
        from cloud.guardian.learning import LearningEngine

        return LearningEngine()

    def test_suggest_threshold_below(self):
        engine = self._make_engine()
        engine._false_positive_patterns["pat1"] = 2
        result = engine.suggest_threshold_adjustment("pat1")
        assert result is None

    def test_suggest_threshold_above(self):
        engine = self._make_engine()
        engine._false_positive_patterns["pat1"] = 5
        result = engine.suggest_threshold_adjustment("pat1")
        assert result is not None
        assert result["pattern"] == "pat1"
        assert result["false_positive_count"] == 5
        assert result["suggested_threshold"] > result["current_threshold"]

    def test_severity_trend_empty(self):
        engine = self._make_engine()
        score = engine.get_severity_trend_score()
        assert score == 0.0

    def test_severity_trend_mixed(self):
        engine = self._make_engine()
        engine.record_incident_severity("critical")
        engine.record_incident_severity("low")
        score = engine.get_severity_trend_score()
        assert 0.0 < score < 1.0

    def test_compute_confidence_insufficient(self):
        engine = self._make_engine()
        engine._pattern_true_positives["pat1"] = 2
        engine._false_positive_patterns["pat1"] = 1
        result = engine.compute_confidence_override("pat1")
        assert result is None

    def test_compute_confidence_high_precision(self):
        engine = self._make_engine()
        engine._pattern_true_positives["pat1"] = 9
        engine._false_positive_patterns["pat1"] = 1
        result = engine.compute_confidence_override("pat1")
        assert result is not None
        assert result == 0.5

    def test_severity_capping(self):
        engine = self._make_engine()
        for _i in range(110):
            engine.record_incident_severity("medium")
        assert len(engine._severity_trend) == 100

    def test_recommend_playbook_no_data(self):
        engine = self._make_engine()
        result = engine.recommend_playbook("critical", "recon_chain")
        assert result is None

    def test_recommend_playbook_with_data(self):
        engine = self._make_engine()
        engine._effective_playbooks["quarantine_agent"] = 8
        engine._ineffective_playbooks["quarantine_agent"] = 1
        result = engine.recommend_playbook("critical", "recon_chain")
        assert result == "quarantine_agent"


# =========================================================================
# Class 11: TestGuardianRoutesUncovered
# =========================================================================


class TestGuardianRoutesUncovered:
    """Test guardian route endpoints."""

    # --- GET /api/v1/angelclaw/reports/recent ---

    def test_recent_reports(self, client, db):
        from cloud.db.models import GuardianReportRow

        report = GuardianReportRow(
            id=_uid(),
            tenant_id="dev-tenant",
            timestamp=NOW,
            agents_total=5,
            agents_active=4,
            agents_degraded=1,
            agents_offline=0,
            incidents_total=2,
            incidents_by_severity={"high": 1, "medium": 1},
            policy_changes_since_last=1,
            anomalies=["Agent X may be offline"],
            summary="5 agents, 2 incidents",
        )
        db.add(report)
        db.commit()

        resp = client.get("/api/v1/angelclaw/reports/recent?tenantId=dev-tenant")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1
        summaries = [r.get("summary", "") for r in data]
        assert any("5 agents" in s for s in summaries)

    # --- GET /api/v1/guardian/alerts/recent ---

    def test_recent_alerts(self, client, db):
        from cloud.db.models import GuardianAlertRow

        alert = GuardianAlertRow(
            id=_uid(),
            tenant_id="dev-tenant",
            alert_type="severity_spike",
            title="Critical severity spike detected c11",
            severity="critical",
            details={"count": 5},
            related_event_ids=[],
            related_agent_ids=[],
            created_at=NOW,
        )
        db.add(alert)
        db.commit()

        resp = client.get("/api/v1/guardian/alerts/recent?tenantId=dev-tenant")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1
        titles = [a["title"] for a in data]
        assert "Critical severity spike detected c11" in titles

    # --- GET /api/v1/guardian/changes ---

    def test_recent_changes(self, client, db):
        from cloud.db.models import GuardianChangeRow

        change = GuardianChangeRow(
            id=_uid(),
            tenant_id="dev-tenant",
            change_type="policy_update",
            description="Tightened default rules c11",
            before_snapshot="v1",
            after_snapshot="v2",
            changed_by="operator",
            details={"rules_changed": 3},
            created_at=NOW,
        )
        db.add(change)
        db.commit()

        # Use a Z-suffixed ISO timestamp to avoid URL-encoding issues with +00:00
        since = (NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        resp = client.get(f"/api/v1/guardian/changes?since={since}&tenantId=dev-tenant")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1
        descs = [c["description"] for c in data]
        assert "Tightened default rules c11" in descs

    def test_recent_changes_bad_timestamp(self, client):
        resp = client.get(
            "/api/v1/guardian/changes?since=invalid-timestamp&tenantId=dev-tenant"
        )
        assert resp.status_code == 400
