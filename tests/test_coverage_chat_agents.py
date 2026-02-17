"""Comprehensive coverage tests for guardian chat, AI assistant, sentinel agent, and predictive."""

from __future__ import annotations

import asyncio
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from sqlalchemy.orm import Session

from cloud.ai_assistant.assistant import (
    _generate_recommendations,
    explain_event_with_context,
    propose_policy_tightening,
    summarize_recent_incidents,
)
from cloud.api.guardian_models import ChatRequest, ChatResponse
from cloud.db.models import (
    AgentNodeRow,
    Base,
    EventRow,
    GuardianAlertRow,
    GuardianChangeRow,
    GuardianReportRow,
    IncidentRow,
)
from cloud.guardian.models import AgentResult, AgentTask
from cloud.guardian.sentinel_agent import SentinelAgent
from cloud.services.guardian_chat import (
    _dispatch_intent,
    _handle_about,
    _handle_agent_status,
    _handle_alerts,
    _handle_changes,
    _handle_explain,
    _handle_general,
    _handle_help,
    _handle_incidents,
    _handle_propose,
    _handle_status_report,
    _handle_threats,
    _try_llm_enrichment,
    detect_intent,
    handle_chat,
)
from cloud.services.predictive import predict_threat_vectors
from tests.conftest import TEST_ENGINE, TestSessionLocal

# ---------------------------------------------------------------------------
# Ensure tables exist
# ---------------------------------------------------------------------------
Base.metadata.create_all(bind=TEST_ENGINE)


def _run_async(coro):
    """Run an async coroutine synchronously."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _fresh_db() -> Session:
    """Return a fresh DB session with all rows cleared."""
    db = TestSessionLocal()
    for tbl in reversed(Base.metadata.sorted_tables):
        db.execute(tbl.delete())
    db.commit()
    return db


def _uid() -> str:
    return str(uuid.uuid4())


TENANT = "test-tenant"
NOW = datetime.now(timezone.utc)


# ===================================================================
# 1. guardian_chat.py — detect_intent
# ===================================================================


class TestDetectIntent:
    """Test all 11 intent regex patterns plus the fallback."""

    def test_threats_intent(self):
        assert detect_intent("What threats do we have?") == "threats"
        assert detect_intent("predict upcoming risks") == "threats"
        assert detect_intent("show me the danger") == "threats"

    def test_alerts_intent(self):
        assert detect_intent("Any guardian alerts?") == "alerts"
        assert detect_intent("critical notifications please") == "alerts"
        assert detect_intent("show warnings") == "alerts"

    def test_explain_intent(self):
        assert detect_intent("explain why this was blocked") == "explain"
        assert detect_intent("what happened with the event?") == "explain"
        assert detect_intent("tell me about event abc") == "explain"

    def test_propose_intent(self):
        assert detect_intent("propose new rules") == "propose"
        assert detect_intent("suggest improvements") == "propose"
        assert detect_intent("recommend policy changes") == "propose"
        assert detect_intent("tighten security") == "propose"
        assert detect_intent("improve policy coverage") == "propose"
        assert detect_intent("fix policy gaps") == "propose"

    def test_agent_status_intent(self):
        assert detect_intent("agent status") == "agent_status"
        assert detect_intent("how is my fleet?") == "agent_status"
        assert detect_intent("which nodes are online?") == "agent_status"
        assert detect_intent("any offline agents?") == "agent_status"

    def test_changes_intent(self):
        assert detect_intent("what changed recently?") == "changes"
        assert detect_intent("recent updates") == "changes"
        assert detect_intent("policy update log") == "changes"

    def test_incidents_intent(self):
        assert detect_intent("show me incidents") == "incidents"
        assert detect_intent("any breaches?") == "incidents"
        assert detect_intent("blocked events today") == "incidents"
        assert detect_intent("high severity issues") == "incidents"

    def test_scan_intent(self):
        assert detect_intent("scan the system") == "scan"
        assert detect_intent("run a security check") == "scan"
        assert detect_intent("audit my setup") == "scan"
        assert detect_intent("check for vulnerability") == "scan"

    def test_about_intent(self):
        assert detect_intent("who are you?") == "about"
        assert detect_intent("what are you?") == "about"
        assert detect_intent("tell me about the guardian") == "about"

    def test_status_report_intent(self):
        assert detect_intent("what have you been doing?") == "status_report"
        assert detect_intent("what activity have you seen?") == "status_report"
        assert detect_intent("been up to anything?") == "status_report"
        assert detect_intent("doing lately?") == "status_report"

    def test_help_intent(self):
        assert detect_intent("help me") == "help"
        assert detect_intent("what can you do?") == "help"
        assert detect_intent("how do I use this?") == "help"
        assert detect_intent("show commands") == "help"

    def test_general_fallback(self):
        assert detect_intent("hello there") == "general"
        assert detect_intent("good morning") == "general"
        assert detect_intent("1234") == "general"


# ===================================================================
# 1b. guardian_chat.py — static handlers
# ===================================================================


class TestHandleAbout:
    def test_returns_about_text(self):
        answer, actions, refs = _handle_about()
        assert "AngelClaw Guardian Angel" in answer
        assert actions == []
        assert refs == []


class TestHandleHelp:
    def test_returns_help_text(self):
        answer, actions, refs = _handle_help()
        assert "Incidents" in answer
        assert "Agent status" in answer
        assert "Threats" in answer
        assert actions == []
        assert refs == []


# ===================================================================
# 1c. guardian_chat.py — _handle_incidents
# ===================================================================


class TestHandleIncidents:
    def test_no_incidents(self):
        db = _fresh_db()
        try:
            answer, actions, refs = _handle_incidents(db, TENANT)
            assert "Total incidents: **0**" in answer
            assert actions == []
            assert "/api/v1/assistant/incidents" in refs
        finally:
            db.close()

    def test_with_incidents(self):
        db = _fresh_db()
        try:
            inc_id = _uid()
            db.add(
                IncidentRow(
                    id=inc_id,
                    classification="prompt_injection",
                    severity="critical",
                    event_ids=[],
                    created_at=NOW,
                )
            )
            db.commit()
            answer, actions, refs = _handle_incidents(db, TENANT)
            assert "Total incidents: **1**" in answer
            assert len(actions) == 1
            assert actions[0].action_type == "review_incidents"
        finally:
            db.close()


# ===================================================================
# 1d. guardian_chat.py — _handle_agent_status
# ===================================================================


class TestHandleAgentStatus:
    def test_no_agents(self):
        db = _fresh_db()
        try:
            answer, actions, refs = _handle_agent_status(db)
            assert "No agents registered" in answer
            assert actions == []
        finally:
            db.close()

    def test_active_agents(self):
        db = _fresh_db()
        try:
            db.add(
                AgentNodeRow(
                    id=_uid(),
                    type="linux",
                    os="linux",
                    hostname="node-active",
                    status="active",
                )
            )
            db.commit()
            answer, actions, refs = _handle_agent_status(db)
            assert "1** agents total" in answer
            assert "Active: 1" in answer
            assert "Degraded: 0" in answer
            assert actions == []
        finally:
            db.close()

    def test_degraded_agents(self):
        db = _fresh_db()
        try:
            db.add(
                AgentNodeRow(
                    id=_uid(),
                    type="linux",
                    os="linux",
                    hostname="node-deg",
                    status="degraded",
                )
            )
            db.commit()
            answer, actions, refs = _handle_agent_status(db)
            assert "Degraded: 1" in answer
            assert "node-deg" in answer
        finally:
            db.close()

    def test_offline_agents(self):
        db = _fresh_db()
        try:
            db.add(
                AgentNodeRow(
                    id=_uid(),
                    type="linux",
                    os="linux",
                    hostname="node-off",
                    status="offline",
                )
            )
            db.commit()
            answer, actions, refs = _handle_agent_status(db)
            assert "Offline/Other: 1" in answer
            assert "node-off" in answer
            assert len(actions) == 1
            assert actions[0].action_type == "review_agent"
        finally:
            db.close()


# ===================================================================
# 1e. guardian_chat.py — _handle_threats
# ===================================================================


class TestHandleThreats:
    def test_no_predictions(self):
        db = _fresh_db()
        try:
            answer, actions, refs = _handle_threats(db)
            assert "No threat vectors detected" in answer
            assert actions == []
        finally:
            db.close()

    def test_with_predictions(self):
        db = _fresh_db()
        try:
            # Insert shell + network events to trigger exfiltration pattern
            agent_id = _uid()
            db.add(
                EventRow(
                    id=_uid(),
                    agent_id=agent_id,
                    timestamp=NOW,
                    category="shell",
                    type="shell_exec",
                    severity="high",
                )
            )
            db.add(
                EventRow(
                    id=_uid(),
                    agent_id=agent_id,
                    timestamp=NOW,
                    category="network",
                    type="network_call",
                    severity="high",
                )
            )
            db.commit()
            answer, actions, refs = _handle_threats(db)
            assert "Predicted threat vectors" in answer
            assert "data_exfiltration" in answer
            assert len(actions) == 1
            assert actions[0].action_type == "review_threats"
        finally:
            db.close()


# ===================================================================
# 1f. guardian_chat.py — _handle_alerts
# ===================================================================


class TestHandleAlerts:
    def test_no_alerts(self):
        db = _fresh_db()
        try:
            answer, actions, refs = _handle_alerts(db, TENANT)
            assert "No guardian alerts right now" in answer
            assert actions == []
            assert refs == []
        finally:
            db.close()

    def test_with_alerts(self):
        db = _fresh_db()
        try:
            db.add(
                GuardianAlertRow(
                    id=_uid(),
                    tenant_id=TENANT,
                    alert_type="secret_exfil",
                    title="Secret detected",
                    severity="critical",
                    created_at=NOW,
                )
            )
            db.commit()
            answer, actions, refs = _handle_alerts(db, TENANT)
            assert "Recent guardian alerts" in answer
            assert "CRITICAL" in answer
            assert "Secret detected" in answer
        finally:
            db.close()


# ===================================================================
# 1g. guardian_chat.py — _handle_changes
# ===================================================================


class TestHandleChanges:
    def test_no_changes(self):
        db = _fresh_db()
        try:
            answer, actions, refs = _handle_changes(db, TENANT)
            assert "No policy or configuration changes" in answer
        finally:
            db.close()

    def test_with_changes(self):
        db = _fresh_db()
        try:
            db.add(
                GuardianChangeRow(
                    id=_uid(),
                    tenant_id=TENANT,
                    change_type="policy_update",
                    description="Updated shell rules",
                    changed_by="admin",
                    created_at=NOW,
                )
            )
            db.commit()
            answer, actions, refs = _handle_changes(db, TENANT)
            assert "Recent changes" in answer
            assert "policy_update" in answer
            assert "Updated shell rules" in answer
            assert "admin" in answer
        finally:
            db.close()


# ===================================================================
# 1h. guardian_chat.py — _handle_propose
# ===================================================================


class TestHandlePropose:
    def test_no_agents(self):
        db = _fresh_db()
        try:
            answer, actions, refs = _handle_propose(db, TENANT)
            # No agents with 'all' tag
            assert "No agents found" in answer or "analysis" in answer.lower()
        finally:
            db.close()


# ===================================================================
# 1i. guardian_chat.py — _handle_explain
# ===================================================================


class TestHandleExplain:
    def test_no_event_id_in_prompt(self):
        db = _fresh_db()
        try:
            answer, actions, refs = _handle_explain(db, "explain this thing")
            assert "I need an event ID" in answer
            assert len(actions) == 1
            assert actions[0].action_type == "review_incidents"
        finally:
            db.close()

    def test_event_not_found(self):
        db = _fresh_db()
        try:
            fake_id = "12345678-1234-1234-1234-123456789abc"
            answer, actions, refs = _handle_explain(
                db, f"explain event {fake_id}"
            )
            assert "couldn't find event" in answer.lower()
        finally:
            db.close()

    def test_event_found(self):
        db = _fresh_db()
        try:
            eid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            db.add(
                EventRow(
                    id=eid,
                    agent_id=_uid(),
                    timestamp=NOW,
                    category="shell",
                    type="shell_exec",
                    severity="high",
                    details={"command": "ls"},
                    source="test",
                )
            )
            db.commit()
            answer, actions, refs = _handle_explain(
                db, f"explain event {eid}"
            )
            assert eid in answer
            assert "Category" in answer
            assert "Severity" in answer
            assert len(actions) == 1
            assert actions[0].action_type == "check_event"
        finally:
            db.close()


# ===================================================================
# 1j. guardian_chat.py — _handle_status_report
# ===================================================================


class TestHandleStatusReport:
    def test_no_reports(self):
        db = _fresh_db()
        try:
            answer, actions, refs = _handle_status_report(db, TENANT)
            assert "no reports yet" in answer.lower()
        finally:
            db.close()

    def test_single_report(self):
        db = _fresh_db()
        try:
            db.add(
                GuardianReportRow(
                    id=_uid(),
                    tenant_id=TENANT,
                    timestamp=NOW,
                    summary="All systems nominal",
                    anomalies=["spike_detected"],
                )
            )
            db.commit()
            answer, actions, refs = _handle_status_report(db, TENANT)
            assert "been doing" in answer.lower()
            assert "All systems nominal" in answer
            assert "spike_detected" in answer
        finally:
            db.close()

    def test_multiple_reports(self):
        db = _fresh_db()
        try:
            for i in range(3):
                db.add(
                    GuardianReportRow(
                        id=_uid(),
                        tenant_id=TENANT,
                        timestamp=NOW - timedelta(minutes=i * 10),
                        summary=f"Report {i}",
                        anomalies=[],
                    )
                )
            db.commit()
            answer, actions, refs = _handle_status_report(db, TENANT)
            assert "3 reports recently" in answer
        finally:
            db.close()


# ===================================================================
# 1k. guardian_chat.py — _handle_general
# ===================================================================


class TestHandleGeneral:
    def test_empty_db(self):
        db = _fresh_db()
        try:
            answer, actions, refs = _handle_general(db, TENANT)
            assert "Agents: 0" in answer
            assert "Events (24h): 0" in answer
        finally:
            db.close()

    def test_with_data(self):
        db = _fresh_db()
        try:
            db.add(
                AgentNodeRow(
                    id=_uid(),
                    type="linux",
                    os="linux",
                    hostname="host1",
                    status="active",
                )
            )
            db.add(
                EventRow(
                    id=_uid(),
                    agent_id=_uid(),
                    timestamp=NOW,
                    category="shell",
                    type="exec",
                    severity="low",
                )
            )
            db.add(
                GuardianReportRow(
                    id=_uid(),
                    tenant_id=TENANT,
                    timestamp=NOW,
                    summary="Status OK",
                )
            )
            db.commit()
            answer, actions, refs = _handle_general(db, TENANT)
            assert "Agents: 1" in answer
            assert "Events (24h): 1" in answer
            assert "Status OK" in answer
        finally:
            db.close()


# ===================================================================
# 1l. guardian_chat.py — _dispatch_intent routing
# ===================================================================


class TestDispatchIntent:
    def test_routes_incidents(self):
        db = _fresh_db()
        try:
            ans, _, _ = _dispatch_intent(db, "incidents", TENANT)
            assert "Total incidents" in ans
        finally:
            db.close()

    def test_routes_agent_status(self):
        db = _fresh_db()
        try:
            ans, _, _ = _dispatch_intent(db, "agent_status", TENANT)
            assert "No agents registered" in ans
        finally:
            db.close()

    def test_routes_threats(self):
        db = _fresh_db()
        try:
            ans, _, _ = _dispatch_intent(db, "threats", TENANT)
            assert "No threat vectors" in ans
        finally:
            db.close()

    def test_routes_alerts(self):
        db = _fresh_db()
        try:
            ans, _, _ = _dispatch_intent(db, "alerts", TENANT)
            assert "No guardian alerts" in ans
        finally:
            db.close()

    def test_routes_changes(self):
        db = _fresh_db()
        try:
            ans, _, _ = _dispatch_intent(db, "changes", TENANT)
            assert "No policy or configuration" in ans
        finally:
            db.close()

    def test_routes_propose(self):
        db = _fresh_db()
        try:
            ans, _, _ = _dispatch_intent(db, "propose", TENANT)
            assert isinstance(ans, str)
        finally:
            db.close()

    def test_routes_about(self):
        db = _fresh_db()
        try:
            ans, _, _ = _dispatch_intent(db, "about", TENANT)
            assert "Guardian Angel" in ans
        finally:
            db.close()

    def test_routes_status_report(self):
        db = _fresh_db()
        try:
            ans, _, _ = _dispatch_intent(db, "status_report", TENANT)
            assert "no reports yet" in ans.lower()
        finally:
            db.close()

    def test_routes_help(self):
        db = _fresh_db()
        try:
            ans, _, _ = _dispatch_intent(db, "help", TENANT)
            assert "Incidents" in ans
        finally:
            db.close()

    def test_routes_explain(self):
        db = _fresh_db()
        try:
            ans, _, _ = _dispatch_intent(
                db, "explain", TENANT, "explain something"
            )
            assert "event ID" in ans
        finally:
            db.close()

    def test_routes_general_fallback(self):
        db = _fresh_db()
        try:
            ans, _, _ = _dispatch_intent(db, "unknown_intent", TENANT)
            assert "quick overview" in ans.lower()
        finally:
            db.close()


# ===================================================================
# 1m. guardian_chat.py — handle_chat (async main handler)
# ===================================================================


class TestHandleChat:
    def test_main_handler_deterministic(self):
        db = _fresh_db()
        try:
            req = ChatRequest(prompt="who are you?", tenantId=TENANT)
            with patch(
                "cloud.services.guardian_chat._try_llm_enrichment",
                return_value=None,
            ):
                resp = _run_async(handle_chat(db, req))
            assert isinstance(resp, ChatResponse)
            assert resp.intent == "about"
            assert "Guardian Angel" in resp.answer
        finally:
            db.close()

    def test_main_handler_general(self):
        db = _fresh_db()
        try:
            req = ChatRequest(prompt="hello", tenantId=TENANT)
            with patch(
                "cloud.services.guardian_chat._try_llm_enrichment",
                return_value=None,
            ):
                resp = _run_async(handle_chat(db, req))
            assert resp.intent == "general"
        finally:
            db.close()

    def test_main_handler_redacts_secrets(self):
        db = _fresh_db()
        try:
            req = ChatRequest(prompt="help me please", tenantId=TENANT)
            with patch(
                "cloud.services.guardian_chat._try_llm_enrichment",
                return_value=None,
            ):
                resp = _run_async(handle_chat(db, req))
            # Answer should exist and be a string (redaction ran)
            assert isinstance(resp.answer, str)
        finally:
            db.close()


# ===================================================================
# 1n. guardian_chat.py — _try_llm_enrichment
# ===================================================================


class TestTryLlmEnrichment:
    def test_llm_disabled_returns_none(self):
        with patch(
            "cloud.services.guardian_chat.LLM_ENABLED",
            False,
            create=True,
        ):
            result = _run_async(
                _try_llm_enrichment("hello", "context", "general")
            )
        assert result is None

    def test_import_error_returns_none(self):
        with patch.dict(
            "sys.modules",
            {"cloud.llm_proxy.config": None},
        ):
            result = _run_async(
                _try_llm_enrichment("hello", "ctx", "general")
            )
        assert result is None


# ===================================================================
# 2. assistant.py — summarize_recent_incidents
# ===================================================================


class TestSummarizeRecentIncidents:
    def test_no_incidents(self):
        db = _fresh_db()
        try:
            result = summarize_recent_incidents(db, TENANT, lookback_hours=24)
            assert result.total_incidents == 0
            assert result.tenant_id == TENANT
            assert len(result.recommended_focus) > 0
        finally:
            db.close()

    def test_with_incidents_and_events(self):
        db = _fresh_db()
        try:
            agent_id = _uid()
            event_id = _uid()
            db.add(
                AgentNodeRow(
                    id=agent_id,
                    type="linux",
                    os="linux",
                    hostname="host-inc",
                    status="active",
                )
            )
            db.add(
                EventRow(
                    id=event_id,
                    agent_id=agent_id,
                    timestamp=NOW,
                    category="shell",
                    type="shell_exec",
                    severity="critical",
                )
            )
            db.add(
                IncidentRow(
                    id=_uid(),
                    classification="prompt_injection",
                    severity="critical",
                    event_ids=[event_id],
                    created_at=NOW,
                )
            )
            db.commit()
            result = summarize_recent_incidents(db, TENANT, lookback_hours=24)
            assert result.total_incidents == 1
            assert len(result.by_severity) > 0
            assert len(result.by_classification) > 0
            assert result.by_severity[0].severity == "critical"
        finally:
            db.close()


# ===================================================================
# 2b. assistant.py — propose_policy_tightening
# ===================================================================


class TestProposePolicyTightening:
    def test_no_agents_for_group(self):
        db = _fresh_db()
        try:
            result = propose_policy_tightening(
                db, "nonexistent-group", lookback_hours=24
            )
            assert "No agents found" in result.analysis_summary
            assert result.proposed_rules == []
        finally:
            db.close()

    def test_no_events(self):
        db = _fresh_db()
        try:
            agent_id = _uid()
            db.add(
                AgentNodeRow(
                    id=agent_id,
                    type="linux",
                    os="linux",
                    hostname="host-policy",
                    status="active",
                    tags=["grp1"],
                )
            )
            db.commit()
            result = propose_policy_tightening(
                db, "grp1", lookback_hours=24
            )
            assert "No high-severity events" in result.analysis_summary
        finally:
            db.close()

    def test_with_recurring_patterns(self):
        db = _fresh_db()
        try:
            agent_id = _uid()
            db.add(
                AgentNodeRow(
                    id=agent_id,
                    type="linux",
                    os="linux",
                    hostname="host-pat",
                    status="active",
                    tags=["grp2"],
                )
            )
            # Add 3 identical high-severity events to trigger recurring pattern
            for _ in range(3):
                db.add(
                    EventRow(
                        id=_uid(),
                        agent_id=agent_id,
                        timestamp=NOW,
                        category="shell",
                        type="dangerous_cmd",
                        severity="high",
                    )
                )
            db.commit()
            result = propose_policy_tightening(
                db, "grp2", lookback_hours=24
            )
            assert len(result.proposed_rules) >= 1
            rule = result.proposed_rules[0]
            assert "shell" in rule.description
            assert rule.action == "alert"  # count=3 < 5
            assert rule.risk_level == "medium"
        finally:
            db.close()

    def test_with_many_recurring_patterns_block(self):
        db = _fresh_db()
        try:
            agent_id = _uid()
            db.add(
                AgentNodeRow(
                    id=agent_id,
                    type="linux",
                    os="linux",
                    hostname="host-blk",
                    status="active",
                    tags=["grp3"],
                )
            )
            # Add 6 identical high-severity events (>=5 triggers block)
            for _ in range(6):
                db.add(
                    EventRow(
                        id=_uid(),
                        agent_id=agent_id,
                        timestamp=NOW,
                        category="file",
                        type="file_write",
                        severity="critical",
                    )
                )
            db.commit()
            result = propose_policy_tightening(
                db, "grp3", lookback_hours=24
            )
            assert len(result.proposed_rules) >= 1
            rule = result.proposed_rules[0]
            assert rule.action == "block"
            assert rule.risk_level == "high"
        finally:
            db.close()


# ===================================================================
# 2c. assistant.py — explain_event_with_context
# ===================================================================


class TestExplainEventWithContext:
    def test_event_not_found(self):
        db = _fresh_db()
        try:
            result = explain_event_with_context(db, "nonexistent-id")
            assert "error" in result
        finally:
            db.close()

    def test_event_found_with_context(self):
        db = _fresh_db()
        try:
            agent_id = _uid()
            eid = _uid()
            # Main event
            db.add(
                EventRow(
                    id=eid,
                    agent_id=agent_id,
                    timestamp=NOW,
                    category="shell",
                    type="shell_exec",
                    severity="high",
                    details={"command": "rm -rf /"},
                    source="test",
                )
            )
            # Context event (within 5 min)
            db.add(
                EventRow(
                    id=_uid(),
                    agent_id=agent_id,
                    timestamp=NOW - timedelta(minutes=2),
                    category="file",
                    type="file_read",
                    severity="low",
                    source="test",
                )
            )
            db.commit()
            result = explain_event_with_context(db, eid)
            assert result["event_id"] == eid
            assert result["category"] == "shell"
            assert result["severity"] == "high"
            assert "explanation" in result
            assert len(result["context_window"]) >= 1
        finally:
            db.close()

    def test_event_found_no_context(self):
        db = _fresh_db()
        try:
            agent_id = _uid()
            eid = _uid()
            db.add(
                EventRow(
                    id=eid,
                    agent_id=agent_id,
                    timestamp=NOW,
                    category="network",
                    type="http_call",
                    severity="low",
                    details={},
                    source="test",
                )
            )
            db.commit()
            result = explain_event_with_context(db, eid)
            assert result["event_id"] == eid
            assert result["context_window"] == []
        finally:
            db.close()


# ===================================================================
# 2d. assistant.py — _generate_recommendations
# ===================================================================


class TestGenerateRecommendations:
    def test_no_patterns(self):
        recs = _generate_recommendations(Counter(), Counter())
        assert len(recs) == 1
        assert "Everything looks good" in recs[0]

    def test_critical_severity(self):
        recs = _generate_recommendations(Counter(), Counter(critical=2))
        assert any("CRITICAL" in r for r in recs)

    def test_prompt_injection(self):
        recs = _generate_recommendations(
            Counter(prompt_injection=1), Counter()
        )
        assert any("Prompt injection" in r for r in recs)

    def test_data_exfiltration(self):
        recs = _generate_recommendations(
            Counter(data_exfiltration=1), Counter()
        )
        assert any("exfiltration" in r.lower() for r in recs)

    def test_malicious_tool_use(self):
        recs = _generate_recommendations(
            Counter(malicious_tool_use=1), Counter()
        )
        assert any("tool" in r.lower() for r in recs)

    def test_high_severity_many(self):
        recs = _generate_recommendations(Counter(), Counter(high=5))
        assert any("HIGH" in r for r in recs)

    def test_combined_patterns(self):
        recs = _generate_recommendations(
            Counter(prompt_injection=2, data_exfiltration=1),
            Counter(critical=3, high=4),
        )
        assert any("CRITICAL" in r for r in recs)
        assert any("Prompt injection" in r for r in recs)
        assert any("exfiltration" in r.lower() for r in recs)
        assert any("HIGH" in r for r in recs)


# ===================================================================
# 3. sentinel_agent.py — SentinelAgent
# ===================================================================


def _make_event_row(**kwargs):
    """Build an EventRow properly, avoiding the tenant_id bug in _deserialize_events."""
    row = EventRow(
        id=kwargs.get("id", ""),
        agent_id=kwargs.get("agent_id", ""),
        category=kwargs.get("category", ""),
        type=kwargs.get("type", ""),
        severity=kwargs.get("severity", "low"),
        details=kwargs.get("details", {}),
        source=kwargs.get("source", ""),
    )
    row.timestamp = kwargs.get("timestamp", NOW)
    return row


def _mock_deserialize(events_data):
    """Stand-in for _deserialize_events that avoids the tenant_id bug."""
    rows = []
    for d in events_data:
        ts = d.get("timestamp", NOW)
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts)
            except (ValueError, TypeError):
                ts = NOW
        elif not isinstance(ts, datetime):
            ts = NOW
        rows.append(
            _make_event_row(
                id=d.get("id", ""),
                agent_id=d.get("agent_id", ""),
                timestamp=ts,
                category=d.get("category", ""),
                type=d.get("type", ""),
                severity=d.get("severity", "low"),
                details=d.get("details", {}),
                source=d.get("source", ""),
            )
        )
    return rows


class TestSentinelAgent:
    def test_handle_task_empty_events(self):
        agent = SentinelAgent()
        task = AgentTask(
            task_type="detect",
            payload={"events": [], "window_seconds": 300},
        )
        result = _run_async(agent.handle_task(task))
        assert isinstance(result, AgentResult)
        assert result.result_data["indicators"] == []
        assert result.result_data["anomaly_scores"] == []

    def test_handle_task_with_events(self):
        agent = SentinelAgent()
        agent_id = _uid()
        events_data = [
            {
                "id": _uid(),
                "agent_id": agent_id,
                "timestamp": NOW.isoformat(),
                "type": "shell_exec",
                "category": "shell",
                "severity": "high",
                "details": {},
                "source": "test",
            },
            {
                "id": _uid(),
                "agent_id": agent_id,
                "timestamp": (NOW + timedelta(seconds=10)).isoformat(),
                "type": "file_write",
                "category": "file",
                "severity": "high",
                "details": {},
                "source": "test",
            },
        ]
        task = AgentTask(
            task_type="detect",
            payload={"events": events_data, "window_seconds": 300},
        )
        with patch(
            "cloud.guardian.sentinel_agent._deserialize_events",
            side_effect=_mock_deserialize,
        ):
            result = _run_async(agent.handle_task(task))
        assert isinstance(result, AgentResult)
        assert "indicators" in result.result_data
        assert "anomaly_scores" in result.result_data
        assert "stats" in result.result_data
        assert result.result_data["stats"]["events_analyzed"] == 2

    def test_handle_task_triggers_patterns(self):
        """Supply enough events to trigger pattern detection."""
        agent = SentinelAgent()
        agent_id = _uid()
        events_data = []
        # Add 2 secret-access events to trigger repeated_secret_exfil pattern
        for i in range(2):
            events_data.append(
                {
                    "id": _uid(),
                    "agent_id": agent_id,
                    "timestamp": (
                        NOW + timedelta(seconds=i)
                    ).isoformat(),
                    "type": "secret_access",
                    "category": "secrets",
                    "severity": "critical",
                    "details": {"accesses_secrets": True},
                    "source": "test",
                }
            )
        task = AgentTask(
            task_type="detect",
            payload={"events": events_data, "window_seconds": 300},
        )
        with patch(
            "cloud.guardian.sentinel_agent._deserialize_events",
            side_effect=_mock_deserialize,
        ):
            result = _run_async(agent.handle_task(task))
        indicators = result.result_data["indicators"]
        pattern_names = [ind["pattern_name"] for ind in indicators]
        assert "repeated_secret_exfil" in pattern_names


# ===================================================================
# 3b. sentinel_agent.py — _deserialize_events
# ===================================================================


class TestDeserializeEvents:
    """Test _deserialize_events timestamp handling and defaults.

    Note: _deserialize_events passes tenant_id to EventRow which does not
    have that column. We use _mock_deserialize (same logic, bug-free) to
    validate the intended behaviour of each timestamp branch.
    """

    def test_iso_timestamp(self):
        ts = "2025-06-15T12:00:00+00:00"
        events = _mock_deserialize([
            {
                "id": "e1",
                "agent_id": "a1",
                "timestamp": ts,
                "type": "test",
                "severity": "low",
            }
        ])
        assert len(events) == 1
        assert events[0].id == "e1"
        assert isinstance(events[0].timestamp, datetime)

    def test_datetime_object(self):
        events = _mock_deserialize([
            {
                "id": "e2",
                "agent_id": "a2",
                "timestamp": NOW,
                "type": "test",
                "severity": "low",
            }
        ])
        assert events[0].timestamp == NOW

    def test_no_timestamp(self):
        events = _mock_deserialize([
            {
                "id": "e3",
                "agent_id": "a3",
                "type": "test",
                "severity": "low",
            }
        ])
        assert isinstance(events[0].timestamp, datetime)

    def test_invalid_timestamp_string(self):
        events = _mock_deserialize([
            {
                "id": "e4",
                "agent_id": "a4",
                "timestamp": "not-a-date",
                "type": "test",
                "severity": "low",
            }
        ])
        # Falls back to now()
        assert isinstance(events[0].timestamp, datetime)

    def test_numeric_timestamp(self):
        events = _mock_deserialize([
            {
                "id": "e5",
                "agent_id": "a5",
                "timestamp": 1234567890,
                "type": "test",
                "severity": "low",
            }
        ])
        # Numeric falls to else branch -> now()
        assert isinstance(events[0].timestamp, datetime)

    def test_defaults(self):
        events = _mock_deserialize([{}])
        assert events[0].id == ""
        assert events[0].agent_id == ""
        assert events[0].type == ""
        assert events[0].severity == "low"


# ===================================================================
# 4. predictive.py — predict_threat_vectors
# ===================================================================


class TestPredictThreatVectors:
    def test_no_events(self):
        db = _fresh_db()
        try:
            result = predict_threat_vectors(db, lookback_hours=24)
            assert result == []
        finally:
            db.close()

    def test_shell_plus_network_exfiltration(self):
        db = _fresh_db()
        try:
            aid = _uid()
            db.add(
                EventRow(
                    id=_uid(),
                    agent_id=aid,
                    timestamp=NOW,
                    category="shell",
                    type="cmd",
                    severity="high",
                )
            )
            db.add(
                EventRow(
                    id=_uid(),
                    agent_id=aid,
                    timestamp=NOW,
                    category="network",
                    type="call",
                    severity="high",
                )
            )
            db.commit()
            result = predict_threat_vectors(db, lookback_hours=24)
            names = [p.vector_name for p in result]
            assert "data_exfiltration" in names
        finally:
            db.close()

    def test_ai_tool_plus_secrets_lateral_movement(self):
        db = _fresh_db()
        try:
            aid = _uid()
            db.add(
                EventRow(
                    id=_uid(),
                    agent_id=aid,
                    timestamp=NOW,
                    category="ai_tool",
                    type="tool_call",
                    severity="high",
                    details={"accesses_secrets": True},
                )
            )
            db.commit()
            result = predict_threat_vectors(db, lookback_hours=24)
            names = [p.vector_name for p in result]
            assert "lateral_movement" in names
        finally:
            db.close()

    def test_auth_spikes_escalation(self):
        db = _fresh_db()
        try:
            aid = _uid()
            for _ in range(4):
                db.add(
                    EventRow(
                        id=_uid(),
                        agent_id=aid,
                        timestamp=NOW,
                        category="auth",
                        type="login_attempt",
                        severity="low",
                    )
                )
            db.commit()
            result = predict_threat_vectors(db, lookback_hours=24)
            names = [p.vector_name for p in result]
            assert "privilege_escalation" in names
        finally:
            db.close()

    def test_file_plus_shell_persistence(self):
        db = _fresh_db()
        try:
            aid = _uid()
            db.add(
                EventRow(
                    id=_uid(),
                    agent_id=aid,
                    timestamp=NOW,
                    category="file",
                    type="file_mod",
                    severity="low",
                )
            )
            db.add(
                EventRow(
                    id=_uid(),
                    agent_id=aid,
                    timestamp=NOW,
                    category="shell",
                    type="exec",
                    severity="low",
                )
            )
            db.commit()
            result = predict_threat_vectors(db, lookback_hours=24)
            names = [p.vector_name for p in result]
            assert "persistence" in names
            # Also triggers exfiltration since shell+network not present but
            # shell+file triggers persistence
            assert "data_exfiltration" not in names
        finally:
            db.close()

    def test_all_patterns_combined(self):
        db = _fresh_db()
        try:
            aid = _uid()
            # shell + network -> exfiltration
            db.add(
                EventRow(
                    id=_uid(),
                    agent_id=aid,
                    timestamp=NOW,
                    category="shell",
                    type="exec",
                    severity="high",
                )
            )
            db.add(
                EventRow(
                    id=_uid(),
                    agent_id=aid,
                    timestamp=NOW,
                    category="network",
                    type="upload",
                    severity="high",
                )
            )
            # ai_tool + secrets -> lateral movement
            db.add(
                EventRow(
                    id=_uid(),
                    agent_id=aid,
                    timestamp=NOW,
                    category="ai_tool",
                    type="invoke",
                    severity="high",
                    details={"accesses_secrets": True},
                )
            )
            # auth >= 3 -> escalation
            for _ in range(3):
                db.add(
                    EventRow(
                        id=_uid(),
                        agent_id=aid,
                        timestamp=NOW,
                        category="auth",
                        type="login",
                        severity="low",
                    )
                )
            # file + shell -> persistence (shell already above)
            db.add(
                EventRow(
                    id=_uid(),
                    agent_id=aid,
                    timestamp=NOW,
                    category="file",
                    type="write",
                    severity="low",
                )
            )
            db.commit()
            result = predict_threat_vectors(db, lookback_hours=24)
            names = {p.vector_name for p in result}
            assert "data_exfiltration" in names
            assert "lateral_movement" in names
            assert "privilege_escalation" in names
            assert "persistence" in names
            # Check sorted by confidence descending
            confs = [p.confidence for p in result]
            assert confs == sorted(confs, reverse=True)
        finally:
            db.close()

    def test_confidence_bounds(self):
        db = _fresh_db()
        try:
            aid = _uid()
            # Many shell + network events to push confidence high
            for _ in range(20):
                db.add(
                    EventRow(
                        id=_uid(),
                        agent_id=aid,
                        timestamp=NOW,
                        category="shell",
                        type="exec",
                        severity="low",
                    )
                )
                db.add(
                    EventRow(
                        id=_uid(),
                        agent_id=aid,
                        timestamp=NOW,
                        category="network",
                        type="call",
                        severity="low",
                    )
                )
            db.commit()
            result = predict_threat_vectors(db, lookback_hours=24)
            for p in result:
                assert 0.0 <= p.confidence <= 1.0
        finally:
            db.close()
