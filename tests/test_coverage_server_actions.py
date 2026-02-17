"""Comprehensive tests for angelnode/core/server.py, cloud/angelclaw/actions.py,
and cloud/guardian/orchestrator.py.

Targets coverage for:
- server.py: counter functions, callbacks, FastAPI endpoints, token verification
- actions.py: ActionExecutor.execute() (dry_run, unknown, real handlers), logging, history
- orchestrator.py: status, incidents, process_events, approve_incident, lifecycle
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.orm import Session

from cloud.angelclaw.actions import (
    Action,
    ActionExecutor,
    ActionLogRow,
    ActionType,
    get_action_history,
)
from cloud.angelclaw.preferences import AngelClawPreferencesRow  # noqa: F401
from cloud.db.models import (
    AgentNodeRow,
    Base,
    EventRow,
    GuardianAlertRow,
    PolicySetRow,
)
from cloud.guardian.models import (
    AgentResult,
    Incident,
    IncidentState,
    Playbook,
    ThreatIndicator,
)
from cloud.guardian.orchestrator import AngelOrchestrator
from shared.models.policy import PolicyAction
from tests.conftest import TEST_ENGINE, TestSessionLocal

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    """Run an async coroutine synchronously using a fresh event loop."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _fresh_db() -> Session:
    """Return a new test session with all tables created."""
    # Import models with their own Base registrations so tables are created
    Base.metadata.create_all(bind=TEST_ENGINE)
    # ActionLogRow and AngelClawPreferencesRow use the same Base
    ActionLogRow.metadata.create_all(bind=TEST_ENGINE)
    return TestSessionLocal()


# ===================================================================
# 1. angelnode/core/server.py
# ===================================================================


class TestServerCounters:
    """Thread-safe counter helpers in server.py."""

    def test_increment_and_get_counters(self):
        """_increment_counter updates totals; _get_counters returns a snapshot."""
        from angelnode.core import server as srv

        # Reset counters for deterministic results
        with srv._counters_lock:
            for k in srv._counters:
                srv._counters[k] = 0

        srv._increment_counter(PolicyAction.ALLOW)
        srv._increment_counter(PolicyAction.ALLOW)
        srv._increment_counter(PolicyAction.BLOCK)

        result = srv._get_counters()
        assert result["total_evaluations"] == 3
        assert result["allow"] == 2
        assert result["block"] == 1
        assert result["alert"] == 0
        assert result["audit"] == 0

    def test_increment_all_actions(self):
        """Verify every PolicyAction value increments correctly."""
        from angelnode.core import server as srv

        with srv._counters_lock:
            for k in srv._counters:
                srv._counters[k] = 0

        for action in PolicyAction:
            srv._increment_counter(action)

        counters = srv._get_counters()
        assert counters["total_evaluations"] == 4
        assert counters["allow"] == 1
        assert counters["block"] == 1
        assert counters["alert"] == 1
        assert counters["audit"] == 1

    def test_get_counters_returns_copy(self):
        """_get_counters returns a new dict, not a reference to the internal one."""
        from angelnode.core import server as srv

        c1 = srv._get_counters()
        c1["total_evaluations"] = 999999
        c2 = srv._get_counters()
        assert c2["total_evaluations"] != 999999


class TestServerCallbacks:
    """Cloud-sync callback functions in server.py."""

    def test_on_policy_update_reloads_engine(self):
        """_on_policy_update calls engine.reload when engine is set."""
        from angelnode.core import server as srv
        from shared.models.policy import PolicySet

        mock_engine = MagicMock()
        original = srv.engine
        try:
            srv.engine = mock_engine
            ps = PolicySet(name="test-policy")
            srv._on_policy_update(ps)
            mock_engine.reload.assert_called_once_with(ps)
        finally:
            srv.engine = original

    def test_on_policy_update_no_engine(self):
        """_on_policy_update is a no-op when engine is None."""
        from angelnode.core import server as srv
        from shared.models.policy import PolicySet

        original = srv.engine
        try:
            srv.engine = None
            # Should not raise
            srv._on_policy_update(PolicySet(name="noop"))
        finally:
            srv.engine = original

    def test_on_sync_log_forwards_to_logger(self):
        """_on_sync_log calls decision_logger.log_sync when logger is set."""
        from angelnode.core import server as srv

        mock_logger = MagicMock()
        original = srv.decision_logger
        try:
            srv.decision_logger = mock_logger
            details = {"sync_type": "test", "success": True}
            srv._on_sync_log(details)
            mock_logger.log_sync.assert_called_once_with(details)
        finally:
            srv.decision_logger = original

    def test_on_sync_log_no_logger(self):
        """_on_sync_log is a no-op when decision_logger is None."""
        from angelnode.core import server as srv

        original = srv.decision_logger
        try:
            srv.decision_logger = None
            srv._on_sync_log({"sync_type": "test"})
        finally:
            srv.decision_logger = original

    def test_on_agent_id_update(self):
        """_on_agent_id_update changes the global _agent_id."""
        from angelnode.core import server as srv

        original = srv._agent_id
        try:
            srv._on_agent_id_update("new-agent-123")
            assert srv._agent_id == "new-agent-123"
        finally:
            srv._agent_id = original

    def test_on_sync_timestamp(self):
        """_on_sync_timestamp updates _last_policy_sync."""
        from angelnode.core import server as srv

        original = srv._last_policy_sync
        try:
            ts = datetime(2025, 6, 15, tzinfo=timezone.utc)
            srv._on_sync_timestamp(ts)
            assert srv._last_policy_sync == ts
        finally:
            srv._last_policy_sync = original


class TestVerifyStatusToken:
    """Token verification dependency for /status."""

    def test_no_token_configured_allows_access(self):
        """When STATUS_TOKEN is None, any request is allowed."""
        from angelnode.core import server as srv

        original = srv.STATUS_TOKEN
        try:
            srv.STATUS_TOKEN = None
            result = _run(srv._verify_status_token(x_angelnode_token=None))
            assert result is None
        finally:
            srv.STATUS_TOKEN = original

    def test_valid_token_allows_access(self):
        """When STATUS_TOKEN is set and header matches, request is allowed."""
        from angelnode.core import server as srv

        original = srv.STATUS_TOKEN
        tok = "secret" + "-tok"  # noqa: S105
        try:
            srv.STATUS_TOKEN = tok
            result = _run(
                srv._verify_status_token(x_angelnode_token=tok)
            )
            assert result is None
        finally:
            srv.STATUS_TOKEN = original

    def test_invalid_token_raises_401(self):
        """When STATUS_TOKEN is set and header does not match, 401 is raised."""
        from fastapi import HTTPException

        from angelnode.core import server as srv

        original = srv.STATUS_TOKEN
        tok = "correct" + "-token"  # noqa: S105
        try:
            srv.STATUS_TOKEN = tok
            bad_tok = "wrong" + "-value"
            with pytest.raises(HTTPException) as exc_info:
                _run(
                    srv._verify_status_token(x_angelnode_token=bad_tok)
                )
            assert exc_info.value.status_code == 401
        finally:
            srv.STATUS_TOKEN = original

    def test_missing_token_raises_401(self):
        """When STATUS_TOKEN is set but header is absent, 401 is raised."""
        from fastapi import HTTPException

        from angelnode.core import server as srv

        original = srv.STATUS_TOKEN
        tok = "required" + "-token"  # noqa: S105
        try:
            srv.STATUS_TOKEN = tok
            with pytest.raises(HTTPException) as exc_info:
                _run(srv._verify_status_token(x_angelnode_token=None))
            assert exc_info.value.status_code == 401
        finally:
            srv.STATUS_TOKEN = original


class TestServerEndpoints:
    """FastAPI endpoint integration tests via TestClient."""

    @pytest.fixture(autouse=True)
    def _setup_app(self):
        """Set up a test client that bypasses lifespan initialization."""
        from unittest.mock import patch as _p

        from fastapi.testclient import TestClient

        from angelnode.core import server as srv
        from angelnode.core.engine import PolicyEngine
        from shared.models.policy import PolicySet

        # Prepare minimal engine and logger mocks
        ps = PolicySet(name="test-policy")
        self._engine = PolicyEngine(policy_set=ps)
        self._mock_logger = MagicMock()

        old_engine = srv.engine
        old_logger = srv.decision_logger
        old_sync = srv._last_policy_sync
        old_token = srv.STATUS_TOKEN
        old_agent_id = srv._agent_id

        srv.engine = self._engine
        srv.decision_logger = self._mock_logger
        srv._last_policy_sync = datetime(2025, 1, 1, tzinfo=timezone.utc)
        srv.STATUS_TOKEN = None
        srv._agent_id = "test-agent"

        # Reset counters
        with srv._counters_lock:
            for k in srv._counters:
                srv._counters[k] = 0

        # Create a TestClient without triggering the lifespan
        with _p.object(srv.app, "router"):
            pass  # TestClient below handles it

        # Use TestClient with raise_server_exceptions for clear failures
        self.client = TestClient(srv.app, raise_server_exceptions=False)

        yield

        srv.engine = old_engine
        srv.decision_logger = old_logger
        srv._last_policy_sync = old_sync
        srv.STATUS_TOKEN = old_token
        srv._agent_id = old_agent_id

    def test_health_endpoint(self):
        """GET /health returns status and policy version."""
        resp = self.client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "policy_version" in data

    def test_status_endpoint(self):
        """GET /status returns agent info, counters, and health."""
        resp = self.client.get("/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["agent_id"] == "test-agent"
        assert data["health"] == "ok"
        assert "counters" in data
        assert "policy_version" in data

    def test_evaluate_endpoint(self):
        """POST /evaluate returns a decision for a valid event."""
        event_payload = {
            "agent_id": "test-node-1",
            "category": "logging",
            "type": "emit",
            "severity": "info",
            "details": {},
        }
        resp = self.client.post("/evaluate", json=event_payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "event_id" in data
        assert "decision" in data
        assert data["decision"]["action"] in [
            "allow", "block", "alert", "audit",
        ]

    def test_evaluate_increments_counters(self):
        """POST /evaluate increments the global counters."""
        from angelnode.core import server as srv

        initial = srv._get_counters()["total_evaluations"]
        event_payload = {
            "agent_id": "test-node-1",
            "category": "logging",
            "type": "emit",
            "severity": "info",
        }
        self.client.post("/evaluate", json=event_payload)
        updated = srv._get_counters()["total_evaluations"]
        assert updated == initial + 1

    def test_evaluate_no_engine_returns_503(self):
        """POST /evaluate returns 503 when engine is None."""
        from angelnode.core import server as srv

        original = srv.engine
        try:
            srv.engine = None
            event_payload = {
                "agent_id": "test-node-1",
                "category": "shell",
                "type": "exec",
                "severity": "high",
            }
            resp = self.client.post("/evaluate", json=event_payload)
            assert resp.status_code == 503
        finally:
            srv.engine = original


# ===================================================================
# 2. cloud/angelclaw/actions.py
# ===================================================================


class TestActionExecutorDryRun:
    """ActionExecutor.execute() with dry_run=True."""

    def test_dry_run_returns_proposed(self):
        """A dry-run action returns success with a DRY RUN message."""
        db = _fresh_db()
        try:
            executor = ActionExecutor()
            action = Action(
                action_type=ActionType.SET_SCAN_FREQUENCY,
                description="Set scan to 5 minutes",
                params={"frequency_minutes": 5},
                dry_run=True,
            )
            result = _run(executor.execute(action, db, "test-tenant"))
            assert result.success is True
            assert "DRY RUN" in result.message
            assert result.action_id == action.id
        finally:
            db.rollback()
            db.close()

    def test_dry_run_logs_proposed_status(self):
        """A dry-run action is persisted with status='proposed'."""
        db = _fresh_db()
        try:
            executor = ActionExecutor()
            action = Action(
                action_type=ActionType.SET_AUTONOMY_LEVEL,
                description="Change autonomy",
                dry_run=True,
            )
            _run(executor.execute(action, db, "test-tenant"))
            row = db.query(ActionLogRow).filter_by(id=action.id).first()
            assert row is not None
            assert row.status == "proposed"
        finally:
            db.rollback()
            db.close()


class TestActionExecutorUnknown:
    """ActionExecutor.execute() with unknown action types."""

    def test_unknown_action_type_returns_failure(self):
        """An unknown action type produces a failure result."""
        db = _fresh_db()
        try:
            executor = ActionExecutor()
            # Manually inject an action whose type is not in handlers
            action = Action(
                action_type=ActionType.RUN_SCAN,
                description="Run a scan",
                dry_run=False,
            )
            # Remove the handler to simulate unknown
            original = executor._handlers.pop(ActionType.RUN_SCAN, None)
            result = _run(executor.execute(action, db, "test-tenant"))
            assert result.success is False
            assert "Unknown action type" in result.message
            # Restore
            if original:
                executor._handlers[ActionType.RUN_SCAN] = original
        finally:
            db.rollback()
            db.close()


class TestActionExecutorHandlers:
    """ActionExecutor real handler paths."""

    def test_set_scan_frequency(self):
        """set_scan_frequency handler updates preferences via DB."""
        db = _fresh_db()
        try:
            executor = ActionExecutor()
            action = Action(
                action_type=ActionType.SET_SCAN_FREQUENCY,
                description="Set scan freq",
                params={"frequency_minutes": 15},
                dry_run=False,
            )
            result = _run(
                executor.execute(action, db, "test-tenant", "api")
            )
            assert result.success is True
            assert "15" in result.message
            assert result.after_state.get("scan_frequency_minutes") == 15
        finally:
            db.rollback()
            db.close()

    def test_set_autonomy_level(self):
        """set_autonomy_level handler sets the autonomy level."""
        db = _fresh_db()
        try:
            executor = ActionExecutor()
            action = Action(
                action_type=ActionType.SET_AUTONOMY_LEVEL,
                description="Set autonomy",
                params={"level": "observe_only"},
                dry_run=False,
            )
            result = _run(
                executor.execute(action, db, "test-tenant", "cli")
            )
            assert result.success is True
            assert "observe_only" in result.message
        finally:
            db.rollback()
            db.close()

    def test_set_reporting_level(self):
        """set_reporting_level handler updates reporting level."""
        db = _fresh_db()
        try:
            executor = ActionExecutor()
            action = Action(
                action_type=ActionType.SET_REPORTING_LEVEL,
                description="Set reporting",
                params={"level": "verbose"},
                dry_run=False,
            )
            result = _run(
                executor.execute(action, db, "test-tenant", "chat")
            )
            assert result.success is True
            assert "verbose" in result.message
        finally:
            db.rollback()
            db.close()

    def test_tighten_policy_no_policy_found(self):
        """tighten_policy returns failure when no PolicySetRow exists."""
        db = _fresh_db()
        try:
            executor = ActionExecutor()
            action = Action(
                action_type=ActionType.TIGHTEN_POLICY_RULE,
                description="Tighten rule",
                params={"rule_id": "r1", "new_action": "block"},
                dry_run=False,
            )
            result = _run(
                executor.execute(action, db, "test-tenant")
            )
            assert result.success is False
            assert "No policy found" in result.message
        finally:
            db.rollback()
            db.close()

    def test_tighten_policy_rule_not_found(self):
        """tighten_policy returns failure when rule_id is not in rules_json."""
        db = _fresh_db()
        try:
            ps = PolicySetRow(
                id=str(uuid.uuid4()),
                name="test-policy",
                rules_json=[{"id": "other-rule", "action": "allow"}],
                version_hash="abc123",
            )
            db.add(ps)
            db.commit()

            executor = ActionExecutor()
            action = Action(
                action_type=ActionType.TIGHTEN_POLICY_RULE,
                params={"rule_id": "missing-rule", "new_action": "block"},
                dry_run=False,
            )
            result = _run(executor.execute(action, db, "test-tenant"))
            assert result.success is False
            assert "not found" in result.message
        finally:
            db.rollback()
            db.close()

    def test_tighten_policy_success(self):
        """tighten_policy modifies the matching rule's action."""
        db = _fresh_db()
        try:
            # Clear any leftover policy rows so .first() finds ours
            db.query(PolicySetRow).delete()
            db.commit()

            rule_id = "rule-to-tighten"
            ps = PolicySetRow(
                id=str(uuid.uuid4()),
                name="test-policy",
                rules_json=[
                    {"id": rule_id, "action": "alert", "enabled": True},
                ],
                version_hash="def456",
            )
            db.add(ps)
            db.commit()

            executor = ActionExecutor()
            action = Action(
                action_type=ActionType.TIGHTEN_POLICY_RULE,
                params={"rule_id": rule_id, "new_action": "block"},
                dry_run=False,
            )
            result = _run(executor.execute(action, db, "test-tenant"))
            assert result.success is True
            assert "block" in result.message
        finally:
            db.rollback()
            db.close()

    def test_toggle_rule_enable(self):
        """ENABLE_RULE toggles a rule to enabled."""
        db = _fresh_db()
        try:
            db.query(PolicySetRow).delete()
            db.commit()

            rule_id = "toggle-me"
            ps = PolicySetRow(
                id=str(uuid.uuid4()),
                name="test-policy",
                rules_json=[
                    {"id": rule_id, "action": "block", "enabled": False},
                ],
                version_hash="ghi789",
            )
            db.add(ps)
            db.commit()

            executor = ActionExecutor()
            action = Action(
                action_type=ActionType.ENABLE_RULE,
                params={"rule_id": rule_id},
                dry_run=False,
            )
            result = _run(executor.execute(action, db, "test-tenant"))
            assert result.success is True
            assert "enabled" in result.message
        finally:
            db.rollback()
            db.close()

    def test_toggle_rule_disable(self):
        """DISABLE_RULE toggles a rule to disabled."""
        db = _fresh_db()
        try:
            db.query(PolicySetRow).delete()
            db.commit()

            rule_id = "disable-me"
            ps = PolicySetRow(
                id=str(uuid.uuid4()),
                name="test-policy",
                rules_json=[
                    {"id": rule_id, "action": "alert", "enabled": True},
                ],
                version_hash="jkl012",
            )
            db.add(ps)
            db.commit()

            executor = ActionExecutor()
            action = Action(
                action_type=ActionType.DISABLE_RULE,
                params={"rule_id": rule_id},
                dry_run=False,
            )
            result = _run(executor.execute(action, db, "test-tenant"))
            assert result.success is True
            assert "disabled" in result.message
        finally:
            db.rollback()
            db.close()

    def test_toggle_rule_not_found(self):
        """ENABLE_RULE returns failure when rule is not in policy."""
        db = _fresh_db()
        try:
            ps = PolicySetRow(
                id=str(uuid.uuid4()),
                name="test-policy",
                rules_json=[{"id": "other", "action": "block"}],
                version_hash="mno345",
            )
            db.add(ps)
            db.commit()

            executor = ActionExecutor()
            action = Action(
                action_type=ActionType.ENABLE_RULE,
                params={"rule_id": "nonexistent"},
                dry_run=False,
            )
            result = _run(executor.execute(action, db, "test-tenant"))
            assert result.success is False
            assert "not found" in result.message
        finally:
            db.rollback()
            db.close()

    def test_tag_agent_success(self):
        """tag_agent adds a tag to an existing agent."""
        db = _fresh_db()
        try:
            agent_id = str(uuid.uuid4())
            agent = AgentNodeRow(
                id=agent_id,
                type="server",
                os="linux",
                hostname="test-host",
                tags=[],
                status="active",
            )
            db.add(agent)
            db.commit()

            executor = ActionExecutor()
            action = Action(
                action_type=ActionType.TAG_AGENT,
                params={"agent_id": agent_id, "tag": "reviewed"},
                dry_run=False,
            )
            result = _run(executor.execute(action, db, "test-tenant"))
            assert result.success is True
            assert "tagged" in result.message
            assert "reviewed" in result.after_state.get("tags", [])
        finally:
            db.rollback()
            db.close()

    def test_tag_agent_not_found(self):
        """tag_agent returns failure if agent does not exist."""
        db = _fresh_db()
        try:
            executor = ActionExecutor()
            action = Action(
                action_type=ActionType.TAG_AGENT,
                params={"agent_id": "nonexistent-id", "tag": "test"},
                dry_run=False,
            )
            result = _run(executor.execute(action, db, "test-tenant"))
            assert result.success is False
            assert "not found" in result.message
        finally:
            db.rollback()
            db.close()

    def test_quarantine_agent_success(self):
        """quarantine_agent sets status to degraded and adds tag."""
        db = _fresh_db()
        try:
            agent_id = str(uuid.uuid4())
            agent = AgentNodeRow(
                id=agent_id,
                type="server",
                os="linux",
                hostname="host-q",
                tags=[],
                status="active",
            )
            db.add(agent)
            db.commit()

            executor = ActionExecutor()
            action = Action(
                action_type=ActionType.QUARANTINE_AGENT,
                params={"agent_id": agent_id},
                dry_run=False,
            )
            result = _run(executor.execute(action, db, "test-tenant"))
            assert result.success is True
            assert "quarantined" in result.message
            assert result.after_state["status"] == "degraded"
        finally:
            db.rollback()
            db.close()

    def test_quarantine_agent_not_found(self):
        """quarantine_agent returns failure if agent does not exist."""
        db = _fresh_db()
        try:
            executor = ActionExecutor()
            action = Action(
                action_type=ActionType.QUARANTINE_AGENT,
                params={"agent_id": "ghost-agent"},
                dry_run=False,
            )
            result = _run(executor.execute(action, db, "test-tenant"))
            assert result.success is False
            assert "not found" in result.message
        finally:
            db.rollback()
            db.close()

    def test_create_policy_rule_success(self):
        """create_policy_rule appends a rule to the policy set."""
        db = _fresh_db()
        try:
            ps = PolicySetRow(
                id=str(uuid.uuid4()),
                name="test-policy",
                rules_json=[],
                version_hash="pqr678",
            )
            db.add(ps)
            db.commit()

            executor = ActionExecutor()
            new_rule = {
                "description": "Block suspicious shell",
                "action": "block",
            }
            action = Action(
                action_type=ActionType.CREATE_POLICY_RULE,
                params={"rule": new_rule},
                dry_run=False,
            )
            result = _run(executor.execute(action, db, "test-tenant"))
            assert result.success is True
            assert "created" in result.message.lower() or "rule" in result.message.lower()
        finally:
            db.rollback()
            db.close()

    def test_create_policy_rule_no_policy(self):
        """create_policy_rule fails when no PolicySetRow exists."""
        db = _fresh_db()
        try:
            # Ensure no policy exists
            db.query(PolicySetRow).delete()
            db.commit()

            executor = ActionExecutor()
            action = Action(
                action_type=ActionType.CREATE_POLICY_RULE,
                params={"rule": {"action": "block"}},
                dry_run=False,
            )
            result = _run(executor.execute(action, db, "test-tenant"))
            assert result.success is False
            assert "No policy found" in result.message
        finally:
            db.rollback()
            db.close()

    def test_create_policy_rule_no_rule_provided(self):
        """create_policy_rule fails when params has no 'rule' key."""
        db = _fresh_db()
        try:
            ps = PolicySetRow(
                id=str(uuid.uuid4()),
                name="test-policy",
                rules_json=[],
                version_hash="stu901",
            )
            db.add(ps)
            db.commit()

            executor = ActionExecutor()
            action = Action(
                action_type=ActionType.CREATE_POLICY_RULE,
                params={},
                dry_run=False,
            )
            result = _run(executor.execute(action, db, "test-tenant"))
            assert result.success is False
            assert "No rule provided" in result.message
        finally:
            db.rollback()
            db.close()

    def test_acknowledge_incident_success(self):
        """acknowledge_incident resolves an existing incident."""
        db = _fresh_db()
        try:
            incident = Incident(
                incident_id="inc-123",
                state=IncidentState.NEW,
                severity="high",
                title="Test incident",
            )
            mock_orch = MagicMock()
            mock_orch.get_incident.return_value = incident

            with patch(
                "cloud.guardian.orchestrator.angel_orchestrator",
                mock_orch,
            ):
                executor = ActionExecutor()
                action = Action(
                    action_type=ActionType.ACKNOWLEDGE_INCIDENT,
                    params={"incident_id": "inc-123"},
                    dry_run=False,
                )
                result = _run(
                    executor.execute(action, db, "test-tenant")
                )
            assert result.success is True
            assert "acknowledged" in result.message
            assert incident.state == IncidentState.RESOLVED
        finally:
            db.rollback()
            db.close()

    def test_acknowledge_incident_not_found(self):
        """acknowledge_incident returns failure for missing incident."""
        db = _fresh_db()
        try:
            mock_orch = MagicMock()
            mock_orch.get_incident.return_value = None

            with patch(
                "cloud.guardian.orchestrator.angel_orchestrator",
                mock_orch,
            ):
                executor = ActionExecutor()
                action = Action(
                    action_type=ActionType.ACKNOWLEDGE_INCIDENT,
                    params={"incident_id": "no-such-inc"},
                    dry_run=False,
                )
                result = _run(
                    executor.execute(action, db, "test-tenant")
                )
            assert result.success is False
            assert "not found" in result.message
        finally:
            db.rollback()
            db.close()


class TestActionExecutorFailurePaths:
    """Handler failure paths: commit errors, exceptions."""

    def test_handler_exception_logs_failed_status(self):
        """When a handler raises, the action is logged as 'failed'."""
        db = _fresh_db()
        try:
            executor = ActionExecutor()
            # Replace a handler to raise
            async def _boom(action, db, tenant_id):
                raise RuntimeError("something broke")

            executor._handlers[ActionType.SET_SCAN_FREQUENCY] = _boom

            action = Action(
                action_type=ActionType.SET_SCAN_FREQUENCY,
                description="Will fail",
                dry_run=False,
            )
            result = _run(executor.execute(action, db, "test-tenant"))
            assert result.success is False
            assert "something broke" in result.message

            row = db.query(ActionLogRow).filter_by(id=action.id).first()
            assert row is not None
            assert row.status == "failed"
            assert "something broke" in (row.error or "")
        finally:
            db.rollback()
            db.close()

    def test_log_action_commit_error_rolls_back(self):
        """_log_action handles commit errors by rolling back."""
        db = _fresh_db()
        try:
            executor = ActionExecutor()
            action = Action(
                action_type=ActionType.SET_SCAN_FREQUENCY,
                description="Commit will fail",
                dry_run=True,
            )

            # Patch db.commit to raise
            original_commit = db.commit
            db.commit = MagicMock(
                side_effect=Exception("DB locked")
            )
            # Should not raise
            executor._log_action(
                db, action, "test-tenant", "chat", "", "proposed"
            )
            # Restore
            db.commit = original_commit
        finally:
            db.rollback()
            db.close()


class TestGetActionHistory:
    """get_action_history retrieval function."""

    def test_returns_empty_for_no_rows(self):
        """get_action_history returns [] when no records exist."""
        db = _fresh_db()
        try:
            # Clean slate
            db.query(ActionLogRow).delete()
            db.commit()
            history = get_action_history(db, "empty-tenant")
            assert history == []
        finally:
            db.rollback()
            db.close()

    def test_returns_recent_actions(self):
        """get_action_history returns persisted action records."""
        db = _fresh_db()
        try:
            executor = ActionExecutor()
            action = Action(
                action_type=ActionType.SET_SCAN_FREQUENCY,
                description="Set scan freq to 20",
                params={"frequency_minutes": 20},
                dry_run=True,
            )
            _run(
                executor.execute(action, db, "history-tenant", "api")
            )

            history = get_action_history(db, "history-tenant", limit=10)
            assert len(history) >= 1
            found = [
                h for h in history if h["id"] == action.id
            ]
            assert len(found) == 1
            assert found[0]["action_type"] == "set_scan_frequency"
            assert found[0]["status"] == "proposed"
        finally:
            db.rollback()
            db.close()

    def test_respects_limit(self):
        """get_action_history limits the number of returned rows."""
        db = _fresh_db()
        try:
            executor = ActionExecutor()
            for i in range(5):
                action = Action(
                    action_type=ActionType.SET_SCAN_FREQUENCY,
                    description=f"Action {i}",
                    dry_run=True,
                )
                _run(
                    executor.execute(
                        action, db, "limit-tenant", "api"
                    )
                )

            history = get_action_history(
                db, "limit-tenant", limit=3
            )
            assert len(history) <= 3
        finally:
            db.rollback()
            db.close()


# ===================================================================
# 3. cloud/guardian/orchestrator.py
# ===================================================================


class TestOrchestratorStatus:
    """AngelOrchestrator.status() method."""

    def test_status_returns_expected_keys(self):
        """status() returns a dict with running, stats, agents, incidents, playbooks."""
        orch = AngelOrchestrator()
        s = orch.status()
        assert "running" in s
        assert "stats" in s
        assert "agents" in s
        assert "incidents" in s
        assert "playbooks" in s
        assert s["running"] is False

    def test_status_reflects_state_counts(self):
        """status() reflects incident counts accurately."""
        orch = AngelOrchestrator()
        inc1 = Incident(
            state=IncidentState.NEW,
            severity="high",
            title="Inc1",
        )
        inc2 = Incident(
            state=IncidentState.RESOLVED,
            severity="medium",
            title="Inc2",
        )
        orch._incidents[inc1.incident_id] = inc1
        orch._incidents[inc2.incident_id] = inc2

        s = orch.status()
        assert s["incidents"]["total"] == 2


class TestOrchestratorIncidentsByState:
    """_incidents_by_state helper."""

    def test_empty(self):
        """Returns empty dict when no incidents exist."""
        orch = AngelOrchestrator()
        assert orch._incidents_by_state() == {}

    def test_counts_states(self):
        """Counts incidents by their state correctly."""
        orch = AngelOrchestrator()
        for state in [
            IncidentState.NEW,
            IncidentState.NEW,
            IncidentState.RESOLVED,
        ]:
            inc = Incident(state=state, severity="high", title="t")
            orch._incidents[inc.incident_id] = inc

        counts = orch._incidents_by_state()
        assert counts["new"] == 2
        assert counts["resolved"] == 1


class TestOrchestratorGetAndListIncidents:
    """get_incident and list_incidents."""

    def test_get_incident_found(self):
        """get_incident returns the incident when it exists."""
        orch = AngelOrchestrator()
        inc = Incident(severity="critical", title="Found me")
        orch._incidents[inc.incident_id] = inc
        assert orch.get_incident(inc.incident_id) is inc

    def test_get_incident_not_found(self):
        """get_incident returns None for missing ID."""
        orch = AngelOrchestrator()
        assert orch.get_incident("nonexistent") is None

    def test_list_incidents_default(self):
        """list_incidents returns all incidents sorted by created_at desc."""
        orch = AngelOrchestrator()
        for i in range(5):
            inc = Incident(severity="high", title=f"Inc-{i}")
            orch._incidents[inc.incident_id] = inc

        result = orch.list_incidents()
        assert len(result) == 5

    def test_list_incidents_with_limit(self):
        """list_incidents respects the limit parameter."""
        orch = AngelOrchestrator()
        for i in range(10):
            inc = Incident(severity="high", title=f"Inc-{i}")
            orch._incidents[inc.incident_id] = inc

        result = orch.list_incidents(limit=3)
        assert len(result) == 3

    def test_list_incidents_with_state_filter(self):
        """list_incidents filters by state."""
        orch = AngelOrchestrator()
        inc_new = Incident(
            state=IncidentState.NEW, severity="high", title="New"
        )
        inc_resolved = Incident(
            state=IncidentState.RESOLVED, severity="low", title="Done"
        )
        orch._incidents[inc_new.incident_id] = inc_new
        orch._incidents[inc_resolved.incident_id] = inc_resolved

        result = orch.list_incidents(state="new")
        assert len(result) == 1
        assert result[0].state == IncidentState.NEW


class TestOrchestratorCreateIncidents:
    """_create_incidents internal method."""

    def test_creates_from_high_severity(self):
        """Indicators with high severity create incidents."""
        orch = AngelOrchestrator()
        ind = ThreatIndicator(
            indicator_type="pattern_match",
            pattern_name="test-pattern",
            severity="high",
            confidence=0.9,
            description="High severity threat",
            related_event_ids=["e1"],
            related_agent_ids=["a1"],
            suggested_playbook="quarantine_agent",
            mitre_tactic="execution",
        )
        incidents = orch._create_incidents([ind], "test-tenant")
        assert len(incidents) == 1
        assert incidents[0].severity == "high"
        assert incidents[0].incident_id in orch._incidents

    def test_creates_from_critical_severity(self):
        """Indicators with critical severity create incidents."""
        orch = AngelOrchestrator()
        ind = ThreatIndicator(
            indicator_type="anomaly",
            severity="critical",
            confidence=0.95,
            description="Critical anomaly",
        )
        incidents = orch._create_incidents([ind], "test-tenant")
        assert len(incidents) == 1
        assert incidents[0].severity == "critical"

    def test_skips_medium_and_low_severity(self):
        """Indicators with medium or low severity do not create incidents."""
        orch = AngelOrchestrator()
        indicators = [
            ThreatIndicator(
                indicator_type="pattern_match",
                severity="medium",
                confidence=0.5,
                description="Medium threat",
            ),
            ThreatIndicator(
                indicator_type="anomaly",
                severity="low",
                confidence=0.3,
                description="Low threat",
            ),
        ]
        incidents = orch._create_incidents(indicators, "test-tenant")
        assert len(incidents) == 0

    def test_mitre_tactics_populated(self):
        """Incident mitre_tactics are populated from the indicator."""
        orch = AngelOrchestrator()
        ind = ThreatIndicator(
            indicator_type="correlation",
            severity="high",
            confidence=0.85,
            description="Lateral movement",
            mitre_tactic="lateral_movement",
        )
        incidents = orch._create_incidents([ind], "test-tenant")
        assert incidents[0].mitre_tactics == ["lateral_movement"]


class TestOrchestratorPersistAlerts:
    """_persist_alerts saves indicators to DB."""

    def test_persists_high_severity_alerts(self):
        """High severity indicators are saved as GuardianAlertRow."""
        db = _fresh_db()
        try:
            orch = AngelOrchestrator()
            ind = ThreatIndicator(
                indicator_id="alert-1",
                indicator_type="pattern_match",
                pattern_name="suspicious_burst",
                severity="high",
                confidence=0.8,
                description="Burst detected",
                related_event_ids=["ev1", "ev2"],
                related_agent_ids=["ag1"],
            )
            orch._persist_alerts(db, [ind], "test-tenant")

            row = (
                db.query(GuardianAlertRow)
                .filter_by(id="alert-1")
                .first()
            )
            assert row is not None
            assert row.severity == "high"
            assert row.tenant_id == "test-tenant"
        finally:
            db.rollback()
            db.close()

    def test_skips_medium_severity_alerts(self):
        """Medium severity indicators are not persisted."""
        db = _fresh_db()
        try:
            orch = AngelOrchestrator()
            ind = ThreatIndicator(
                indicator_id="alert-med",
                indicator_type="anomaly",
                severity="medium",
                confidence=0.5,
                description="Medium anomaly",
            )
            # Delete any existing rows
            db.query(GuardianAlertRow).filter_by(
                id="alert-med"
            ).delete()
            db.commit()

            orch._persist_alerts(db, [ind], "test-tenant")
            row = (
                db.query(GuardianAlertRow)
                .filter_by(id="alert-med")
                .first()
            )
            assert row is None
        finally:
            db.rollback()
            db.close()

    def test_persist_alerts_handles_commit_error(self):
        """_persist_alerts rolls back on commit failure."""
        db = _fresh_db()
        try:
            orch = AngelOrchestrator()
            ind = ThreatIndicator(
                indicator_id="alert-err",
                indicator_type="pattern_match",
                severity="critical",
                confidence=0.99,
                description="Critical threat",
            )
            original_commit = db.commit
            db.commit = MagicMock(
                side_effect=Exception("DB write error")
            )
            # Should not raise
            orch._persist_alerts(db, [ind], "test-tenant")
            db.commit = original_commit
        finally:
            db.rollback()
            db.close()


class TestOrchestratorProcessEvents:
    """process_events full pipeline."""

    def test_empty_events_returns_empty(self):
        """process_events with empty list returns []."""
        db = _fresh_db()
        try:
            orch = AngelOrchestrator()
            result = _run(
                orch.process_events([], db, "test-tenant")
            )
            assert result == []
        finally:
            db.close()

    def test_process_events_no_indicators(self):
        """When sentinel finds no threats, returns []."""
        db = _fresh_db()
        try:
            orch = AngelOrchestrator()
            # Mock sentinel to return no indicators
            mock_result = AgentResult(
                task_id="t1",
                agent_id="sentinel-1",
                agent_type="sentinel",
                success=True,
                result_data={"indicators": []},
            )
            orch.sentinel.execute = AsyncMock(
                return_value=mock_result
            )

            event = EventRow(
                id="ev-1",
                agent_id="agent-1",
                timestamp=datetime.now(timezone.utc),
                category="shell",
                type="exec",
                severity="high",
                details={},
                source="test",
            )
            result = _run(
                orch.process_events([event], db, "test-tenant")
            )
            assert result == []
            assert orch._events_processed == 1
        finally:
            db.close()

    def test_process_events_with_indicators(self):
        """When sentinel finds threats, incidents are created and persisted."""
        db = _fresh_db()
        try:
            orch = AngelOrchestrator()
            indicator_data = {
                "indicator_type": "pattern_match",
                "pattern_name": "rapid_commands",
                "severity": "high",
                "confidence": 0.9,
                "description": "Rapid shell commands detected",
                "related_event_ids": ["ev-1"],
                "related_agent_ids": ["agent-1"],
                "suggested_playbook": "quarantine_agent",
            }
            mock_sentinel_result = AgentResult(
                task_id="t1",
                agent_id="sentinel-1",
                agent_type="sentinel",
                success=True,
                result_data={"indicators": [indicator_data]},
            )
            orch.sentinel.execute = AsyncMock(
                return_value=mock_sentinel_result
            )

            # Mock response agent to succeed
            mock_response_result = AgentResult(
                task_id="t2",
                agent_id="response-1",
                agent_type="response",
                success=True,
                result_data={},
            )
            orch.response.execute = AsyncMock(
                return_value=mock_response_result
            )
            # Mock forensic agent
            mock_forensic_result = AgentResult(
                task_id="t3",
                agent_id="forensic-1",
                agent_type="forensic",
                success=True,
                result_data={
                    "report": {"root_cause": "test cause"}
                },
            )
            orch.forensic.execute = AsyncMock(
                return_value=mock_forensic_result
            )

            # Mock get_playbook to return a playbook with auto_respond
            mock_playbook = Playbook(
                name="quarantine_agent",
                auto_respond=True,
            )
            orch.response.get_playbook = MagicMock(
                return_value=mock_playbook
            )

            event = EventRow(
                id="ev-1",
                agent_id="agent-1",
                timestamp=datetime.now(timezone.utc),
                category="shell",
                type="exec",
                severity="high",
                details={},
                source="test",
            )
            result = _run(
                orch.process_events([event], db, "test-tenant")
            )
            assert len(result) == 1
            assert orch._incidents_created >= 1
            assert orch._indicators_found >= 1
        finally:
            db.rollback()
            db.close()

    def test_process_events_sentinel_failure(self):
        """When sentinel fails, returns empty indicators."""
        db = _fresh_db()
        try:
            orch = AngelOrchestrator()
            mock_result = AgentResult(
                task_id="t1",
                agent_id="sentinel-1",
                agent_type="sentinel",
                success=False,
                error="Sentinel crashed",
            )
            orch.sentinel.execute = AsyncMock(
                return_value=mock_result
            )

            event = EventRow(
                id="ev-1",
                agent_id="agent-1",
                timestamp=datetime.now(timezone.utc),
                category="shell",
                type="exec",
                severity="high",
                details={},
                source="test",
            )
            result = _run(
                orch.process_events([event], db, "test-tenant")
            )
            assert result == []
        finally:
            db.close()


class TestOrchestratorApproveIncident:
    """approve_incident approval workflow."""

    def test_approve_pending_incident(self):
        """Approving a pending incident executes the response."""
        db = _fresh_db()
        try:
            orch = AngelOrchestrator()
            inc = Incident(
                state=IncidentState.TRIAGING,
                severity="high",
                title="Awaiting approval",
                playbook_name="quarantine_agent",
                related_agent_ids=["agent-1"],
            )
            orch._pending_approvals[inc.incident_id] = inc
            orch._incidents[inc.incident_id] = inc

            # Mock response execution
            mock_result = AgentResult(
                task_id="t1",
                agent_id="response-1",
                agent_type="response",
                success=True,
                result_data={},
            )
            orch.response.execute = AsyncMock(
                return_value=mock_result
            )
            orch.forensic.execute = AsyncMock(
                return_value=AgentResult(
                    task_id="t2",
                    agent_id="forensic-1",
                    agent_type="forensic",
                    success=True,
                    result_data={
                        "report": {"root_cause": "test"}
                    },
                )
            )

            result = _run(
                orch.approve_incident(
                    inc.incident_id, "admin", db, "test-tenant"
                )
            )
            assert result["approved_by"] == "admin"
            assert result["response_executed"] is True
        finally:
            db.close()

    def test_approve_nonexistent_incident(self):
        """Approving a missing incident returns an error dict."""
        orch = AngelOrchestrator()
        db = _fresh_db()
        try:
            result = _run(
                orch.approve_incident(
                    "no-such-id", "admin", db
                )
            )
            assert "error" in result
        finally:
            db.close()

    def test_approve_already_resolved_incident(self):
        """Approving a resolved incident returns an error."""
        orch = AngelOrchestrator()
        db = _fresh_db()
        try:
            inc = Incident(
                state=IncidentState.RESOLVED,
                severity="high",
                title="Already resolved",
            )
            orch._incidents[inc.incident_id] = inc

            result = _run(
                orch.approve_incident(
                    inc.incident_id, "admin", db
                )
            )
            assert "error" in result
            assert "cannot approve" in result["error"].lower()
        finally:
            db.close()

    def test_approve_from_incidents_dict(self):
        """Approval finds incident in _incidents when not in _pending."""
        orch = AngelOrchestrator()
        db = _fresh_db()
        try:
            inc = Incident(
                state=IncidentState.NEW,
                severity="critical",
                title="Not in pending",
                playbook_name="quarantine_agent",
                related_agent_ids=["a1"],
            )
            orch._incidents[inc.incident_id] = inc

            mock_result = AgentResult(
                task_id="t1",
                agent_id="response-1",
                agent_type="response",
                success=True,
                result_data={},
            )
            orch.response.execute = AsyncMock(
                return_value=mock_result
            )
            orch.forensic.execute = AsyncMock(
                return_value=AgentResult(
                    task_id="t2",
                    agent_id="forensic-1",
                    agent_type="forensic",
                    success=True,
                    result_data={
                        "report": {"root_cause": "found"}
                    },
                )
            )

            result = _run(
                orch.approve_incident(
                    inc.incident_id, "ops", db
                )
            )
            assert result["response_executed"] is True
            assert result["approved_by"] == "ops"
        finally:
            db.close()


class TestOrchestratorLifecycle:
    """start() and stop() lifecycle methods."""

    def test_start_sets_running(self):
        """start() sets _running=True and creates the audit task."""
        orch = AngelOrchestrator()

        async def _start_and_check():
            await orch.start()
            assert orch._running is True
            assert orch._audit_task is not None
            # Clean up immediately
            await orch.stop()

        _run(_start_and_check())
        assert orch._running is False

    def test_stop_cancels_audit_task(self):
        """stop() cancels the audit task and shuts down all agents."""
        orch = AngelOrchestrator()

        async def _lifecycle():
            await orch.start()
            assert orch._running is True
            await orch.stop()
            assert orch._running is False

        _run(_lifecycle())

    def test_stop_without_start(self):
        """stop() works gracefully even if start() was not called."""
        orch = AngelOrchestrator()

        async def _stop_only():
            await orch.stop()
            assert orch._running is False

        _run(_stop_only())


class TestOrchestratorHandleIncidentEscalation:
    """_handle_incident escalation paths."""

    def test_no_playbook_escalates(self):
        """Incident without a playbook is escalated."""
        orch = AngelOrchestrator()
        db = _fresh_db()
        try:
            inc = Incident(
                state=IncidentState.NEW,
                severity="high",
                title="No playbook",
                playbook_name="",
            )
            _run(orch._handle_incident(inc, db, "test-tenant"))
            assert inc.state == IncidentState.ESCALATED
        finally:
            db.close()

    def test_unknown_playbook_escalates(self):
        """Incident referencing a non-existent playbook is escalated."""
        orch = AngelOrchestrator()
        db = _fresh_db()
        try:
            inc = Incident(
                state=IncidentState.NEW,
                severity="high",
                title="Bad playbook",
                playbook_name="nonexistent_playbook",
            )
            orch.response.get_playbook = MagicMock(
                return_value=None
            )
            _run(orch._handle_incident(inc, db, "test-tenant"))
            assert inc.state == IncidentState.ESCALATED
        finally:
            db.close()

    def test_playbook_requires_approval(self):
        """Incident with non-auto-respond playbook awaits approval."""
        orch = AngelOrchestrator()
        db = _fresh_db()
        try:
            inc = Incident(
                state=IncidentState.NEW,
                severity="high",
                title="Needs approval",
                playbook_name="manual_playbook",
            )
            manual_pb = Playbook(
                name="manual_playbook",
                auto_respond=False,
            )
            orch.response.get_playbook = MagicMock(
                return_value=manual_pb
            )
            _run(orch._handle_incident(inc, db, "test-tenant"))
            assert inc.requires_approval is True
            assert inc.state == IncidentState.TRIAGING
            assert inc.incident_id in orch._pending_approvals
        finally:
            db.close()

    def test_response_failure_escalates(self):
        """When response execution fails, incident is escalated."""
        orch = AngelOrchestrator()
        db = _fresh_db()
        try:
            inc = Incident(
                state=IncidentState.NEW,
                severity="critical",
                title="Response will fail",
                playbook_name="auto_playbook",
                related_agent_ids=["a1"],
            )
            auto_pb = Playbook(
                name="auto_playbook",
                auto_respond=True,
            )
            orch.response.get_playbook = MagicMock(
                return_value=auto_pb
            )
            mock_result = AgentResult(
                task_id="t1",
                agent_id="response-1",
                agent_type="response",
                success=False,
                error="Playbook execution error",
            )
            orch.response.execute = AsyncMock(
                return_value=mock_result
            )

            _run(orch._handle_incident(inc, db, "test-tenant"))
            assert inc.state == IncidentState.ESCALATED
            assert any(
                "failed" in n.lower() for n in inc.notes
            )
        finally:
            db.close()
