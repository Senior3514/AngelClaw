"""Coverage tests for cloud_sync, routes, event_bus, and wazuh_client.

Targets:
  - angelnode/core/cloud_sync.py  (CloudSyncClient lifecycle)
  - cloud/angelclaw/routes.py     (FastAPI API routes)
  - cloud/services/event_bus.py   (critical pattern detection)
  - cloud/integrations/wazuh_client.py (Wazuh XDR client)
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Force test settings before importing app modules
os.environ.setdefault("ANGELCLAW_AUTH_ENABLED", "false")
os.environ.setdefault("ANGELCLAW_LOG_FORMAT", "text")
os.environ.setdefault("ANGELGRID_DATABASE_URL", "sqlite:///test_angelgrid.db")

from cloud.angelclaw.preferences import (
    AngelClawPreferencesRow,
)
from cloud.db.models import (
    Base,
    EventRow,
    GuardianReportRow,
)

# In-memory SQLite for DB tests
TEST_ENGINE = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
# Create tables from all known models (including preferences/actions)
from cloud.angelclaw.actions import ActionLogRow  # noqa: E402

_all_tables = [
    Base.metadata,
    AngelClawPreferencesRow.__table__,
    ActionLogRow.__table__,
]
Base.metadata.create_all(TEST_ENGINE)
TestSession = sessionmaker(bind=TEST_ENGINE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    """Run an async coroutine synchronously."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_db():
    """Create a fresh test DB session."""
    return TestSession()


def _make_event(
    agent_id="agent-1",
    category="process",
    etype="exec",
    severity="low",
    details=None,
):
    return EventRow(
        id=str(uuid.uuid4()),
        agent_id=agent_id,
        timestamp=datetime.now(timezone.utc),
        category=category,
        type=etype,
        severity=severity,
        details=details or {},
    )


# ===========================================================================
# 1. angelnode/core/cloud_sync.py — CloudSyncClient
# ===========================================================================


class TestCloudSyncClientInit:
    """CloudSyncClient.__init__ and properties."""

    def test_init_stores_url_and_tenant(self):
        from angelnode.core.cloud_sync import CloudSyncClient

        cb = MagicMock()
        client = CloudSyncClient(
            cloud_url="https://cloud.example.com/",
            tenant_id="t1",
            on_policy_update=cb,
            on_sync_log=cb,
            on_agent_id_update=cb,
            on_sync_timestamp=cb,
        )
        assert client._cloud_url == "https://cloud.example.com"
        assert client._tenant_id == "t1"
        assert client.agent_id is None

    def test_trailing_slash_stripped(self):
        from angelnode.core.cloud_sync import CloudSyncClient

        cb = MagicMock()
        client = CloudSyncClient(
            cloud_url="https://host///",
            tenant_id="t",
            on_policy_update=cb,
            on_sync_log=cb,
            on_agent_id_update=cb,
            on_sync_timestamp=cb,
        )
        assert not client._cloud_url.endswith("/")


class TestCloudSyncRegister:
    """register() success and failure paths."""

    def _make_client(self):
        from angelnode.core.cloud_sync import CloudSyncClient

        cbs = {
            "on_policy_update": MagicMock(),
            "on_sync_log": MagicMock(),
            "on_agent_id_update": MagicMock(),
            "on_sync_timestamp": MagicMock(),
        }
        client = CloudSyncClient(
            cloud_url="https://cloud.test",
            tenant_id="tenant-1",
            **cbs,
        )
        return client, cbs

    def test_register_success_no_policy(self):
        client, cbs = self._make_client()

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"agent_id": "a-123"}
        mock_resp.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_http):
            result = _run(client.register())

        assert result is True
        assert client.agent_id == "a-123"
        cbs["on_agent_id_update"].assert_called_once_with("a-123")
        cbs["on_sync_timestamp"].assert_called_once()
        cbs["on_sync_log"].assert_called_once()
        log_record = cbs["on_sync_log"].call_args[0][0]
        assert log_record["sync_type"] == "register"
        assert log_record["success"] is True

    def test_register_success_with_policy(self):
        client, cbs = self._make_client()

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "agent_id": "a-456",
            "policy_set": {
                "rules": [
                    {
                        "match": {"categories": ["process"]},
                        "action": "block",
                    }
                ],
                "id": "ps-1",
                "name": "test-policy",
            },
        }
        mock_resp.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_http):
            result = _run(client.register())

        assert result is True
        cbs["on_policy_update"].assert_called_once()
        ps = cbs["on_policy_update"].call_args[0][0]
        assert ps.name == "test-policy"
        assert len(ps.rules) == 1

    def test_register_failure_http_error(self):
        client, cbs = self._make_client()

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(
            side_effect=httpx.ConnectError("refused")
        )

        with patch("httpx.AsyncClient", return_value=mock_http):
            result = _run(client.register())

        assert result is False
        assert client.agent_id is None
        cbs["on_sync_log"].assert_called_once()
        log_record = cbs["on_sync_log"].call_args[0][0]
        assert log_record["success"] is False
        assert "error" in log_record


class TestCloudSyncPolicy:
    """_sync_policy() with version change, no change, and error."""

    def _make_registered_client(self):
        from angelnode.core.cloud_sync import CloudSyncClient

        cbs = {
            "on_policy_update": MagicMock(),
            "on_sync_log": MagicMock(),
            "on_agent_id_update": MagicMock(),
            "on_sync_timestamp": MagicMock(),
        }
        client = CloudSyncClient(
            cloud_url="https://cloud.test",
            tenant_id="tenant-1",
            **cbs,
        )
        client._agent_id = "agent-registered"
        client._current_version = "v1"
        return client, cbs

    def test_sync_policy_version_changed(self):
        client, cbs = self._make_registered_client()

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "version": "v2",
            "rules": [
                {
                    "match": {"categories": ["file"]},
                    "action": "alert",
                }
            ],
            "id": "ps-new",
            "name": "updated",
        }
        mock_resp.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_http):
            _run(client._sync_policy())

        cbs["on_policy_update"].assert_called_once()
        log_record = cbs["on_sync_log"].call_args[0][0]
        assert log_record["changed"] is True
        assert log_record["success"] is True

    def test_sync_policy_no_change(self):
        client, cbs = self._make_registered_client()

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"version": "v1", "rules": []}
        mock_resp.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_http):
            _run(client._sync_policy())

        cbs["on_policy_update"].assert_not_called()
        log_record = cbs["on_sync_log"].call_args[0][0]
        assert log_record["changed"] is False

    def test_sync_policy_error(self):
        client, cbs = self._make_registered_client()

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.get = AsyncMock(
            side_effect=httpx.ConnectError("timeout")
        )

        with patch("httpx.AsyncClient", return_value=mock_http):
            _run(client._sync_policy())

        cbs["on_policy_update"].assert_not_called()
        log_record = cbs["on_sync_log"].call_args[0][0]
        assert log_record["success"] is False

    def test_sync_policy_not_registered_triggers_register(self):
        """If agent_id is None, _sync_policy calls register() first."""
        from angelnode.core.cloud_sync import CloudSyncClient

        cbs = {
            "on_policy_update": MagicMock(),
            "on_sync_log": MagicMock(),
            "on_agent_id_update": MagicMock(),
            "on_sync_timestamp": MagicMock(),
        }
        client = CloudSyncClient(
            cloud_url="https://cloud.test",
            tenant_id="t",
            **cbs,
        )
        assert client._agent_id is None

        with patch.object(
            client, "register", new_callable=AsyncMock
        ) as mock_reg:
            mock_reg.return_value = False
            _run(client._sync_policy())

        mock_reg.assert_awaited_once()
        # Since register returns False, no policy fetch happens
        cbs["on_policy_update"].assert_not_called()


class TestCloudSyncApplyPolicy:
    """_apply_policy() parses rules correctly."""

    def test_apply_policy_parses_rules(self):
        from angelnode.core.cloud_sync import CloudSyncClient

        cb_policy = MagicMock()
        client = CloudSyncClient(
            cloud_url="https://cloud.test",
            tenant_id="t",
            on_policy_update=cb_policy,
            on_sync_log=MagicMock(),
            on_agent_id_update=MagicMock(),
            on_sync_timestamp=MagicMock(),
        )
        policy_data = {
            "id": "ps-1",
            "name": "my-policy",
            "description": "test policy",
            "rules": [
                {
                    "match": {"categories": ["network"]},
                    "action": "block",
                    "risk_level": "high",
                },
                {
                    "match": {"types": ["exec"]},
                    "action": "audit",
                },
            ],
        }
        client._apply_policy(policy_data)

        cb_policy.assert_called_once()
        ps = cb_policy.call_args[0][0]
        assert ps.name == "my-policy"
        assert len(ps.rules) == 2
        assert ps.rules[0].action.value == "block"
        assert client._current_version is not None

    def test_apply_policy_empty_rules(self):
        from angelnode.core.cloud_sync import CloudSyncClient

        cb_policy = MagicMock()
        client = CloudSyncClient(
            cloud_url="https://cloud.test",
            tenant_id="t",
            on_policy_update=cb_policy,
            on_sync_log=MagicMock(),
            on_agent_id_update=MagicMock(),
            on_sync_timestamp=MagicMock(),
        )
        client._apply_policy({"rules": []})
        ps = cb_policy.call_args[0][0]
        assert len(ps.rules) == 0
        assert ps.id == "cloud-synced"


class TestCloudSyncLogEvent:
    """_log_sync_event() emits correct record structure."""

    def test_log_event_success(self):
        from angelnode.core.cloud_sync import CloudSyncClient

        log_cb = MagicMock()
        client = CloudSyncClient(
            cloud_url="https://cloud.test",
            tenant_id="t-abc",
            on_policy_update=MagicMock(),
            on_sync_log=log_cb,
            on_agent_id_update=MagicMock(),
            on_sync_timestamp=MagicMock(),
        )
        client._agent_id = "ag-99"
        client._log_sync_event(
            "policy_sync",
            success=True,
            policy_version="v5",
            changed=True,
        )

        record = log_cb.call_args[0][0]
        assert record["sync_type"] == "policy_sync"
        assert record["success"] is True
        assert record["agent_id"] == "ag-99"
        assert record["tenant_id"] == "t-abc"
        assert record["policy_version"] == "v5"
        assert record["changed"] is True
        assert "error" not in record

    def test_log_event_failure(self):
        from angelnode.core.cloud_sync import CloudSyncClient

        log_cb = MagicMock()
        client = CloudSyncClient(
            cloud_url="https://cloud.test",
            tenant_id="t",
            on_policy_update=MagicMock(),
            on_sync_log=log_cb,
            on_agent_id_update=MagicMock(),
            on_sync_timestamp=MagicMock(),
        )
        client._log_sync_event(
            "register", success=False, error="connection refused"
        )
        record = log_cb.call_args[0][0]
        assert record["success"] is False
        assert record["error"] == "connection refused"

    def test_log_event_optional_fields_omitted(self):
        from angelnode.core.cloud_sync import CloudSyncClient

        log_cb = MagicMock()
        client = CloudSyncClient(
            cloud_url="https://cloud.test",
            tenant_id="t",
            on_policy_update=MagicMock(),
            on_sync_log=log_cb,
            on_agent_id_update=MagicMock(),
            on_sync_timestamp=MagicMock(),
        )
        client._log_sync_event("register", success=True)
        record = log_cb.call_args[0][0]
        assert "error" not in record
        assert "policy_version" not in record
        assert "previous_version" not in record
        assert "changed" not in record


class TestCloudSyncPollingLifecycle:
    """start_polling()/stop() lifecycle."""

    def test_start_and_stop(self):
        from angelnode.core.cloud_sync import CloudSyncClient

        cb = MagicMock()
        client = CloudSyncClient(
            cloud_url="https://cloud.test",
            tenant_id="t",
            on_policy_update=cb,
            on_sync_log=cb,
            on_agent_id_update=cb,
            on_sync_timestamp=cb,
        )

        async def _lifecycle():
            await client.start_polling()
            assert client._running is True
            assert client._task is not None
            await client.stop()
            assert client._running is False
            assert client._task is None

        _run(_lifecycle())

    def test_stop_when_not_started(self):
        from angelnode.core.cloud_sync import CloudSyncClient

        cb = MagicMock()
        client = CloudSyncClient(
            cloud_url="https://cloud.test",
            tenant_id="t",
            on_policy_update=cb,
            on_sync_log=cb,
            on_agent_id_update=cb,
            on_sync_timestamp=cb,
        )
        # Should not raise
        _run(client.stop())
        assert client._running is False


# ===========================================================================
# 2. cloud/angelclaw/routes.py — FastAPI API Routes
# ===========================================================================


def _get_test_app():
    """Create a FastAPI app with the AngelClaw router for testing."""
    from fastapi import FastAPI

    from cloud.angelclaw.routes import router

    app = FastAPI()
    app.include_router(router)

    # Override DB dependency to use in-memory SQLite
    from cloud.db.session import get_db

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    return app


class TestRoutesChat:
    """POST /api/v1/angelclaw/chat."""

    def test_chat_success(self):
        from fastapi.testclient import TestClient

        app = _get_test_app()
        client = TestClient(app)

        mock_result = {
            "answer": "All systems operational.",
            "actions": [],
            "effects": [],
            "references": [],
            "meta": {},
        }

        with patch(
            "cloud.angelclaw.routes.brain",
            create=True,
        ):
            mock_brain = MagicMock()
            mock_brain.chat = AsyncMock(return_value=mock_result)
            # The route does `from cloud.angelclaw.brain import brain`
            with patch(
                "cloud.angelclaw.brain.brain", mock_brain
            ):
                resp = client.post(
                    "/api/v1/angelclaw/chat",
                    json={
                        "prompt": "status",
                        "tenantId": "dev-tenant",
                    },
                )

        assert resp.status_code == 200
        data = resp.json()
        assert data["answer"] == "All systems operational."


class TestRoutesPreferences:
    """GET and POST /api/v1/angelclaw/preferences."""

    def test_get_preferences(self):
        from fastapi.testclient import TestClient

        app = _get_test_app()
        client = TestClient(app)

        resp = client.get(
            "/api/v1/angelclaw/preferences",
            params={"tenantId": "test-t"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "autonomy_level" in data
        assert "scan_frequency_minutes" in data

    def test_post_preferences(self):
        from fastapi.testclient import TestClient

        app = _get_test_app()
        client = TestClient(app)

        resp = client.post(
            "/api/v1/angelclaw/preferences",
            json={"autonomy_level": "observe_only"},
            params={"tenantId": "test-pref"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["autonomy_level"] == "observe_only"


class TestRoutesReports:
    """GET /api/v1/angelclaw/reports/recent."""

    def test_reports_empty(self):
        from fastapi.testclient import TestClient

        app = _get_test_app()
        client = TestClient(app)

        resp = client.get(
            "/api/v1/angelclaw/reports/recent",
            params={"tenantId": "no-reports", "limit": 5},
        )
        assert resp.status_code == 200
        assert resp.json() == []

    def test_reports_with_data(self):
        from fastapi.testclient import TestClient

        db = _make_db()
        report = GuardianReportRow(
            id=str(uuid.uuid4()),
            tenant_id="rpt-tenant",
            timestamp=datetime.now(timezone.utc),
            agents_total=10,
            agents_active=8,
            agents_degraded=1,
            agents_offline=1,
            incidents_total=3,
            incidents_by_severity={"high": 1, "low": 2},
            anomalies=["drift"],
            summary="All good",
        )
        db.add(report)
        db.commit()
        db.close()

        app = _get_test_app()
        client = TestClient(app)
        resp = client.get(
            "/api/v1/angelclaw/reports/recent",
            params={"tenantId": "rpt-tenant", "limit": 10},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1
        assert data[0]["agents_total"] == 10
        assert data[0]["summary"] == "All good"


class TestRoutesActivity:
    """GET /api/v1/angelclaw/activity/recent."""

    def test_activity_recent(self):
        from fastapi.testclient import TestClient

        app = _get_test_app()
        client = TestClient(app)

        mock_activity = [
            {
                "id": "act-1",
                "timestamp": "2025-01-01T00:00:00Z",
                "category": "scan",
                "summary": "Scan complete",
                "details": {},
            }
        ]

        with patch(
            "cloud.angelclaw.daemon.get_recent_activity",
            return_value=mock_activity,
        ):
            resp = client.get(
                "/api/v1/angelclaw/activity/recent",
                params={"limit": 5},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["id"] == "act-1"


class TestRoutesActionsHistory:
    """GET /api/v1/angelclaw/actions/history."""

    def test_actions_history(self):
        from fastapi.testclient import TestClient

        app = _get_test_app()
        client = TestClient(app)

        mock_history = [
            {"id": "h-1", "action_type": "scan", "status": "applied"}
        ]

        with patch(
            "cloud.angelclaw.actions.get_action_history",
            return_value=mock_history,
        ):
            resp = client.get(
                "/api/v1/angelclaw/actions/history",
                params={"tenantId": "dev-tenant", "limit": 10},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1


class TestRoutesDaemonStatus:
    """GET /api/v1/angelclaw/daemon/status."""

    def test_daemon_status(self):
        from fastapi.testclient import TestClient

        app = _get_test_app()
        client = TestClient(app)

        mock_status = {
            "running": True,
            "cycles_completed": 42,
            "last_scan_summary": "ok",
            "activity_count": 100,
        }

        with patch(
            "cloud.angelclaw.daemon.get_daemon_status",
            return_value=mock_status,
        ):
            resp = client.get("/api/v1/angelclaw/daemon/status")

        assert resp.status_code == 200
        data = resp.json()
        assert data["running"] is True
        assert data["cycles_completed"] == 42


class TestRoutesShieldStatus:
    """GET /api/v1/angelclaw/shield/status."""

    def test_shield_status(self):
        from fastapi.testclient import TestClient

        app = _get_test_app()
        client = TestClient(app)

        mock_status = {
            "enabled": True,
            "assessments_run": 5,
            "skills_registered": 8,
        }

        with patch(
            "cloud.angelclaw.shield.shield"
        ) as mock_shield:
            mock_shield.get_status.return_value = mock_status
            resp = client.get(
                "/api/v1/angelclaw/shield/status"
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["enabled"] is True


class TestRoutesShieldAssess:
    """POST /api/v1/angelclaw/shield/assess."""

    def test_shield_assess(self):
        from fastapi.testclient import TestClient

        from cloud.angelclaw.context import EnvironmentContext
        from cloud.angelclaw.shield import (
            ShieldReport,
            ThreatSeverity,
        )

        app = _get_test_app()
        client = TestClient(app)

        ctx = EnvironmentContext()
        ctx.recent_events = [
            {"category": "process", "type": "exec", "details": {}}
        ]

        report = ShieldReport(
            overall_risk=ThreatSeverity.LOW,
            lethal_trifecta_score=0.0,
            checks_run=10,
            indicators=[],
            skills_status={"total": 0},
        )

        with patch(
            "cloud.angelclaw.context.gather_context",
            return_value=ctx,
        ), patch(
            "cloud.angelclaw.shield.shield"
        ) as mock_shield:
            mock_shield.assess_events.return_value = report
            resp = client.post(
                "/api/v1/angelclaw/shield/assess",
                params={"tenantId": "dev-tenant"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["overall_risk"] == "low"
        assert data["checks_run"] == 10


class TestRoutesSkillsStatus:
    """GET /api/v1/angelclaw/skills/status."""

    def test_skills_status(self):
        from fastapi.testclient import TestClient

        app = _get_test_app()
        client = TestClient(app)

        mock_skills = {
            "total": 3,
            "verified": 3,
            "drifted": 0,
            "missing": 0,
            "skills": {},
        }

        with patch(
            "cloud.angelclaw.shield.verify_all_skills",
            return_value=mock_skills,
        ):
            resp = client.get(
                "/api/v1/angelclaw/skills/status"
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert data["verified"] == 3


# ===========================================================================
# 3. cloud/services/event_bus.py — Critical Pattern Detection
# ===========================================================================


class TestEventBusEmpty:
    """Empty events returns []."""

    def test_empty_events(self):
        from cloud.services.event_bus import check_for_alerts

        db = _make_db()
        alerts = check_for_alerts(db, [], "test-tenant")
        assert alerts == []
        db.close()


class TestEventBusSecretExfil:
    """Pattern 1: repeated secret exfiltration."""

    def test_two_secret_events_triggers_alert(self):
        from cloud.services.event_bus import check_for_alerts

        db = _make_db()
        events = [
            _make_event(
                details={"accesses_secrets": True},
                etype="read_env",
            ),
            _make_event(
                details={"accesses_secrets": True},
                etype="read_key",
                agent_id="agent-2",
            ),
        ]
        for e in events:
            db.add(e)
        db.commit()

        with patch(
            "cloud.services.event_bus._fire_webhooks"
        ):
            alerts = check_for_alerts(
                db, events, "test-tenant"
            )

        secret_alerts = [
            a
            for a in alerts
            if a.alert_type == "repeated_secret_exfil"
        ]
        assert len(secret_alerts) == 1
        assert secret_alerts[0].severity == "critical"
        assert (
            secret_alerts[0].details["secret_event_count"]
            == 2
        )
        db.close()

    def test_one_secret_event_no_alert(self):
        from cloud.services.event_bus import check_for_alerts

        db = _make_db()
        events = [
            _make_event(
                details={"accesses_secrets": True},
                etype="read_env",
            ),
            _make_event(details={}, etype="normal_op"),
        ]
        for e in events:
            db.add(e)
        db.commit()

        with patch(
            "cloud.services.event_bus._fire_webhooks"
        ):
            alerts = check_for_alerts(
                db, events, "test-tenant"
            )

        secret_alerts = [
            a
            for a in alerts
            if a.alert_type == "repeated_secret_exfil"
        ]
        assert len(secret_alerts) == 0
        db.close()


class TestEventBusHighSeverityBurst:
    """Pattern 2: high severity burst (>=5 high/critical from one agent)."""

    def test_five_high_severity_triggers_alert(self):
        from cloud.services.event_bus import check_for_alerts

        db = _make_db()
        events = [
            _make_event(
                agent_id="agent-burst",
                severity="high",
                etype=f"op-{i}",
            )
            for i in range(5)
        ]
        for e in events:
            db.add(e)
        db.commit()

        with patch(
            "cloud.services.event_bus._fire_webhooks"
        ):
            alerts = check_for_alerts(
                db, events, "test-tenant"
            )

        burst_alerts = [
            a
            for a in alerts
            if a.alert_type == "high_severity_burst"
        ]
        assert len(burst_alerts) == 1
        assert burst_alerts[0].severity == "high"
        assert (
            burst_alerts[0].details["event_count"] == 5
        )
        db.close()

    def test_four_high_severity_no_alert(self):
        from cloud.services.event_bus import check_for_alerts

        db = _make_db()
        events = [
            _make_event(
                agent_id="agent-x",
                severity="high",
                etype=f"op-{i}",
            )
            for i in range(4)
        ]
        for e in events:
            db.add(e)
        db.commit()

        with patch(
            "cloud.services.event_bus._fire_webhooks"
        ):
            alerts = check_for_alerts(
                db, events, "test-tenant"
            )

        burst_alerts = [
            a
            for a in alerts
            if a.alert_type == "high_severity_burst"
        ]
        assert len(burst_alerts) == 0
        db.close()

    def test_mixed_high_critical_counts(self):
        from cloud.services.event_bus import check_for_alerts

        db = _make_db()
        events = [
            _make_event(
                agent_id="agent-mix",
                severity="high",
                etype=f"h-{i}",
            )
            for i in range(3)
        ] + [
            _make_event(
                agent_id="agent-mix",
                severity="critical",
                etype=f"c-{i}",
            )
            for i in range(2)
        ]
        for e in events:
            db.add(e)
        db.commit()

        with patch(
            "cloud.services.event_bus._fire_webhooks"
        ):
            alerts = check_for_alerts(
                db, events, "test-tenant"
            )

        burst_alerts = [
            a
            for a in alerts
            if a.alert_type == "high_severity_burst"
        ]
        assert len(burst_alerts) == 1
        db.close()


class TestEventBusAgentFlapping:
    """Pattern 3: agent flapping (>=8 distinct types)."""

    def test_eight_types_triggers_alert(self):
        from cloud.services.event_bus import check_for_alerts

        db = _make_db()
        events = [
            _make_event(
                agent_id="flapper",
                etype=f"type-{i}",
            )
            for i in range(8)
        ]
        for e in events:
            db.add(e)
        db.commit()

        with patch(
            "cloud.services.event_bus._fire_webhooks"
        ):
            alerts = check_for_alerts(
                db, events, "test-tenant"
            )

        flap_alerts = [
            a
            for a in alerts
            if a.alert_type == "agent_flapping"
        ]
        assert len(flap_alerts) == 1
        assert flap_alerts[0].severity == "warn"
        assert (
            flap_alerts[0].details["distinct_types"] == 8
        )
        db.close()

    def test_seven_types_no_alert(self):
        from cloud.services.event_bus import check_for_alerts

        db = _make_db()
        events = [
            _make_event(
                agent_id="almost-flap",
                etype=f"type-{i}",
            )
            for i in range(7)
        ]
        for e in events:
            db.add(e)
        db.commit()

        with patch(
            "cloud.services.event_bus._fire_webhooks"
        ):
            alerts = check_for_alerts(
                db, events, "test-tenant"
            )

        flap_alerts = [
            a
            for a in alerts
            if a.alert_type == "agent_flapping"
        ]
        assert len(flap_alerts) == 0
        db.close()


class TestEventBusCombinedPatterns:
    """Multiple patterns firing in one batch."""

    def test_secret_exfil_and_burst_combined(self):
        from cloud.services.event_bus import check_for_alerts

        db = _make_db()
        # 2 secret events (pattern 1) + 5 high severity (pattern 2)
        events = [
            _make_event(
                agent_id="combo",
                severity="high",
                details={"accesses_secrets": True},
                etype="secret-read",
            ),
            _make_event(
                agent_id="combo",
                severity="high",
                details={"accesses_secrets": True},
                etype="secret-write",
            ),
        ] + [
            _make_event(
                agent_id="combo",
                severity="high",
                etype=f"burst-{i}",
            )
            for i in range(3)
        ]
        for e in events:
            db.add(e)
        db.commit()

        with patch(
            "cloud.services.event_bus._fire_webhooks"
        ):
            alerts = check_for_alerts(
                db, events, "test-tenant"
            )

        types = {a.alert_type for a in alerts}
        assert "repeated_secret_exfil" in types
        assert "high_severity_burst" in types
        db.close()


class TestFireWebhooks:
    """_fire_webhooks edge cases."""

    def test_fire_webhooks_disabled(self):
        """Webhook disabled means no sends."""
        from cloud.services.event_bus import (
            _fire_webhooks,
        )

        mock_sink = MagicMock()
        mock_sink.enabled = False

        with patch(
            "cloud.services.webhook.webhook_sink",
            mock_sink,
        ):
            _fire_webhooks([], "test")

    def test_fire_webhooks_import_error(self):
        """If webhook module is unavailable, no crash."""
        from cloud.services.event_bus import (
            _fire_webhooks,
        )

        with patch.dict(
            "sys.modules",
            {"cloud.services.webhook": None},
        ):
            # Should not raise
            _fire_webhooks([], "test")

    def test_fire_webhooks_with_low_severity_skipped(self):
        """Alerts with severity not in critical/high skip."""
        from cloud.services.event_bus import (
            _fire_webhooks,
        )

        alert = MagicMock()
        alert.severity = "warn"
        alert.alert_type = "agent_flapping"
        alert.id = "a-1"

        mock_sink = MagicMock()
        mock_sink.enabled = True

        with patch(
            "cloud.services.webhook.webhook_sink",
            mock_sink,
        ):
            _fire_webhooks([alert], "test")

        # send_alert should not be called since severity is warn
        mock_sink.send_alert.assert_not_called()


# ===========================================================================
# 4. cloud/integrations/wazuh_client.py — WazuhClient
# ===========================================================================


class TestWazuhClientDisabled:
    """WazuhClient disabled (no URL) returns empty for all."""

    def _make_disabled_client(self):
        from cloud.integrations.wazuh_client import (
            WazuhClient,
        )

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ANGELCLAW_WAZUH_URL", None)
            os.environ.pop("ANGELCLAW_WAZUH_USER", None)
            client = WazuhClient()
        return client

    def test_enabled_false(self):
        client = self._make_disabled_client()
        assert client.enabled is False

    def test_get_alerts_disabled(self):
        client = self._make_disabled_client()
        result = _run(client.get_alerts())
        assert result == []

    def test_get_agent_status_disabled(self):
        client = self._make_disabled_client()
        result = _run(client.get_agent_status("a1"))
        assert result == {}

    def test_get_all_agents_disabled(self):
        client = self._make_disabled_client()
        result = _run(client.get_all_agents())
        assert result == []

    def test_send_active_response_disabled(self):
        client = self._make_disabled_client()
        result = _run(
            client.send_active_response("a1", "block")
        )
        assert result is False

    def test_get_syscheck_events_disabled(self):
        client = self._make_disabled_client()
        result = _run(client.get_syscheck_events("a1"))
        assert result == []

    def test_health_check_disabled(self):
        client = self._make_disabled_client()
        result = _run(client.health_check())
        assert result["status"] == "disabled"


class TestWazuhClientEnabled:
    """WazuhClient.enabled property."""

    def test_enabled_with_url_and_user(self):
        from cloud.integrations.wazuh_client import (
            WazuhClient,
        )

        with patch.dict(
            os.environ,
            {
                "ANGELCLAW_WAZUH_URL": "https://wazuh:55000",
                "ANGELCLAW_WAZUH_USER": "admin",
                "ANGELCLAW_WAZUH_PASSWORD": "secret",
            },
        ):
            client = WazuhClient()
        assert client.enabled is True

    def test_enabled_without_user(self):
        from cloud.integrations.wazuh_client import (
            WazuhClient,
        )

        with patch.dict(
            os.environ,
            {
                "ANGELCLAW_WAZUH_URL": "https://wazuh:55000",
                "ANGELCLAW_WAZUH_USER": "",
            },
        ):
            client = WazuhClient()
        assert client.enabled is False


class TestWazuhEnsureToken:
    """_ensure_token() success, failure, and cached."""

    def _make_enabled_client(self):
        from cloud.integrations.wazuh_client import (
            WazuhClient,
        )

        with patch.dict(
            os.environ,
            {
                "ANGELCLAW_WAZUH_URL": "https://wazuh:55000",
                "ANGELCLAW_WAZUH_USER": "admin",
                "ANGELCLAW_WAZUH_PASSWORD": "pass",
                "ANGELCLAW_WAZUH_VERIFY_SSL": "false",
            },
        ):
            client = WazuhClient()
        return client

    def test_ensure_token_success(self):
        client = self._make_enabled_client()

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {"token": "jwt-abc-123"}
        }
        mock_resp.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(
            return_value=mock_http
        )
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(return_value=mock_resp)

        with patch(
            "httpx.AsyncClient", return_value=mock_http
        ):
            token = _run(client._ensure_token())

        assert token == "jwt-abc-123"
        assert client._token == "jwt-abc-123"
        assert client._token_expires is not None

    def test_ensure_token_cached(self):
        client = self._make_enabled_client()
        client._token = "cached-token"
        client._token_expires = (
            datetime.now(timezone.utc) + timedelta(minutes=5)
        )

        token = _run(client._ensure_token())
        assert token == "cached-token"

    def test_ensure_token_failure(self):
        client = self._make_enabled_client()

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(
            return_value=mock_http
        )
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(
            side_effect=httpx.ConnectError("refused")
        )

        with patch(
            "httpx.AsyncClient", return_value=mock_http
        ):
            token = _run(client._ensure_token())

        assert token is None
        assert client._token is None

    def test_ensure_token_not_enabled(self):
        from cloud.integrations.wazuh_client import (
            WazuhClient,
        )

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ANGELCLAW_WAZUH_URL", None)
            os.environ.pop("ANGELCLAW_WAZUH_USER", None)
            client = WazuhClient()

        token = _run(client._ensure_token())
        assert token is None


class TestWazuhRequest:
    """_request() with auth, HTTP 401 re-auth, and errors."""

    def _make_enabled_client(self):
        from cloud.integrations.wazuh_client import (
            WazuhClient,
        )

        with patch.dict(
            os.environ,
            {
                "ANGELCLAW_WAZUH_URL": "https://wazuh:55000",
                "ANGELCLAW_WAZUH_USER": "admin",
                "ANGELCLAW_WAZUH_PASSWORD": "pass",
                "ANGELCLAW_WAZUH_VERIFY_SSL": "false",
            },
        ):
            client = WazuhClient()
        client._token = "valid-token"
        client._token_expires = (
            datetime.now(timezone.utc) + timedelta(minutes=5)
        )
        return client

    def test_request_success(self):
        client = self._make_enabled_client()

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {"items": ["a"]}
        }
        mock_resp.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(
            return_value=mock_http
        )
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.request = AsyncMock(
            return_value=mock_resp
        )

        with patch(
            "httpx.AsyncClient", return_value=mock_http
        ):
            result = _run(client._request("GET", "/test"))

        assert result == {"data": {"items": ["a"]}}

    def test_request_401_clears_token(self):
        client = self._make_enabled_client()

        resp_401 = httpx.Response(
            401,
            request=httpx.Request("GET", "https://wazuh:55000/test"),
        )
        exc = httpx.HTTPStatusError(
            "Unauthorized",
            request=resp_401.request,
            response=resp_401,
        )

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(
            return_value=mock_http
        )
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.request = AsyncMock(side_effect=exc)

        with patch(
            "httpx.AsyncClient", return_value=mock_http
        ):
            result = _run(client._request("GET", "/test"))

        assert result == {}
        assert client._token is None

    def test_request_generic_error(self):
        client = self._make_enabled_client()

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(
            return_value=mock_http
        )
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.request = AsyncMock(
            side_effect=httpx.ConnectError("down")
        )

        with patch(
            "httpx.AsyncClient", return_value=mock_http
        ):
            result = _run(client._request("GET", "/fail"))

        assert result == {}

    def test_request_no_token(self):
        """If _ensure_token returns None, request returns {}."""
        client = self._make_enabled_client()
        client._token = None
        client._token_expires = None

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(
            return_value=mock_http
        )
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(
            side_effect=httpx.ConnectError("no auth")
        )

        with patch(
            "httpx.AsyncClient", return_value=mock_http
        ):
            result = _run(client._request("GET", "/x"))

        assert result == {}


class TestWazuhGetAlerts:
    """get_alerts() method."""

    def _make_client_with_token(self):
        from cloud.integrations.wazuh_client import (
            WazuhClient,
        )

        with patch.dict(
            os.environ,
            {
                "ANGELCLAW_WAZUH_URL": "https://w:55000",
                "ANGELCLAW_WAZUH_USER": "u",
                "ANGELCLAW_WAZUH_PASSWORD": "p",
            },
        ):
            client = WazuhClient()
        client._token = "tok"
        client._token_expires = (
            datetime.now(timezone.utc) + timedelta(minutes=5)
        )
        return client

    def test_get_alerts_returns_items(self):
        client = self._make_client_with_token()

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {
                "affected_items": [
                    {"id": 1, "rule": {"level": 10}}
                ]
            }
        }
        mock_resp.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(
            return_value=mock_http
        )
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.request = AsyncMock(
            return_value=mock_resp
        )

        with patch(
            "httpx.AsyncClient", return_value=mock_http
        ):
            alerts = _run(client.get_alerts(limit=10))

        assert len(alerts) == 1
        assert alerts[0]["id"] == 1

    def test_get_alerts_with_severity(self):
        client = self._make_client_with_token()

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {"affected_items": []}
        }
        mock_resp.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(
            return_value=mock_http
        )
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.request = AsyncMock(
            return_value=mock_resp
        )

        with patch(
            "httpx.AsyncClient", return_value=mock_http
        ):
            alerts = _run(
                client.get_alerts(severity=7, limit=50)
            )

        assert alerts == []


class TestWazuhAgentStatus:
    """get_agent_status() and get_all_agents()."""

    def _make_client_with_token(self):
        from cloud.integrations.wazuh_client import (
            WazuhClient,
        )

        with patch.dict(
            os.environ,
            {
                "ANGELCLAW_WAZUH_URL": "https://w:55000",
                "ANGELCLAW_WAZUH_USER": "u",
                "ANGELCLAW_WAZUH_PASSWORD": "p",
            },
        ):
            client = WazuhClient()
        client._token = "tok"
        client._token_expires = (
            datetime.now(timezone.utc) + timedelta(minutes=5)
        )
        return client

    def test_get_agent_status_found(self):
        client = self._make_client_with_token()

        with patch.object(
            client,
            "_request",
            new_callable=AsyncMock,
        ) as mock_req:
            mock_req.return_value = {
                "data": {
                    "affected_items": [
                        {
                            "id": "001",
                            "status": "active",
                        }
                    ]
                }
            }
            result = _run(
                client.get_agent_status("001")
            )

        assert result["status"] == "active"

    def test_get_agent_status_not_found(self):
        client = self._make_client_with_token()

        with patch.object(
            client,
            "_request",
            new_callable=AsyncMock,
        ) as mock_req:
            mock_req.return_value = {
                "data": {"affected_items": []}
            }
            result = _run(
                client.get_agent_status("999")
            )

        assert result == {}

    def test_get_all_agents(self):
        client = self._make_client_with_token()

        with patch.object(
            client,
            "_request",
            new_callable=AsyncMock,
        ) as mock_req:
            mock_req.return_value = {
                "data": {
                    "affected_items": [
                        {"id": "001"},
                        {"id": "002"},
                    ]
                }
            }
            result = _run(client.get_all_agents())

        assert len(result) == 2


class TestWazuhActiveResponse:
    """send_active_response() success and failure."""

    def _make_client_with_token(self):
        from cloud.integrations.wazuh_client import (
            WazuhClient,
        )

        with patch.dict(
            os.environ,
            {
                "ANGELCLAW_WAZUH_URL": "https://w:55000",
                "ANGELCLAW_WAZUH_USER": "u",
                "ANGELCLAW_WAZUH_PASSWORD": "p",
            },
        ):
            client = WazuhClient()
        client._token = "tok"
        client._token_expires = (
            datetime.now(timezone.utc) + timedelta(minutes=5)
        )
        return client

    def test_active_response_success(self):
        client = self._make_client_with_token()

        with patch.object(
            client,
            "_request",
            new_callable=AsyncMock,
        ) as mock_req:
            mock_req.return_value = {
                "data": {"total_affected_items": 1}
            }
            result = _run(
                client.send_active_response(
                    "001", "block-ip", ["-ip", "10.0.0.1"]
                )
            )

        assert result is True

    def test_active_response_failure(self):
        client = self._make_client_with_token()

        with patch.object(
            client,
            "_request",
            new_callable=AsyncMock,
        ) as mock_req:
            mock_req.return_value = {
                "data": {"total_affected_items": 0}
            }
            result = _run(
                client.send_active_response(
                    "001", "quarantine"
                )
            )

        assert result is False


class TestWazuhSyscheck:
    """get_syscheck_events()."""

    def test_syscheck_returns_items(self):
        from cloud.integrations.wazuh_client import (
            WazuhClient,
        )

        with patch.dict(
            os.environ,
            {
                "ANGELCLAW_WAZUH_URL": "https://w:55000",
                "ANGELCLAW_WAZUH_USER": "u",
                "ANGELCLAW_WAZUH_PASSWORD": "p",
            },
        ):
            client = WazuhClient()
        client._token = "tok"
        client._token_expires = (
            datetime.now(timezone.utc) + timedelta(minutes=5)
        )

        with patch.object(
            client,
            "_request",
            new_callable=AsyncMock,
        ) as mock_req:
            mock_req.return_value = {
                "data": {
                    "affected_items": [
                        {"file": "/etc/passwd", "event": "m"}
                    ]
                }
            }
            result = _run(
                client.get_syscheck_events("001")
            )

        assert len(result) == 1
        assert result[0]["file"] == "/etc/passwd"


class TestWazuhHealthCheck:
    """health_check() enabled and disabled."""

    def test_health_check_ok(self):
        from cloud.integrations.wazuh_client import (
            WazuhClient,
        )

        with patch.dict(
            os.environ,
            {
                "ANGELCLAW_WAZUH_URL": "https://w:55000",
                "ANGELCLAW_WAZUH_USER": "u",
                "ANGELCLAW_WAZUH_PASSWORD": "p",
            },
        ):
            client = WazuhClient()
        client._token = "tok"
        client._token_expires = (
            datetime.now(timezone.utc) + timedelta(minutes=5)
        )

        with patch.object(
            client,
            "_request",
            new_callable=AsyncMock,
        ) as mock_req:
            mock_req.return_value = {
                "data": {"nodes": ["master"]}
            }
            result = _run(client.health_check())

        assert result["status"] == "ok"
        assert "manager" in result

    def test_health_check_unreachable(self):
        from cloud.integrations.wazuh_client import (
            WazuhClient,
        )

        with patch.dict(
            os.environ,
            {
                "ANGELCLAW_WAZUH_URL": "https://w:55000",
                "ANGELCLAW_WAZUH_USER": "u",
                "ANGELCLAW_WAZUH_PASSWORD": "p",
            },
        ):
            client = WazuhClient()
        client._token = "tok"
        client._token_expires = (
            datetime.now(timezone.utc) + timedelta(minutes=5)
        )

        with patch.object(
            client,
            "_request",
            new_callable=AsyncMock,
        ) as mock_req:
            mock_req.return_value = {}
            result = _run(client.health_check())

        assert result["status"] == "unreachable"


class TestWazuhVerifySSL:
    """verify_ssl configuration from environment."""

    def test_verify_ssl_true_default(self):
        from cloud.integrations.wazuh_client import (
            WazuhClient,
        )

        with patch.dict(
            os.environ,
            {
                "ANGELCLAW_WAZUH_URL": "https://w:55000",
                "ANGELCLAW_WAZUH_USER": "u",
                "ANGELCLAW_WAZUH_PASSWORD": "p",
            },
        ):
            os.environ.pop(
                "ANGELCLAW_WAZUH_VERIFY_SSL", None
            )
            client = WazuhClient()
        assert client.verify_ssl is True

    def test_verify_ssl_false(self):
        from cloud.integrations.wazuh_client import (
            WazuhClient,
        )

        with patch.dict(
            os.environ,
            {
                "ANGELCLAW_WAZUH_URL": "https://w:55000",
                "ANGELCLAW_WAZUH_USER": "u",
                "ANGELCLAW_WAZUH_PASSWORD": "p",
                "ANGELCLAW_WAZUH_VERIFY_SSL": "false",
            },
        ):
            client = WazuhClient()
        assert client.verify_ssl is False

    def test_verify_ssl_zero(self):
        from cloud.integrations.wazuh_client import (
            WazuhClient,
        )

        with patch.dict(
            os.environ,
            {
                "ANGELCLAW_WAZUH_URL": "https://w:55000",
                "ANGELCLAW_WAZUH_USER": "u",
                "ANGELCLAW_WAZUH_PASSWORD": "p",
                "ANGELCLAW_WAZUH_VERIFY_SSL": "0",
            },
        ):
            client = WazuhClient()
        assert client.verify_ssl is False

    def test_verify_ssl_no(self):
        from cloud.integrations.wazuh_client import (
            WazuhClient,
        )

        with patch.dict(
            os.environ,
            {
                "ANGELCLAW_WAZUH_URL": "https://w:55000",
                "ANGELCLAW_WAZUH_USER": "u",
                "ANGELCLAW_WAZUH_PASSWORD": "p",
                "ANGELCLAW_WAZUH_VERIFY_SSL": "no",
            },
        ):
            client = WazuhClient()
        assert client.verify_ssl is False
