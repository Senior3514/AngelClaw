"""Comprehensive coverage tests for auth dependencies, webhook sink, and response agent."""

from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from cloud.auth.models import AuthUser, UserRole
from cloud.guardian.models import (
    AgentTask,
    Playbook,
    PlaybookStep,
)

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


def _make_request():
    """Create a mock FastAPI Request object."""
    req = MagicMock()
    req.state = MagicMock()
    return req


def _admin_user():
    return AuthUser(username="admin", role=UserRole.ADMIN, tenant_id="test-tenant")


def _viewer_user():
    return AuthUser(username="viewer", role=UserRole.VIEWER, tenant_id="test-tenant")


# ===========================================================================
# 1. cloud/auth/dependencies.py
# ===========================================================================


class TestGetCurrentUserAuthDisabled:
    """get_current_user() with AUTH_ENABLED=False returns anonymous."""

    @patch("cloud.auth.dependencies.AUTH_ENABLED", False)
    def test_returns_anonymous(self):
        from cloud.auth.dependencies import get_current_user

        user = _run(get_current_user(_make_request(), None, None))
        assert user.username == "anonymous"
        assert user.role == UserRole.OPERATOR
        assert user.tenant_id == "dev-tenant"


class TestGetCurrentUserBearerToken:
    """get_current_user() with Bearer token calls verify_jwt."""

    @patch("cloud.auth.dependencies.AUTH_ENABLED", True)
    @patch("cloud.auth.dependencies.verify_jwt")
    def test_bearer_header_calls_verify_jwt(self, mock_jwt):
        from cloud.auth.dependencies import get_current_user

        mock_jwt.return_value = _admin_user()
        user = _run(get_current_user(_make_request(), "Bearer my-token", None))
        mock_jwt.assert_called_once_with("my-token")
        assert user.username == "admin"

    @patch("cloud.auth.dependencies.AUTH_ENABLED", True)
    @patch("cloud.auth.dependencies.verify_jwt")
    def test_raw_authorization_header(self, mock_jwt):
        """Authorization header without 'Bearer ' prefix is used as-is."""
        from cloud.auth.dependencies import get_current_user

        mock_jwt.return_value = _admin_user()
        user = _run(get_current_user(_make_request(), "raw-token-value", None))
        mock_jwt.assert_called_once_with("raw-token-value")
        assert user.username == "admin"


class TestGetCurrentUserCookieToken:
    """get_current_user() with cookie token calls verify_jwt."""

    @patch("cloud.auth.dependencies.AUTH_ENABLED", True)
    @patch("cloud.auth.dependencies.verify_jwt")
    def test_cookie_fallback(self, mock_jwt):
        from cloud.auth.dependencies import get_current_user

        mock_jwt.return_value = _admin_user()
        user = _run(get_current_user(_make_request(), None, "cookie-token"))
        mock_jwt.assert_called_once_with("cookie-token")
        assert user.username == "admin"


class TestGetCurrentUserNoToken:
    """get_current_user() with no token raises 401."""

    @patch("cloud.auth.dependencies.AUTH_ENABLED", True)
    def test_raises_401(self):
        from fastapi import HTTPException

        from cloud.auth.dependencies import get_current_user

        with pytest.raises(HTTPException) as exc_info:
            _run(get_current_user(_make_request(), None, None))
        assert exc_info.value.status_code == 401
        assert "Authentication required" in exc_info.value.detail


class TestGetCurrentUserInvalidToken:
    """get_current_user() with invalid token raises 401."""

    @patch("cloud.auth.dependencies.AUTH_ENABLED", True)
    @patch("cloud.auth.dependencies.AUTH_MODE", "local")
    @patch("cloud.auth.dependencies.verify_jwt", return_value=None)
    def test_raises_401_invalid(self, _mock_jwt):
        from fastapi import HTTPException

        from cloud.auth.dependencies import get_current_user

        with pytest.raises(HTTPException) as exc_info:
            _run(get_current_user(_make_request(), "Bearer bad-token", None))
        assert exc_info.value.status_code == 401
        assert "Invalid or expired token" in exc_info.value.detail


class TestGetCurrentUserBearerModeFallback:
    """get_current_user() falls back to verify_bearer when AUTH_MODE='bearer'."""

    @patch("cloud.auth.dependencies.AUTH_ENABLED", True)
    @patch("cloud.auth.dependencies.AUTH_MODE", "bearer")
    @patch("cloud.auth.dependencies.verify_jwt", return_value=None)
    @patch("cloud.auth.dependencies.verify_bearer")
    def test_bearer_fallback_success(self, mock_bearer, _mock_jwt):
        from cloud.auth.dependencies import get_current_user

        mock_bearer.return_value = AuthUser(
            username="bearer-user", role=UserRole.OPERATOR, tenant_id="dev-tenant"
        )
        user = _run(get_current_user(_make_request(), "Bearer static-tok", None))
        mock_bearer.assert_called_once_with("static-tok")
        assert user.username == "bearer-user"

    @patch("cloud.auth.dependencies.AUTH_ENABLED", True)
    @patch("cloud.auth.dependencies.AUTH_MODE", "bearer")
    @patch("cloud.auth.dependencies.verify_jwt", return_value=None)
    @patch("cloud.auth.dependencies.verify_bearer", return_value=None)
    def test_bearer_fallback_failure_raises_401(self, _mock_bearer, _mock_jwt):
        from fastapi import HTTPException

        from cloud.auth.dependencies import get_current_user

        with pytest.raises(HTTPException) as exc_info:
            _run(get_current_user(_make_request(), "Bearer bad", None))
        assert exc_info.value.status_code == 401


class TestRequireRole:
    """require_role() returns a dependency that checks role hierarchy."""

    @patch("cloud.auth.dependencies.AUTH_ENABLED", True)
    @patch("cloud.auth.dependencies.verify_jwt")
    def test_admin_passes_admin_check(self, mock_jwt):
        from cloud.auth.dependencies import require_role

        mock_jwt.return_value = _admin_user()
        checker = require_role(UserRole.ADMIN)
        user = _run(checker(_make_request(), "Bearer tok", None))
        assert user.username == "admin"

    @patch("cloud.auth.dependencies.AUTH_ENABLED", True)
    @patch("cloud.auth.dependencies.verify_jwt")
    def test_viewer_fails_admin_check(self, mock_jwt):
        from fastapi import HTTPException

        from cloud.auth.dependencies import require_role

        mock_jwt.return_value = _viewer_user()
        checker = require_role(UserRole.ADMIN)
        with pytest.raises(HTTPException) as exc_info:
            _run(checker(_make_request(), "Bearer tok", None))
        assert exc_info.value.status_code == 403
        assert "Requires admin role" in exc_info.value.detail

    @patch("cloud.auth.dependencies.AUTH_ENABLED", True)
    @patch("cloud.auth.dependencies.verify_jwt")
    def test_admin_passes_viewer_check(self, mock_jwt):
        from cloud.auth.dependencies import require_role

        mock_jwt.return_value = _admin_user()
        checker = require_role(UserRole.VIEWER)
        user = _run(checker(_make_request(), "Bearer tok", None))
        assert user.role == UserRole.ADMIN

    @patch("cloud.auth.dependencies.AUTH_ENABLED", False)
    def test_auth_disabled_passes(self):
        from cloud.auth.dependencies import require_role

        # Operator (level 3) < Admin (level 4) — anonymous is OPERATOR.
        # Test with VIEWER requirement instead.
        checker_viewer = require_role(UserRole.VIEWER)
        user = _run(checker_viewer(_make_request(), None, None))
        assert user.username == "anonymous"


class TestOptionalAuth:
    """optional_auth() tests."""

    @patch("cloud.auth.dependencies.AUTH_ENABLED", False)
    def test_auth_disabled_returns_anonymous(self):
        from cloud.auth.dependencies import optional_auth

        user = _run(optional_auth(_make_request(), None, None))
        assert user is not None
        assert user.username == "anonymous"

    @patch("cloud.auth.dependencies.AUTH_ENABLED", True)
    def test_no_token_returns_none(self):
        from cloud.auth.dependencies import optional_auth

        user = _run(optional_auth(_make_request(), None, None))
        assert user is None

    @patch("cloud.auth.dependencies.AUTH_ENABLED", True)
    @patch("cloud.auth.dependencies.verify_jwt")
    def test_valid_jwt_returns_user(self, mock_jwt):
        from cloud.auth.dependencies import optional_auth

        mock_jwt.return_value = _admin_user()
        user = _run(optional_auth(_make_request(), "Bearer valid-jwt", None))
        assert user is not None
        assert user.username == "admin"

    @patch("cloud.auth.dependencies.AUTH_ENABLED", True)
    @patch("cloud.auth.dependencies.verify_jwt", return_value=None)
    def test_invalid_jwt_returns_none(self, _mock_jwt):
        from cloud.auth.dependencies import optional_auth

        user = _run(optional_auth(_make_request(), "Bearer bad-jwt", None))
        assert user is None

    @patch("cloud.auth.dependencies.AUTH_ENABLED", True)
    @patch("cloud.auth.dependencies.verify_jwt")
    def test_cookie_token(self, mock_jwt):
        from cloud.auth.dependencies import optional_auth

        mock_jwt.return_value = _admin_user()
        user = _run(optional_auth(_make_request(), None, "cookie-value"))
        mock_jwt.assert_called_once_with("cookie-value")
        assert user.username == "admin"

    @patch("cloud.auth.dependencies.AUTH_ENABLED", True)
    @patch("cloud.auth.dependencies.AUTH_MODE", "bearer")
    @patch("cloud.auth.dependencies.verify_jwt", return_value=None)
    @patch("cloud.auth.dependencies.verify_bearer")
    def test_bearer_mode_fallback(self, mock_bearer, _mock_jwt):
        from cloud.auth.dependencies import optional_auth

        mock_bearer.return_value = AuthUser(
            username="bearer-user", role=UserRole.OPERATOR, tenant_id="dev-tenant"
        )
        user = _run(optional_auth(_make_request(), "raw-token", None))
        mock_bearer.assert_called_once_with("raw-token")
        assert user.username == "bearer-user"

    @patch("cloud.auth.dependencies.AUTH_ENABLED", True)
    @patch("cloud.auth.dependencies.AUTH_MODE", "bearer")
    @patch("cloud.auth.dependencies.verify_jwt", return_value=None)
    @patch("cloud.auth.dependencies.verify_bearer", return_value=None)
    def test_bearer_mode_no_match_returns_none(self, _mock_bearer, _mock_jwt):
        from cloud.auth.dependencies import optional_auth

        user = _run(optional_auth(_make_request(), "Bearer unknown", None))
        assert user is None

    @patch("cloud.auth.dependencies.AUTH_ENABLED", True)
    @patch("cloud.auth.dependencies.AUTH_MODE", "local")
    @patch("cloud.auth.dependencies.verify_jwt", return_value=None)
    def test_local_mode_invalid_returns_none(self, _mock_jwt):
        from cloud.auth.dependencies import optional_auth

        user = _run(optional_auth(_make_request(), "Bearer bad-jwt", None))
        assert user is None


# ===========================================================================
# 2. cloud/services/webhook.py
# ===========================================================================


class TestWebhookSinkDisabled:
    """WebhookSink with no env vars has enabled=False."""

    def test_no_url_means_disabled(self):
        with patch.dict(os.environ, {}, clear=True):
            # Remove keys if they exist
            env = os.environ.copy()
            env.pop("ANGELCLAW_WEBHOOK_URL", None)
            env.pop("ANGELCLAW_WEBHOOK_SECRET", None)
            with patch.dict(os.environ, env, clear=True):
                from cloud.services.webhook import WebhookSink

                sink = WebhookSink()
                assert sink.enabled is False


class TestWebhookSendAlertDisabled:
    """send_alert() when disabled returns False."""

    def test_send_alert_disabled(self):
        with patch.dict(
            os.environ,
            {"ANGELCLAW_WEBHOOK_URL": "", "ANGELCLAW_WEBHOOK_SECRET": ""},
            clear=False,
        ):
            from cloud.services.webhook import WebhookSink

            sink = WebhookSink()
            assert sink.enabled is False
            result = _run(sink.send_alert("test", "title", "high"))
            assert result is False


class TestWebhookSendAlertSuccess:
    """send_alert() with valid URL sends POST."""

    def test_send_alert_success(self):
        with patch.dict(
            os.environ,
            {"ANGELCLAW_WEBHOOK_URL": "https://hooks.example.com/alert"},
            clear=False,
        ):
            from cloud.services.webhook import WebhookSink

            sink = WebhookSink()
            assert sink.enabled is True

            mock_response = MagicMock()
            mock_response.status_code = 200

            mock_client = AsyncMock(spec=httpx.AsyncClient)
            mock_client.post = AsyncMock(return_value=mock_response)
            sink._client = mock_client

            result = _run(
                sink.send_alert(
                    alert_type="threat_detected",
                    title="Suspicious activity",
                    severity="high",
                    details={"agent_id": "node-001"},
                    tenant_id="test-tenant",
                    related_event_ids=["evt-1", "evt-2"],
                )
            )
            assert result is True
            mock_client.post.assert_called_once()
            call_kwargs = mock_client.post.call_args
            assert call_kwargs[0][0] == "https://hooks.example.com/alert"


class TestWebhookSendAlertHMAC:
    """send_alert() with HMAC secret includes X-AngelClaw-Signature header."""

    def test_hmac_signature_header(self):
        test_secret = "my-secret-key"  # noqa: S105
        with patch.dict(
            os.environ,
            {
                "ANGELCLAW_WEBHOOK_URL": "https://hooks.example.com/alert",
                "ANGELCLAW_WEBHOOK_SECRET": test_secret,
            },
            clear=False,
        ):
            from cloud.services.webhook import WebhookSink

            sink = WebhookSink()
            assert sink.secret == test_secret

            mock_response = MagicMock()
            mock_response.status_code = 200

            mock_client = AsyncMock(spec=httpx.AsyncClient)
            mock_client.post = AsyncMock(return_value=mock_response)
            sink._client = mock_client

            result = _run(sink.send_alert("alert", "Test Alert", "medium"))
            assert result is True

            call_kwargs = mock_client.post.call_args
            headers = call_kwargs[1]["headers"]
            assert "X-AngelClaw-Signature" in headers
            assert headers["X-AngelClaw-Signature"].startswith("sha256=")


class TestWebhookSendAlertRequestFails:
    """send_alert() when request fails returns False."""

    def test_network_error(self):
        with patch.dict(
            os.environ,
            {"ANGELCLAW_WEBHOOK_URL": "https://hooks.example.com/alert"},
            clear=False,
        ):
            from cloud.services.webhook import WebhookSink

            sink = WebhookSink()

            mock_client = AsyncMock(spec=httpx.AsyncClient)
            mock_client.post = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
            sink._client = mock_client

            result = _run(sink.send_alert("alert", "Title", "high"))
            assert result is False


class TestWebhookSendAlertServerError:
    """send_alert() when server returns error returns False."""

    def test_server_500(self):
        with patch.dict(
            os.environ,
            {"ANGELCLAW_WEBHOOK_URL": "https://hooks.example.com/alert"},
            clear=False,
        ):
            from cloud.services.webhook import WebhookSink

            sink = WebhookSink()

            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_response.text = "Internal Server Error"

            mock_client = AsyncMock(spec=httpx.AsyncClient)
            mock_client.post = AsyncMock(return_value=mock_response)
            sink._client = mock_client

            result = _run(sink.send_alert("alert", "Title", "high"))
            assert result is False


class TestWebhookSendAlertClientCreation:
    """send_alert() creates client when _client is None."""

    def test_auto_creates_client(self):
        with patch.dict(
            os.environ,
            {"ANGELCLAW_WEBHOOK_URL": "https://hooks.example.com/alert"},
            clear=False,
        ):
            from cloud.services.webhook import WebhookSink

            sink = WebhookSink()
            assert sink._client is None

            mock_response = MagicMock()
            mock_response.status_code = 200

            with patch("cloud.services.webhook.httpx.AsyncClient") as mock_cls:
                mock_inst = AsyncMock()
                mock_inst.post = AsyncMock(return_value=mock_response)
                mock_cls.return_value = mock_inst

                result = _run(sink.send_alert("alert", "Title", "high"))
                assert result is True
                mock_cls.assert_called_once_with(timeout=10)


class TestWebhookClose:
    """close() closes the client."""

    def test_close_with_client(self):
        from cloud.services.webhook import WebhookSink

        sink = WebhookSink()
        mock_client = AsyncMock()
        mock_client.aclose = AsyncMock()
        sink._client = mock_client

        _run(sink.close())
        mock_client.aclose.assert_called_once()
        assert sink._client is None

    def test_close_without_client(self):
        from cloud.services.webhook import WebhookSink

        sink = WebhookSink()
        assert sink._client is None
        _run(sink.close())  # Should not raise
        assert sink._client is None


# ===========================================================================
# 3. cloud/guardian/response_agent.py
# ===========================================================================


def _make_agent():
    """Create a ResponseAgent with mocked playbook loading."""
    with patch(
        "cloud.guardian.response_agent.PLAYBOOKS_DIR",
        MagicMock(exists=MagicMock(return_value=False)),
    ):
        from cloud.guardian.response_agent import ResponseAgent

        agent = ResponseAgent()
    return agent


def _make_task(payload: dict) -> AgentTask:
    return AgentTask(
        task_id="test-task-001",
        task_type="respond",
        payload=payload,
    )


def _sample_playbook(auto_respond=True, steps=None, rollback=None):
    return Playbook(
        name="test-playbook",
        description="Test playbook",
        auto_respond=auto_respond,
        steps=steps
        or [
            PlaybookStep(
                action="pause_agent",
                target="{{ agent_id }}",
                description="Pause the agent",
            ),
        ],
        rollback_steps=rollback or [],
    )


class TestResponseAgentHandleTaskUnknownPlaybook:
    """handle_task() with unknown playbook returns error."""

    def test_unknown_playbook(self):
        agent = _make_agent()
        task = _make_task({"playbook_name": "nonexistent"})
        result = _run(agent.handle_task(task))
        assert result.success is False
        assert "Unknown playbook" in result.error


class TestResponseAgentHandleTaskApprovalRequired:
    """handle_task() with approval required returns requires_approval."""

    def test_requires_approval(self):
        agent = _make_agent()
        pb = _sample_playbook(auto_respond=False)
        agent._playbooks["needs-approval"] = pb
        task = _make_task({"playbook_name": "needs-approval", "approved": False})
        result = _run(agent.handle_task(task))
        assert result.success is False
        assert "requires operator approval" in result.error.lower()
        assert result.result_data["requires_approval"] is True
        assert result.result_data["playbook"] == "needs-approval"

    def test_approved_playbook_runs(self):
        agent = _make_agent()
        pb = _sample_playbook(auto_respond=False)
        agent._playbooks["needs-approval"] = pb
        task = _make_task(
            {
                "playbook_name": "needs-approval",
                "approved": True,
                "incident": {"agent_id": "node-42"},
            }
        )
        result = _run(agent.handle_task(task))
        assert result.success is True


class TestResponseAgentCircuitBreaker:
    """handle_task() with circuit breaker tripped."""

    def test_circuit_breaker_tripped(self):
        agent = _make_agent()
        agent._consecutive_failures = 3  # >= _max_failures
        pb = _sample_playbook()
        agent._playbooks["test-playbook"] = pb
        task = _make_task(
            {
                "playbook_name": "test-playbook",
                "incident": {},
            }
        )
        result = _run(agent.handle_task(task))
        assert result.success is False
        assert "Circuit breaker" in result.error


class TestResponseAgentDryRun:
    """handle_task() in dry_run mode."""

    def test_dry_run(self):
        agent = _make_agent()
        pb = _sample_playbook()
        agent._playbooks["test-playbook"] = pb
        task = _make_task(
            {
                "playbook_name": "test-playbook",
                "incident": {"agent_id": "node-99"},
                "dry_run": True,
            }
        )
        result = _run(agent.handle_task(task))
        assert result.success is True
        assert result.result_data["dry_run"] is True
        step_results = result.result_data["results"]
        assert len(step_results) > 0
        assert "[DRY RUN]" in step_results[0]["message"]


class TestResponseAgentExecuteStep:
    """_execute_step() tests."""

    def test_unknown_action(self):
        agent = _make_agent()
        step = PlaybookStep(action="unknown_action", target="target")
        result = _run(agent._execute_step(step, "target", {}, False))
        assert result.success is False
        assert "Unknown action" in result.message

    def test_dry_run_step(self):
        agent = _make_agent()
        step = PlaybookStep(action="pause_agent", target="node-1")
        result = _run(agent._execute_step(step, "node-1", {}, True))
        assert result.success is True
        assert result.dry_run is True
        assert "[DRY RUN]" in result.message

    def test_action_exception(self):
        agent = _make_agent()
        step = PlaybookStep(action="pause_agent", target="node-1")

        async def _explode(*args, **kwargs):
            raise RuntimeError("boom")

        agent._action_registry["pause_agent"] = _explode
        result = _run(agent._execute_step(step, "node-1", {}, False))
        assert result.success is False
        assert "boom" in result.message


class TestResponseAgentResolveTemplate:
    """_resolve_template() variable substitution."""

    def test_double_brace_space(self):
        from cloud.guardian.response_agent import ResponseAgent

        result = ResponseAgent._resolve_template(
            "Agent {{ agent_id }} is compromised",
            {"agent_id": "node-42"},
        )
        assert result == "Agent node-42 is compromised"

    def test_double_brace_no_space(self):
        from cloud.guardian.response_agent import ResponseAgent

        result = ResponseAgent._resolve_template(
            "Agent {{agent_id}} blocked",
            {"agent_id": "node-99"},
        )
        assert result == "Agent node-99 blocked"

    def test_multiple_vars(self):
        from cloud.guardian.response_agent import ResponseAgent

        result = ResponseAgent._resolve_template(
            "{{ user }} on {{ host }}",
            {"user": "alice", "host": "srv-1"},
        )
        assert result == "alice on srv-1"

    def test_no_match(self):
        from cloud.guardian.response_agent import ResponseAgent

        result = ResponseAgent._resolve_template(
            "no variables here",
            {"key": "val"},
        )
        assert result == "no variables here"


class TestResponseAgentActions:
    """Individual action tests."""

    def test_pause_agent(self):
        agent = _make_agent()
        result = _run(agent._action_pause_agent("node-1", {}, {}))
        assert result.success is True
        assert result.action == "pause_agent"
        assert "paused" in result.message.lower()
        assert result.after_state["status"] == "quarantined"

    def test_resume_agent(self):
        agent = _make_agent()
        result = _run(agent._action_resume_agent("node-1", {}, {}))
        assert result.success is True
        assert result.action == "resume_agent"
        assert "resumed" in result.message.lower()
        assert result.after_state["status"] == "active"

    def test_revoke_token(self):
        agent = _make_agent()
        result = _run(agent._action_revoke_token("user-abc", {}, {}))
        assert result.success is True
        assert "revoked" in result.message.lower()

    def test_throttle_agent_default_rate(self):
        agent = _make_agent()
        result = _run(agent._action_throttle_agent("node-1", {}, {}))
        assert result.success is True
        assert "1req/10s" in result.message

    def test_throttle_agent_custom_rate(self):
        agent = _make_agent()
        result = _run(agent._action_throttle_agent("node-1", {}, {"rate": "5req/1s"}))
        assert result.success is True
        assert "5req/1s" in result.message
        assert result.after_state["throttle_rate"] == "5req/1s"

    def test_block_source_default_duration(self):
        agent = _make_agent()
        result = _run(agent._action_block_source("10.0.0.1", {}, {}))
        assert result.success is True
        assert "blocked" in result.message.lower()
        assert result.after_state["duration"] == 3600

    def test_block_source_custom_duration(self):
        agent = _make_agent()
        result = _run(agent._action_block_source("10.0.0.1", {}, {"duration_seconds": 7200}))
        assert result.success is True
        assert result.after_state["duration"] == 7200

    def test_snapshot_state(self):
        agent = _make_agent()
        result = _run(agent._action_snapshot_state("node-1", {}, {}))
        assert result.success is True
        assert "snapshot" in result.message.lower()

    def test_notify_operator(self):
        agent = _make_agent()
        with patch("cloud.services.webhook.webhook_sink") as mock_sink:
            mock_sink.enabled = False
            result = _run(
                agent._action_notify_operator(
                    "ops-channel",
                    {"severity": "critical"},
                    {"channel": "slack", "message": "Alert!"},
                )
            )
        assert result.success is True
        assert result.action == "notify_operator"
        assert result.target == "slack"

    def test_notify_operator_default_params(self):
        agent = _make_agent()
        with patch("cloud.services.webhook.webhook_sink") as mock_sink:
            mock_sink.enabled = False
            result = _run(agent._action_notify_operator("target", {}, {}))
        assert result.success is True
        assert result.target == "webhook"

    def test_notify_operator_webhook_enabled(self):
        agent = _make_agent()
        mock_sink = MagicMock()
        mock_sink.enabled = True
        mock_sink.send_alert = AsyncMock(return_value=True)
        with patch("cloud.services.webhook.webhook_sink", mock_sink):
            result = _run(
                agent._action_notify_operator(
                    "target",
                    {"severity": "high", "tenant_id": "t1"},
                    {"message": "Test alert"},
                )
            )
        assert result.success is True
        mock_sink.send_alert.assert_called_once()

    def test_notify_operator_webhook_exception(self):
        agent = _make_agent()
        mock_sink = MagicMock()
        mock_sink.enabled = True
        mock_sink.send_alert = AsyncMock(side_effect=RuntimeError("webhook fail"))
        with patch("cloud.services.webhook.webhook_sink", mock_sink):
            result = _run(agent._action_notify_operator("target", {}, {"message": "Alert"}))
        # Should still succeed (webhook failure is swallowed)
        assert result.success is True

    def test_create_investigation(self):
        agent = _make_agent()
        result = _run(
            agent._action_create_investigation(
                "incident-123",
                {"incident_id": "INC-001"},
                {},
            )
        )
        assert result.success is True
        assert "investigation" in result.message.lower()
        assert result.after_state.get("investigation_requested") is True

    def test_log_incident(self):
        agent = _make_agent()
        result = _run(
            agent._action_log_incident(
                "target",
                {"title": "Suspicious login"},
                {},
            )
        )
        assert result.success is True
        assert result.action == "log_incident"


class TestResponseAgentWazuhAction:
    """_action_wazuh_active_response() tests."""

    def test_no_command(self):
        agent = _make_agent()
        result = _run(agent._action_wazuh_active_response("agent-1", {}, {"command": ""}))
        assert result.success is False
        assert "No command" in result.message

    def test_no_command_param(self):
        agent = _make_agent()
        result = _run(agent._action_wazuh_active_response("agent-1", {}, {}))
        assert result.success is False
        assert "No command" in result.message

    def test_wazuh_disabled(self):
        agent = _make_agent()
        mock_client = MagicMock()
        mock_client.enabled = False
        with patch("cloud.integrations.wazuh_client.wazuh_client", mock_client):
            result = _run(
                agent._action_wazuh_active_response("agent-1", {}, {"command": "firewall-drop"})
            )
        assert result.success is False
        assert "not configured" in result.message

    def test_wazuh_success(self):
        agent = _make_agent()
        mock_client = MagicMock()
        mock_client.enabled = True
        mock_client.send_active_response = AsyncMock(return_value=True)
        with patch("cloud.integrations.wazuh_client.wazuh_client", mock_client):
            result = _run(
                agent._action_wazuh_active_response(
                    "agent-1",
                    {},
                    {"command": "firewall-drop", "arguments": ["-srcip", "10.0.0.1"]},
                )
            )
        assert result.success is True
        assert "dispatched" in result.message
        mock_client.send_active_response.assert_called_once_with(
            agent_id="agent-1",
            command="firewall-drop",
            arguments=["-srcip", "10.0.0.1"],
        )

    def test_wazuh_failure(self):
        agent = _make_agent()
        mock_client = MagicMock()
        mock_client.enabled = True
        mock_client.send_active_response = AsyncMock(return_value=False)
        with patch("cloud.integrations.wazuh_client.wazuh_client", mock_client):
            result = _run(
                agent._action_wazuh_active_response("agent-1", {}, {"command": "firewall-drop"})
            )
        assert result.success is False
        assert "failed" in result.message

    def test_wazuh_exception(self):
        agent = _make_agent()
        with patch(
            "cloud.integrations.wazuh_client.wazuh_client",
            side_effect=ImportError("No wazuh module"),
        ):
            # The import itself inside the method will work but the module
            # access will fail. Let's patch at the import location.
            pass

        # Patch the import to raise
        with patch.dict("sys.modules", {"cloud.integrations.wazuh_client": None}):
            result = _run(
                agent._action_wazuh_active_response("agent-1", {}, {"command": "firewall-drop"})
            )
        assert result.success is False
        assert "error" in result.message.lower()


class TestResponseAgentLoadPlaybooks:
    """load_playbooks() tests."""

    def test_no_playbooks_dir(self):
        agent = _make_agent()
        mock_dir = MagicMock()
        mock_dir.exists.return_value = False
        with patch("cloud.guardian.response_agent.PLAYBOOKS_DIR", mock_dir):
            count = agent.load_playbooks()
        assert count == 0

    def test_load_valid_playbook(self, tmp_path):
        import yaml

        pb_file = tmp_path / "test_pb.yaml"
        pb_data = {
            "playbook": "quarantine-agent",
            "description": "Quarantine a rogue agent",
            "trigger_patterns": ["anomaly_detected"],
            "severity_threshold": "high",
            "auto_respond": True,
            "steps": [
                {
                    "action": "pause_agent",
                    "target": "{{ agent_id }}",
                    "description": "Pause agent",
                },
            ],
            "rollback": [
                {
                    "action": "resume_agent",
                    "target": "{{ agent_id }}",
                    "description": "Resume agent",
                },
            ],
        }
        pb_file.write_text(yaml.dump(pb_data))

        with patch("cloud.guardian.response_agent.PLAYBOOKS_DIR", tmp_path):
            agent = _make_agent()
            count = agent.load_playbooks()

        assert count == 1
        assert "quarantine-agent" in agent._playbooks
        pb = agent._playbooks["quarantine-agent"]
        assert pb.auto_respond is True
        assert len(pb.steps) == 1
        assert len(pb.rollback_steps) == 1

    def test_load_empty_yaml(self, tmp_path):
        pb_file = tmp_path / "empty.yaml"
        pb_file.write_text("")

        with patch("cloud.guardian.response_agent.PLAYBOOKS_DIR", tmp_path):
            agent = _make_agent()
            count = agent.load_playbooks()

        assert count == 0

    def test_load_invalid_yaml(self, tmp_path):
        pb_file = tmp_path / "bad.yaml"
        pb_file.write_text("steps:\n  - action: pause_agent\n    target: [invalid")

        with patch("cloud.guardian.response_agent.PLAYBOOKS_DIR", tmp_path):
            agent = _make_agent()
            count = agent.load_playbooks()

        assert count == 0


class TestResponseAgentPlaybookAccessors:
    """get_playbook() and list_playbooks() tests."""

    def test_get_playbook_exists(self):
        agent = _make_agent()
        pb = _sample_playbook()
        agent._playbooks["test-playbook"] = pb
        result = agent.get_playbook("test-playbook")
        assert result is not None
        assert result.name == "test-playbook"

    def test_get_playbook_not_found(self):
        agent = _make_agent()
        result = agent.get_playbook("nonexistent")
        assert result is None

    def test_list_playbooks_empty(self):
        agent = _make_agent()
        assert agent.list_playbooks() == []

    def test_list_playbooks_with_entries(self):
        agent = _make_agent()
        agent._playbooks["pb-1"] = _sample_playbook()
        agent._playbooks["pb-2"] = _sample_playbook()
        names = agent.list_playbooks()
        assert sorted(names) == ["pb-1", "pb-2"]


class TestResponseAgentRollback:
    """Rollback on step failure."""

    def test_rollback_on_failure(self):
        agent = _make_agent()

        # Create a playbook with a failing step and rollback
        failing_step = PlaybookStep(action="fail_action", target="target")
        rollback_step = PlaybookStep(action="resume_agent", target="{{ agent_id }}")

        pb = Playbook(
            name="failing-playbook",
            auto_respond=True,
            steps=[failing_step],
            rollback_steps=[rollback_step],
        )
        agent._playbooks["failing-playbook"] = pb

        task = _make_task(
            {
                "playbook_name": "failing-playbook",
                "incident": {"agent_id": "node-77"},
            }
        )

        result = _run(agent.handle_task(task))
        assert result.success is False
        # Should have the failed step + rollback step in results
        results_list = result.result_data["results"]
        assert len(results_list) >= 2
        # First is the failed step
        assert results_list[0]["success"] is False
        # Second is the rollback step (resume_agent)
        assert results_list[1]["action"] == "resume_agent"
        assert results_list[1]["rolled_back"] is True

    def test_dry_run_no_rollback(self):
        """In dry_run mode, a failing step does NOT trigger rollback."""
        agent = _make_agent()

        # unknown_action will fail since it's not in the registry
        failing_step = PlaybookStep(action="unknown_action", target="target")
        rollback_step = PlaybookStep(action="resume_agent", target="target")

        pb = Playbook(
            name="dry-fail",
            auto_respond=True,
            steps=[failing_step],
            rollback_steps=[rollback_step],
        )
        agent._playbooks["dry-fail"] = pb

        task = _make_task(
            {
                "playbook_name": "dry-fail",
                "dry_run": True,
                "incident": {},
            }
        )

        result = _run(agent.handle_task(task))
        # In dry_run, unknown_action still returns failure (not a dry run skip)
        # Actually let's check: _execute_step checks action_fn first, then dry_run
        # So unknown action returns failure even in dry_run
        assert result.success is False
        # Rollback should not execute because dry_run is True
        results_list = result.result_data["results"]
        assert len(results_list) == 1  # Only the failed step, no rollback


class TestResponseAgentConsecutiveFailures:
    """Circuit breaker increments/resets on success/failure."""

    def test_failure_increments_counter(self):
        agent = _make_agent()
        agent._consecutive_failures = 0

        failing_step = PlaybookStep(action="unknown_action", target="target")
        pb = Playbook(
            name="fail-pb",
            auto_respond=True,
            steps=[failing_step],
        )
        agent._playbooks["fail-pb"] = pb

        task = _make_task(
            {
                "playbook_name": "fail-pb",
                "incident": {},
            }
        )
        _run(agent.handle_task(task))
        assert agent._consecutive_failures == 1

    def test_success_resets_counter(self):
        agent = _make_agent()
        agent._consecutive_failures = 2

        pb = _sample_playbook()
        agent._playbooks["test-playbook"] = pb
        task = _make_task(
            {
                "playbook_name": "test-playbook",
                "incident": {"agent_id": "node-1"},
            }
        )
        result = _run(agent.handle_task(task))
        assert result.success is True
        assert agent._consecutive_failures == 0


class TestResponseAgentApplyPolicyRule:
    """apply_policy_rule requires WRITE_POLICIES permission."""

    def test_apply_policy_rule_no_permission(self):
        agent = _make_agent()
        # Remove WRITE_POLICIES from permissions
        agent.permissions.discard("write_policies")

        with pytest.raises(PermissionError):
            _run(agent._action_apply_policy_rule("target", {}, {"rule_id": "r-1"}))

    def test_apply_policy_rule_with_rule_id(self):
        agent = _make_agent()
        # Add the needed permission
        from cloud.guardian.models import Permission

        agent.permissions.add(Permission.WRITE_POLICIES)
        result = _run(agent._action_apply_policy_rule("target", {}, {"rule_id": "block-ip"}))
        assert result.success is True
        assert "block-ip" in result.message

    def test_apply_policy_rule_default_rule_id(self):
        agent = _make_agent()
        from cloud.guardian.models import Permission

        agent.permissions.add(Permission.WRITE_POLICIES)
        result = _run(agent._action_apply_policy_rule("target", {}, {}))
        assert result.success is True
        assert "auto-generated" in result.message
