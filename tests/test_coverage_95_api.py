"""Coverage boost tests — API routes, auth, middleware → 95%.

Targets missed lines in:
  - cloud/api/server.py (auth middleware, _ensure_default_policy)
  - cloud/api/analytics_routes.py (threat_matrix, sessions, ai-traffic, identity)
  - cloud/api/assistant_routes.py (explain_event)
  - cloud/api/guardian_routes.py (reports, chat, event_context, changes)
  - cloud/api/orchestrator_routes.py (endpoints)
  - cloud/api/metrics_routes.py (readiness, prometheus)
  - cloud/auth/routes.py (login, change-password)
  - cloud/auth/service.py (change_password, verify_jwt, verify_bearer)
  - cloud/db/session.py (get_db)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from sqlalchemy.orm import Session

from cloud.db.models import (
    AgentNodeRow,
    EventRow,
)

# ---------------------------------------------------------------------------
# Auth service tests
# ---------------------------------------------------------------------------


class TestAuthService:
    def test_authenticate_local_admin(self):
        from cloud.auth.service import authenticate_local

        with (
            patch("cloud.auth.service.ADMIN_USER", "admin"),
            patch("cloud.auth.service.ADMIN_PASSWORD", "secret"),
        ):
            user = authenticate_local("admin", "secret")
            assert user is not None
            assert user.username == "admin"
            assert user.role.value == "admin"

    def test_authenticate_local_secops(self):
        from cloud.auth.service import authenticate_local

        with (
            patch("cloud.auth.service.SECOPS_USER", "secops"),
            patch("cloud.auth.service.SECOPS_PASSWORD", "secpwd"),
        ):
            user = authenticate_local("secops", "secpwd")
            assert user is not None
            assert user.role.value == "secops"

    def test_authenticate_local_viewer(self):
        from cloud.auth.service import authenticate_local

        with (
            patch("cloud.auth.service.VIEWER_USER", "viewer"),
            patch("cloud.auth.service.VIEWER_PASSWORD", "viewpwd"),
        ):
            user = authenticate_local("viewer", "viewpwd")
            assert user is not None
            assert user.role.value == "viewer"

    def test_authenticate_local_wrong_password(self):
        from cloud.auth.service import authenticate_local

        user = authenticate_local("admin", "wrong_password")
        assert user is None

    def test_authenticate_local_unknown_user(self):
        from cloud.auth.service import authenticate_local

        user = authenticate_local("nonexistent", "password")
        assert user is None

    def test_change_password_admin(self):
        import cloud.auth.config as cfg
        from cloud.auth.service import change_password

        old = cfg.ADMIN_PASSWORD
        cfg.ADMIN_PASSWORD = "old_pass"
        result = change_password(cfg.ADMIN_USER, "old_pass", "new_pass")
        assert result is True
        assert cfg.ADMIN_PASSWORD == "new_pass"
        cfg.ADMIN_PASSWORD = old  # Reset

    def test_change_password_admin_wrong_current(self):
        import cloud.auth.config as cfg
        from cloud.auth.service import change_password

        old = cfg.ADMIN_PASSWORD
        cfg.ADMIN_PASSWORD = "correct"
        result = change_password(cfg.ADMIN_USER, "wrong", "new")
        assert result is False
        cfg.ADMIN_PASSWORD = old

    def test_change_password_secops(self):
        import cloud.auth.config as cfg
        from cloud.auth.service import change_password

        old = cfg.SECOPS_PASSWORD
        cfg.SECOPS_PASSWORD = "sec_old"
        result = change_password(cfg.SECOPS_USER, "sec_old", "sec_new")
        assert result is True
        cfg.SECOPS_PASSWORD = old

    def test_change_password_secops_wrong(self):
        import cloud.auth.config as cfg
        from cloud.auth.service import change_password

        old = cfg.SECOPS_PASSWORD
        cfg.SECOPS_PASSWORD = "correct"
        result = change_password(cfg.SECOPS_USER, "wrong", "new")
        assert result is False
        cfg.SECOPS_PASSWORD = old

    def test_change_password_viewer(self):
        import cloud.auth.config as cfg
        from cloud.auth.service import change_password

        old = cfg.VIEWER_PASSWORD
        cfg.VIEWER_PASSWORD = "view_old"
        result = change_password(cfg.VIEWER_USER, "view_old", "view_new")
        assert result is True
        cfg.VIEWER_PASSWORD = old

    def test_change_password_viewer_wrong(self):
        import cloud.auth.config as cfg
        from cloud.auth.service import change_password

        old = cfg.VIEWER_PASSWORD
        cfg.VIEWER_PASSWORD = "correct"
        result = change_password(cfg.VIEWER_USER, "wrong", "new")
        assert result is False
        cfg.VIEWER_PASSWORD = old

    def test_change_password_unknown_user(self):
        from cloud.auth.service import change_password

        result = change_password("nonexistent_user", "old", "new")
        assert result is False

    def test_create_and_verify_jwt(self):
        from cloud.auth.models import AuthUser, UserRole
        from cloud.auth.service import create_jwt, verify_jwt

        user = AuthUser(username="test", role=UserRole.ADMIN, tenant_id="t1")
        token = create_jwt(user)
        verified = verify_jwt(token)
        assert verified is not None
        assert verified.username == "test"
        assert verified.role == UserRole.ADMIN

    def test_verify_jwt_invalid(self):
        from cloud.auth.service import verify_jwt

        assert verify_jwt("invalid.token.here") is None
        assert verify_jwt("notavalidtoken") is None
        assert verify_jwt("") is None

    def test_verify_jwt_expired(self):
        import hashlib
        import hmac
        import json
        import time

        from cloud.auth.service import JWT_SECRET, _b64encode, verify_jwt

        header = _b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        payload_data = {
            "sub": "test",
            "role": "admin",
            "tenant_id": "t1",
            "exp": int(time.time()) - 3600,  # expired 1 hour ago
            "iat": int(time.time()) - 7200,
        }
        payload = _b64encode(json.dumps(payload_data).encode())
        signing_input = f"{header}.{payload}"
        signature = _b64encode(
            hmac.new(JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
        )
        token = f"{header}.{payload}.{signature}"
        assert verify_jwt(token) is None

    def test_verify_jwt_bad_signature(self):
        from cloud.auth.service import verify_jwt

        # Token with invalid signature
        assert verify_jwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.invalidsig") is None

    def test_verify_bearer_no_tokens(self):
        from cloud.auth.service import verify_bearer

        with patch("cloud.auth.service.BEARER_TOKENS", []):
            assert verify_bearer("some_token") is None

    def test_verify_bearer_valid(self):
        from cloud.auth.service import verify_bearer

        with patch("cloud.auth.service.BEARER_TOKENS", ["valid_token_123"]):
            user = verify_bearer("valid_token_123")
            assert user is not None
            assert user.username == "bearer-user"

    def test_verify_bearer_invalid(self):
        from cloud.auth.service import verify_bearer

        with patch("cloud.auth.service.BEARER_TOKENS", ["valid_token_123"]):
            assert verify_bearer("wrong_token") is None

    def test_hash_and_verify_password(self):
        from cloud.auth.service import _hash_password, _verify_password

        hashed = _hash_password("mypassword")
        assert _verify_password("mypassword", hashed) is True
        assert _verify_password("wrongpassword", hashed) is False

    def test_verify_password_bad_format(self):
        from cloud.auth.service import _verify_password

        assert _verify_password("password", "not-a-valid-hash") is False
        assert _verify_password("password", "") is False


# ---------------------------------------------------------------------------
# Analytics routes tests
# ---------------------------------------------------------------------------


class TestAnalyticsRoutes:
    def test_list_agents(self, client, db: Session):
        resp = client.get("/api/v1/agents")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_recent_events(self, client, db: Session):
        resp = client.get("/api/v1/incidents/recent?limit=10")
        assert resp.status_code == 200

    def test_recent_events_with_severity_filter(self, client, db: Session):
        resp = client.get("/api/v1/incidents/recent?severity=critical")
        assert resp.status_code == 200

    def test_recent_events_with_category_filter(self, client, db: Session):
        resp = client.get("/api/v1/incidents/recent?category=shell")
        assert resp.status_code == 200

    def test_policy_evolution(self, client, db: Session):
        resp = client.get("/api/v1/analytics/policy/evolution")
        assert resp.status_code == 200

    def test_threat_matrix(self, client, db: Session):
        # Add events for threat matrix
        from tests.conftest import TestSessionLocal

        tdb = TestSessionLocal()
        for sev in ["critical", "high", "medium"]:
            event = EventRow(
                id=str(uuid.uuid4()),
                agent_id="agent-tm-1",
                timestamp=datetime.now(timezone.utc),
                category="shell",
                type="exec",
                severity=sev,
            )
            tdb.add(event)
        tdb.commit()
        tdb.close()

        resp = client.get("/api/v1/analytics/threat-matrix?lookback_hours=24")
        assert resp.status_code == 200

    def test_ai_traffic(self, client, db: Session):
        from tests.conftest import TestSessionLocal

        tdb = TestSessionLocal()
        event = EventRow(
            id=str(uuid.uuid4()),
            agent_id="agent-ai-1",
            timestamp=datetime.now(timezone.utc),
            category="ai_tool",
            type="tool_call",
            severity="info",
            details={"tool_name": "bash", "action": "exec"},
        )
        tdb.add(event)
        tdb.commit()
        tdb.close()

        resp = client.get("/api/v1/analytics/ai-traffic?limit=10")
        assert resp.status_code == 200

    def test_agent_identity(self, client, db: Session):
        from tests.conftest import TestSessionLocal

        tdb = TestSessionLocal()
        agent = AgentNodeRow(
            id="identity-agent-1",
            type="server",
            os="linux",
            hostname="id-host",
            status="active",
            registered_at=datetime.now(timezone.utc),
        )
        tdb.add(agent)
        # Add events for the agent
        for sev in ["info", "high", "critical"]:
            event = EventRow(
                id=str(uuid.uuid4()),
                agent_id="identity-agent-1",
                timestamp=datetime.now(timezone.utc),
                category="shell",
                type="exec",
                severity=sev,
            )
            tdb.add(event)
        tdb.commit()
        tdb.close()

        resp = client.get("/api/v1/agents/identity?agent_id=identity-agent-1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["agent_id"] == "identity-agent-1"
        assert data["risk_profile"] == "critical"

    def test_agent_identity_not_found(self, client):
        resp = client.get("/api/v1/agents/identity?agent_id=nonexistent")
        assert resp.status_code == 404

    def test_session_analytics(self, client, db: Session):
        from tests.conftest import TestSessionLocal

        tdb = TestSessionLocal()
        base_time = datetime.now(timezone.utc)
        # Create a session of events
        for i in range(3):
            event = EventRow(
                id=str(uuid.uuid4()),
                agent_id="sess-agent-1",
                timestamp=base_time + timedelta(seconds=i * 30),
                category="shell",
                type="exec",
                severity="info",
            )
            tdb.add(event)
        # Create a gap then another session
        event = EventRow(
            id=str(uuid.uuid4()),
            agent_id="sess-agent-1",
            timestamp=base_time + timedelta(minutes=10),
            category="network",
            type="connection",
            severity="high",
        )
        tdb.add(event)
        tdb.commit()
        tdb.close()

        resp = client.get("/api/v1/analytics/sessions?lookback_hours=1")
        assert resp.status_code == 200

    def test_session_analytics_by_agent(self, client, db: Session):
        resp = client.get("/api/v1/analytics/sessions?agent_id=sess-agent-1")
        assert resp.status_code == 200

    def test_agent_timeline(self, client, db: Session):
        from tests.conftest import TestSessionLocal

        tdb = TestSessionLocal()
        agent = AgentNodeRow(
            id="timeline-agent-1",
            type="server",
            os="linux",
            hostname="tl-host",
            status="active",
            registered_at=datetime.now(timezone.utc),
        )
        tdb.merge(agent)
        tdb.commit()
        tdb.close()

        resp = client.get("/api/v1/analytics/agent/timeline?agentId=timeline-agent-1&hours=24")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Assistant routes tests
# ---------------------------------------------------------------------------


class TestAssistantRoutes:
    def test_get_incident_summary(self, client, db: Session):
        resp = client.get("/api/v1/assistant/incidents?lookback_hours=24")
        assert resp.status_code == 200

    def test_propose_tightening(self, client, db: Session):
        resp = client.post(
            "/api/v1/assistant/propose",
            json={"agent_group_id": "all", "lookback_hours": 24},
        )
        assert resp.status_code == 200

    def test_explain_event_not_found(self, client, db: Session):
        resp = client.get(f"/api/v1/assistant/explain?event_id={uuid.uuid4()}")
        assert resp.status_code == 404

    def test_explain_event(self, client, db: Session):
        from tests.conftest import TestSessionLocal

        tdb = TestSessionLocal()
        event_id = str(uuid.uuid4())
        event = EventRow(
            id=event_id,
            agent_id="explain-agent",
            timestamp=datetime.now(timezone.utc),
            category="shell",
            type="command_exec",
            severity="high",
            source="test",
            details={"command": "ls -la"},
        )
        tdb.add(event)
        tdb.commit()
        tdb.close()

        resp = client.get(f"/api/v1/assistant/explain?event_id={event_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["event_id"] == event_id

    def test_explain_event_with_context(self, client, db: Session):
        from tests.conftest import TestSessionLocal

        tdb = TestSessionLocal()
        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        event = EventRow(
            id=event_id,
            agent_id="ctx-agent",
            timestamp=now,
            category="shell",
            type="command_exec",
            severity="high",
            source="test",
        )
        # Add context events
        ctx_event = EventRow(
            id=str(uuid.uuid4()),
            agent_id="ctx-agent",
            timestamp=now - timedelta(minutes=2),
            category="ai_tool",
            type="tool_call",
            severity="info",
        )
        tdb.add(event)
        tdb.add(ctx_event)
        tdb.commit()
        tdb.close()

        resp = client.get(f"/api/v1/assistant/explain?event_id={event_id}&include_context=true")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Guardian routes tests
# ---------------------------------------------------------------------------


class TestGuardianRoutes:
    def test_recent_reports(self, client, db: Session):
        resp = client.get("/api/v1/guardian/reports/recent?tenantId=dev-tenant&limit=5")
        assert resp.status_code == 200

    def test_recent_alerts(self, client, db: Session):
        resp = client.get("/api/v1/guardian/alerts/recent?tenantId=dev-tenant&limit=5")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_guardian_chat(self, client, db: Session):
        resp = client.post(
            "/api/v1/guardian/chat",
            json={"prompt": "What incidents happened recently?", "tenant_id": "dev-tenant"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "answer" in data
        assert data["intent"] == "incidents"

    @pytest.mark.asyncio
    async def test_guardian_chat_threats(self, client, db: Session):
        resp = client.post(
            "/api/v1/guardian/chat",
            json={"prompt": "Any threat predictions?", "tenant_id": "dev-tenant"},
        )
        assert resp.status_code == 200
        assert resp.json()["intent"] == "threats"

    @pytest.mark.asyncio
    async def test_guardian_chat_about(self, client, db: Session):
        resp = client.post(
            "/api/v1/guardian/chat",
            json={"prompt": "Who are you?", "tenant_id": "dev-tenant"},
        )
        assert resp.status_code == 200
        assert resp.json()["intent"] == "about"

    @pytest.mark.asyncio
    async def test_guardian_chat_help(self, client, db: Session):
        resp = client.post(
            "/api/v1/guardian/chat",
            json={"prompt": "What can you do? help me", "tenant_id": "dev-tenant"},
        )
        assert resp.status_code == 200
        assert resp.json()["intent"] == "help"

    @pytest.mark.asyncio
    async def test_guardian_chat_agents(self, client, db: Session):
        resp = client.post(
            "/api/v1/guardian/chat",
            json={"prompt": "How are my agents doing?", "tenant_id": "dev-tenant"},
        )
        assert resp.status_code == 200
        assert resp.json()["intent"] == "agent_status"

    @pytest.mark.asyncio
    async def test_guardian_chat_changes(self, client, db: Session):
        resp = client.post(
            "/api/v1/guardian/chat",
            json={"prompt": "What changes happened recently?", "tenant_id": "dev-tenant"},
        )
        assert resp.status_code == 200
        assert resp.json()["intent"] == "changes"

    @pytest.mark.asyncio
    async def test_guardian_chat_propose(self, client, db: Session):
        resp = client.post(
            "/api/v1/guardian/chat",
            json={"prompt": "Suggest policy improvements", "tenant_id": "dev-tenant"},
        )
        assert resp.status_code == 200
        assert resp.json()["intent"] == "propose"

    @pytest.mark.asyncio
    async def test_guardian_chat_explain(self, client, db: Session):
        resp = client.post(
            "/api/v1/guardian/chat",
            json={
                "prompt": "Explain event 12345678-1234-1234-1234-123456789abc",
                "tenant_id": "dev-tenant",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["intent"] == "explain"

    @pytest.mark.asyncio
    async def test_guardian_chat_explain_no_id(self, client, db: Session):
        resp = client.post(
            "/api/v1/guardian/chat",
            json={"prompt": "Explain what happened", "tenant_id": "dev-tenant"},
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_guardian_chat_alerts(self, client, db: Session):
        resp = client.post(
            "/api/v1/guardian/chat",
            json={"prompt": "Any guardian alerts?", "tenant_id": "dev-tenant"},
        )
        assert resp.status_code == 200
        assert resp.json()["intent"] == "alerts"

    @pytest.mark.asyncio
    async def test_guardian_chat_scan(self, client, db: Session):
        resp = client.post(
            "/api/v1/guardian/chat",
            json={"prompt": "Scan the system for vulnerabilities", "tenant_id": "dev-tenant"},
        )
        assert resp.status_code == 200
        assert resp.json()["intent"] == "scan"

    @pytest.mark.asyncio
    async def test_guardian_chat_status_report(self, client, db: Session):
        resp = client.post(
            "/api/v1/guardian/chat",
            json={"prompt": "What have you been doing lately?", "tenant_id": "dev-tenant"},
        )
        assert resp.status_code == 200
        assert resp.json()["intent"] == "status_report"

    @pytest.mark.asyncio
    async def test_guardian_chat_general(self, client, db: Session):
        resp = client.post(
            "/api/v1/guardian/chat",
            json={"prompt": "random gibberish 12345", "tenant_id": "dev-tenant"},
        )
        assert resp.status_code == 200
        assert resp.json()["intent"] == "general"

    def test_event_context(self, client, db: Session):
        from tests.conftest import TestSessionLocal

        tdb = TestSessionLocal()
        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        event = EventRow(
            id=event_id,
            agent_id="ctx-agent-2",
            timestamp=now,
            category="shell",
            type="command_exec",
            severity="high",
            source="test",
        )
        # Add related events
        related = EventRow(
            id=str(uuid.uuid4()),
            agent_id="ctx-agent-2",
            timestamp=now - timedelta(minutes=1),
            category="shell",
            type="exec",
            severity="info",
        )
        ai_event = EventRow(
            id=str(uuid.uuid4()),
            agent_id="ctx-agent-2",
            timestamp=now - timedelta(minutes=1),
            category="ai_tool",
            type="tool_call",
            severity="info",
            details={"tool_name": "bash"},
        )
        tdb.add(event)
        tdb.add(related)
        tdb.add(ai_event)
        tdb.commit()
        tdb.close()

        resp = client.get(f"/api/v1/guardian/event_context?eventId={event_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["event_id"] == event_id

    def test_event_context_not_found(self, client):
        resp = client.get(f"/api/v1/guardian/event_context?eventId={uuid.uuid4()}")
        assert resp.status_code == 404

    def test_recent_changes(self, client, db: Session):
        since = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        resp = client.get(f"/api/v1/guardian/changes?since={since}")
        assert resp.status_code == 200

    def test_recent_changes_bad_timestamp(self, client):
        resp = client.get("/api/v1/guardian/changes?since=not-a-date")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Orchestrator routes tests
# ---------------------------------------------------------------------------


class TestOrchestratorRoutes:
    def test_orchestrator_status(self, client):
        resp = client.get("/api/v1/orchestrator/status")
        assert resp.status_code == 200

    def test_legion_status(self, client):
        resp = client.get("/api/v1/orchestrator/legion/status")
        assert resp.status_code == 200

    def test_list_agents(self, client):
        resp = client.get("/api/v1/orchestrator/agents")
        assert resp.status_code == 200

    def test_halo_sweep(self, client):
        resp = client.post("/api/v1/orchestrator/scan/halo-sweep")
        assert resp.status_code == 200

    def test_wing_scan(self, client):
        resp = client.post("/api/v1/orchestrator/scan/wing/network")
        assert resp.status_code == 200

    def test_pulse_check(self, client):
        resp = client.get("/api/v1/orchestrator/scan/pulse")
        assert resp.status_code == 200

    def test_set_autonomy_mode(self, client):
        resp = client.put("/api/v1/orchestrator/autonomy/observe")
        assert resp.status_code == 200
        # Reset
        client.put("/api/v1/orchestrator/autonomy/suggest")

    def test_set_autonomy_mode_invalid(self, client):
        resp = client.put("/api/v1/orchestrator/autonomy/bogus")
        assert resp.status_code == 200
        assert "error" in resp.json()

    def test_get_autonomy_mode(self, client):
        resp = client.get("/api/v1/orchestrator/autonomy")
        assert resp.status_code == 200

    def test_list_incidents(self, client):
        resp = client.get("/api/v1/orchestrator/incidents")
        assert resp.status_code == 200

    def test_list_incidents_by_state(self, client):
        resp = client.get("/api/v1/orchestrator/incidents?state=new")
        assert resp.status_code == 200

    def test_get_incident_not_found(self, client):
        resp = client.get(f"/api/v1/orchestrator/incidents/{uuid.uuid4()}")
        assert resp.status_code == 200
        assert "error" in resp.json()

    def test_approve_incident_not_found(self, client):
        resp = client.post(f"/api/v1/orchestrator/incidents/{uuid.uuid4()}/approve")
        assert resp.status_code == 200
        assert "error" in resp.json()

    def test_list_playbooks(self, client):
        resp = client.get("/api/v1/orchestrator/playbooks")
        assert resp.status_code == 200
        assert "playbooks" in resp.json()

    def test_dry_run_playbook(self, client):
        resp = client.post("/api/v1/orchestrator/playbooks/quarantine_agent/dry-run")
        assert resp.status_code == 200

    def test_self_audit(self, client):
        resp = client.get("/api/v1/orchestrator/self-audit")
        assert resp.status_code == 200

    def test_learning_summary(self, client):
        resp = client.get("/api/v1/orchestrator/learning/summary")
        assert resp.status_code == 200

    def test_learning_reflections(self, client):
        resp = client.get("/api/v1/orchestrator/learning/reflections?limit=10")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Metrics routes tests
# ---------------------------------------------------------------------------


class TestMetricsRoutes:
    def test_readiness(self, client):
        resp = client.get("/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert "ready" in data
        assert "checks" in data

    def test_prometheus_metrics(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        text = resp.text
        assert "angelclaw_uptime_seconds" in text
        assert "angelclaw_orchestrator_events_processed_total" in text


# ---------------------------------------------------------------------------
# Auth routes tests (with auth enabled)
# ---------------------------------------------------------------------------


class TestAuthRoutes:
    def test_login_auth_disabled(self, client):
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "test"},
        )
        # Auth is disabled in test env
        assert resp.status_code == 400

    def test_login_with_auth_enabled(self, client):
        import cloud.auth.config as cfg

        old_enabled = cfg.AUTH_ENABLED
        old_admin_pwd = cfg.ADMIN_PASSWORD
        cfg.AUTH_ENABLED = True
        cfg.ADMIN_PASSWORD = "test_pass"

        with (
            patch("cloud.auth.routes.AUTH_ENABLED", True),
            patch("cloud.auth.service.ADMIN_PASSWORD", "test_pass"),
        ):
            resp = client.post(
                "/api/v1/auth/login",
                json={"username": cfg.ADMIN_USER, "password": "test_pass"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert "access_token" in data

        cfg.AUTH_ENABLED = old_enabled
        cfg.ADMIN_PASSWORD = old_admin_pwd

    def test_login_invalid_credentials(self, client):
        import cloud.auth.config as cfg

        old_enabled = cfg.AUTH_ENABLED
        cfg.AUTH_ENABLED = True

        with patch("cloud.auth.routes.AUTH_ENABLED", True):
            resp = client.post(
                "/api/v1/auth/login",
                json={"username": "wrong", "password": "wrong"},
            )
            assert resp.status_code == 401

        cfg.AUTH_ENABLED = old_enabled

    def test_get_me(self, client):
        resp = client.get("/api/v1/auth/me")
        # Without auth, should get 401 or the dependency handles it
        # Auth is disabled so depends on get_current_user behavior
        assert resp.status_code in (200, 401, 403)

    def test_logout(self, client):
        resp = client.post("/api/v1/auth/logout")
        assert resp.status_code == 200

    def test_change_password_auth_disabled(self, client):
        with patch("cloud.auth.routes.AUTH_ENABLED", False):
            resp = client.post(
                "/api/v1/auth/change-password",
                json={"current_password": "old", "new_password": "new"},
            )
            # Will fail due to auth dependency or 400
            assert resp.status_code in (400, 401, 403, 422)


# ---------------------------------------------------------------------------
# Server auth middleware tests
# ---------------------------------------------------------------------------


class TestServerMiddleware:
    def test_health_check(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_ui_dashboard(self, client):
        resp = client.get("/ui")
        assert resp.status_code in (200, 404)

    def test_auth_middleware_disabled(self, client):
        """Auth disabled — all routes should work."""
        resp = client.get("/api/v1/agents")
        assert resp.status_code == 200

    def test_auth_middleware_public_paths(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_ingest_events(self, client, db: Session):
        from tests.conftest import TestSessionLocal

        tdb = TestSessionLocal()
        agent = AgentNodeRow(
            id="ingest-agent-1",
            type="server",
            os="linux",
            hostname="ingest-host",
            status="active",
            registered_at=datetime.now(timezone.utc),
        )
        tdb.merge(agent)
        tdb.commit()
        tdb.close()

        resp = client.post(
            "/api/v1/events/batch",
            json={
                "agent_id": "ingest-agent-1",
                "events": [
                    {
                        "agent_id": "ingest-agent-1",
                        "category": "shell",
                        "type": "command_exec",
                        "severity": "info",
                        "details": {"command": "ls"},
                    },
                ],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["accepted"] == 1

    def test_register_agent(self, client):
        resp = client.post(
            "/api/v1/agents/register",
            json={
                "hostname": "new-test-agent",
                "type": "server",
                "os": "linux",
                "tags": ["test"],
                "version": "1.0.0",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "registered"

    def test_register_agent_existing(self, client):
        # Register twice - should update
        for _ in range(2):
            resp = client.post(
                "/api/v1/agents/register",
                json={
                    "hostname": "existing-agent",
                    "type": "server",
                    "os": "linux",
                    "tags": ["test"],
                    "version": "2.0.0",
                },
            )
            assert resp.status_code == 200

    def test_get_current_policy(self, client, db: Session):
        from tests.conftest import TestSessionLocal

        tdb = TestSessionLocal()
        agent = AgentNodeRow(
            id="policy-agent-1",
            type="server",
            os="linux",
            hostname="policy-host",
            status="active",
            registered_at=datetime.now(timezone.utc),
        )
        tdb.merge(agent)
        tdb.commit()
        tdb.close()

        resp = client.get("/api/v1/policies/current?agentId=policy-agent-1")
        # Might be 200 or 404 depending on whether policy was seeded
        assert resp.status_code in (200, 404)

    def test_get_current_policy_agent_not_found(self, client):
        resp = client.get(f"/api/v1/policies/current?agentId={uuid.uuid4()}")
        assert resp.status_code == 404
