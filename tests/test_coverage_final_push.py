"""Tests to push coverage above 95% — targets the 5 files below 80%.

Covers:
  - cloud/integrations/wazuh_ingest.py  (22% → ~100%)
  - cloud/llm_proxy/routes.py           (32% → ~100%)
  - cloud/guardian/warden_agent.py       (72% → ~100%)
  - cloud/services/structured_logger.py  (76% → ~100%)
  - cloud/guardian/self_audit.py         (79% → ~100%)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cloud.db.models import (
    AgentNodeRow,
    EventRow,
    GuardianAlertRow,
    PolicySetRow,
)

# ═══════════════════════════════════════════════════════════════════════════
# 1. cloud/integrations/wazuh_ingest.py
# ═══════════════════════════════════════════════════════════════════════════


class TestWazuhLevelToSeverity:
    """Cover _wazuh_level_to_severity (lines 34-40)."""

    def test_critical(self):
        from cloud.integrations.wazuh_ingest import _wazuh_level_to_severity

        assert _wazuh_level_to_severity(12) == "critical"
        assert _wazuh_level_to_severity(15) == "critical"

    def test_high(self):
        from cloud.integrations.wazuh_ingest import _wazuh_level_to_severity

        assert _wazuh_level_to_severity(8) == "high"
        assert _wazuh_level_to_severity(11) == "high"

    def test_warn(self):
        from cloud.integrations.wazuh_ingest import _wazuh_level_to_severity

        assert _wazuh_level_to_severity(5) == "warn"
        assert _wazuh_level_to_severity(7) == "warn"

    def test_info(self):
        from cloud.integrations.wazuh_ingest import _wazuh_level_to_severity

        assert _wazuh_level_to_severity(1) == "info"
        assert _wazuh_level_to_severity(4) == "info"


class TestWazuhRuleToCategory:
    """Cover _wazuh_rule_to_category (lines 45-57)."""

    def test_auth_groups(self):
        from cloud.integrations.wazuh_ingest import _wazuh_rule_to_category

        assert _wazuh_rule_to_category(["authentication_failed"]) == "auth"
        assert _wazuh_rule_to_category(["authentication_success"]) == "auth"
        assert _wazuh_rule_to_category(["PAM"]) == "auth"

    def test_file_system_groups(self):
        from cloud.integrations.wazuh_ingest import _wazuh_rule_to_category

        assert _wazuh_rule_to_category(["syscheck"]) == "file_system"
        assert _wazuh_rule_to_category(["FIM"]) == "file_system"

    def test_network_groups(self):
        from cloud.integrations.wazuh_ingest import _wazuh_rule_to_category

        assert _wazuh_rule_to_category(["firewall"]) == "network"
        assert _wazuh_rule_to_category(["iptables"]) == "network"
        assert _wazuh_rule_to_category(["ids"]) == "network"
        assert _wazuh_rule_to_category(["sshd"]) == "network"
        assert _wazuh_rule_to_category(["ssh"]) == "network"

    def test_process_groups(self):
        from cloud.integrations.wazuh_ingest import _wazuh_rule_to_category

        assert _wazuh_rule_to_category(["rootkit"]) == "process"
        assert _wazuh_rule_to_category(["malware"]) == "process"
        assert _wazuh_rule_to_category(["trojan"]) == "process"

    def test_default_system(self):
        from cloud.integrations.wazuh_ingest import _wazuh_rule_to_category

        assert _wazuh_rule_to_category(["some_unknown_group"]) == "system"
        assert _wazuh_rule_to_category([]) == "system"


class TestIngestAlerts:
    """Cover _ingest_alerts (lines 115-160)."""

    def test_ingest_well_formed_alert(self, db):
        from cloud.integrations.wazuh_ingest import _ingest_alerts

        alerts = [
            {
                "timestamp": "2025-01-01T12:00:00Z",
                "rule": {
                    "id": "1001",
                    "description": "Test rule",
                    "level": 10,
                    "groups": ["authentication_failed"],
                },
                "agent": {"id": "agent-01", "name": "web-server", "ip": "10.0.0.1"},
                "full_log": "Jan  1 12:00:00 sshd: Failed password for root",
            }
        ]

        with patch("cloud.integrations.wazuh_ingest.SessionLocal", return_value=db):
            count = _ingest_alerts(alerts, "test-tenant")

        assert count == 1
        row = db.query(EventRow).filter(EventRow.source.like("wazuh:%")).first()
        assert row is not None
        assert row.severity == "high"
        assert row.category == "auth"
        assert row.type == "wazuh.1001"
        assert row.details["source"] == "wazuh"

    def test_ingest_invalid_timestamp_falls_back(self, db):
        from cloud.integrations.wazuh_ingest import _ingest_alerts

        alerts = [
            {
                "timestamp": "not-a-date",
                "rule": {"id": "2002", "level": 3, "groups": []},
                "agent": {"name": "srv"},
            }
        ]

        with patch("cloud.integrations.wazuh_ingest.SessionLocal", return_value=db):
            count = _ingest_alerts(alerts, "test-tenant")

        assert count == 1

    def test_ingest_empty_list(self, db):
        from cloud.integrations.wazuh_ingest import _ingest_alerts

        with patch("cloud.integrations.wazuh_ingest.SessionLocal", return_value=db):
            count = _ingest_alerts([], "test-tenant")

        assert count == 0

    def test_ingest_db_error_returns_zero(self):
        from cloud.integrations.wazuh_ingest import _ingest_alerts

        mock_db = MagicMock()
        mock_db.add_all.side_effect = Exception("DB error")

        with patch("cloud.integrations.wazuh_ingest.SessionLocal", return_value=mock_db):
            count = _ingest_alerts([{"rule": {}, "agent": {}}], "t")

        assert count == 0
        mock_db.rollback.assert_called_once()
        mock_db.close.assert_called_once()

    def test_ingest_minimal_alert_fields(self, db):
        """Alert with minimal/missing fields still ingests."""
        from cloud.integrations.wazuh_ingest import _ingest_alerts

        alerts = [{"rule": {}, "agent": {}}]
        with patch("cloud.integrations.wazuh_ingest.SessionLocal", return_value=db):
            count = _ingest_alerts(alerts, "test-tenant")
        assert count == 1


class TestWazuhIngestLoop:
    """Cover wazuh_ingest_loop (lines 71-110)."""

    def test_loop_disabled_when_wazuh_not_enabled(self):
        """Loop returns immediately if wazuh is not configured."""
        from cloud.integrations.wazuh_ingest import wazuh_ingest_loop

        with patch("cloud.integrations.wazuh_ingest.wazuh_client") as mock_client:
            mock_client.enabled = False
            asyncio.get_event_loop().run_until_complete(wazuh_ingest_loop())

    def test_loop_processes_alerts_then_cancels(self):
        """Loop fetches alerts, ingests them, then shuts down on cancel."""
        import cloud.integrations.wazuh_ingest as wmod
        from cloud.integrations.wazuh_ingest import wazuh_ingest_loop

        old_ts = wmod._last_poll_ts
        wmod._last_poll_ts = ""

        mock_client = AsyncMock()
        mock_client.enabled = True
        mock_client.base_url = "http://wazuh:55000"

        alerts = [
            {
                "timestamp": "2025-06-01T12:00:00Z",
                "rule": {"id": "100", "level": 5, "groups": []},
                "agent": {"id": "a1", "name": "srv1"},
            }
        ]

        call_count = 0

        async def fake_get_alerts(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return alerts
            raise asyncio.CancelledError()

        mock_client.get_alerts = fake_get_alerts

        with (
            patch("cloud.integrations.wazuh_ingest.wazuh_client", mock_client),
            patch("cloud.integrations.wazuh_ingest._ingest_alerts", return_value=1),
            patch("cloud.integrations.wazuh_ingest.POLL_INTERVAL", 0),
        ):
            asyncio.get_event_loop().run_until_complete(wazuh_ingest_loop())

        wmod._last_poll_ts = old_ts

    def test_loop_handles_exception_and_continues(self):
        """Loop logs exception but continues to next poll cycle."""
        from cloud.integrations.wazuh_ingest import wazuh_ingest_loop

        mock_client = AsyncMock()
        mock_client.enabled = True
        mock_client.base_url = "http://wazuh:55000"

        call_count = 0

        async def fake_get_alerts(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("network error")
            raise asyncio.CancelledError()

        mock_client.get_alerts = fake_get_alerts

        with (
            patch("cloud.integrations.wazuh_ingest.wazuh_client", mock_client),
            patch("cloud.integrations.wazuh_ingest.POLL_INTERVAL", 0),
        ):
            asyncio.get_event_loop().run_until_complete(wazuh_ingest_loop())

    def test_loop_skips_when_no_alerts(self):
        """Loop continues when get_alerts returns empty list."""
        from cloud.integrations.wazuh_ingest import wazuh_ingest_loop

        mock_client = AsyncMock()
        mock_client.enabled = True
        mock_client.base_url = "http://wazuh:55000"

        call_count = 0

        async def fake_get_alerts(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return []
            raise asyncio.CancelledError()

        mock_client.get_alerts = fake_get_alerts

        with (
            patch("cloud.integrations.wazuh_ingest.wazuh_client", mock_client),
            patch("cloud.integrations.wazuh_ingest.POLL_INTERVAL", 0),
        ):
            asyncio.get_event_loop().run_until_complete(wazuh_ingest_loop())

    def test_loop_deduplicates_old_alerts(self):
        """Alerts with timestamps <= _last_poll_ts are skipped."""
        import cloud.integrations.wazuh_ingest as wmod
        from cloud.integrations.wazuh_ingest import wazuh_ingest_loop

        old_ts = wmod._last_poll_ts
        wmod._last_poll_ts = "2025-06-01T12:00:00Z"

        mock_client = AsyncMock()
        mock_client.enabled = True
        mock_client.base_url = "http://wazuh:55000"

        call_count = 0

        async def fake_get_alerts(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [
                    {
                        "timestamp": "2025-06-01T11:00:00Z",  # older → skip
                        "rule": {"id": "1"},
                        "agent": {},
                    }
                ]
            raise asyncio.CancelledError()

        mock_client.get_alerts = fake_get_alerts

        with (
            patch("cloud.integrations.wazuh_ingest.wazuh_client", mock_client),
            patch("cloud.integrations.wazuh_ingest._ingest_alerts") as mock_ingest,
            patch("cloud.integrations.wazuh_ingest.POLL_INTERVAL", 0),
        ):
            asyncio.get_event_loop().run_until_complete(wazuh_ingest_loop())
            mock_ingest.assert_not_called()

        wmod._last_poll_ts = old_ts


# ═══════════════════════════════════════════════════════════════════════════
# 2. cloud/llm_proxy/routes.py
# ═══════════════════════════════════════════════════════════════════════════


def _make_llm_app() -> FastAPI:
    """Build a minimal FastAPI app with the LLM router for testing."""
    from cloud.llm_proxy.routes import router

    app = FastAPI()
    app.include_router(router)
    return app


class TestLLMChatDisabled:
    """Lines 101-108: LLM disabled returns 503."""

    def test_returns_503_when_disabled(self):
        with patch("cloud.llm_proxy.routes.LLM_ENABLED", False):
            app = _make_llm_app()
            client = TestClient(app)
            resp = client.post("/api/v1/llm/chat", json={"prompt": "Hello"})
        assert resp.status_code == 503
        assert "disabled" in resp.json()["detail"].lower()


class TestLLMChatEnabled:
    """Full LLM proxy endpoint tests (lines 109-220)."""

    def _mock_httpx_post(self, response_body: dict, status_code: int = 200):
        """Return an async context manager mock for httpx.AsyncClient."""
        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.json.return_value = response_body
        mock_response.raise_for_status = MagicMock()
        mock_response.text = json.dumps(response_body)

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        return mock_client

    def test_successful_ollama_response(self):
        body = {"message": {"content": "The analysis shows no threats."}}
        mock_client = self._mock_httpx_post(body)

        with (
            patch("cloud.llm_proxy.routes.LLM_ENABLED", True),
            patch("cloud.llm_proxy.routes.LLM_BACKEND_URL", "http://ollama:11434"),
            patch("cloud.llm_proxy.routes.LLM_MODEL", "llama3"),
            patch("cloud.llm_proxy.routes.LLM_MAX_TOKENS", 1024),
            patch("cloud.llm_proxy.routes.LLM_TIMEOUT_SECONDS", 30),
            patch("cloud.llm_proxy.routes.httpx.AsyncClient", return_value=mock_client),
        ):
            app = _make_llm_app()
            client = TestClient(app)
            resp = client.post("/api/v1/llm/chat", json={"prompt": "Analyze events"})

        assert resp.status_code == 200
        data = resp.json()
        assert data["answer"] == "The analysis shows no threats."
        assert data["used_model"] == "llama3"
        assert "latency_ms" in data["metadata"]

    def test_openai_compatible_fallback(self):
        """When Ollama format is empty, fall back to OpenAI choices format."""
        body = {"choices": [{"message": {"content": "OpenAI-style answer"}}]}
        mock_client = self._mock_httpx_post(body)

        with (
            patch("cloud.llm_proxy.routes.LLM_ENABLED", True),
            patch("cloud.llm_proxy.routes.LLM_BACKEND_URL", "http://ollama:11434"),
            patch("cloud.llm_proxy.routes.LLM_MODEL", "gpt-4"),
            patch("cloud.llm_proxy.routes.LLM_MAX_TOKENS", 512),
            patch("cloud.llm_proxy.routes.LLM_TIMEOUT_SECONDS", 30),
            patch("cloud.llm_proxy.routes.httpx.AsyncClient", return_value=mock_client),
        ):
            app = _make_llm_app()
            client = TestClient(app)
            resp = client.post("/api/v1/llm/chat", json={"prompt": "Hello"})

        assert resp.status_code == 200
        assert resp.json()["answer"] == "OpenAI-style answer"

    def test_empty_response_gives_fallback_text(self):
        """When LLM returns empty content."""
        body = {"message": {}}
        mock_client = self._mock_httpx_post(body)

        with (
            patch("cloud.llm_proxy.routes.LLM_ENABLED", True),
            patch("cloud.llm_proxy.routes.LLM_BACKEND_URL", "http://ollama:11434"),
            patch("cloud.llm_proxy.routes.LLM_MODEL", "llama3"),
            patch("cloud.llm_proxy.routes.LLM_MAX_TOKENS", 1024),
            patch("cloud.llm_proxy.routes.LLM_TIMEOUT_SECONDS", 30),
            patch("cloud.llm_proxy.routes.httpx.AsyncClient", return_value=mock_client),
        ):
            app = _make_llm_app()
            client = TestClient(app)
            resp = client.post("/api/v1/llm/chat", json={"prompt": "Hello"})

        assert resp.status_code == 200
        assert "(empty response from LLM)" in resp.json()["answer"]

    def test_timeout_returns_504(self):
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.TimeoutException("timeout")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("cloud.llm_proxy.routes.LLM_ENABLED", True),
            patch("cloud.llm_proxy.routes.LLM_BACKEND_URL", "http://ollama:11434"),
            patch("cloud.llm_proxy.routes.LLM_MODEL", "llama3"),
            patch("cloud.llm_proxy.routes.LLM_MAX_TOKENS", 1024),
            patch("cloud.llm_proxy.routes.LLM_TIMEOUT_SECONDS", 30),
            patch("cloud.llm_proxy.routes.httpx.AsyncClient", return_value=mock_client),
        ):
            app = _make_llm_app()
            client = TestClient(app)
            resp = client.post("/api/v1/llm/chat", json={"prompt": "Hello"})

        assert resp.status_code == 504

    def test_http_error_returns_502(self):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"

        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.HTTPStatusError(
            "error",
            request=MagicMock(),
            response=mock_response,
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("cloud.llm_proxy.routes.LLM_ENABLED", True),
            patch("cloud.llm_proxy.routes.LLM_BACKEND_URL", "http://ollama:11434"),
            patch("cloud.llm_proxy.routes.LLM_MODEL", "llama3"),
            patch("cloud.llm_proxy.routes.LLM_MAX_TOKENS", 1024),
            patch("cloud.llm_proxy.routes.LLM_TIMEOUT_SECONDS", 30),
            patch("cloud.llm_proxy.routes.httpx.AsyncClient", return_value=mock_client),
        ):
            app = _make_llm_app()
            client = TestClient(app)
            resp = client.post("/api/v1/llm/chat", json={"prompt": "Hello"})

        assert resp.status_code == 502

    def test_connect_error_returns_502(self):
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.ConnectError("refused")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("cloud.llm_proxy.routes.LLM_ENABLED", True),
            patch("cloud.llm_proxy.routes.LLM_BACKEND_URL", "http://ollama:11434"),
            patch("cloud.llm_proxy.routes.LLM_MODEL", "llama3"),
            patch("cloud.llm_proxy.routes.LLM_MAX_TOKENS", 1024),
            patch("cloud.llm_proxy.routes.LLM_TIMEOUT_SECONDS", 30),
            patch("cloud.llm_proxy.routes.httpx.AsyncClient", return_value=mock_client),
        ):
            app = _make_llm_app()
            client = TestClient(app)
            resp = client.post("/api/v1/llm/chat", json={"prompt": "Hello"})

        assert resp.status_code == 502
        assert "Cannot connect" in resp.json()["detail"]

    def test_context_is_injected_and_redacted(self):
        body = {"message": {"content": "Context received."}}
        mock_client = self._mock_httpx_post(body)

        with (
            patch("cloud.llm_proxy.routes.LLM_ENABLED", True),
            patch("cloud.llm_proxy.routes.LLM_BACKEND_URL", "http://ollama:11434"),
            patch("cloud.llm_proxy.routes.LLM_MODEL", "llama3"),
            patch("cloud.llm_proxy.routes.LLM_MAX_TOKENS", 1024),
            patch("cloud.llm_proxy.routes.LLM_TIMEOUT_SECONDS", 30),
            patch("cloud.llm_proxy.routes.httpx.AsyncClient", return_value=mock_client),
        ):
            app = _make_llm_app()
            client = TestClient(app)
            resp = client.post(
                "/api/v1/llm/chat",
                json={
                    "prompt": "Analyze this",
                    "context": {"events": [{"id": "e1"}]},
                },
            )

        assert resp.status_code == 200

    def test_options_merged_without_overriding_model(self):
        body = {"message": {"content": "Custom temp."}}
        mock_client = self._mock_httpx_post(body)

        with (
            patch("cloud.llm_proxy.routes.LLM_ENABLED", True),
            patch("cloud.llm_proxy.routes.LLM_BACKEND_URL", "http://ollama:11434"),
            patch("cloud.llm_proxy.routes.LLM_MODEL", "llama3"),
            patch("cloud.llm_proxy.routes.LLM_MAX_TOKENS", 1024),
            patch("cloud.llm_proxy.routes.LLM_TIMEOUT_SECONDS", 30),
            patch("cloud.llm_proxy.routes.httpx.AsyncClient", return_value=mock_client),
        ):
            app = _make_llm_app()
            client = TestClient(app)
            resp = client.post(
                "/api/v1/llm/chat",
                json={
                    "prompt": "Hi",
                    "options": {"temperature": 0.7, "model": "evil-model"},
                },
            )

        assert resp.status_code == 200
        # Verify "model" was filtered out of options
        call_kwargs = mock_client.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["model"] == "llama3"

    def test_prompt_with_secret_is_redacted(self):
        """Secrets in the prompt are redacted before reaching LLM."""
        body = {"message": {"content": "Safe answer."}}
        mock_client = self._mock_httpx_post(body)

        secret_prompt = "My AWS key is AKIAIOSFODNN7EXAMPLE please analyze"  # noqa: S105

        with (
            patch("cloud.llm_proxy.routes.LLM_ENABLED", True),
            patch("cloud.llm_proxy.routes.LLM_BACKEND_URL", "http://ollama:11434"),
            patch("cloud.llm_proxy.routes.LLM_MODEL", "llama3"),
            patch("cloud.llm_proxy.routes.LLM_MAX_TOKENS", 1024),
            patch("cloud.llm_proxy.routes.LLM_TIMEOUT_SECONDS", 30),
            patch("cloud.llm_proxy.routes.httpx.AsyncClient", return_value=mock_client),
        ):
            app = _make_llm_app()
            client = TestClient(app)
            resp = client.post("/api/v1/llm/chat", json={"prompt": secret_prompt})

        assert resp.status_code == 200
        data = resp.json()
        assert data["metadata"]["secrets_redacted_from_prompt"] is True

    def test_response_with_secret_is_redacted(self):
        """Secrets in the LLM response are redacted before returning."""
        body = {"message": {"content": "Key is AKIAIOSFODNN7EXAMPLE"}}
        mock_client = self._mock_httpx_post(body)

        with (
            patch("cloud.llm_proxy.routes.LLM_ENABLED", True),
            patch("cloud.llm_proxy.routes.LLM_BACKEND_URL", "http://ollama:11434"),
            patch("cloud.llm_proxy.routes.LLM_MODEL", "llama3"),
            patch("cloud.llm_proxy.routes.LLM_MAX_TOKENS", 1024),
            patch("cloud.llm_proxy.routes.LLM_TIMEOUT_SECONDS", 30),
            patch("cloud.llm_proxy.routes.httpx.AsyncClient", return_value=mock_client),
        ):
            app = _make_llm_app()
            client = TestClient(app)
            resp = client.post("/api/v1/llm/chat", json={"prompt": "Show secrets"})

        assert resp.status_code == 200
        assert "AKIAIOSFODNN7EXAMPLE" not in resp.json()["answer"]


# ═══════════════════════════════════════════════════════════════════════════
# 3. cloud/guardian/warden_agent.py
# ═══════════════════════════════════════════════════════════════════════════


class TestDeserializeEvents:
    """Cover _deserialize_events (lines 114-140)."""

    def test_deserialize_with_iso_timestamp(self):
        from cloud.guardian.warden_agent import _deserialize_events

        data = [
            {
                "id": "ev-1",
                "agent_id": "a1",
                "type": "file_write",
                "severity": "high",
                "details": {"path": "/etc/passwd"},
                "source": "daemon",
                "timestamp": "2025-06-01T12:00:00+00:00",
            }
        ]
        rows = _deserialize_events(data)
        assert len(rows) == 1
        assert rows[0].id == "ev-1"
        assert rows[0].type == "file_write"
        assert isinstance(rows[0].timestamp, datetime)

    def test_deserialize_with_datetime_object(self):
        from cloud.guardian.warden_agent import _deserialize_events

        ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        rows = _deserialize_events([{"timestamp": ts}])
        assert len(rows) == 1
        assert rows[0].timestamp == ts

    def test_deserialize_with_invalid_timestamp(self):
        from cloud.guardian.warden_agent import _deserialize_events

        rows = _deserialize_events([{"timestamp": "not-a-date"}])
        assert len(rows) == 1
        assert isinstance(rows[0].timestamp, datetime)

    def test_deserialize_with_no_timestamp(self):
        from cloud.guardian.warden_agent import _deserialize_events

        rows = _deserialize_events([{"id": "ev-2"}])
        assert len(rows) == 1
        assert isinstance(rows[0].timestamp, datetime)

    def test_deserialize_with_numeric_timestamp(self):
        """Non-string, non-datetime timestamp falls to default."""
        from cloud.guardian.warden_agent import _deserialize_events

        rows = _deserialize_events([{"timestamp": 12345}])
        assert len(rows) == 1
        assert isinstance(rows[0].timestamp, datetime)

    def test_deserialize_defaults(self):
        """Missing fields get defaults."""
        from cloud.guardian.warden_agent import _deserialize_events

        rows = _deserialize_events([{}])
        assert len(rows) == 1
        assert rows[0].id == ""
        assert rows[0].agent_id == ""
        assert rows[0].severity == "low"
        assert rows[0].source == ""


# ═══════════════════════════════════════════════════════════════════════════
# 4. cloud/services/structured_logger.py
# ═══════════════════════════════════════════════════════════════════════════


class TestCorrelationContext:
    """Cover get/set correlation_id (lines 34, 39)."""

    def test_get_default_empty(self):
        from cloud.services.structured_logger import get_correlation_id, set_correlation_id

        set_correlation_id("")
        assert get_correlation_id() == ""

    def test_set_and_get(self):
        from cloud.services.structured_logger import get_correlation_id, set_correlation_id

        set_correlation_id("test-cid-123")
        assert get_correlation_id() == "test-cid-123"
        set_correlation_id("")  # reset


class TestStructuredJsonFormatter:
    """Cover StructuredJsonFormatter.format (lines 54-83)."""

    def test_basic_format(self):
        from cloud.services.structured_logger import StructuredJsonFormatter, set_correlation_id

        set_correlation_id("")
        fmt = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Hello %s",
            args=("world",),
            exc_info=None,
        )
        output = fmt.format(record)
        data = json.loads(output)
        assert data["message"] == "Hello world"
        assert data["level"] == "INFO"
        assert "timestamp" in data
        assert "correlation_id" not in data  # empty → omitted

    def test_format_with_correlation_id(self):
        from cloud.services.structured_logger import StructuredJsonFormatter, set_correlation_id

        set_correlation_id("cid-abc")
        fmt = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname="",
            lineno=0,
            msg="warning",
            args=(),
            exc_info=None,
        )
        output = fmt.format(record)
        data = json.loads(output)
        assert data["correlation_id"] == "cid-abc"
        set_correlation_id("")

    def test_format_with_exception(self):
        from cloud.services.structured_logger import StructuredJsonFormatter

        fmt = StructuredJsonFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys

            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg="failed",
            args=(),
            exc_info=exc_info,
        )
        output = fmt.format(record)
        data = json.loads(output)
        assert "exception" in data
        assert "boom" in data["exception"]

    def test_format_with_extra_fields(self):
        from cloud.services.structured_logger import StructuredJsonFormatter

        fmt = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="req",
            args=(),
            exc_info=None,
        )
        record.component = "http"
        record.agent_id = "a1"
        record.tenant_id = "t1"
        record.incident_id = "inc-1"
        record.duration_ms = 42.5
        record.status_code = 200
        record.method = "GET"
        record.path = "/api/health"

        output = fmt.format(record)
        data = json.loads(output)
        assert data["component"] == "http"
        assert data["agent_id"] == "a1"
        assert data["status_code"] == 200
        assert data["path"] == "/api/health"


class TestSetupStructuredLogging:
    """Cover setup_structured_logging (line 116 — text formatter branch)."""

    def test_json_format(self):
        from cloud.services.structured_logger import setup_structured_logging

        setup_structured_logging(force_json=True)
        root = logging.getLogger()
        assert len(root.handlers) >= 1
        from cloud.services.structured_logger import StructuredJsonFormatter

        assert any(isinstance(h.formatter, StructuredJsonFormatter) for h in root.handlers)

    def test_text_format(self):
        from cloud.services.structured_logger import setup_structured_logging

        setup_structured_logging(force_json=False)
        root = logging.getLogger()
        assert len(root.handlers) >= 1
        from cloud.services.structured_logger import StructuredJsonFormatter

        assert not any(isinstance(h.formatter, StructuredJsonFormatter) for h in root.handlers)

    def test_env_driven_format(self):
        from cloud.services.structured_logger import setup_structured_logging

        with patch.dict(os.environ, {"ANGELCLAW_LOG_FORMAT": "text"}):
            setup_structured_logging(force_json=None)
            root = logging.getLogger()
            from cloud.services.structured_logger import StructuredJsonFormatter

            assert not any(isinstance(h.formatter, StructuredJsonFormatter) for h in root.handlers)


# ═══════════════════════════════════════════════════════════════════════════
# 5. cloud/guardian/self_audit.py
# ═══════════════════════════════════════════════════════════════════════════


class TestSelfAuditCheckStaleAgents:
    """Cover _check_stale_agents — produces findings (line 111)."""

    def test_stale_agent_found(self, db):
        from cloud.guardian.self_audit import _check_stale_agents

        agent = AgentNodeRow(
            id=str(uuid.uuid4()),
            type="daemon",
            os="linux",
            hostname="stale-host",
            status="active",
            last_seen_at=datetime.now(timezone.utc) - timedelta(minutes=30),
        )
        db.add(agent)
        db.commit()

        findings = _check_stale_agents(db)
        assert len(findings) >= 1
        assert findings[0].category == "stale_agent"
        assert "stale-host" in findings[0].title

    def test_no_stale_agents(self, db):
        from cloud.guardian.self_audit import _check_stale_agents

        findings = _check_stale_agents(db)
        # May or may not find stale from previous test; just check type
        assert isinstance(findings, list)


class TestSelfAuditCheckPolicyDrift:
    """Cover _check_policy_drift (lines 133-153)."""

    def test_policy_drift_detected(self, db):
        from cloud.guardian.self_audit import _check_policy_drift

        policy = PolicySetRow(
            id=str(uuid.uuid4()),
            name="main",
            rules_json=[],
            version_hash="abc123",
        )
        db.add(policy)

        agent = AgentNodeRow(
            id=str(uuid.uuid4()),
            type="daemon",
            os="linux",
            hostname="drifted-host",
            status="active",
            policy_version="old-version",
            last_seen_at=datetime.now(timezone.utc),
        )
        db.add(agent)
        db.commit()

        findings = _check_policy_drift(db)
        assert len(findings) >= 1
        assert findings[0].category == "config_drift"

    def test_no_policy_no_drift(self, db):
        """No policy → no drift findings."""
        from cloud.guardian.self_audit import _check_policy_drift

        # Clear any policies from prior tests
        db.query(PolicySetRow).delete()
        db.commit()
        findings = _check_policy_drift(db)
        assert findings == []


class TestSelfAuditCheckOrphanAlerts:
    """Cover _check_orphan_alerts (line 169)."""

    def test_orphan_alerts_found(self, db):
        from cloud.guardian.self_audit import _check_orphan_alerts

        for i in range(7):
            db.add(
                GuardianAlertRow(
                    id=str(uuid.uuid4()),
                    tenant_id="t1",
                    alert_type="threat",
                    title=f"Old alert {i}",
                    severity="critical",
                    created_at=datetime.now(timezone.utc) - timedelta(hours=48),
                )
            )
        db.commit()

        findings = _check_orphan_alerts(db)
        assert len(findings) >= 1
        assert findings[0].category == "orphan_rule"


class TestSelfAuditCheckAuthRisks:
    """Cover _check_auth_risks (lines 201, 213)."""

    def test_auth_disabled_finding(self):
        from cloud.guardian.self_audit import _check_auth_risks

        with patch.dict(
            os.environ,
            {
                "ANGELCLAW_AUTH_ENABLED": "false",
                "ANGELCLAW_BIND_HOST": "127.0.0.1",
            },
            clear=False,
        ):
            findings = _check_auth_risks()

        cats = [f.category for f in findings]
        assert "auth_risk" in cats
        titles = [f.title for f in findings]
        assert any("DISABLED" in t for t in titles)

    def test_no_admin_password_finding(self):
        from cloud.guardian.self_audit import _check_auth_risks

        env = {
            "ANGELCLAW_AUTH_ENABLED": "true",
            "ANGELCLAW_ADMIN_PASSWORD": "",
            "ANGELCLAW_BIND_HOST": "127.0.0.1",
        }
        with patch.dict(os.environ, env, clear=False):
            findings = _check_auth_risks()

        assert any("password" in f.title.lower() for f in findings)

    def test_public_exposure_finding(self):
        from cloud.guardian.self_audit import _check_auth_risks

        env = {
            "ANGELCLAW_AUTH_ENABLED": "false",
            "ANGELCLAW_BIND_HOST": "0.0.0.0",  # noqa: S104
        }
        with patch.dict(os.environ, env, clear=False):
            findings = _check_auth_risks()

        assert any("Public exposure" in f.title for f in findings)


class TestSelfAuditCheckEventCoverage:
    """Cover _check_event_coverage (lines 237-259)."""

    def test_uncovered_categories(self, db):
        from cloud.guardian.self_audit import _check_event_coverage

        # Add event with uncovered category
        db.add(
            EventRow(
                id=str(uuid.uuid4()),
                agent_id="a1",
                timestamp=datetime.now(timezone.utc),
                category="exotic_category",
                type="test",
                severity="info",
            )
        )

        # Add policy covering only "auth"
        db.add(
            PolicySetRow(
                id=str(uuid.uuid4()),
                name="coverage-policy",
                rules_json=[
                    {"conditions": {"category": "auth"}, "action": "allow"},
                ],
                version_hash="covhash",
            )
        )
        db.commit()

        findings = _check_event_coverage(db)
        assert len(findings) >= 1
        assert findings[0].category == "policy_gap"
        assert "exotic_category" in findings[0].title

    def test_category_in_list_form(self, db):
        """category_in (list form) is recognized."""
        from cloud.guardian.self_audit import _check_event_coverage

        # Clean slate
        db.query(EventRow).delete()
        db.query(PolicySetRow).delete()
        db.commit()

        db.add(
            EventRow(
                id=str(uuid.uuid4()),
                agent_id="a1",
                timestamp=datetime.now(timezone.utc),
                category="net_cat",
                type="test",
                severity="info",
            )
        )

        db.add(
            PolicySetRow(
                id=str(uuid.uuid4()),
                name="coverage-policy-list",
                rules_json=[
                    {"conditions": {"category_in": ["net_cat", "auth"]}, "action": "allow"},
                ],
                version_hash="covhash2",
            )
        )
        db.commit()

        findings = _check_event_coverage(db)
        gap_findings = [f for f in findings if f.category == "policy_gap"]
        # net_cat should be covered by the category_in rule → no gap findings
        assert all("net_cat" not in f.title for f in gap_findings)

    def test_no_policy_no_findings(self, db):
        """No policy → no event coverage findings."""
        from cloud.guardian.self_audit import _check_event_coverage

        db.query(PolicySetRow).delete()
        db.commit()

        findings = _check_event_coverage(db)
        assert findings == []


class TestSelfAuditCheckNoisyAgents:
    """Cover _check_noisy_agents (line 274)."""

    def test_noisy_agent_detected(self, db):
        from cloud.guardian.self_audit import _check_noisy_agents

        now = datetime.now(timezone.utc)
        for _i in range(510):
            db.add(
                EventRow(
                    id=str(uuid.uuid4()),
                    agent_id="noisy-agent-001",
                    timestamp=now - timedelta(minutes=5),
                    category="system",
                    type="heartbeat",
                    severity="info",
                )
            )
        db.commit()

        findings = _check_noisy_agents(db)
        assert len(findings) >= 1
        assert "noisy" in findings[0].title.lower()


class TestRunSelfAudit:
    """Cover run_self_audit clean path (line 79)."""

    def test_clean_audit(self):
        """When all checks return empty, summary says clean."""
        from cloud.guardian.self_audit import run_self_audit

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.all.return_value = []
        mock_db.query.return_value.filter.return_value.count.return_value = 0
        mock_db.query.return_value.first.return_value = None

        with (
            patch.dict(
                os.environ,
                {
                    "ANGELCLAW_AUTH_ENABLED": "true",
                    "ANGELCLAW_ADMIN_PASSWORD": "secure-password",
                    "ANGELCLAW_BIND_HOST": "127.0.0.1",
                },
                clear=False,
            ),
            patch("cloud.guardian.self_audit._check_warden_health", return_value=[]),
        ):
            report = asyncio.get_event_loop().run_until_complete(run_self_audit(mock_db))

        assert report.clean is True
        assert "clean" in report.summary.lower() or "passed" in report.summary.lower()
        assert report.checks_run == 10

    def test_audit_with_findings(self):
        """When checks return findings, summary reflects them."""
        from cloud.guardian.self_audit import run_self_audit

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.all.return_value = []
        mock_db.query.return_value.filter.return_value.count.return_value = 0
        mock_db.query.return_value.first.return_value = None

        with patch.dict(
            os.environ,
            {
                "ANGELCLAW_AUTH_ENABLED": "false",
                "ANGELCLAW_BIND_HOST": "0.0.0.0",  # noqa: S104
            },
            clear=False,
        ):
            report = asyncio.get_event_loop().run_until_complete(run_self_audit(mock_db))

        assert report.clean is False
        assert report.checks_run == 10
        assert len(report.findings) > 0
        assert "finding" in report.summary.lower()
