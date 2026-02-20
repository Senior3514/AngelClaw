"""Tests for V2.4 Compliance Warden and API Warden."""

from __future__ import annotations

import uuid

import pytest

from cloud.guardian.api_warden import ApiWarden
from cloud.guardian.compliance_warden import ComplianceWarden
from cloud.guardian.models import AgentTask, AgentType


def _make_event(category="shell", etype="shell.exec", severity="medium", details=None):
    return {
        "id": str(uuid.uuid4()),
        "agent_id": str(uuid.uuid4()),
        "category": category,
        "type": etype,
        "severity": severity,
        "details": details or {},
        "source": "test",
    }


def _get_indicators(result):
    """Extract indicators list from AgentResult."""
    return result.result_data.get("indicators", [])


class TestComplianceWarden:
    @pytest.mark.asyncio
    async def test_init(self):
        warden = ComplianceWarden()
        assert warden.agent_type == AgentType.COMPLIANCE

    @pytest.mark.asyncio
    async def test_detect_unencrypted_transfer(self):
        warden = ComplianceWarden()
        events = [
            _make_event(
                "network",
                "network.connection",
                "high",
                {"command": "http://insecure-server.com/data"},
            ),
        ]
        task = AgentTask(task_type="detect", payload={"events": events, "window_seconds": 300})
        result = await warden.handle_task(task)
        indicators = _get_indicators(result)
        assert any("ncrypted" in i.get("description", "") for i in indicators)

    @pytest.mark.asyncio
    async def test_detect_access_violations(self):
        warden = ComplianceWarden()
        events = [
            _make_event("auth", "auth.failure", "high", {"response": "unauthorized access denied"}),
            _make_event("auth", "auth.failure", "high", {"response": "permission denied"}),
            _make_event("auth", "auth.failure", "high", {"response": "forbidden access"}),
        ]
        task = AgentTask(task_type="detect", payload={"events": events, "window_seconds": 300})
        result = await warden.handle_task(task)
        indicators = _get_indicators(result)
        assert any("access control" in i.get("description", "").lower() for i in indicators)

    @pytest.mark.asyncio
    async def test_detect_encryption_gaps(self):
        warden = ComplianceWarden()
        events = [
            _make_event(
                "compliance",
                "compliance.encryption_gap",
                "high",
                {"command": "using weak cipher MD5 for hashing"},
            ),
        ]
        task = AgentTask(task_type="detect", payload={"events": events, "window_seconds": 300})
        result = await warden.handle_task(task)
        indicators = _get_indicators(result)
        assert any(
            "ncryption" in i.get("description", "") or "ncryption" in i.get("pattern_name", "")
            for i in indicators
        )

    @pytest.mark.asyncio
    async def test_no_issues_clean_events(self):
        warden = ComplianceWarden()
        events = [
            _make_event("shell", "shell.exec", "low", {"command": "ls -la"}),
        ]
        task = AgentTask(task_type="detect", payload={"events": events, "window_seconds": 300})
        result = await warden.handle_task(task)
        indicators = _get_indicators(result)
        assert len(indicators) == 0

    @pytest.mark.asyncio
    async def test_empty_events(self):
        warden = ComplianceWarden()
        task = AgentTask(task_type="detect", payload={"events": [], "window_seconds": 300})
        result = await warden.handle_task(task)
        indicators = _get_indicators(result)
        assert len(indicators) == 0

    @pytest.mark.asyncio
    async def test_result_has_stats(self):
        warden = ComplianceWarden()
        task = AgentTask(task_type="detect", payload={"events": [], "window_seconds": 300})
        result = await warden.handle_task(task)
        assert "stats" in result.result_data
        assert "summary" in result.result_data

    @pytest.mark.asyncio
    async def test_retention_breach(self):
        warden = ComplianceWarden()
        events = [
            _make_event(
                "compliance",
                "compliance.retention_breach",
                "medium",
                {"message": "retention violation detected"},
            ),
        ]
        task = AgentTask(task_type="detect", payload={"events": events, "window_seconds": 300})
        result = await warden.handle_task(task)
        indicators = _get_indicators(result)
        assert any("retention" in i.get("pattern_name", "") for i in indicators)


class TestApiWarden:
    @pytest.mark.asyncio
    async def test_init(self):
        warden = ApiWarden()
        assert warden.agent_type == AgentType.API_SECURITY

    @pytest.mark.asyncio
    async def test_detect_enumeration(self):
        warden = ApiWarden()
        events = [
            _make_event(
                "api_security",
                "api_security.enumeration",
                "medium",
                {"status_code": "404", "source_ip": "1.2.3.4"},
            )
            for _ in range(6)
        ]
        task = AgentTask(task_type="detect", payload={"events": events, "window_seconds": 300})
        result = await warden.handle_task(task)
        indicators = _get_indicators(result)
        assert any(
            "numeration" in i.get("description", "") or "numeration" in i.get("pattern_name", "")
            for i in indicators
        )

    @pytest.mark.asyncio
    async def test_detect_auth_failure_spike(self):
        warden = ApiWarden()
        events = [
            _make_event(
                "api_security",
                "api_security.auth_failure",
                "high",
                {"status_code": 401, "source_ip": "10.0.0.1"},
            )
            for _ in range(6)
        ]
        task = AgentTask(task_type="detect", payload={"events": events, "window_seconds": 300})
        result = await warden.handle_task(task)
        indicators = _get_indicators(result)
        assert any("uthentication" in i.get("description", "") for i in indicators)

    @pytest.mark.asyncio
    async def test_detect_oversized_payload(self):
        warden = ApiWarden()
        events = [
            _make_event(
                "api_security",
                "api_security.payload_oversize",
                "medium",
                {"payload_size": 5_000_000},
            ),
        ]
        task = AgentTask(task_type="detect", payload={"events": events, "window_seconds": 300})
        result = await warden.handle_task(task)
        indicators = _get_indicators(result)
        assert any(
            "versize" in i.get("description", "") or "versize" in i.get("pattern_name", "")
            for i in indicators
        )

    @pytest.mark.asyncio
    async def test_no_issues_clean(self):
        warden = ApiWarden()
        events = [_make_event("shell", "shell.exec", "low")]
        task = AgentTask(task_type="detect", payload={"events": events, "window_seconds": 300})
        result = await warden.handle_task(task)
        indicators = _get_indicators(result)
        assert len(indicators) == 0

    @pytest.mark.asyncio
    async def test_empty_events(self):
        warden = ApiWarden()
        task = AgentTask(task_type="detect", payload={"events": [], "window_seconds": 300})
        result = await warden.handle_task(task)
        indicators = _get_indicators(result)
        assert len(indicators) == 0

    @pytest.mark.asyncio
    async def test_unusual_http_methods(self):
        warden = ApiWarden()
        events = [
            _make_event("api_security", "api_security.method_abuse", "medium", {"method": "TRACE"})
            for _ in range(4)
        ]
        task = AgentTask(task_type="detect", payload={"events": events, "window_seconds": 300})
        result = await warden.handle_task(task)
        indicators = _get_indicators(result)
        assert any(
            "method" in i.get("description", "").lower() or "method" in i.get("pattern_name", "")
            for i in indicators
        )

    @pytest.mark.asyncio
    async def test_result_has_stats(self):
        warden = ApiWarden()
        task = AgentTask(task_type="detect", payload={"events": [], "window_seconds": 300})
        result = await warden.handle_task(task)
        assert "stats" in result.result_data
        assert "summary" in result.result_data
