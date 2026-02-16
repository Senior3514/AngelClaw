"""Tests for guardian sub-agents: permission enforcement, task lifecycle, and error handling."""

from __future__ import annotations

import pytest

from cloud.guardian.base_agent import SubAgent
from cloud.guardian.models import (
    AgentResult,
    AgentStatus,
    AgentTask,
    AgentType,
    Permission,
)
from cloud.guardian.sentinel_agent import SentinelAgent
from cloud.guardian.response_agent import ResponseAgent
from cloud.guardian.forensic_agent import ForensicAgent
from cloud.guardian.audit_agent import AuditAgent


# ---------------------------------------------------------------------------
# Permission enforcement
# ---------------------------------------------------------------------------

class TestPermissions:

    def test_sentinel_has_read_permissions(self):
        """Sentinel agent has READ_EVENTS and READ_AGENTS."""
        agent = SentinelAgent()
        assert agent.check_permission(Permission.READ_EVENTS)
        assert agent.check_permission(Permission.READ_AGENTS)

    def test_sentinel_lacks_write_permissions(self):
        """Sentinel agent cannot execute responses."""
        agent = SentinelAgent()
        assert not agent.check_permission(Permission.EXECUTE_RESPONSE)
        assert not agent.check_permission(Permission.WRITE_AGENT_STATE)

    def test_response_has_execute_permission(self):
        """Response agent has EXECUTE_RESPONSE."""
        agent = ResponseAgent()
        assert agent.check_permission(Permission.EXECUTE_RESPONSE)
        assert agent.check_permission(Permission.WRITE_AGENT_STATE)
        assert agent.check_permission(Permission.CALL_EXTERNAL)

    def test_require_permission_raises(self):
        """require_permission raises PermissionError when lacking permission."""
        agent = SentinelAgent()
        with pytest.raises(PermissionError):
            agent.require_permission(Permission.EXECUTE_RESPONSE)

    def test_require_permission_passes(self):
        """require_permission succeeds when permission is held."""
        agent = ResponseAgent()
        agent.require_permission(Permission.EXECUTE_RESPONSE)  # Should not raise


# ---------------------------------------------------------------------------
# Agent lifecycle
# ---------------------------------------------------------------------------

class TestAgentLifecycle:

    def test_initial_status_idle(self):
        """Agents start in IDLE status."""
        for AgentClass in [SentinelAgent, ResponseAgent, ForensicAgent, AuditAgent]:
            agent = AgentClass()
            assert agent.status == AgentStatus.IDLE

    @pytest.mark.asyncio
    async def test_shutdown_sets_stopped(self):
        """shutdown() transitions agent to STOPPED."""
        agent = SentinelAgent()
        await agent.shutdown()
        assert agent.status == AgentStatus.STOPPED

    @pytest.mark.asyncio
    async def test_health_check_idle(self):
        """Healthy agent reports True."""
        agent = SentinelAgent()
        assert await agent.health_check() is True

    @pytest.mark.asyncio
    async def test_health_check_error(self):
        """Agent in ERROR status reports False."""
        agent = SentinelAgent()
        agent.status = AgentStatus.ERROR
        assert await agent.health_check() is False


# ---------------------------------------------------------------------------
# Agent info
# ---------------------------------------------------------------------------

class TestAgentInfo:

    def test_info_structure(self):
        """info() returns expected fields."""
        agent = SentinelAgent()
        info = agent.info()
        assert "agent_id" in info
        assert "agent_type" in info
        assert "status" in info
        assert "permissions" in info
        assert "tasks_completed" in info
        assert "tasks_failed" in info
        assert info["agent_type"] == "sentinel"
        assert info["status"] == "idle"
        assert info["tasks_completed"] == 0

    def test_all_agents_have_unique_ids(self):
        """Each agent instance gets a unique ID."""
        agents = [SentinelAgent(), SentinelAgent(), ResponseAgent(), ForensicAgent()]
        ids = [a.agent_id for a in agents]
        assert len(ids) == len(set(ids))

    def test_agent_types_correct(self):
        """Each agent class reports its correct type."""
        assert SentinelAgent().agent_type == AgentType.SENTINEL
        assert ResponseAgent().agent_type == AgentType.RESPONSE
        assert ForensicAgent().agent_type == AgentType.FORENSIC
        assert AuditAgent().agent_type == AgentType.AUDIT


# ---------------------------------------------------------------------------
# Task execution
# ---------------------------------------------------------------------------

class TestTaskExecution:

    @pytest.mark.asyncio
    async def test_sentinel_detect_empty(self):
        """Sentinel handles empty detection task."""
        agent = SentinelAgent()
        task = AgentTask(
            task_type="detect",
            payload={"events": []},
        )
        result = await agent.execute(task)
        assert result.success is True
        assert result.agent_type == "sentinel"
        assert result.duration_ms >= 0
        assert agent.status == AgentStatus.IDLE  # Returns to idle

    @pytest.mark.asyncio
    async def test_task_increments_completed(self):
        """Successful task increments _tasks_completed counter."""
        agent = SentinelAgent()
        assert agent._tasks_completed == 0
        task = AgentTask(task_type="detect", payload={"events": []})
        await agent.execute(task)
        assert agent._tasks_completed == 1

    @pytest.mark.asyncio
    async def test_response_dry_run(self):
        """Response agent handles dry-run playbook execution."""
        agent = ResponseAgent()
        task = AgentTask(
            task_type="respond",
            payload={
                "playbook_name": "quarantine_agent",
                "incident": {
                    "incident_id": "test-dry-run",
                    "agent_id": "test-agent",
                    "severity": "high",
                    "title": "Test",
                    "tenant_id": "dev-tenant",
                },
                "dry_run": True,
                "approved": True,
            },
        )
        result = await agent.execute(task)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_response_unknown_playbook(self):
        """Response agent fails gracefully for unknown playbook."""
        agent = ResponseAgent()
        task = AgentTask(
            task_type="respond",
            payload={
                "playbook_name": "nonexistent_playbook",
                "incident": {
                    "incident_id": "test",
                    "agent_id": "test-agent",
                    "severity": "high",
                    "title": "Test",
                    "tenant_id": "dev-tenant",
                },
                "dry_run": True,
                "approved": True,
            },
        )
        result = await agent.execute(task)
        assert result.success is False


# ---------------------------------------------------------------------------
# Playbook loading
# ---------------------------------------------------------------------------

class TestPlaybookLoading:

    def test_playbooks_loaded(self):
        """Response agent loads playbooks from YAML files."""
        agent = ResponseAgent()
        playbooks = agent.list_playbooks()
        assert "quarantine_agent" in playbooks
        assert "throttle_agent" in playbooks
        assert "block_source" in playbooks
        assert "revoke_token" in playbooks
        assert len(playbooks) >= 4

    def test_get_playbook_details(self):
        """Playbook details include name, steps, severity."""
        agent = ResponseAgent()
        pb = agent.get_playbook("quarantine_agent")
        assert pb is not None
        assert pb.name == "quarantine_agent"
        assert len(pb.steps) > 0
        assert pb.severity_threshold in ("critical", "high", "medium", "low")

    def test_get_nonexistent_playbook(self):
        """get_playbook returns None for unknown name."""
        agent = ResponseAgent()
        assert agent.get_playbook("does_not_exist") is None
