"""Tests for V3.0 Agent Mesh."""

from __future__ import annotations

import uuid

import pytest

from cloud.services.agent_mesh import AgentMesh


class TestAgentMesh:
    @pytest.mark.asyncio
    async def test_register_agent(self):
        mesh = AgentMesh()
        result = await mesh.register_agent("agent-1", "network", ["scan", "monitor"])
        assert result["registered"] is True

    @pytest.mark.asyncio
    async def test_deregister_agent(self):
        mesh = AgentMesh()
        await mesh.register_agent("agent-2", "shell")
        result = await mesh.deregister_agent("agent-2")
        assert result is True

    @pytest.mark.asyncio
    async def test_send_message(self):
        mesh = AgentMesh()
        await mesh.register_agent("src", "network")
        await mesh.register_agent("dst", "shell")
        result = await mesh.send_message("src", "dst", {"action": "scan"})
        assert result["sent"] is True

    @pytest.mark.asyncio
    async def test_send_to_unregistered(self):
        mesh = AgentMesh()
        result = await mesh.send_message("src", "unknown", {"action": "test"})
        assert result["sent"] is False

    @pytest.mark.asyncio
    async def test_get_inbox(self):
        mesh = AgentMesh()
        await mesh.register_agent("sender", "network")
        await mesh.register_agent("receiver", "shell")
        await mesh.send_message("sender", "receiver", {"data": "hello"})
        inbox = await mesh.get_inbox("receiver")
        assert len(inbox) >= 1
        assert inbox[0]["payload"]["data"] == "hello"

    @pytest.mark.asyncio
    async def test_respond_to_message(self):
        mesh = AgentMesh()
        await mesh.register_agent("a", "network")
        await mesh.register_agent("b", "shell")
        sent = await mesh.send_message("a", "b", {"request": "status"})
        msg_id = sent["message_id"]
        result = await mesh.respond(msg_id, {"status": "ok"})
        assert result is True

    @pytest.mark.asyncio
    async def test_respond_nonexistent(self):
        mesh = AgentMesh()
        result = await mesh.respond("fake-id", {"status": "error"})
        assert result is False

    def test_list_agents(self):
        mesh = AgentMesh()
        assert isinstance(mesh.list_agents(), list)

    def test_status(self):
        mesh = AgentMesh()
        status = mesh.status()
        assert "agents_registered" in status
        assert "total_messages" in status


class TestMeshRoutes:
    def test_mesh_status_endpoint(self, client):
        resp = client.get("/api/v1/mesh/status")
        assert resp.status_code == 200

    def test_list_agents_endpoint(self, client):
        resp = client.get("/api/v1/mesh/agents")
        assert resp.status_code == 200

    def test_register_endpoint(self, client):
        resp = client.post(
            "/api/v1/mesh/register",
            json={
                "agent_id": str(uuid.uuid4()),
                "agent_type": "test",
                "capabilities": ["scan"],
            },
        )
        assert resp.status_code == 200
