"""Tests for V2.4 WebSocket Live Feed."""

from __future__ import annotations

import pytest

from cloud.websocket.manager import ConnectionManager, WSClient


class TestConnectionManager:
    def test_create_manager(self):
        mgr = ConnectionManager()
        assert mgr.active_connections == 0

    def test_status(self):
        mgr = ConnectionManager()
        status = mgr.status()
        assert "active_connections" in status
        assert status["active_connections"] == 0
        assert "clients" in status

    @pytest.mark.asyncio
    async def test_broadcast_no_clients(self):
        mgr = ConnectionManager()
        sent = await mgr.broadcast({"type": "test", "data": "hello"})
        assert sent == 0

    @pytest.mark.asyncio
    async def test_send_personal_missing_client(self):
        mgr = ConnectionManager()
        result = await mgr.send_personal("nonexistent", {"test": True})
        assert result is False

    def test_ws_client_dataclass(self):
        # Can't create real WebSocket, but test the dataclass
        client = WSClient.__dataclass_fields__
        assert "tenant_id" in client
        assert "subscriptions" in client
        assert "connected_at" in client

    def test_manager_counter(self):
        mgr = ConnectionManager()
        assert mgr._counter == 0


class TestWebSocketRoutes:
    def test_websocket_status_endpoint(self, client):
        """Test the HTTP status endpoint for WebSocket."""
        resp = client.get("/api/v1/websocket/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "active_connections" in data
