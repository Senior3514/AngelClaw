"""AngelClaw Cloud – WebSocket Connection Manager.

Manages WebSocket connections with tenant-scoped filtering,
heartbeat, and broadcast capabilities.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field

from fastapi import WebSocket

logger = logging.getLogger("angelgrid.cloud.websocket")


@dataclass
class WSClient:
    """Tracked WebSocket client."""

    websocket: WebSocket
    tenant_id: str
    connected_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)
    subscriptions: set[str] = field(default_factory=lambda: {"events", "alerts"})


class ConnectionManager:
    """Manages WebSocket connections with tenant filtering and broadcast."""

    def __init__(self) -> None:
        self._clients: dict[str, WSClient] = {}  # ws_id -> WSClient
        self._lock = asyncio.Lock()
        self._counter = 0

    async def connect(self, websocket: WebSocket, tenant_id: str) -> str:
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        async with self._lock:
            self._counter += 1
            ws_id = f"ws-{self._counter}"
            self._clients[ws_id] = WSClient(
                websocket=websocket,
                tenant_id=tenant_id,
            )
        logger.info("WebSocket connected: %s (tenant=%s)", ws_id, tenant_id)
        return ws_id

    async def disconnect(self, ws_id: str) -> None:
        """Remove a WebSocket connection."""
        async with self._lock:
            self._clients.pop(ws_id, None)
        logger.info("WebSocket disconnected: %s", ws_id)

    async def broadcast(
        self,
        message: dict,
        *,
        tenant_id: str | None = None,
        channel: str = "events",
    ) -> int:
        """Broadcast a message to matching clients. Returns count sent."""
        payload = json.dumps(message)
        sent = 0
        stale: list[str] = []

        async with self._lock:
            clients = list(self._clients.items())

        for ws_id, client in clients:
            if tenant_id and client.tenant_id != tenant_id:
                continue
            if channel not in client.subscriptions:
                continue
            try:
                await client.websocket.send_text(payload)
                sent += 1
            except Exception:
                stale.append(ws_id)

        if stale:
            async with self._lock:
                for ws_id in stale:
                    self._clients.pop(ws_id, None)

        return sent

    async def send_personal(self, ws_id: str, message: dict) -> bool:
        """Send message to a specific client."""
        async with self._lock:
            client = self._clients.get(ws_id)
        if not client:
            return False
        try:
            await client.websocket.send_text(json.dumps(message))
            return True
        except Exception:
            await self.disconnect(ws_id)
            return False

    @property
    def active_connections(self) -> int:
        return len(self._clients)

    def status(self) -> dict:
        """Return connection manager status."""
        return {
            "active_connections": self.active_connections,
            "clients": [
                {
                    "id": ws_id,
                    "tenant_id": c.tenant_id,
                    "connected_at": c.connected_at,
                    "subscriptions": list(c.subscriptions),
                }
                for ws_id, c in self._clients.items()
            ],
        }


# Module singleton
ws_manager = ConnectionManager()
