"""AngelClaw Cloud – WebSocket Routes.

WebSocket endpoints for real-time event and alert streaming.
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from cloud.websocket.manager import ws_manager

logger = logging.getLogger("angelgrid.cloud.websocket")

router = APIRouter(tags=["WebSocket"])


@router.websocket("/ws/events")
async def ws_events(websocket: WebSocket, tenant_id: str = "dev-tenant"):
    """Real-time event stream via WebSocket."""
    ws_id = await ws_manager.connect(websocket, tenant_id)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await ws_manager.send_personal(ws_id, {"type": "pong"})
                elif msg.get("type") == "subscribe":
                    channels = msg.get("channels", [])
                    if channels:
                        async with ws_manager._lock:
                            client = ws_manager._clients.get(ws_id)
                            if client:
                                client.subscriptions = set(channels)
                        await ws_manager.send_personal(
                            ws_id, {"type": "subscribed", "channels": channels}
                        )
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        await ws_manager.disconnect(ws_id)
    except Exception:
        await ws_manager.disconnect(ws_id)


@router.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket, tenant_id: str = "dev-tenant"):
    """Real-time alert stream via WebSocket."""
    ws_id = await ws_manager.connect(websocket, tenant_id)
    try:
        # Set subscription to alerts only
        async with ws_manager._lock:
            client = ws_manager._clients.get(ws_id)
            if client:
                client.subscriptions = {"alerts"}
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await ws_manager.send_personal(ws_id, {"type": "pong"})
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        await ws_manager.disconnect(ws_id)
    except Exception:
        await ws_manager.disconnect(ws_id)


@router.get("/api/v1/websocket/status", tags=["WebSocket"])
def websocket_status():
    """Return WebSocket connection manager status."""
    return ws_manager.status()
