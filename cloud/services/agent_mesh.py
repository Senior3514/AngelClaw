"""AngelClaw Cloud – Agent Mesh Service.

Provides agent-to-agent communication via a message-passing mesh network.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger("angelgrid.cloud.agent_mesh")


@dataclass
class MeshMessage:
    """Message in the agent mesh."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_agent: str = ""
    target_agent: str = ""
    message_type: str = "request"
    payload: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    ttl: int = 30
    response: dict | None = None
    responded: bool = False


class AgentMesh:
    """Agent-to-agent communication mesh."""

    def __init__(self) -> None:
        self._agents: dict[str, dict] = {}
        self._messages: dict[str, MeshMessage] = {}
        self._inbox: dict[str, list[str]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def register_agent(self, agent_id: str, agent_type: str, capabilities: list[str] | None = None) -> dict:
        """Register an agent in the mesh."""
        self._agents[agent_id] = {
            "agent_id": agent_id,
            "agent_type": agent_type,
            "capabilities": capabilities or [],
            "registered_at": time.time(),
            "last_seen": time.time(),
            "messages_sent": 0,
            "messages_received": 0,
        }
        logger.info("Agent %s registered in mesh (type=%s)", agent_id[:8], agent_type)
        return {"registered": True, "agent_id": agent_id}

    async def deregister_agent(self, agent_id: str) -> bool:
        """Remove an agent from the mesh."""
        return self._agents.pop(agent_id, None) is not None

    async def send_message(
        self,
        source_agent: str,
        target_agent: str,
        payload: dict,
        message_type: str = "request",
    ) -> dict:
        """Send a message between agents."""
        if target_agent not in self._agents:
            return {"error": "Target agent not registered", "sent": False}

        msg = MeshMessage(
            source_agent=source_agent,
            target_agent=target_agent,
            message_type=message_type,
            payload=payload,
        )
        self._messages[msg.id] = msg
        self._inbox[target_agent].append(msg.id)

        if source_agent in self._agents:
            self._agents[source_agent]["messages_sent"] += 1
        self._agents[target_agent]["messages_received"] += 1

        return {"sent": True, "message_id": msg.id}

    async def get_inbox(self, agent_id: str, limit: int = 50) -> list[dict]:
        """Get pending messages for an agent."""
        msg_ids = self._inbox.get(agent_id, [])[-limit:]
        messages = []
        for mid in msg_ids:
            msg = self._messages.get(mid)
            if msg and not msg.responded:
                messages.append({
                    "id": msg.id,
                    "source_agent": msg.source_agent,
                    "message_type": msg.message_type,
                    "payload": msg.payload,
                    "timestamp": msg.timestamp,
                })
        return messages

    async def respond(self, message_id: str, response: dict) -> bool:
        """Respond to a mesh message."""
        msg = self._messages.get(message_id)
        if not msg:
            return False
        msg.response = response
        msg.responded = True
        return True

    def list_agents(self) -> list[dict]:
        """List all agents in the mesh."""
        return list(self._agents.values())

    def status(self) -> dict:
        """Mesh network status."""
        return {
            "agents_registered": len(self._agents),
            "total_messages": len(self._messages),
            "pending_messages": sum(
                1 for m in self._messages.values() if not m.responded
            ),
            "agents": [
                {"agent_id": a["agent_id"], "type": a["agent_type"], "capabilities": a["capabilities"]}
                for a in self._agents.values()
            ],
        }


agent_mesh = AgentMesh()
