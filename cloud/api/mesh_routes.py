"""AngelClaw Cloud – Agent Mesh API Routes."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from cloud.services.agent_mesh import agent_mesh

logger = logging.getLogger("angelgrid.cloud.api.mesh")

router = APIRouter(prefix="/api/v1/mesh", tags=["Agent Mesh"])


class RegisterRequest(BaseModel):
    agent_id: str
    agent_type: str
    capabilities: list[str] = []


class SendRequest(BaseModel):
    source_agent: str
    target_agent: str
    payload: dict
    message_type: str = "request"


class RespondRequest(BaseModel):
    response: dict


@router.post("/register")
async def register_agent(req: RegisterRequest):
    """Register an agent in the mesh."""
    return await agent_mesh.register_agent(req.agent_id, req.agent_type, req.capabilities)


@router.delete("/agents/{agent_id}")
async def deregister_agent(agent_id: str):
    """Remove an agent from the mesh."""
    if not await agent_mesh.deregister_agent(agent_id):
        raise HTTPException(status_code=404, detail="Agent not in mesh")
    return {"deregistered": True}


@router.post("/send")
async def send_message(req: SendRequest):
    """Send a message between agents."""
    result = await agent_mesh.send_message(
        req.source_agent, req.target_agent, req.payload, req.message_type
    )
    if not result.get("sent"):
        raise HTTPException(status_code=404, detail=result.get("error", "Send failed"))
    return result


@router.get("/inbox/{agent_id}")
async def get_inbox(agent_id: str, limit: int = 50):
    """Get pending messages for an agent."""
    return await agent_mesh.get_inbox(agent_id, limit)


@router.post("/messages/{message_id}/respond")
async def respond_to_message(message_id: str, req: RespondRequest):
    """Respond to a mesh message."""
    if not await agent_mesh.respond(message_id, req.response):
        raise HTTPException(status_code=404, detail="Message not found")
    return {"responded": True}


@router.get("/status")
def mesh_status():
    """Get mesh network status."""
    return agent_mesh.status()


@router.get("/agents")
def list_mesh_agents():
    """List agents in the mesh."""
    return agent_mesh.list_agents()
