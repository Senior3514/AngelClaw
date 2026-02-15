"""ANGELGRID – OpenClaw AI Agent Adapter.

This adapter sits between an AI agent framework (OpenClaw, MoltBot, Claude Code,
or any tool-calling LLM agent) and the ANGELNODE policy engine.  It receives
tool-call metadata, converts it into an ANGELGRID Event, evaluates it via the
local /evaluate API, and returns an allow/block decision the agent can consume.

SECURITY NOTE: This is the zero-trust boundary for AI tool use.  Every tool
invocation from an AI agent must pass through this adapter before execution.
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Any, Optional

import httpx
from fastapi import APIRouter
from pydantic import BaseModel, Field

from shared.models.event import Event, EventCategory, Severity
from shared.models.policy import PolicyAction

logger = logging.getLogger("angelnode.ai_shield")

# The local ANGELNODE evaluation endpoint
EVALUATE_URL = os.environ.get("ANGELNODE_EVALUATE_URL", "http://127.0.0.1:8400/evaluate")

router = APIRouter(prefix="/ai/openclaw", tags=["AI Shield – OpenClaw"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ToolCallRequest(BaseModel):
    """Metadata about an AI agent's tool invocation.

    This is what the AI framework sends before executing a tool.
    """

    tool_name: str = Field(description="Name of the tool being invoked (e.g. 'bash', 'write_file')")
    arguments: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments the agent is passing to the tool",
    )
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context: agent name, session ID, conversation history hash, etc.",
    )
    agent_id: str = Field(
        default="unknown",
        description="Identifier of the ANGELNODE / host this request originates from",
    )
    agent_name: Optional[str] = Field(
        default=None,
        description="Human-readable name of the AI agent (e.g. 'OpenClaw-v2')",
    )


class ToolCallResponse(BaseModel):
    """Decision returned to the AI agent."""

    allowed: bool
    action: str = Field(description="Policy action: allow, block, alert, audit")
    reason: str
    risk_level: str = Field(
        default="none",
        description="Risk level: none, low, medium, high, critical",
    )
    correlation_id: str = Field(
        description="Unique ID for this evaluation — use for log correlation and debugging",
    )


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post("/evaluate_tool", response_model=ToolCallResponse)
async def evaluate_tool(request: ToolCallRequest):
    """Evaluate an AI agent's tool call against ANGELNODE policy.

    Converts the tool-call metadata into a standard ANGELGRID Event, forwards
    it to the local policy engine, and translates the result into a simple
    allow/block response the AI agent can act on.

    Every request is assigned a unique correlation_id that appears in:
    - the response JSON (for the calling agent),
    - the Event.details (for Cloud-side correlation),
    - the structured decision log (for forensic review / Wazuh).
    """
    # Generate a per-request correlation ID for end-to-end tracing
    correlation_id = str(uuid.uuid4())

    # Build a standard Event from the tool-call metadata
    # SECURITY: details are logged and matched against policy rules
    event = Event(
        agent_id=request.agent_id,
        category=EventCategory.AI_TOOL,
        type="tool_call",
        severity=_infer_severity(request.tool_name),
        source=request.agent_name or "ai_agent",
        details={
            "tool_name": request.tool_name,
            "arguments": request.arguments,
            "context": request.context,
            # Flag secret access if argument keys hint at credentials
            "accesses_secrets": _detects_secret_access(request.arguments),
            # Embed correlation_id so it flows into logs and Cloud events
            "correlation_id": correlation_id,
        },
    )

    # Forward to the local evaluation endpoint
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                EVALUATE_URL,
                json=event.model_dump(mode="json"),
            )
            resp.raise_for_status()
            result = resp.json()
    except httpx.HTTPError as exc:
        logger.error(
            "Failed to reach local evaluation engine (correlation_id=%s): %s",
            correlation_id, exc,
        )
        # SECURITY: fail-closed — if the engine is unreachable, block the action
        return ToolCallResponse(
            allowed=False,
            action="block",
            reason="Policy engine unreachable — fail-closed",
            risk_level="critical",
            correlation_id=correlation_id,
        )

    decision = result["decision"]
    action = decision["action"]

    return ToolCallResponse(
        allowed=action in (PolicyAction.ALLOW.value, PolicyAction.AUDIT.value),
        action=action,
        reason=decision["reason"],
        risk_level=decision.get("risk_level", "none"),
        correlation_id=correlation_id,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _infer_severity(tool_name: str) -> Severity:
    """Assign a base severity based on the tool name.

    Tools with system-level access get a higher default severity.
    """
    high_risk_tools = {"bash", "shell", "exec", "terminal", "sudo", "ssh"}
    medium_risk_tools = {"write_file", "delete_file", "http_request", "database_query"}

    name_lower = tool_name.lower()
    if name_lower in high_risk_tools:
        return Severity.HIGH
    if name_lower in medium_risk_tools:
        return Severity.WARN
    return Severity.INFO


def _detects_secret_access(arguments: dict[str, Any]) -> bool:
    """Heuristic: flag if argument keys or values suggest secret/credential access."""
    sensitive_patterns = {"password", "secret", "token", "api_key", "credential", "private_key"}
    for key in arguments:
        if any(pat in key.lower() for pat in sensitive_patterns):
            return True
    for val in arguments.values():
        if isinstance(val, str) and any(pat in val.lower() for pat in sensitive_patterns):
            return True
    return False
