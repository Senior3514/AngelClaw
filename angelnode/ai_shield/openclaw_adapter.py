"""ANGELGRID – OpenClaw AI Agent Adapter.

This adapter sits between an AI agent framework (OpenClaw, MoltBot, Claude Code,
or any tool-calling LLM agent) and the ANGELNODE policy engine.  It receives
tool-call metadata, converts it into an ANGELGRID Event, evaluates it via the
local /evaluate API, and returns an allow/block decision the agent can consume.

SECURITY NOTE: This is the zero-trust boundary for AI tool use.  Every tool
invocation from an AI agent must pass through this adapter before execution.

SECRET PROTECTION: The adapter scans all tool arguments for secret patterns
and sensitive file paths.  If secrets are detected, the event is flagged with
higher risk and the `accesses_secrets` detail is set to True, which triggers
the block-ai-tool-secrets-access policy rule.

Philosophy: Guardian Angel — AI agents can use any tool they want; we just
make sure secrets never get exposed or exfiltrated in the process.
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
from shared.security.secret_scanner import (
    contains_secret,
    is_sensitive_key,
    is_sensitive_path,
    redact_dict,
)

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

    SECRET PROTECTION: Arguments are scanned for secret patterns, sensitive
    key names, and sensitive file paths.  If any are found, the event is
    flagged with accesses_secrets=True and elevated severity.

    Every request is assigned a unique correlation_id that appears in:
    - the response JSON (for the calling agent),
    - the Event.details (for Cloud-side correlation),
    - the structured decision log (for forensic review / Wazuh).
    """
    # Generate a per-request correlation ID for end-to-end tracing
    correlation_id = str(uuid.uuid4())

    # Detect secret access across all arguments
    secret_detected = _detects_secret_access(request.tool_name, request.arguments)

    # Build a standard Event from the tool-call metadata
    # SECURITY: details are logged and matched against policy rules
    event = Event(
        agent_id=request.agent_id,
        category=EventCategory.AI_TOOL,
        type="tool_call",
        severity=_infer_severity(request.tool_name, secret_detected),
        source=request.agent_name or "ai_agent",
        details={
            "tool_name": request.tool_name,
            # SECURITY: redact secrets from arguments before logging
            "arguments": redact_dict(request.arguments),
            "context": redact_dict(request.context),
            "accesses_secrets": secret_detected,
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
            correlation_id,
            exc,
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
    allowed = action in (PolicyAction.ALLOW.value, PolicyAction.AUDIT.value)

    # Human-friendly decision log
    if not allowed:
        logger.warning(
            "[AI SHIELD BLOCK] tool=%s agent=%s reason='%s' risk=%s correlation=%s",
            request.tool_name,
            request.agent_id[:8],
            decision["reason"],
            decision.get("risk_level", "none"),
            correlation_id[:8],
        )
    elif secret_detected:
        logger.warning(
            "[AI SHIELD SECRET] Secrets detected in tool=%s "
            "from agent=%s — action=%s correlation=%s",
            request.tool_name,
            request.agent_id[:8],
            action,
            correlation_id[:8],
        )
    else:
        logger.info(
            "[AI SHIELD] tool=%s agent=%s action=%s risk=%s",
            request.tool_name,
            request.agent_id[:8],
            action,
            decision.get("risk_level", "none"),
        )

    return ToolCallResponse(
        allowed=allowed,
        action=action,
        reason=decision["reason"],
        risk_level=decision.get("risk_level", "none"),
        correlation_id=correlation_id,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _infer_severity(tool_name: str, secret_detected: bool) -> Severity:
    """Assign a base severity based on the tool name and secret access.

    If secrets are detected, severity is always escalated to CRITICAL.
    """
    if secret_detected:
        return Severity.CRITICAL

    high_risk_tools = {"bash", "shell", "exec", "terminal", "sudo", "ssh"}
    medium_risk_tools = {"write_file", "delete_file", "http_request", "database_query"}

    name_lower = tool_name.lower()
    if name_lower in high_risk_tools:
        return Severity.HIGH
    if name_lower in medium_risk_tools:
        return Severity.WARN
    return Severity.INFO


def _detects_secret_access(tool_name: str, arguments: dict[str, Any]) -> bool:
    """Comprehensive check for secret/credential access in tool arguments.

    Checks:
    1. Argument key names matching sensitive patterns (password, token, etc.)
    2. Argument string values containing secret patterns (API keys, JWTs, etc.)
    3. File path arguments pointing to sensitive files (.env, .ssh/*, etc.)
    """
    # Check argument keys for sensitive names
    for key in arguments:
        if is_sensitive_key(key):
            return True

    # Check argument values
    for key, val in arguments.items():
        if isinstance(val, str):
            # Check for secret values (API keys, tokens, etc.)
            if contains_secret(val):
                return True
            # Check for sensitive file paths
            if is_sensitive_path(val):
                return True
        elif isinstance(val, dict):
            # Recurse into nested dicts
            if _detects_secret_access(tool_name, val):
                return True

    return False
