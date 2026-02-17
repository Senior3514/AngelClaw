"""ANGELGRID – AgentNode model.

Represents a registered ANGELNODE instance: a lightweight protection agent
running on an endpoint, server, or AI-agent host.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class AgentType(str, Enum):
    """Deployment type of the agent."""

    ENDPOINT = "endpoint"  # Workstation / developer machine
    SERVER = "server"  # Production server
    AI_HOST = "ai_host"  # Host running AI agents (OpenClaw, MoltBot, etc.)
    CONTAINER = "container"  # Ephemeral container sidecar
    AGENTLESS = "agentless"  # Cloud connector (no resident process)


class AgentStatus(str, Enum):
    """Lifecycle status of the agent."""

    PENDING = "pending"  # Registered but not yet reporting
    ACTIVE = "active"  # Healthy and reporting
    DEGRADED = "degraded"  # Reporting but with errors
    OFFLINE = "offline"  # Not reporting within expected interval
    DECOMMISSIONED = "decommissioned"


class AgentNode(BaseModel):
    """A registered ANGELNODE instance."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: AgentType
    os: str = Field(description="Operating system: linux, windows, darwin")
    hostname: str
    tags: list[str] = Field(default_factory=list)
    policy_version: str = Field(
        default="0",
        description="Version hash of the currently loaded PolicySet",
    )
    status: AgentStatus = AgentStatus.PENDING
    registered_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    last_seen_at: Optional[datetime] = None
    version: str = Field(
        default="0.1.0",
        description="ANGELNODE software version",
    )


class AgentRegistrationRequest(BaseModel):
    """Payload sent by an ANGELNODE when registering with ANGELGRID Cloud."""

    type: AgentType
    os: str
    hostname: str
    tags: list[str] = Field(default_factory=list)
    version: str = "0.1.0"
