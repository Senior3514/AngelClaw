"""ANGELGRID – Event model.

An Event is the atomic unit of telemetry in ANGELGRID.  Every action observed
by an ANGELNODE — shell command, file access, network call, AI tool invocation —
is captured as an Event and evaluated against the active PolicySet.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class EventCategory(str, Enum):
    """Top-level classification of an event."""

    SHELL = "shell"            # Shell / process execution
    FILE = "file"              # File system access
    NETWORK = "network"        # Outbound / inbound network activity
    DB = "db"                  # Database query or connection
    AI_TOOL = "ai_tool"        # AI agent tool invocation
    AUTH = "auth"              # Authentication / privilege change
    CONFIG = "config"          # Configuration modification
    SYSTEM = "system"          # OS-level / kernel event


class Severity(str, Enum):
    """Risk severity assigned to an event or policy match."""

    INFO = "info"
    LOW = "low"
    WARN = "warn"
    HIGH = "high"
    CRITICAL = "critical"


class Event(BaseModel):
    """A single security-relevant event captured by ANGELNODE."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = Field(description="ID of the ANGELNODE that generated this event")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    category: EventCategory
    type: str = Field(
        description="Sub-type within category, e.g. 'exec', 'read', 'connect', 'tool_call'",
    )
    severity: Severity = Severity.INFO
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary structured payload — contents depend on category/type",
    )
    source: Optional[str] = Field(
        default=None,
        description="Origin identifier: process name, AI agent name, user, etc.",
    )


class EventBatch(BaseModel):
    """A batch of events submitted by an ANGELNODE to ANGELGRID Cloud."""

    agent_id: str
    events: list[Event]
