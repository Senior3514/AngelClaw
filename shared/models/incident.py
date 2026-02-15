"""ANGELGRID – Incident model.

An Incident is a correlated group of Events that together represent a
confirmed or suspected security issue.  Incidents are created by the
policy engine when block/alert actions fire, and are escalated to
ANGELGRID Cloud for triage and response.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from .event import Event, Severity


class IncidentStatus(str, Enum):
    """Lifecycle status of an incident."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class IncidentClassification(str, Enum):
    """High-level threat classification."""

    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    MISCONFIGURATION = "misconfiguration"
    MALICIOUS_TOOL_USE = "malicious_tool_use"
    POLICY_VIOLATION = "policy_violation"
    ANOMALY = "anomaly"
    UNKNOWN = "unknown"


class Incident(BaseModel):
    """A security incident composed of one or more correlated Events."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    events: list[Event] = Field(
        min_length=1,
        description="Events that constitute this incident",
    )
    status: IncidentStatus = IncidentStatus.OPEN
    classification: IncidentClassification = IncidentClassification.UNKNOWN
    severity: Severity = Severity.WARN
    recommended_actions: list[str] = Field(
        default_factory=list,
        description="Human-readable recommended response actions",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    summary: str = ""
