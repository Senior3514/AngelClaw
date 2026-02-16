"""ANGELGRID AI – Response models for the security assistant.

These are the structured data objects returned by assistant functions.
They are designed for programmatic consumption by the Cloud console
frontend and for serialization into the chat-style UX.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class ClassificationCount(BaseModel):
    """Count of incidents by classification."""

    classification: str
    count: int


class SeverityCount(BaseModel):
    """Count of incidents by severity."""

    severity: str
    count: int


class AffectedAgent(BaseModel):
    """An agent with a notable number of recent incidents."""

    agent_id: str
    hostname: str
    incident_count: int


class IncidentSummary(BaseModel):
    """Structured summary of recent incidents for a tenant."""

    tenant_id: str
    period_start: datetime
    period_end: datetime
    total_incidents: int
    by_classification: list[ClassificationCount] = Field(default_factory=list)
    by_severity: list[SeverityCount] = Field(default_factory=list)
    top_affected_agents: list[AffectedAgent] = Field(default_factory=list)
    recommended_focus: list[str] = Field(
        default_factory=list,
        description="Human-readable recommendations based on incident patterns",
    )


class ProposedRule(BaseModel):
    """A single policy rule proposed by the assistant."""

    description: str
    match_summary: str = Field(
        description="Human-readable summary of what this rule would match",
    )
    action: str
    risk_level: str
    rationale: str = Field(
        description="Why the assistant is proposing this rule",
    )


class ProposedPolicyChanges(BaseModel):
    """A set of proposed policy changes.

    SECURITY NOTE: These are proposals only.  They MUST NOT be applied
    without explicit human approval.  The approval event must be logged
    as an Incident/ChangeEvent.
    """

    agent_group_id: str
    current_policy_version: Optional[str] = None
    proposed_rules: list[ProposedRule] = Field(default_factory=list)
    analysis_summary: str = Field(
        default="",
        description="Overall analysis of the agent group's security posture",
    )
    requires_approval: bool = Field(
        default=True,
        description="Always True — assistant proposals must be approved",
    )


class ThreatPrediction(BaseModel):
    """A predicted threat vector based on deterministic pattern rules."""

    vector_name: str = Field(description="e.g. 'data_exfiltration', 'lateral_movement'")
    confidence: float = Field(ge=0.0, le=1.0, description="0.0–1.0 confidence score")
    rationale: str
    contributing_categories: list[str] = Field(default_factory=list)
    event_count: int = 0
