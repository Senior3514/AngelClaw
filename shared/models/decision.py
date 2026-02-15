"""ANGELGRID – Decision model.

Represents the output of the policy engine after evaluating an Event
against the active PolicySet.  Returned to callers of the /evaluate API.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from .policy import PolicyAction, RiskLevel


class Decision(BaseModel):
    """Result of evaluating an event against the policy engine."""

    action: PolicyAction
    reason: str
    matched_rule_id: Optional[str] = Field(
        default=None,
        description="ID of the PolicyRule that triggered this decision",
    )
    risk_level: RiskLevel = RiskLevel.NONE


class EvaluationResponse(BaseModel):
    """Top-level response wrapper for the /evaluate endpoint."""

    event_id: str
    decision: Decision
