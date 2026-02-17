"""ANGELGRID – Policy models.

Policies are the core enforcement mechanism.  A PolicySet is a versioned
collection of PolicyRules that an ANGELNODE loads and evaluates locally.
Rules are matched against incoming Events to produce allow/block/alert decisions.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class PolicyAction(str, Enum):
    """Action to take when a rule matches an event."""

    ALLOW = "allow"
    BLOCK = "block"
    ALERT = "alert"  # Allow but raise an alert / incident
    AUDIT = "audit"  # Allow and log (no alert)


class RiskLevel(str, Enum):
    """Risk classification assigned to a rule."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyMatch(BaseModel):
    """Conditions that determine whether a rule applies to an event.

    All specified fields must match (logical AND).  Unset fields are wildcards.
    """

    categories: Optional[list[str]] = Field(
        default=None,
        description="Event categories this rule applies to (OR within list)",
    )
    types: Optional[list[str]] = Field(
        default=None,
        description="Event sub-types this rule applies to (OR within list)",
    )
    source_pattern: Optional[str] = Field(
        default=None,
        description="Regex pattern matched against event.source",
    )
    detail_conditions: Optional[dict[str, Any]] = Field(
        default=None,
        description="Key-value conditions matched against event.details (exact match)",
    )


class PolicyRule(BaseModel):
    """A single policy rule within a PolicySet."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scope: str = Field(
        default="global",
        description="Scope: 'global', 'agent:<id>', 'tag:<tag>', etc.",
    )
    match: PolicyMatch
    action: PolicyAction
    risk_level: RiskLevel = RiskLevel.MEDIUM
    description: str = ""
    enabled: bool = True


class PolicySet(BaseModel):
    """A versioned collection of PolicyRules distributed to ANGELNODEs."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "default"
    rules: list[PolicyRule] = Field(default_factory=list)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    description: str = ""

    @property
    def version(self) -> str:
        """Deterministic version hash derived from rule content."""
        content = json.dumps(
            [r.model_dump(mode="json") for r in self.rules],
            sort_keys=True,
        )
        return hashlib.sha256(content.encode()).hexdigest()[:12]
