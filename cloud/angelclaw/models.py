"""AngelClaw AGI Guardian – API Models.

Pydantic schemas for the unified AngelClaw API endpoints.
Lightweight: no extra dependencies beyond Pydantic.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Chat
# ---------------------------------------------------------------------------


class AngelClawChatRequest(BaseModel):
    tenant_id: str = Field(alias="tenantId", default="dev-tenant")
    prompt: str = Field(min_length=1, max_length=8192)
    mode: Optional[str] = Field(default=None, description="Optional hint: status, scan, help, etc.")
    preferences: Optional[dict[str, Any]] = None

    model_config = {"populate_by_name": True}


class AngelClawChatResponse(BaseModel):
    answer: str
    actions: list[dict[str, Any]] = Field(default_factory=list)
    effects: list[dict[str, Any]] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list, alias="refs")
    meta: dict[str, Any] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# Activity
# ---------------------------------------------------------------------------


class ActivityEntry(BaseModel):
    id: str
    timestamp: str
    category: str
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Daemon Status
# ---------------------------------------------------------------------------


class DaemonStatus(BaseModel):
    running: bool = False
    cycles_completed: int = 0
    last_scan_summary: str = ""
    activity_count: int = 0


# ---------------------------------------------------------------------------
# Shield
# ---------------------------------------------------------------------------


class ShieldIndicator(BaseModel):
    category: str
    severity: str
    title: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)


class ShieldAssessment(BaseModel):
    overall_risk: str = "info"
    lethal_trifecta_score: float = 0.0
    checks_run: int = 0
    indicators: list[ShieldIndicator] = Field(default_factory=list)
    skills_status: dict[str, Any] = Field(default_factory=dict)
    scanned_at: str = ""
