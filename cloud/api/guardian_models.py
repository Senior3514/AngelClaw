"""AngelClaw Cloud – Pydantic schemas for Guardian V3 APIs.

Request/response models for guardian reports, alerts, chat, event context,
timeline, and change tracking.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Guardian Reports
# ---------------------------------------------------------------------------


class GuardianReport(BaseModel):
    id: str
    tenant_id: str
    timestamp: datetime
    agents_total: int = 0
    agents_active: int = 0
    agents_degraded: int = 0
    agents_offline: int = 0
    incidents_total: int = 0
    incidents_by_severity: dict[str, int] = Field(default_factory=dict)
    policy_changes_since_last: int = 0
    anomalies: list[str] = Field(default_factory=list)
    summary: str = ""


# ---------------------------------------------------------------------------
# Guardian Alerts
# ---------------------------------------------------------------------------


class GuardianAlert(BaseModel):
    id: str
    tenant_id: str
    alert_type: str
    title: str
    severity: str
    details: dict[str, Any] = Field(default_factory=dict)
    related_event_ids: list[str] = Field(default_factory=list)
    related_agent_ids: list[str] = Field(default_factory=list)
    created_at: datetime


# ---------------------------------------------------------------------------
# Guardian Chat
# ---------------------------------------------------------------------------


class ActionSuggestion(BaseModel):
    """A suggested action the user can take. Never auto-applied."""

    action_type: str = Field(description="e.g. 'propose_rule', 'review_agent', 'check_event'")
    title: str
    description: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class ChatRequest(BaseModel):
    tenant_id: str = Field(alias="tenantId", default="dev-tenant")
    prompt: str = Field(min_length=1, max_length=4096)
    context: Optional[dict[str, Any]] = None

    model_config = {"populate_by_name": True}


class ChatResponse(BaseModel):
    answer: str
    actions: list[ActionSuggestion] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    intent: str = "unknown"


# ---------------------------------------------------------------------------
# Event Context
# ---------------------------------------------------------------------------


class EvaluationResult(BaseModel):
    """Policy evaluation result for an event."""

    action: str = Field(description="ALLOW, BLOCK, ALERT, or AUDIT")
    reason: str = ""
    matched_rule_id: Optional[str] = None
    risk_level: str = "unknown"


class EventContext(BaseModel):
    event_id: str
    category: str
    type: str
    timestamp: datetime
    severity: str
    source: Optional[str] = None
    details: dict[str, Any] = Field(default_factory=dict)
    explanation: str = ""
    evaluation: Optional[EvaluationResult] = None
    agent_decision_history: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Last N decisions for the same agent",
    )
    history_window: list[dict[str, Any]] = Field(default_factory=list)
    related_ai_traffic: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


class TimelineEntry(BaseModel):
    timestamp: datetime
    entry_type: str = Field(description="event, policy_change, session_start, ai_tool_call")
    summary: str
    severity: Optional[str] = None
    details: dict[str, Any] = Field(default_factory=dict)


class AgentTimeline(BaseModel):
    agent_id: str
    hours: int
    entries: list[TimelineEntry] = Field(default_factory=list)
    total_events: int = 0


# ---------------------------------------------------------------------------
# Guardian Changes
# ---------------------------------------------------------------------------


class GuardianChange(BaseModel):
    id: str
    tenant_id: str
    change_type: str
    description: str = ""
    before_snapshot: Optional[str] = None
    after_snapshot: Optional[str] = None
    changed_by: str = "system"
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
