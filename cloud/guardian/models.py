"""AngelClaw – ANGEL AGI Guardian data models.

Defines the core types used across the Orchestrator, sub-agents,
detection layer, and response engine.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class IncidentState(str, Enum):
    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    RESPONDING = "responding"
    CONTAINED = "contained"      # V2.2 — threat contained, monitoring
    RESOLVED = "resolved"
    ESCALATED = "escalated"


class AgentType(str, Enum):
    # V1 core agents
    WARDEN = "warden"
    RESPONSE = "response"
    FORENSIC = "forensic"
    AUDIT = "audit"
    # V2 specialized wardens (Angel Legion)
    NETWORK = "network"
    SECRETS = "secrets"
    TOOLCHAIN = "toolchain"
    BEHAVIOR = "behavior"
    TIMELINE = "timeline"
    BROWSER = "browser"
    # V2.2 — new agent types
    CLOUD = "cloud"
    IDENTITY = "identity"


class AgentStatus(str, Enum):
    IDLE = "idle"
    BUSY = "busy"
    ERROR = "error"
    STOPPED = "stopped"


class Permission(str, Enum):
    READ_EVENTS = "read_events"
    READ_AGENTS = "read_agents"
    READ_POLICIES = "read_policies"
    READ_LOGS = "read_logs"
    WRITE_AGENT_STATE = "write_agent_state"
    WRITE_POLICIES = "write_policies"
    CALL_EXTERNAL = "call_external"
    EXECUTE_RESPONSE = "execute_response"
    # V2 specialized permissions
    READ_NETWORK = "read_network"
    READ_SECRETS = "read_secrets"
    READ_TOOLS = "read_tools"
    READ_BROWSER = "read_browser"
    READ_TIMELINE = "read_timeline"
    # V2.2 permissions
    READ_CLOUD = "read_cloud"
    READ_IDENTITY = "read_identity"
    CONTAIN_INCIDENT = "contain_incident"


class SerenityLevel(str, Enum):
    """AngelClaw-themed risk levels (Serenity Scale)."""

    SERENE = "serene"        # info
    WHISPER = "whisper"      # low
    MURMUR = "murmur"        # medium
    DISTURBED = "disturbed"  # high
    STORM = "storm"          # critical


# Bidirectional severity <-> serenity mapping
SERENITY_MAP: dict[str, SerenityLevel] = {
    "info": SerenityLevel.SERENE,
    "low": SerenityLevel.WHISPER,
    "medium": SerenityLevel.MURMUR,
    "high": SerenityLevel.DISTURBED,
    "critical": SerenityLevel.STORM,
}

SEVERITY_MAP: dict[SerenityLevel, str] = {v: k for k, v in SERENITY_MAP.items()}


class MitreTactic(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"           # V2.2
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"                        # V2.2
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"                      # V2.2
    COMMAND_AND_CONTROL = "command_and_control"     # V2.2
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


# ---------------------------------------------------------------------------
# Detection models
# ---------------------------------------------------------------------------


class ThreatIndicator(BaseModel):
    """Output of the Warden detection layer."""

    indicator_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    indicator_type: str  # pattern_match, anomaly, correlation
    pattern_name: str = ""
    severity: str  # critical, high, medium, low
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    related_event_ids: list[str] = Field(default_factory=list)
    related_agent_ids: list[str] = Field(default_factory=list)
    suggested_playbook: str = ""
    mitre_tactic: str | None = None
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)


class AnomalyScore(BaseModel):
    """Per-agent behavioral anomaly score."""

    agent_id: str
    score: float = Field(ge=0.0, le=1.0)
    baseline_event_rate: float = 0.0
    current_event_rate: float = 0.0
    category_deviation: dict[str, float] = Field(default_factory=dict)
    top_anomalous_types: list[str] = Field(default_factory=list)
    scored_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CorrelationChain(BaseModel):
    """A sequence of related events forming a potential kill chain."""

    chain_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_ids: list[str] = Field(default_factory=list)
    agent_ids: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    severity: str = "medium"
    confidence: float = 0.5
    description: str = ""
    time_span_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Incident lifecycle
# ---------------------------------------------------------------------------


class Incident(BaseModel):
    """A tracked security incident managed by the Orchestrator."""

    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    state: IncidentState = IncidentState.NEW
    severity: str = "medium"
    title: str = ""
    description: str = ""
    trigger_indicator_id: str = ""
    related_event_ids: list[str] = Field(default_factory=list)
    related_agent_ids: list[str] = Field(default_factory=list)
    playbook_name: str = ""
    response_results: list[ResponseResult] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: datetime | None = None
    mitre_tactics: list[str] = Field(default_factory=list)
    assigned_to: str = ""  # sub-agent id
    requires_approval: bool = False
    approved_by: str = ""
    notes: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Response / Playbook models
# ---------------------------------------------------------------------------


class PlaybookStep(BaseModel):
    """A single step in a response playbook."""

    action: str
    target: str = ""
    description: str = ""
    reversible: bool = True
    timeout_seconds: int = 300
    params: dict[str, Any] = Field(default_factory=dict)


class Playbook(BaseModel):
    """A response playbook definition."""

    name: str
    description: str = ""
    trigger_patterns: list[str] = Field(default_factory=list)
    severity_threshold: str = "high"
    auto_respond: bool = False
    steps: list[PlaybookStep] = Field(default_factory=list)
    rollback_steps: list[PlaybookStep] = Field(default_factory=list)


class ResponseResult(BaseModel):
    """Result of executing a single response action."""

    action: str
    target: str = ""
    success: bool = True
    message: str = ""
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    rolled_back: bool = False
    dry_run: bool = False
    before_state: dict[str, Any] = Field(default_factory=dict)
    after_state: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Sub-agent task models
# ---------------------------------------------------------------------------


class AgentTask(BaseModel):
    """A task dispatched by the Orchestrator to a sub-agent."""

    task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str = ""
    task_type: str  # detect, respond, investigate, audit
    priority: int = 5  # 1=highest, 10=lowest
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    timeout_seconds: int = 300


class AgentResult(BaseModel):
    """Result returned by a sub-agent after handling a task."""

    task_id: str
    agent_id: str
    agent_type: str
    success: bool = True
    result_data: dict[str, Any] = Field(default_factory=dict)
    error: str = ""
    completed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: float = 0.0


# ---------------------------------------------------------------------------
# Forensic models
# ---------------------------------------------------------------------------


class ForensicEvidence(BaseModel):
    """A piece of evidence collected during forensic investigation."""

    evidence_type: str  # event, decision, policy_hit, state_snapshot
    timestamp: datetime
    data: dict[str, Any] = Field(default_factory=dict)
    source: str = ""


class ForensicReport(BaseModel):
    """Output of a forensic investigation."""

    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str
    agent_id: str = ""
    timeline: list[ForensicEvidence] = Field(default_factory=list)
    kill_chain: list[str] = Field(default_factory=list)
    root_cause: str = ""
    impact_assessment: str = ""
    recommendations: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Audit models
# ---------------------------------------------------------------------------


class AuditDiscrepancy(BaseModel):
    """A mismatch between intended and actual agent behavior."""

    agent_id: str
    expected_action: str
    actual_action: str
    event_id: str = ""
    severity: str = "medium"
    description: str = ""


class AuditReport(BaseModel):
    """Output of the audit agent's verification."""

    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    period_start: datetime
    period_end: datetime
    agents_audited: int = 0
    discrepancies: list[AuditDiscrepancy] = Field(default_factory=list)
    clean: bool = True
    summary: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
