"""AngelBot API Adapter — Defense-side mirror of OpenClaw Adapter.

Where the OpenClaw adapter evaluates tool calls for threats, the AngelBot
adapter provides active defense operations: scanning, hunting, posture
assessment, countermeasure deployment, and protection chain execution.

OpenClaw Adapter (offense detection):
  POST /ai/openclaw/evaluate_tool  →  "Is this tool call safe?"

AngelBot Adapter (active defense):
  POST /ai/angelbot/scan           →  "Scan this for threats & respond"
  POST /ai/angelbot/hunt           →  "Hunt threats across events"
  POST /ai/angelbot/assess         →  "What's our defense posture?"
  POST /ai/angelbot/respond        →  "Execute protection chain"
  POST /ai/angelbot/deploy         →  "Deploy a countermeasure"
  GET  /ai/angelbot/status         →  "AngelBot agent status"
  GET  /ai/angelbot/countermeasures →  "List available defenses"

Philosophy: The OpenClaw adapter is a shield (reactive).
The AngelBot adapter is a sword + shield (proactive + reactive).
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from angelnode.ai_shield.angelbot import (
    DefenseAction,
    angelbot,
)

logger = logging.getLogger("angelbot.adapter")

router = APIRouter(
    prefix="/ai/angelbot",
    tags=["AI Shield — AngelBot"],
)


# -----------------------------------------------------------------------
# Request / Response Models
# -----------------------------------------------------------------------


class ScanRequest(BaseModel):
    """Request to scan text for threats."""

    text: str = Field(
        description="Text to scan for threats",
    )
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context",
    )


class ScanResponse(BaseModel):
    """Scan result with countermeasures."""

    agent_id: str
    mode: str
    threats_detected: int
    countermeasures_triggered: list[dict[str, Any]]
    hunt_indicators: list[dict[str, Any]]
    verdict: str = Field(
        description="'clean' or 'threat'",
    )
    scanned_at: str


class HuntRequest(BaseModel):
    """Request to hunt threats across events."""

    events: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Events to hunt through",
    )
    scope: str = Field(
        default="full",
        description="Hunt scope: full, network, process, file",
    )


class HuntResponse(BaseModel):
    """Threat hunt results."""

    hunt_id: str
    threats_found: int
    indicators: list[dict[str, Any]]
    coverage: dict[str, bool]
    clean: bool
    hunted_at: str


class AssessRequest(BaseModel):
    """Request for posture assessment."""

    events: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    policies: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    agents: list[dict[str, Any]] = Field(
        default_factory=list,
    )


class AssessResponse(BaseModel):
    """Security posture assessment."""

    score: float
    grade: str
    strengths: list[str]
    weaknesses: list[str]
    recommendations: list[str]
    holy_trifecta_score: float
    fortress_mode: bool
    assessed_at: str


class RespondRequest(BaseModel):
    """Request to respond to a specific threat."""

    threat: dict[str, Any] = Field(
        description="Threat details",
    )


class RespondResponse(BaseModel):
    """Protection chain execution result."""

    threat_id: str
    stages_completed: list[str]
    actions_taken: list[dict[str, Any]]
    is_complete: bool
    progress: float
    confidence: float
    started_at: str


class DeployRequest(BaseModel):
    """Request to deploy a protection."""

    name: str = Field(description="Protection name")
    target: str = Field(description="Target to protect")
    action: str = Field(
        default="harden",
        description="Defense action",
    )


class DeployResponse(BaseModel):
    """Protection deployment result."""

    id: str
    name: str
    target: str
    action: str
    deployed_by: str
    deployed_at: str
    status: str


class CountermeasureInfo(BaseModel):
    """Info about an available countermeasure."""

    name: str
    targets: str
    description: str
    response_action: str
    severity: str


# -----------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------


@router.post("/scan", response_model=ScanResponse)
async def scan_for_threats(request: ScanRequest):
    """Scan text for threats and deploy countermeasures.

    AngelBot scans the input for evil AGI patterns, prompt injection,
    data exfiltration, and all known attack signatures.  For each
    threat found, the corresponding countermeasure is activated.
    """
    result = angelbot.scan(request.text)
    return ScanResponse(**result)


@router.post("/hunt", response_model=HuntResponse)
async def hunt_threats_endpoint(request: HuntRequest):
    """Active threat hunt across events.

    Unlike passive detection, this actively searches for indicators
    of compromise using AngelBot's hunt signatures — hidden processes,
    rogue listeners, credential harvesters, webshells, rootkits, and
    reverse tunnels.
    """
    result = angelbot.hunt(
        events=request.events,
        scope=request.scope,
    )
    return HuntResponse(
        hunt_id=result.hunt_id,
        threats_found=result.threats_found,
        indicators=result.indicators,
        coverage=result.coverage,
        clean=result.clean,
        hunted_at=result.hunted_at,
    )


@router.post("/assess", response_model=AssessResponse)
async def assess_posture_endpoint(request: AssessRequest):
    """Assess security posture.

    Evaluates the Holy Trifecta, policy coverage, agent health,
    block effectiveness, and secret protection to produce an
    overall security grade (A-F) and actionable recommendations.
    """
    result = angelbot.assess(
        events=request.events,
        policies=request.policies,
        agents=request.agents,
    )
    return AssessResponse(
        score=result.score,
        grade=result.grade,
        strengths=result.strengths,
        weaknesses=result.weaknesses,
        recommendations=result.recommendations,
        holy_trifecta_score=result.holy_trifecta.score,
        fortress_mode=result.holy_trifecta.fortress_mode,
        assessed_at=result.assessed_at,
    )


@router.post("/respond", response_model=RespondResponse)
async def respond_to_threat(request: RespondRequest):
    """Execute a full protection chain against a threat.

    Runs the 6-stage protection chain:
    Detect → Analyze → Contain → Remediate → Harden → Verify

    The depth of response depends on AngelBot's operating mode:
    - Sentinel: Detect + Analyze only
    - Guardian: + Contain + Harden + Verify
    - Archangel: Full chain including Remediate
    """
    chain = angelbot.respond_to_threat(request.threat)
    return RespondResponse(
        threat_id=chain.threat_id,
        stages_completed=[s.value for s in chain.stages_completed],
        actions_taken=chain.actions_taken,
        is_complete=chain.is_complete,
        progress=chain.progress,
        confidence=chain.confidence,
        started_at=chain.started_at,
    )


@router.post("/deploy", response_model=DeployResponse)
async def deploy_protection(request: DeployRequest):
    """Deploy a specific protection to a target.

    Protections can be deployed to agents, networks, or services
    to harden defenses proactively.
    """
    try:
        action = DefenseAction(request.action)
    except ValueError:
        action = DefenseAction.HARDEN

    result = angelbot.deploy_protection(
        name=request.name,
        target=request.target,
        action=action,
    )
    return DeployResponse(**result)


@router.get("/status")
async def get_status():
    """Get AngelBot agent status.

    Returns version, mode, statistics, and available capabilities.
    """
    return angelbot.status()


@router.get("/countermeasures")
async def list_countermeasures():
    """List all available countermeasures.

    Each countermeasure is the angel-side mirror of a specific
    evil AGI attack pattern.
    """
    from angelnode.ai_shield.angelbot import _COUNTERMEASURES

    return {
        "total": len(_COUNTERMEASURES),
        "countermeasures": [
            CountermeasureInfo(
                name=cm.name,
                targets=cm.targets,
                description=cm.description,
                response_action=cm.response_action.value,
                severity=cm.severity,
            ).model_dump()
            for cm in _COUNTERMEASURES
        ],
    }


@router.get("/action-log")
async def get_action_log():
    """Get AngelBot's action log.

    Every action AngelBot takes is logged with full audit trail.
    """
    log = angelbot.get_action_log()
    return {
        "total": len(log),
        "actions": log[-100:],  # Last 100 actions
    }
