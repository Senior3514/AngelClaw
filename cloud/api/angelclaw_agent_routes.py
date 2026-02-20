"""AngelClaw Agent — Cloud API Routes.

Cloud-side endpoints for the AngelClaw autonomous defense agent.
These complement the local AngelNode AngelClaw adapter by providing
fleet-wide threat hunting, posture assessment, and countermeasure
orchestration across all registered agents.

OpenClaw (evil)  →  AngelClaw (angel)
Attack fleet     →  Defense fleet
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Header
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/api/v1/angelclaw-agent",
    tags=["AngelClaw Agent"],
)


# -----------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------


class FleetScanRequest(BaseModel):
    """Scan text across the entire fleet's context."""

    text: str = Field(description="Text to scan")


class FleetHuntRequest(BaseModel):
    """Fleet-wide threat hunt."""

    scope: str = Field(
        default="full",
        description="Hunt scope: full, network, process, file",
    )
    max_events: int = Field(default=500, ge=1, le=5000)


class FleetAssessRequest(BaseModel):
    """Fleet-wide posture assessment."""

    include_agents: bool = Field(default=True)


class ThreatResponseRequest(BaseModel):
    """Respond to a specific threat."""

    threat_id: str = Field(default="")
    title: str = Field(default="unknown threat")
    severity: str = Field(default="high")
    source_agent: str = Field(default="")


class DeployCountermeasureRequest(BaseModel):
    """Deploy a countermeasure fleet-wide."""

    name: str = Field(description="Countermeasure name")
    target: str = Field(
        default="fleet",
        description="Target: fleet, agent ID, or network segment",
    )
    action: str = Field(default="harden")


# -----------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------


@router.post("/scan")
def angelclaw_agent_scan(
    req: FleetScanRequest,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Scan text using AngelClaw's countermeasure engine."""
    from angelnode.ai_shield.angelbot import (
        hunt_threats,
        run_countermeasures,
    )

    countermeasures = run_countermeasures(req.text)
    hunt = hunt_threats(req.text)

    triggered = [r for r in countermeasures if r.triggered]
    return {
        "tenant_id": tenant_id,
        "threats_detected": len(triggered) + hunt.threats_found,
        "countermeasures": [
            {
                "name": r.countermeasure,
                "action": r.action.value,
                "severity": r.severity,
                "targets": r.targets,
                "response": r.response,
                "evidence": r.evidence,
            }
            for r in triggered
        ],
        "hunt_indicators": hunt.indicators,
        "verdict": "clean" if not triggered else "threat",
    }


@router.post("/hunt")
def angelclaw_agent_hunt(
    req: FleetHuntRequest,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Run fleet-wide threat hunt across recent events."""
    from angelnode.ai_shield.angelbot import hunt_threats
    from cloud.db.models import EventRow
    from cloud.db.session import get_db

    db = next(get_db())
    try:
        rows = (
            db.query(EventRow)
            .order_by(EventRow.timestamp.desc())
            .limit(req.max_events)
            .all()
        )
        events = [
            {
                "category": r.category or "",
                "type": r.type or "",
                "details": {
                    "command": r.details or "",
                },
            }
            for r in rows
        ]
    finally:
        db.close()

    combined_text = " ".join(
        str(e.get("details", {})) for e in events
    )
    result = hunt_threats(combined_text, events)

    return {
        "tenant_id": tenant_id,
        "hunt_id": result.hunt_id,
        "events_scanned": len(events),
        "threats_found": result.threats_found,
        "indicators": result.indicators,
        "coverage": result.coverage,
        "clean": result.clean,
        "hunted_at": result.hunted_at,
    }


@router.post("/assess")
def angelclaw_agent_assess(
    req: FleetAssessRequest,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Assess fleet-wide security posture."""
    from angelnode.ai_shield.angelbot import assess_posture
    from cloud.db.models import (
        AgentNodeRow,
        EventRow,
        PolicySnapshotRow,
    )
    from cloud.db.session import get_db

    db = next(get_db())
    try:
        event_rows = (
            db.query(EventRow)
            .order_by(EventRow.timestamp.desc())
            .limit(200)
            .all()
        )
        events = [
            {
                "category": r.category or "",
                "type": r.type or "",
                "details": {},
                "decision": {"action": "audit"},
            }
            for r in event_rows
        ]

        # Get policies
        snapshot = (
            db.query(PolicySnapshotRow)
            .order_by(PolicySnapshotRow.created_at.desc())
            .first()
        )
        policies: list[dict[str, Any]] = []
        if snapshot and snapshot.rules_json:
            import json

            try:
                rules = json.loads(snapshot.rules_json)
                if isinstance(rules, list):
                    policies = rules
            except (json.JSONDecodeError, TypeError):
                pass

        # Get agents
        agents: list[dict[str, Any]] = []
        if req.include_agents:
            try:
                agent_rows = db.query(AgentNodeRow).all()
                agents = [
                    {
                        "agent_id": a.agent_id,
                        "health": getattr(a, "health", "unknown")
                        or "unknown",
                    }
                    for a in agent_rows
                ]
            except Exception:
                agents = []
    finally:
        db.close()

    result = assess_posture(events, policies, agents)

    return {
        "tenant_id": tenant_id,
        "score": result.score,
        "grade": result.grade,
        "strengths": result.strengths,
        "weaknesses": result.weaknesses,
        "recommendations": result.recommendations,
        "holy_trifecta": {
            "score": result.holy_trifecta.score,
            "fortress_mode": result.holy_trifecta.fortress_mode,
            "data_sovereign": (
                result.holy_trifecta.data_sovereign
            ),
            "trust_verified": (
                result.holy_trifecta.trust_verified
            ),
            "isolation_enforced": (
                result.holy_trifecta.isolation_enforced
            ),
            "evidence": result.holy_trifecta.evidence,
        },
        "assessed_at": result.assessed_at,
    }


@router.post("/respond")
def angelclaw_agent_respond(
    req: ThreatResponseRequest,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Execute protection chain against a threat."""
    from angelnode.ai_shield.angelbot import AgentMode, AngelBot

    agent = AngelBot(
        agent_id=f"angelclaw-{tenant_id[:8]}",
        mode=AgentMode.GUARDIAN,
        tenant_id=tenant_id,
    )

    chain = agent.respond_to_threat({
        "id": req.threat_id or "auto",
        "title": req.title,
        "severity": req.severity,
        "source_agent": req.source_agent,
    })

    return {
        "tenant_id": tenant_id,
        "threat_id": chain.threat_id,
        "stages_completed": [
            s.value for s in chain.stages_completed
        ],
        "actions_taken": chain.actions_taken,
        "is_complete": chain.is_complete,
        "progress": chain.progress,
        "confidence": chain.confidence,
    }


@router.post("/deploy")
def angelclaw_agent_deploy(
    req: DeployCountermeasureRequest,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Deploy a countermeasure to a target."""
    from angelnode.ai_shield.angelbot import (
        AgentMode,
        AngelBot,
        DefenseAction,
    )

    agent = AngelBot(
        agent_id=f"angelclaw-{tenant_id[:8]}",
        mode=AgentMode.GUARDIAN,
        tenant_id=tenant_id,
    )

    try:
        action = DefenseAction(req.action)
    except ValueError:
        action = DefenseAction.HARDEN

    result = agent.deploy_protection(
        name=req.name,
        target=req.target,
        action=action,
    )

    return {
        "tenant_id": tenant_id,
        **result,
    }


@router.get("/status")
def angelclaw_agent_status(
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Get AngelClaw agent status and capabilities."""
    from angelnode.ai_shield.angelbot import (
        _COUNTERMEASURES,
        _HUNT_SIGNATURES,
        ANGELBOT_CODENAME,
        ANGELBOT_VERSION,
    )

    return {
        "name": "AngelClaw",
        "version": ANGELBOT_VERSION,
        "codename": ANGELBOT_CODENAME,
        "tenant_id": tenant_id,
        "capabilities": {
            "countermeasures": len(_COUNTERMEASURES),
            "hunt_signatures": len(_HUNT_SIGNATURES),
            "protection_chain_stages": 6,
            "modes": ["sentinel", "guardian", "archangel"],
        },
        "countermeasures": [
            {
                "name": cm.name,
                "targets": cm.targets,
                "action": cm.response_action.value,
                "severity": cm.severity,
            }
            for cm in _COUNTERMEASURES
        ],
        "hunt_signatures": [
            {
                "name": name,
                "description": desc,
            }
            for name, desc, _ in _HUNT_SIGNATURES
        ],
        "philosophy": (
            "Guardian angel with teeth. AngelClaw doesn't"
            " just detect — it hunts, contains, remediates,"
            " and hardens."
        ),
    }


@router.get("/holy-trifecta")
def angelclaw_holy_trifecta(
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Get Holy Trifecta status (inverse of Lethal Trifecta)."""
    import json

    from angelnode.ai_shield.angelbot import assess_holy_trifecta
    from cloud.db.models import EventRow, PolicySnapshotRow
    from cloud.db.session import get_db

    db = next(get_db())
    try:
        event_rows = (
            db.query(EventRow)
            .order_by(EventRow.timestamp.desc())
            .limit(200)
            .all()
        )
        events = [
            {
                "category": r.category or "",
                "type": r.type or "",
                "details": {},
                "decision": {"action": "audit"},
            }
            for r in event_rows
        ]

        snapshot = (
            db.query(PolicySnapshotRow)
            .order_by(PolicySnapshotRow.created_at.desc())
            .first()
        )
        policies: list[dict[str, Any]] = []
        if snapshot and snapshot.rules_json:
            try:
                rules = json.loads(snapshot.rules_json)
                if isinstance(rules, list):
                    policies = rules
            except (json.JSONDecodeError, TypeError):
                pass
    finally:
        db.close()

    ht = assess_holy_trifecta(events, policies)

    return {
        "tenant_id": tenant_id,
        "holy_trifecta": {
            "score": ht.score,
            "fortress_mode": ht.fortress_mode,
            "pillars": {
                "data_sovereignty": {
                    "active": ht.data_sovereign,
                    "description": (
                        "All sensitive data is classified"
                        " and protected"
                    ),
                    "evidence": ht.evidence["data_sovereignty"],
                },
                "trust_verification": {
                    "active": ht.trust_verified,
                    "description": (
                        "All inputs are verified"
                        " before processing"
                    ),
                    "evidence": ht.evidence["trust_verification"],
                },
                "isolation_control": {
                    "active": ht.isolation_enforced,
                    "description": (
                        "All communications are authorized"
                        " and audited"
                    ),
                    "evidence": ht.evidence["isolation_control"],
                },
            },
        },
        "vs_lethal_trifecta": (
            "The Holy Trifecta is the inverse of OpenClaw's"
            " Lethal Trifecta. Where the Lethal Trifecta"
            " maximizes attack surface, the Holy Trifecta"
            " minimizes it."
        ),
    }
