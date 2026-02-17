"""AngelClaw – Orchestrator API routes (V2.0).

Exposes the Seraph orchestrator: Angel Legion status, scan types,
autonomy mode, incident management, approval workflow, and agent info.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from cloud.db.session import get_db
from cloud.guardian.learning import learning_engine
from cloud.guardian.orchestrator import angel_orchestrator
from cloud.guardian.self_audit import run_self_audit

router = APIRouter(prefix="/api/v1/orchestrator", tags=["orchestrator"])


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


@router.get("/status")
async def orchestrator_status():
    """Return full orchestrator status: legion, agents, incidents, stats."""
    return angel_orchestrator.status()


# ---------------------------------------------------------------------------
# Angel Legion
# ---------------------------------------------------------------------------


@router.get("/legion/status")
async def legion_status():
    """Return Angel Legion status: all agents, summary, circuit breakers."""
    return {
        "summary": angel_orchestrator.registry.summary(),
        "agents": angel_orchestrator.registry.info_all(),
        "circuit_breakers": dict(angel_orchestrator._sentinel_failures),
        "autonomy_mode": angel_orchestrator.autonomy_mode,
    }


@router.get("/agents")
async def list_agents():
    """List all guardian sub-agents and their status."""
    return {
        "agents": [a.info() for a in angel_orchestrator.registry.all_agents()],
    }


# ---------------------------------------------------------------------------
# Scan Types (Halo Sweep, Wing Scan, Pulse Check)
# ---------------------------------------------------------------------------


@router.post("/scan/halo-sweep")
async def halo_sweep(db: Session = Depends(get_db)):
    """Halo Sweep — full system scan, all sentinels fire."""
    return await angel_orchestrator.halo_sweep(db)


@router.post("/scan/wing/{domain}")
async def wing_scan(domain: str, db: Session = Depends(get_db)):
    """Wing Scan — targeted scan for a single sentinel domain."""
    return await angel_orchestrator.wing_scan(db, domain)


@router.get("/scan/pulse")
async def pulse_check():
    """Pulse Check — quick health of all agents."""
    return angel_orchestrator.pulse_check()


# ---------------------------------------------------------------------------
# Autonomy Mode
# ---------------------------------------------------------------------------


@router.put("/autonomy/{mode}")
async def set_autonomy_mode(mode: str):
    """Set orchestrator autonomy mode: observe, suggest, or auto_apply."""
    try:
        new_mode = angel_orchestrator.set_autonomy_mode(mode)
        return {"autonomy_mode": new_mode}
    except ValueError as e:
        return {"error": str(e)}


@router.get("/autonomy")
async def get_autonomy_mode():
    """Get current autonomy mode."""
    return {"autonomy_mode": angel_orchestrator.autonomy_mode}


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------


@router.get("/incidents")
async def list_incidents(
    limit: int = 20,
    state: str | None = None,
):
    """List tracked incidents, optionally filtered by state."""
    incidents = angel_orchestrator.list_incidents(limit=limit, state=state)
    return {
        "incidents": [inc.model_dump(mode="json") for inc in incidents],
        "total": len(incidents),
    }


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """Get details of a specific incident."""
    incident = angel_orchestrator.get_incident(incident_id)
    if not incident:
        return {"error": "Incident not found"}
    return incident.model_dump(mode="json")


@router.post("/incidents/{incident_id}/approve")
async def approve_incident(
    incident_id: str,
    db: Session = Depends(get_db),
):
    """Approve a pending incident response (operator action)."""
    result = await angel_orchestrator.approve_incident(
        incident_id=incident_id,
        approved_by="operator",
        db=db,
    )
    return result


# ---------------------------------------------------------------------------
# Playbooks
# ---------------------------------------------------------------------------


@router.get("/playbooks")
async def list_playbooks():
    """List available response playbooks."""
    playbooks = []
    for name in angel_orchestrator.response.list_playbooks():
        pb = angel_orchestrator.response.get_playbook(name)
        if pb:
            playbooks.append(
                {
                    "name": pb.name,
                    "description": pb.description,
                    "trigger_patterns": pb.trigger_patterns,
                    "severity_threshold": pb.severity_threshold,
                    "auto_respond": pb.auto_respond,
                    "steps": [s.action for s in pb.steps],
                }
            )
    return {"playbooks": playbooks}


@router.post("/playbooks/{playbook_name}/dry-run")
async def dry_run_playbook(
    playbook_name: str,
    agent_id: str = "test-agent",
    db: Session = Depends(get_db),
):
    """Dry-run a playbook without executing actions."""
    from cloud.guardian.models import AgentTask

    task = AgentTask(
        task_type="respond",
        payload={
            "playbook_name": playbook_name,
            "incident": {
                "incident_id": "dry-run",
                "agent_id": agent_id,
                "severity": "high",
                "title": "Dry run test",
                "tenant_id": "dev-tenant",
            },
            "dry_run": True,
            "approved": True,
        },
    )

    result = await angel_orchestrator.response.execute(task)
    return {
        "playbook": playbook_name,
        "dry_run": True,
        "success": result.success,
        "results": result.result_data,
    }


# ---------------------------------------------------------------------------
# Self-Audit
# ---------------------------------------------------------------------------


@router.get("/self-audit")
async def self_audit(db: Session = Depends(get_db)):
    """Run a self-audit and return findings."""
    report = await run_self_audit(db)
    return report.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Learning Engine
# ---------------------------------------------------------------------------


@router.get("/learning/summary")
async def learning_summary():
    """Return the learning engine state."""
    return learning_engine.summary()


@router.get("/learning/reflections")
async def learning_reflections(limit: int = 50, category: str | None = None):
    """Return recent learning reflections."""
    return {
        "reflections": learning_engine.get_reflections(limit=limit, category=category),
        "total": len(learning_engine._reflections),
    }
