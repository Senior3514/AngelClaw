"""AngelClaw – Orchestrator API routes.

Exposes the ANGEL AGI Orchestrator status, incident management,
sub-agent info, and approval workflow.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from cloud.db.session import get_db
from cloud.guardian.orchestrator import angel_orchestrator

router = APIRouter(prefix="/api/v1/orchestrator", tags=["orchestrator"])


@router.get("/status")
async def orchestrator_status():
    """Return orchestrator status: agents, incidents, stats."""
    return angel_orchestrator.status()


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
        approved_by="operator",  # In production, extract from auth
        db=db,
    )
    return result


@router.get("/agents")
async def list_agents():
    """List all guardian sub-agents and their status."""
    return {
        "agents": [
            angel_orchestrator.sentinel.info(),
            angel_orchestrator.response.info(),
            angel_orchestrator.forensic.info(),
            angel_orchestrator.audit.info(),
        ],
    }


@router.get("/playbooks")
async def list_playbooks():
    """List available response playbooks."""
    playbooks = []
    for name in angel_orchestrator.response.list_playbooks():
        pb = angel_orchestrator.response.get_playbook(name)
        if pb:
            playbooks.append({
                "name": pb.name,
                "description": pb.description,
                "trigger_patterns": pb.trigger_patterns,
                "severity_threshold": pb.severity_threshold,
                "auto_respond": pb.auto_respond,
                "steps": [s.action for s in pb.steps],
            })
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
