"""AngelClaw Cloud – Remediation Workflow API Routes."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from cloud.db.models import RemediationWorkflowRow
from cloud.db.session import get_db

logger = logging.getLogger("angelgrid.cloud.api.remediation")

router = APIRouter(prefix="/api/v1/remediation", tags=["Remediation Workflows"])


class WorkflowCreateRequest(BaseModel):
    name: str
    description: str = ""
    trigger_conditions: dict = {}
    steps: list[dict] = []
    rollback_steps: list[dict] = []


@router.post("/workflows")
def create_workflow(
    req: WorkflowCreateRequest,
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Create a remediation workflow."""
    wf_id = str(uuid.uuid4())
    row = RemediationWorkflowRow(
        id=wf_id,
        tenant_id=tenant_id,
        name=req.name,
        description=req.description,
        trigger_conditions=req.trigger_conditions,
        steps=req.steps,
        rollback_steps=req.rollback_steps,
    )
    db.add(row)
    db.commit()
    return {"id": wf_id, "name": req.name, "created": True}


@router.get("/workflows")
def list_workflows(
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """List all remediation workflows."""
    rows = (
        db.query(RemediationWorkflowRow)
        .filter_by(tenant_id=tenant_id)
        .order_by(RemediationWorkflowRow.created_at.desc())
        .all()
    )
    return [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "enabled": r.enabled,
            "executions": r.executions,
            "steps_count": len(r.steps or []),
            "last_executed_at": r.last_executed_at.isoformat() if r.last_executed_at else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.get("/workflows/{workflow_id}")
def get_workflow(
    workflow_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Get workflow details."""
    row = db.query(RemediationWorkflowRow).filter_by(id=workflow_id, tenant_id=tenant_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "trigger_conditions": row.trigger_conditions,
        "steps": row.steps,
        "rollback_steps": row.rollback_steps,
        "enabled": row.enabled,
        "executions": row.executions,
        "last_executed_at": row.last_executed_at.isoformat() if row.last_executed_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.post("/workflows/{workflow_id}/execute")
def execute_workflow(
    workflow_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Manually trigger a remediation workflow."""
    row = db.query(RemediationWorkflowRow).filter_by(id=workflow_id, tenant_id=tenant_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Workflow not found")
    if row.enabled != "true":
        raise HTTPException(status_code=400, detail="Workflow is disabled")

    # Simulate execution
    row.executions = (row.executions or 0) + 1
    row.last_executed_at = datetime.now(timezone.utc)
    db.commit()

    return {
        "executed": True,
        "workflow_id": workflow_id,
        "steps_executed": len(row.steps or []),
        "execution_count": row.executions,
    }


@router.put("/workflows/{workflow_id}/toggle")
def toggle_workflow(
    workflow_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Enable or disable a workflow."""
    row = db.query(RemediationWorkflowRow).filter_by(id=workflow_id, tenant_id=tenant_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Workflow not found")
    row.enabled = "false" if row.enabled == "true" else "true"
    db.commit()
    return {"id": workflow_id, "enabled": row.enabled}
