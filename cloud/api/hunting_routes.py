"""AngelClaw Cloud – Threat Hunting API Routes."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from cloud.db.session import get_db
from cloud.services.threat_hunting import threat_hunting_service

logger = logging.getLogger("angelgrid.cloud.api.hunting")

router = APIRouter(prefix="/api/v1/hunting", tags=["Threat Hunting"])


class HuntQueryRequest(BaseModel):
    query_dsl: dict


class SaveQueryRequest(BaseModel):
    name: str
    description: str = ""
    query_dsl: dict


@router.post("/execute")
def execute_hunt(
    req: HuntQueryRequest,
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Execute a threat hunting query."""
    return threat_hunting_service.execute_query(db, tenant_id, req.query_dsl)


@router.post("/queries")
def save_query(
    req: SaveQueryRequest,
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Save a hunting query for reuse."""
    return threat_hunting_service.save_query(
        db, tenant_id, req.name, req.description, req.query_dsl
    )


@router.get("/queries")
def list_queries(
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """List saved hunting queries."""
    return threat_hunting_service.list_saved_queries(db, tenant_id)


@router.post("/queries/{query_id}/run")
def run_saved(
    query_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Run a saved hunting query."""
    result = threat_hunting_service.run_saved_query(db, tenant_id, query_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result
