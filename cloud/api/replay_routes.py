"""AngelClaw Cloud – Event Replay API Routes."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from cloud.db.models import EventReplayRow
from cloud.db.session import get_db
from cloud.services.event_replay import replay_service as event_replay_service

logger = logging.getLogger("angelgrid.cloud.api.replay")

router = APIRouter(prefix="/api/v1/replays", tags=["Event Replay"])


class ReplayCreateRequest(BaseModel):
    name: str
    source_filter: dict = {}


@router.post("")
def create_replay(
    req: ReplayCreateRequest,
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Create and run an event replay session."""
    return event_replay_service.create_replay(
        db, tenant_id, name=req.name, source_filter=req.source_filter
    )


@router.get("")
def list_replays(
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """List all replay sessions."""
    rows = (
        db.query(EventReplayRow)
        .filter_by(tenant_id=tenant_id)
        .order_by(EventReplayRow.created_at.desc())
        .all()
    )
    return [
        {
            "id": r.id,
            "name": r.name,
            "status": r.status,
            "event_count": r.event_count,
            "indicators_found": r.indicators_found,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        }
        for r in rows
    ]


@router.get("/{replay_id}")
def get_replay(
    replay_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Get replay details and results."""
    row = db.query(EventReplayRow).filter_by(id=replay_id, tenant_id=tenant_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Replay not found")
    return {
        "id": row.id,
        "name": row.name,
        "status": row.status,
        "event_count": row.event_count,
        "indicators_found": row.indicators_found,
        "source_filter": row.source_filter,
        "results": row.results,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
    }
