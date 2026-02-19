"""AngelClaw Cloud -- Quarantine API Routes.

REST endpoints for agent quarantine management.  Supports quarantine,
release, listing, and status inspection.

Router prefix: /api/v1/quarantine
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from cloud.db.session import get_db
from cloud.services.quarantine import quarantine_manager

logger = logging.getLogger("angelgrid.cloud.quarantine_api")

router = APIRouter(prefix="/api/v1/quarantine", tags=["Quarantine"])


# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------


class QuarantineRequest(BaseModel):
    """Body for quarantine-agent requests."""

    reason: str = Field(
        ..., min_length=1, max_length=1024, description="Reason for quarantining the agent"
    )
    release_at: Optional[datetime] = Field(
        default=None, description="Optional ISO-8601 timestamp for automatic release"
    )


class QuarantineRecord(BaseModel):
    """Serialised quarantine record returned by all endpoints."""

    id: str
    tenant_id: str
    agent_id: str
    reason: str
    quarantined_by: str
    quarantined_at: datetime
    release_at: Optional[datetime] = None
    released_at: Optional[datetime] = None
    released_by: Optional[str] = None
    status: str
    suppressed_events: int = 0


class QuarantineStatusResponse(BaseModel):
    """Wrapper for single-agent quarantine status."""

    quarantined: bool
    record: Optional[QuarantineRecord] = None


# ---------------------------------------------------------------------------
# Auth / tenant dependency
# ---------------------------------------------------------------------------


async def _require_tenant(
    x_tenant_id: Optional[str] = Header(default=None),
) -> str:
    """Extract tenant from X-TENANT-ID header, defaulting to dev-tenant."""
    return x_tenant_id or "dev-tenant"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row_to_record(row: Any) -> QuarantineRecord:
    """Convert a QuarantineRecordRow ORM object to a Pydantic response model."""
    return QuarantineRecord(
        id=row.id,
        tenant_id=row.tenant_id,
        agent_id=row.agent_id,
        reason=row.reason or "",
        quarantined_by=row.quarantined_by or "system",
        quarantined_at=row.quarantined_at,
        release_at=row.release_at,
        released_at=row.released_at,
        released_by=row.released_by,
        status=row.status,
        suppressed_events=row.suppressed_events or 0,
    )


# ---------------------------------------------------------------------------
# POST /api/v1/quarantine/agents/{agent_id}  --  Quarantine an agent
# ---------------------------------------------------------------------------


@router.post(
    "/agents/{agent_id}",
    response_model=QuarantineRecord,
    summary="Quarantine an agent",
    status_code=201,
)
def quarantine_agent(
    agent_id: str,
    body: QuarantineRequest,
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> QuarantineRecord:
    """Place an agent under quarantine.

    If the agent is already quarantined the existing record is returned
    with a 201 status (idempotent).
    """
    try:
        record = quarantine_manager.quarantine_agent(
            db=db,
            tenant_id=tenant_id,
            agent_id=agent_id,
            reason=body.reason,
            quarantined_by="api",
            release_at=body.release_at,
        )
        logger.info(
            "[API] Quarantine request for agent %s by tenant %s",
            agent_id[:8],
            tenant_id,
        )
        return _row_to_record(record)
    except Exception as exc:
        logger.exception("[API] Failed to quarantine agent %s", agent_id[:8])
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# POST /api/v1/quarantine/agents/{agent_id}/release  --  Release an agent
# ---------------------------------------------------------------------------


@router.post(
    "/agents/{agent_id}/release",
    response_model=QuarantineRecord,
    summary="Release an agent from quarantine",
)
def release_agent(
    agent_id: str,
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> QuarantineRecord:
    """Release an agent from active quarantine.

    Returns 404 if the agent has no active quarantine record.
    """
    record = quarantine_manager.release_agent(
        db=db,
        tenant_id=tenant_id,
        agent_id=agent_id,
        released_by="api",
    )
    if not record:
        raise HTTPException(
            status_code=404,
            detail=f"No active quarantine found for agent {agent_id}",
        )
    logger.info(
        "[API] Released agent %s by tenant %s",
        agent_id[:8],
        tenant_id,
    )
    return _row_to_record(record)


# ---------------------------------------------------------------------------
# GET /api/v1/quarantine/agents  --  List quarantined agents
# ---------------------------------------------------------------------------


@router.get(
    "/agents",
    response_model=list[QuarantineRecord],
    summary="List all quarantined agents for a tenant",
)
def list_quarantined(
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> list[QuarantineRecord]:
    """Return every active quarantine record for the calling tenant."""
    rows = quarantine_manager.list_quarantined(db=db, tenant_id=tenant_id)
    return [_row_to_record(r) for r in rows]


# ---------------------------------------------------------------------------
# GET /api/v1/quarantine/agents/{agent_id}  --  Get quarantine status
# ---------------------------------------------------------------------------


@router.get(
    "/agents/{agent_id}",
    response_model=QuarantineStatusResponse,
    summary="Get quarantine status for a specific agent",
)
def get_quarantine_status(
    agent_id: str,
    db: Session = Depends(get_db),
) -> QuarantineStatusResponse:
    """Return quarantine status for a single agent.

    The response includes a boolean ``quarantined`` flag and the full
    record when one exists.
    """
    row = quarantine_manager.get_quarantine_status(db=db, agent_id=agent_id)
    if row:
        return QuarantineStatusResponse(
            quarantined=True,
            record=_row_to_record(row),
        )
    return QuarantineStatusResponse(quarantined=False, record=None)
