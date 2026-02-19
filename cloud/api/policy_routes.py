"""AngelClaw Cloud – Policy Snapshot API Routes.

Provides CRUD endpoints for policy snapshots, diff comparison, and rollback.
All endpoints require a tenant context via the X-TENANT-ID header (falls back
to "dev-tenant" for local development).

Router prefix: /api/v1/policies
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from cloud.db.session import get_db
from cloud.services.policy_snapshots import snapshot_service

logger = logging.getLogger("angelgrid.cloud.policy_routes")

router = APIRouter(prefix="/api/v1/policies", tags=["Policies"])


# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------


class SnapshotCreateRequest(BaseModel):
    """Body for POST /snapshots."""

    name: str = Field(..., min_length=1, max_length=128)
    description: str = Field(default="", max_length=1024)


class SnapshotResponse(BaseModel):
    """Single snapshot representation."""

    id: str
    tenant_id: str
    name: str
    description: str = ""
    policy_set_id: str
    rules_json: list[Any] = Field(default_factory=list)
    version_hash: str
    rule_count: int = 0
    created_by: str = "system"
    created_at: datetime


class SnapshotSummaryResponse(BaseModel):
    """Lightweight snapshot for list endpoints (omits full rules_json)."""

    id: str
    tenant_id: str
    name: str
    description: str = ""
    policy_set_id: str
    version_hash: str
    rule_count: int = 0
    created_by: str = "system"
    created_at: datetime


class RuleDiffEntry(BaseModel):
    """A single modified rule in a diff result."""

    rule_id: str
    before: dict[str, Any] = Field(default_factory=dict)
    after: dict[str, Any] = Field(default_factory=dict)


class SnapshotDiffResponse(BaseModel):
    """Result of comparing two snapshots."""

    snapshot_a: str
    snapshot_b: str
    added: list[dict[str, Any]] = Field(default_factory=list)
    removed: list[dict[str, Any]] = Field(default_factory=list)
    modified: list[RuleDiffEntry] = Field(default_factory=list)


class RollbackResponse(BaseModel):
    """Confirmation payload after a successful rollback."""

    policy_set_id: str
    name: str
    version_hash: str
    rule_count: int
    rolled_back_from_snapshot: str
    created_at: datetime


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------


async def _require_tenant(
    x_tenant_id: Optional[str] = Header(default=None),
) -> str:
    return x_tenant_id or "dev-tenant"


# ---------------------------------------------------------------------------
# POST /api/v1/policies/snapshots
# ---------------------------------------------------------------------------


@router.post(
    "/snapshots",
    response_model=SnapshotResponse,
    status_code=201,
    summary="Create a policy snapshot",
)
def create_snapshot(
    body: SnapshotCreateRequest,
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> SnapshotResponse:
    try:
        snap = snapshot_service.create_snapshot(
            db=db,
            tenant_id=tenant_id,
            name=body.name,
            description=body.description,
            created_by=tenant_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return SnapshotResponse(
        id=snap.id,
        tenant_id=snap.tenant_id,
        name=snap.name,
        description=snap.description or "",
        policy_set_id=snap.policy_set_id,
        rules_json=snap.rules_json or [],
        version_hash=snap.version_hash,
        rule_count=snap.rule_count or 0,
        created_by=snap.created_by or "system",
        created_at=snap.created_at,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/policies/snapshots
# ---------------------------------------------------------------------------


@router.get(
    "/snapshots",
    response_model=list[SnapshotSummaryResponse],
    summary="List policy snapshots",
)
def list_snapshots(
    limit: int = Query(default=50, ge=1, le=200),
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> list[SnapshotSummaryResponse]:
    rows = snapshot_service.list_snapshots(db=db, tenant_id=tenant_id, limit=limit)
    return [
        SnapshotSummaryResponse(
            id=r.id,
            tenant_id=r.tenant_id,
            name=r.name,
            description=r.description or "",
            policy_set_id=r.policy_set_id,
            version_hash=r.version_hash,
            rule_count=r.rule_count or 0,
            created_by=r.created_by or "system",
            created_at=r.created_at,
        )
        for r in rows
    ]


# ---------------------------------------------------------------------------
# GET /api/v1/policies/snapshots/diff  (must be before {snapshot_id})
# ---------------------------------------------------------------------------


@router.get(
    "/snapshots/diff",
    response_model=SnapshotDiffResponse,
    summary="Diff two policy snapshots",
)
def diff_snapshots(
    id_a: str = Query(..., description="First snapshot ID"),
    id_b: str = Query(..., description="Second snapshot ID"),
    db: Session = Depends(get_db),
) -> SnapshotDiffResponse:
    try:
        result = snapshot_service.diff_snapshots(db=db, id_a=id_a, id_b=id_b)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return SnapshotDiffResponse(
        snapshot_a=result["snapshot_a"],
        snapshot_b=result["snapshot_b"],
        added=result["added"],
        removed=result["removed"],
        modified=[
            RuleDiffEntry(
                rule_id=m["rule_id"],
                before=m["before"],
                after=m["after"],
            )
            for m in result["modified"]
        ],
    )


# ---------------------------------------------------------------------------
# GET /api/v1/policies/snapshots/{snapshot_id}
# ---------------------------------------------------------------------------


@router.get(
    "/snapshots/{snapshot_id}",
    response_model=SnapshotResponse,
    summary="Get a single policy snapshot",
)
def get_snapshot(
    snapshot_id: str,
    db: Session = Depends(get_db),
) -> SnapshotResponse:
    snap = snapshot_service.get_snapshot(db=db, snapshot_id=snapshot_id)
    if snap is None:
        raise HTTPException(status_code=404, detail=f"Snapshot '{snapshot_id}' not found")

    return SnapshotResponse(
        id=snap.id,
        tenant_id=snap.tenant_id,
        name=snap.name,
        description=snap.description or "",
        policy_set_id=snap.policy_set_id,
        rules_json=snap.rules_json or [],
        version_hash=snap.version_hash,
        rule_count=snap.rule_count or 0,
        created_by=snap.created_by or "system",
        created_at=snap.created_at,
    )


# ---------------------------------------------------------------------------
# POST /api/v1/policies/snapshots/{snapshot_id}/rollback
# ---------------------------------------------------------------------------


@router.post(
    "/snapshots/{snapshot_id}/rollback",
    response_model=RollbackResponse,
    summary="Rollback policy to a snapshot",
)
def rollback_to_snapshot(
    snapshot_id: str,
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> RollbackResponse:
    try:
        new_policy = snapshot_service.rollback_to(
            db=db,
            tenant_id=tenant_id,
            snapshot_id=snapshot_id,
            rolled_back_by=tenant_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    rule_count = (
        len(new_policy.rules_json)
        if isinstance(new_policy.rules_json, list)
        else 0
    )

    return RollbackResponse(
        policy_set_id=new_policy.id,
        name=new_policy.name,
        version_hash=new_policy.version_hash,
        rule_count=rule_count,
        rolled_back_from_snapshot=snapshot_id,
        created_at=new_policy.created_at,
    )
