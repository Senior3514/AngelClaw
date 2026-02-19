"""AngelClaw Cloud – Role & Permission API routes (V3.0 Dominion).

CRUD endpoints for custom RBAC roles and a permission catalogue
listing.  System roles are returned in listings but cannot be
modified or deleted through these endpoints.

Router prefix: /api/v1/auth/roles
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from cloud.auth.custom_roles import GRANULAR_PERMISSIONS, role_service
from cloud.db.session import get_db

logger = logging.getLogger("angelgrid.cloud.auth.role_routes")

router = APIRouter(prefix="/api/v1/auth/roles", tags=["Roles & Permissions"])


# ---------------------------------------------------------------------------
# Auth / tenant dependency
# ---------------------------------------------------------------------------


async def _require_tenant(
    x_tenant_id: Optional[str] = Header(default=None),
) -> str:
    return x_tenant_id or "dev-tenant"


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class CreateRoleRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    permissions: list[str] = Field(min_length=1)
    description: str = ""
    created_by: str = "system"


class UpdateRoleRequest(BaseModel):
    permissions: list[str] | None = None
    description: str | None = None


class RoleResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    description: str = ""
    permissions: list[str] = Field(default_factory=list)
    is_system: bool = False
    created_by: str = "system"
    created_at: str | None = None


# ---------------------------------------------------------------------------
# GET /api/v1/auth/roles -- list all roles
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=list[RoleResponse],
    summary="List all roles (system + custom)",
)
def list_roles(
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> list[RoleResponse]:
    roles = role_service.list_roles(db, tenant_id)
    return [RoleResponse(**r) for r in roles]


# ---------------------------------------------------------------------------
# POST /api/v1/auth/roles -- create custom role
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=RoleResponse,
    status_code=201,
    summary="Create a custom role",
)
def create_role(
    req: CreateRoleRequest,
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> RoleResponse:
    try:
        role = role_service.create_role(
            db,
            tenant_id=tenant_id,
            name=req.name,
            permissions=req.permissions,
            description=req.description,
            created_by=req.created_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return RoleResponse(**role)


# ---------------------------------------------------------------------------
# PUT /api/v1/auth/roles/{role_id} -- update custom role
# ---------------------------------------------------------------------------


@router.put(
    "/{role_id}",
    response_model=RoleResponse,
    summary="Update a custom role",
)
def update_role(
    role_id: str,
    req: UpdateRoleRequest,
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> RoleResponse:
    try:
        role = role_service.update_role(
            db,
            tenant_id=tenant_id,
            role_id=role_id,
            permissions=req.permissions,
            description=req.description,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if role is None:
        raise HTTPException(status_code=404, detail=f"Role '{role_id}' not found")

    return RoleResponse(**role)


# ---------------------------------------------------------------------------
# DELETE /api/v1/auth/roles/{role_id} -- delete custom role
# ---------------------------------------------------------------------------


@router.delete(
    "/{role_id}",
    summary="Delete a custom role",
)
def delete_role(
    role_id: str,
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> dict:
    try:
        deleted = role_service.delete_role(db, tenant_id=tenant_id, role_id=role_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not deleted:
        raise HTTPException(status_code=404, detail=f"Role '{role_id}' not found")

    return {"status": "ok", "deleted": role_id}


# ---------------------------------------------------------------------------
# GET /api/v1/auth/permissions -- permission catalogue
# ---------------------------------------------------------------------------

permissions_router = APIRouter(prefix="/api/v1/auth", tags=["Roles & Permissions"])


@permissions_router.get(
    "/permissions",
    summary="List all available granular permissions",
)
def list_permissions() -> dict:
    return {
        "permissions": GRANULAR_PERMISSIONS,
        "total": len(GRANULAR_PERMISSIONS),
    }
