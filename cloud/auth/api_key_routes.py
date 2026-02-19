"""AngelClaw Cloud -- API Key Routes.

FastAPI router for managing service-to-service API keys.
Supports creation, listing, rotation, and revocation.

Router prefix: /api/v1/auth/api-keys
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from cloud.auth.api_keys import api_key_service
from cloud.db.session import get_db

logger = logging.getLogger("angelgrid.cloud.auth.api_key_routes")

router = APIRouter(prefix="/api/v1/auth/api-keys", tags=["API Keys"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class CreateApiKeyRequest(BaseModel):
    """Request body for creating a new API key."""

    name: str = Field(..., min_length=1, max_length=128, description="Human-readable key name")
    scopes: list[str] = Field(default_factory=list, description="Permission scopes for this key")
    expires_in_days: Optional[int] = Field(
        default=None,
        ge=1,
        le=365,
        description="Days until key expiration (None = never expires)",
    )


class ApiKeyCreatedResponse(BaseModel):
    """Response returned after key creation -- contains the raw key ONCE."""

    key_id: str
    raw_key: str
    prefix: str
    name: str
    scopes: list[str]
    message: str = "Store this key securely. It will NOT be shown again."


class ApiKeyInfo(BaseModel):
    """Public key metadata (never includes raw key or hash)."""

    key_id: str
    tenant_id: str
    name: str
    prefix: str
    scopes: list[str]
    created_by: str
    created_at: Optional[str] = None
    expires_at: Optional[str] = None
    last_used_at: Optional[str] = None
    revoked: bool = False
    revoked_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------


async def _require_tenant(
    x_tenant_id: Optional[str] = Header(default=None),
) -> str:
    """Extract tenant ID from request header, defaulting to dev-tenant."""
    return x_tenant_id or "dev-tenant"


# ---------------------------------------------------------------------------
# POST /api/v1/auth/api-keys
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=ApiKeyCreatedResponse,
    status_code=201,
    summary="Create a new API key",
)
def create_api_key(
    body: CreateApiKeyRequest,
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> ApiKeyCreatedResponse:
    """Generate a new API key for service-to-service authentication.

    The raw key is returned **only once** in this response.  Store it
    securely -- it cannot be recovered later.
    """
    expires_at = None
    if body.expires_in_days is not None:
        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_in_days)

    try:
        result = api_key_service.create_key(
            db=db,
            tenant_id=tenant_id,
            name=body.name,
            scopes=body.scopes,
            created_by=tenant_id,
            expires_at=expires_at,
        )
    except Exception as exc:
        logger.exception("Failed to create API key")
        raise HTTPException(status_code=500, detail=f"Failed to create API key: {exc}") from exc

    return ApiKeyCreatedResponse(
        key_id=result["key_id"],
        raw_key=result["raw_key"],
        prefix=result["prefix"],
        name=result["name"],
        scopes=result["scopes"],
    )


# ---------------------------------------------------------------------------
# GET /api/v1/auth/api-keys
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=list[ApiKeyInfo],
    summary="List all API keys for the tenant",
)
def list_api_keys(
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> list[ApiKeyInfo]:
    """Return metadata for all API keys belonging to the tenant.

    Raw keys and hashes are **never** included in the response.
    """
    keys = api_key_service.list_keys(db, tenant_id)
    return [ApiKeyInfo(**k) for k in keys]


# ---------------------------------------------------------------------------
# POST /api/v1/auth/api-keys/{key_id}/rotate
# ---------------------------------------------------------------------------


@router.post(
    "/{key_id}/rotate",
    response_model=ApiKeyCreatedResponse,
    summary="Rotate an API key",
)
def rotate_api_key(
    key_id: str,
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> ApiKeyCreatedResponse:
    """Revoke the specified key and issue a replacement with the same
    name, scopes, and tenant.  The new raw key is returned once.
    """
    result = api_key_service.rotate_key(db, key_id, rotated_by=tenant_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"API key '{key_id}' not found")

    return ApiKeyCreatedResponse(
        key_id=result["key_id"],
        raw_key=result["raw_key"],
        prefix=result["prefix"],
        name=result["name"],
        scopes=result["scopes"],
    )


# ---------------------------------------------------------------------------
# POST /api/v1/auth/api-keys/{key_id}/revoke
# ---------------------------------------------------------------------------


@router.post(
    "/{key_id}/revoke",
    summary="Revoke an API key",
)
def revoke_api_key(
    key_id: str,
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> dict:
    """Permanently revoke an API key.  The key can no longer be used
    for authentication after this call.
    """
    success = api_key_service.revoke_key(db, key_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"API key '{key_id}' not found")

    return {"status": "ok", "message": f"API key '{key_id}' has been revoked"}
