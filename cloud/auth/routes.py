"""AngelClaw Cloud – Auth API routes."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException

from .config import AUTH_ENABLED
from .dependencies import get_current_user
from .models import AuthUser, LoginRequest, TokenResponse
from .service import authenticate_local, create_jwt

logger = logging.getLogger("angelgrid.cloud.auth")

router = APIRouter(prefix="/api/v1/auth", tags=["Auth"])


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest):
    """Authenticate and receive a JWT token."""
    if not AUTH_ENABLED:
        raise HTTPException(status_code=400, detail="Auth is disabled")

    user = authenticate_local(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_jwt(user)
    logger.info("User '%s' logged in (role=%s)", user.username, user.role.value)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        role=user.role.value,
        username=user.username,
    )


@router.get("/me")
async def get_me(user: AuthUser = Depends(get_current_user)):
    """Return the current authenticated user's info."""
    return {
        "username": user.username,
        "role": user.role.value,
        "tenant_id": user.tenant_id,
        "auth_enabled": AUTH_ENABLED,
    }


@router.post("/logout")
async def logout():
    """Logout (client-side — invalidate token in localStorage)."""
    return {"status": "ok", "message": "Token should be cleared client-side"}
