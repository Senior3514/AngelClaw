"""AngelClaw Cloud – FastAPI auth dependencies."""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import Cookie, Header, HTTPException, Request

from .config import AUTH_ENABLED, AUTH_MODE
from .models import AuthUser, UserRole, role_at_least
from .service import verify_bearer, verify_jwt

logger = logging.getLogger("angelgrid.cloud.auth")


async def get_current_user(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    angelclaw_token: Optional[str] = Cookie(default=None, alias="angelclaw_token"),
) -> AuthUser:
    """Extract and verify the current user from Authorization header or cookie.

    Raises 401 if auth is enabled and no valid credentials are provided.
    """
    if not AUTH_ENABLED:
        # Auth disabled — return a default operator user
        return AuthUser(username="anonymous", role=UserRole.OPERATOR, tenant_id="dev-tenant")

    # Try Authorization header first
    token = None
    if authorization:
        if authorization.startswith("Bearer "):
            token = authorization[7:]
        else:
            token = authorization

    # Fall back to cookie
    if not token and angelclaw_token:
        token = angelclaw_token

    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Try JWT first, then bearer
    user = verify_jwt(token)
    if user:
        return user

    if AUTH_MODE == "bearer":
        user = verify_bearer(token)
        if user:
            return user

    raise HTTPException(status_code=401, detail="Invalid or expired token")


def require_role(required_role: UserRole):
    """Return a dependency that checks the user has the required role."""
    async def _check_role(
        request: Request,
        authorization: Optional[str] = Header(default=None),
        angelclaw_token: Optional[str] = Cookie(default=None, alias="angelclaw_token"),
    ) -> AuthUser:
        user = await get_current_user(request, authorization, angelclaw_token)

        # Check role hierarchy
        if not role_at_least(user.role, required_role):
            raise HTTPException(
                status_code=403,
                detail=f"Requires {required_role.value} role (you are {user.role.value})",
            )

        return user

    return _check_role


async def optional_auth(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    angelclaw_token: Optional[str] = Cookie(default=None, alias="angelclaw_token"),
) -> AuthUser | None:
    """Extract user if authenticated, return None otherwise. Never raises 401."""
    if not AUTH_ENABLED:
        return AuthUser(username="anonymous", role=UserRole.OPERATOR, tenant_id="dev-tenant")

    token = None
    if authorization:
        if authorization.startswith("Bearer "):
            token = authorization[7:]
        else:
            token = authorization

    if not token and angelclaw_token:
        token = angelclaw_token

    if not token:
        return None

    user = verify_jwt(token)
    if user:
        return user

    if AUTH_MODE == "bearer":
        return verify_bearer(token)

    return None
