"""AngelClaw Cloud – Auth data models."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class UserRole(str, Enum):
    VIEWER = "viewer"
    OPERATOR = "operator"  # Alias for backward compat — maps to secops+admin
    SECOPS = "secops"
    ADMIN = "admin"


# Role hierarchy: admin > secops > operator > viewer
ROLE_HIERARCHY = {
    UserRole.ADMIN: 4,
    UserRole.SECOPS: 3,
    UserRole.OPERATOR: 3,  # operator == secops level
    UserRole.VIEWER: 1,
}


def role_at_least(user_role: UserRole, required: UserRole) -> bool:
    """Check if user_role meets the minimum required role level."""
    return ROLE_HIERARCHY.get(user_role, 0) >= ROLE_HIERARCHY.get(required, 0)


class AuthUser(BaseModel):
    username: str
    role: UserRole
    tenant_id: str = "dev-tenant"
    organization_id: str = "default-org"


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=8, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str
