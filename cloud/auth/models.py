"""AngelClaw Cloud – Auth data models."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class UserRole(str, Enum):
    VIEWER = "viewer"
    OPERATOR = "operator"


class AuthUser(BaseModel):
    username: str
    role: UserRole
    tenant_id: str = "dev-tenant"


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str
