"""Tests for authentication and RBAC."""

import os

from cloud.auth.models import UserRole, role_at_least
from cloud.auth.service import authenticate_local, create_jwt, verify_jwt


def test_role_hierarchy():
    assert role_at_least(UserRole.ADMIN, UserRole.VIEWER)
    assert role_at_least(UserRole.ADMIN, UserRole.SECOPS)
    assert role_at_least(UserRole.ADMIN, UserRole.ADMIN)
    assert role_at_least(UserRole.SECOPS, UserRole.VIEWER)
    assert not role_at_least(UserRole.VIEWER, UserRole.SECOPS)
    assert not role_at_least(UserRole.VIEWER, UserRole.ADMIN)


def test_jwt_roundtrip():
    from cloud.auth.models import AuthUser
    user = AuthUser(username="testuser", role=UserRole.ADMIN, tenant_id="test")
    token = create_jwt(user)
    assert token
    decoded = verify_jwt(token)
    assert decoded is not None
    assert decoded.username == "testuser"
    assert decoded.role == UserRole.ADMIN


def test_jwt_invalid():
    assert verify_jwt("invalid.token.here") is None
    assert verify_jwt("") is None
    assert verify_jwt("abc") is None


def test_authenticate_local():
    os.environ["ANGELCLAW_ADMIN_PASSWORD"] = "test-pass-123"
    # Need to reload config to pick up the new env var
    import importlib
    import cloud.auth.config
    importlib.reload(cloud.auth.config)
    import cloud.auth.service
    importlib.reload(cloud.auth.service)
    from cloud.auth.service import authenticate_local as auth_local

    user = auth_local("admin", "test-pass-123")
    assert user is not None
    assert user.role == UserRole.ADMIN

    user2 = auth_local("admin", "wrong")
    assert user2 is None

    # Clean up
    os.environ.pop("ANGELCLAW_ADMIN_PASSWORD", None)
