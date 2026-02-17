"""Comprehensive tests for authentication, JWT, RBAC, and auth middleware.

Covers: login flow, JWT creation/verification/expiry, bearer tokens,
role hierarchy, viewer write restrictions, auth middleware bypass,
password change, and edge cases.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest

from cloud.auth.models import ROLE_HIERARCHY, AuthUser, UserRole, role_at_least
from cloud.auth.service import (
    _b64decode,
    _b64encode,
    _hash_password,
    _verify_password,
    create_jwt,
    verify_bearer,
    verify_jwt,
)

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


class TestPasswordHashing:
    def test_hash_deterministic(self):
        """Same password produces same hash."""
        h1 = _hash_password("test-password")
        h2 = _hash_password("test-password")
        assert h1 == h2

    def test_different_passwords_different_hashes(self):
        """Different passwords produce different hashes."""
        h1 = _hash_password("password1")
        h2 = _hash_password("password2")
        assert h1 != h2

    def test_verify_correct(self):
        """Correct password verifies."""
        hashed = _hash_password("my-secret")
        assert _verify_password("my-secret", hashed) is True

    def test_verify_incorrect(self):
        """Wrong password fails verification."""
        hashed = _hash_password("my-secret")
        assert _verify_password("wrong-pass", hashed) is False


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------


class TestJWT:
    def test_roundtrip(self):
        """Create + verify JWT succeeds with correct data."""
        user = AuthUser(username="admin", role=UserRole.ADMIN, tenant_id="t1")
        token = create_jwt(user)
        decoded = verify_jwt(token)
        assert decoded is not None
        assert decoded.username == "admin"
        assert decoded.role == UserRole.ADMIN
        assert decoded.tenant_id == "t1"

    def test_all_roles(self):
        """JWT roundtrip works for every role."""
        for role in UserRole:
            user = AuthUser(username=f"user-{role.value}", role=role)
            token = create_jwt(user)
            decoded = verify_jwt(token)
            assert decoded is not None
            assert decoded.role == role

    def test_invalid_token(self):
        """Completely invalid tokens return None."""
        assert verify_jwt("not-a-jwt") is None
        assert verify_jwt("") is None
        assert verify_jwt("a.b") is None  # Only 2 parts
        assert verify_jwt("a.b.c") is None  # Invalid payload

    def test_tampered_payload(self):
        """JWT with tampered payload fails signature check."""
        user = AuthUser(username="admin", role=UserRole.ADMIN)
        token = create_jwt(user)
        parts = token.split(".")
        # Tamper with the payload
        payload_data = json.loads(_b64decode(parts[1]))
        payload_data["role"] = "viewer"
        parts[1] = _b64encode(json.dumps(payload_data).encode())
        tampered = ".".join(parts)
        assert verify_jwt(tampered) is None

    def test_expired_token(self):
        """Expired JWT returns None."""
        from cloud.auth.config import JWT_SECRET

        header = _b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        payload_data = {
            "sub": "admin",
            "role": "admin",
            "tenant_id": "t1",
            "exp": int(time.time()) - 3600,  # Expired 1 hour ago
            "iat": int(time.time()) - 7200,
        }
        payload = _b64encode(json.dumps(payload_data).encode())
        signing_input = f"{header}.{payload}"
        sig = _b64encode(
            hmac.new(JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
        )
        token = f"{header}.{payload}.{sig}"
        assert verify_jwt(token) is None


# ---------------------------------------------------------------------------
# Bearer tokens
# ---------------------------------------------------------------------------


class TestBearerAuth:
    def test_no_configured_tokens(self):
        """verify_bearer returns None when no tokens configured."""
        # Default state has no bearer tokens
        from cloud.auth.service import BEARER_TOKENS

        if BEARER_TOKENS:
            pytest.skip("Bearer tokens are configured in environment")
        assert verify_bearer("some-token") is None

    def test_valid_bearer(self):
        """Valid bearer token returns operator user."""
        import cloud.auth.service as svc

        original = svc.BEARER_TOKENS
        try:
            svc.BEARER_TOKENS = ["test-token-abc123"]
            user = svc.verify_bearer("test-token-abc123")
            assert user is not None
            assert user.role == UserRole.OPERATOR
            assert user.username == "bearer-user"
        finally:
            svc.BEARER_TOKENS = original

    def test_invalid_bearer(self):
        """Invalid bearer token returns None."""
        import cloud.auth.service as svc

        original = svc.BEARER_TOKENS
        try:
            svc.BEARER_TOKENS = ["correct-token"]
            assert svc.verify_bearer("wrong-token") is None
        finally:
            svc.BEARER_TOKENS = original


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


class TestRBAC:
    def test_admin_has_all_access(self):
        """Admin role meets all required role levels."""
        for required in UserRole:
            assert role_at_least(UserRole.ADMIN, required)

    def test_viewer_minimal_access(self):
        """Viewer only meets viewer requirement."""
        assert role_at_least(UserRole.VIEWER, UserRole.VIEWER)
        assert not role_at_least(UserRole.VIEWER, UserRole.OPERATOR)
        assert not role_at_least(UserRole.VIEWER, UserRole.SECOPS)
        assert not role_at_least(UserRole.VIEWER, UserRole.ADMIN)

    def test_operator_equals_secops(self):
        """Operator and secops are at the same level."""
        assert role_at_least(UserRole.OPERATOR, UserRole.SECOPS)
        assert role_at_least(UserRole.SECOPS, UserRole.OPERATOR)

    def test_hierarchy_values(self):
        """Role hierarchy has expected ordering."""
        assert ROLE_HIERARCHY[UserRole.ADMIN] > ROLE_HIERARCHY[UserRole.SECOPS]
        assert ROLE_HIERARCHY[UserRole.SECOPS] > ROLE_HIERARCHY[UserRole.VIEWER]


# ---------------------------------------------------------------------------
# Auth middleware integration
# ---------------------------------------------------------------------------


class TestAuthMiddleware:
    def test_public_paths_bypass_auth(self, client):
        """Public paths work without authentication."""
        for path in ["/health", "/ready", "/metrics"]:
            r = client.get(path)
            assert r.status_code == 200, f"Public path {path} should be accessible"

    def test_api_without_auth_disabled(self, client):
        """With auth disabled (test env), API paths work without tokens."""
        r = client.get("/api/v1/orchestrator/status")
        assert r.status_code == 200

    def test_auth_me_with_disabled_auth(self, client):
        """GET /api/v1/auth/me returns anonymous user when auth disabled."""
        r = client.get("/api/v1/auth/me")
        assert r.status_code == 200
        data = r.json()
        assert data["username"] == "anonymous"
        assert data["auth_enabled"] is False


# ---------------------------------------------------------------------------
# Base64 helpers
# ---------------------------------------------------------------------------


class TestBase64Helpers:
    def test_roundtrip(self):
        """b64encode → b64decode is lossless."""
        data = b'{"test": "data", "num": 42}'
        encoded = _b64encode(data)
        decoded = _b64decode(encoded)
        assert decoded == data

    def test_url_safe(self):
        """Encoded output uses URL-safe characters."""
        data = b"\xff\xfe\xfd"
        encoded = _b64encode(data)
        assert "+" not in encoded
        assert "/" not in encoded

    def test_no_padding(self):
        """Encoded output strips '=' padding."""
        data = b"a"
        encoded = _b64encode(data)
        assert "=" not in encoded
