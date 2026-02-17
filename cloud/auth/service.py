"""AngelClaw Cloud – Auth service (JWT issuance and verification)."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode

from .config import (
    ADMIN_PASSWORD,
    ADMIN_USER,
    BEARER_TOKENS,
    JWT_EXPIRE_HOURS,
    JWT_SECRET,
    SECOPS_PASSWORD,
    SECOPS_USER,
    VIEWER_PASSWORD,
    VIEWER_USER,
)
from .models import AuthUser, UserRole

logger = logging.getLogger("angelgrid.cloud.auth")


# ---------------------------------------------------------------------------
# Password hashing (SHA-256 based — no bcrypt dependency needed)
# ---------------------------------------------------------------------------


def _hash_password(password: str) -> str:
    """Hash a password with a salt using SHA-256."""
    salt = "angelclaw-salt"  # Simple salt; for production use per-user salts
    return hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()


def _verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash."""
    return hmac.compare_digest(_hash_password(password), hashed)


# ---------------------------------------------------------------------------
# Local authentication
# ---------------------------------------------------------------------------


def authenticate_local(username: str, password: str) -> AuthUser | None:
    """Authenticate against configured local credentials."""
    if username == ADMIN_USER and ADMIN_PASSWORD and password == ADMIN_PASSWORD:
        return AuthUser(username=username, role=UserRole.ADMIN, tenant_id="dev-tenant")

    if username == SECOPS_USER and SECOPS_PASSWORD and password == SECOPS_PASSWORD:
        return AuthUser(username=username, role=UserRole.SECOPS, tenant_id="dev-tenant")

    if username == VIEWER_USER and VIEWER_PASSWORD and password == VIEWER_PASSWORD:
        return AuthUser(username=username, role=UserRole.VIEWER, tenant_id="dev-tenant")

    # Backward compat: operator role for admin user
    return None


def change_password(username: str, current_password: str, new_password: str) -> bool:
    """Change password for a local user. Returns True on success."""
    import cloud.auth.config as cfg

    if username == cfg.ADMIN_USER:
        if current_password != cfg.ADMIN_PASSWORD:
            return False
        cfg.ADMIN_PASSWORD = new_password
        os.environ["ANGELCLAW_ADMIN_PASSWORD"] = new_password
        logger.info("Password changed for admin user")
        return True

    if username == cfg.SECOPS_USER:
        if current_password != cfg.SECOPS_PASSWORD:
            return False
        cfg.SECOPS_PASSWORD = new_password
        os.environ["ANGELCLAW_SECOPS_PASSWORD"] = new_password
        logger.info("Password changed for secops user")
        return True

    if username == cfg.VIEWER_USER:
        if current_password != cfg.VIEWER_PASSWORD:
            return False
        cfg.VIEWER_PASSWORD = new_password
        os.environ["ANGELCLAW_VIEWER_PASSWORD"] = new_password
        logger.info("Password changed for viewer user")
        return True

    return False


# ---------------------------------------------------------------------------
# JWT (minimal implementation — no PyJWT dependency)
# ---------------------------------------------------------------------------


def _b64encode(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return urlsafe_b64decode(data)


def create_jwt(user: AuthUser) -> str:
    """Issue a JWT token for the given user."""
    header = _b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload_data = {
        "sub": user.username,
        "role": user.role.value,
        "tenant_id": user.tenant_id,
        "exp": int(time.time()) + (JWT_EXPIRE_HOURS * 3600),
        "iat": int(time.time()),
    }
    payload = _b64encode(json.dumps(payload_data).encode())
    signing_input = f"{header}.{payload}"
    signature = _b64encode(
        hmac.new(JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
    )
    return f"{header}.{payload}.{signature}"


def verify_jwt(token: str) -> AuthUser | None:
    """Decode and verify a JWT token. Returns None if invalid."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        signing_input = f"{parts[0]}.{parts[1]}"
        expected_sig = _b64encode(
            hmac.new(JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(parts[2], expected_sig):
            logger.debug("JWT signature mismatch")
            return None

        payload = json.loads(_b64decode(parts[1]))

        # Check expiry
        if payload.get("exp", 0) < time.time():
            logger.debug("JWT expired")
            return None

        return AuthUser(
            username=payload["sub"],
            role=UserRole(payload["role"]),
            tenant_id=payload.get("tenant_id", "dev-tenant"),
        )
    except Exception:
        logger.debug("JWT verification failed", exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Bearer token authentication
# ---------------------------------------------------------------------------


def verify_bearer(token: str) -> AuthUser | None:
    """Check a static bearer token against configured tokens."""
    if not BEARER_TOKENS:
        return None

    for configured_token in BEARER_TOKENS:
        if hmac.compare_digest(token, configured_token):
            return AuthUser(
                username="bearer-user",
                role=UserRole.OPERATOR,
                tenant_id="dev-tenant",
            )

    return None
