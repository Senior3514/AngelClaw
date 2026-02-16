"""AngelClaw Cloud – Auth configuration from environment variables."""

from __future__ import annotations

import hashlib
import os
import secrets


# Whether auth is enabled (secure by default)
AUTH_ENABLED: bool = os.environ.get("ANGELCLAW_AUTH_ENABLED", "true").lower() in ("true", "1", "yes")

# Auth mode: "local" (username/password with bcrypt) or "bearer" (static tokens)
AUTH_MODE: str = os.environ.get("ANGELCLAW_AUTH_MODE", "local")

# Local mode credentials
ADMIN_USER: str = os.environ.get("ANGELCLAW_ADMIN_USER", "admin")
ADMIN_PASSWORD: str = os.environ.get("ANGELCLAW_ADMIN_PASSWORD", "")

SECOPS_USER: str = os.environ.get("ANGELCLAW_SECOPS_USER", "")
SECOPS_PASSWORD: str = os.environ.get("ANGELCLAW_SECOPS_PASSWORD", "")

VIEWER_USER: str = os.environ.get("ANGELCLAW_VIEWER_USER", "viewer")
VIEWER_PASSWORD: str = os.environ.get("ANGELCLAW_VIEWER_PASSWORD", "")

# JWT secret — auto-generated if not set
JWT_SECRET: str = os.environ.get("ANGELCLAW_JWT_SECRET", "")
if not JWT_SECRET:
    # Deterministic fallback derived from machine identity so it survives restarts
    # but is unique per deployment. For production, always set ANGELCLAW_JWT_SECRET.
    _seed = f"angelclaw-{os.environ.get('HOSTNAME', 'local')}-jwt"
    JWT_SECRET = hashlib.sha256(_seed.encode()).hexdigest()

JWT_ALGORITHM: str = "HS256"
JWT_EXPIRE_HOURS: int = int(os.environ.get("ANGELCLAW_JWT_EXPIRE_HOURS", "24"))

# Bearer mode: comma-separated static tokens
BEARER_TOKENS: list[str] = [
    t.strip() for t in os.environ.get("ANGELCLAW_BEARER_TOKENS", "").split(",") if t.strip()
]
