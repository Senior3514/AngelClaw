"""AngelClaw Cloud – Security Middleware.

Provides:
  - Rate limiting (per-IP, sliding window)
  - CORS configuration
  - Input size limiting
  - Security headers
"""

from __future__ import annotations

import os
import time
from collections import defaultdict

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------

# Requests per minute per IP
RATE_LIMIT = int(os.environ.get("ANGELCLAW_RATE_LIMIT", "120"))
RATE_WINDOW = 60  # seconds

# Per-IP sliding window counters
_rate_windows: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(client_ip: str) -> bool:
    """Return True if the request is within rate limits."""
    now = time.monotonic()
    window = _rate_windows[client_ip]

    # Prune old entries
    cutoff = now - RATE_WINDOW
    _rate_windows[client_ip] = [t for t in window if t > cutoff]

    if len(_rate_windows[client_ip]) >= RATE_LIMIT:
        return False

    _rate_windows[client_ip].append(now)
    return True


# Paths exempt from rate limiting
_RATE_EXEMPT = {"/health", "/ready", "/metrics"}

# Max request body size (1 MB)
MAX_BODY_SIZE = int(os.environ.get("ANGELCLAW_MAX_BODY_SIZE", str(1024 * 1024)))


# ---------------------------------------------------------------------------
# Setup function — call once on app startup
# ---------------------------------------------------------------------------


def setup_security_middleware(app: FastAPI) -> None:
    """Attach all security middleware to the FastAPI app."""

    # 1. CORS
    allowed_origins = os.environ.get("ANGELCLAW_CORS_ORIGINS", "*").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in allowed_origins],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Correlation-ID"],
    )

    # 2. Rate limiting + security headers + body size
    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        path = request.url.path

        # Rate limiting (skip exempt paths)
        if path not in _RATE_EXEMPT:
            client_ip = request.client.host if request.client else "unknown"
            if not _check_rate_limit(client_ip):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Try again later."},
                    headers={"Retry-After": str(RATE_WINDOW)},
                )

        # Body size check for POST/PUT
        if request.method in ("POST", "PUT"):
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > MAX_BODY_SIZE:
                return JSONResponse(
                    status_code=413,
                    content={"detail": f"Request body too large (max {MAX_BODY_SIZE} bytes)"},
                )

        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"

        # V2.4 — Adaptive rate limit headers
        try:
            from cloud.middleware.rate_limiter import adaptive_rate_limiter
            rl_info = adaptive_rate_limiter.get_status()
            response.headers["X-RateLimit-Limit"] = str(rl_info.get("default_limit", RATE_LIMIT))
        except Exception:
            pass

        return response
