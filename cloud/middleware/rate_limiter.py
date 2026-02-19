"""AngelClaw Cloud – Adaptive Rate Limiter.

Provides:
  - Token-bucket algorithm with per-role tier enforcement
  - Per-endpoint burst allowance (2x tier limit for short bursts)
  - X-RateLimit-Limit / X-RateLimit-Remaining / X-RateLimit-Reset headers
  - Thread-safe in-memory state (no external dependencies)
  - Exempt paths: /health, /ready, /metrics
  - GET /api/v1/system/rate-limits endpoint for config and per-IP usage stats

Role tiers:
  ADMIN    — 300 req/min
  SECOPS   — 200 req/min
  VIEWER   — 100 req/min
  ANONYMOUS — 60 req/min
  SERVICE  — 500 req/min
"""

from __future__ import annotations

import logging
import math
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger("angelgrid.cloud.rate_limiter")

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class RoleTierName(str, Enum):
    """Supported rate-limit role tiers."""

    ADMIN = "admin"
    SECOPS = "secops"
    VIEWER = "viewer"
    ANONYMOUS = "anonymous"
    SERVICE = "service"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RateLimitTier:
    """Configuration for a single rate-limit tier.

    Attributes:
        name:           Tier identifier (matches RoleTierName).
        requests_per_minute: Sustained request ceiling per minute.
        burst_limit:    Maximum burst allowance (2x sustained by default).
        refill_rate:    Tokens added per second (derived from requests_per_minute).
    """

    name: RoleTierName
    requests_per_minute: int
    burst_limit: int = 0  # 0 means auto-compute as 2x requests_per_minute

    def __post_init__(self) -> None:
        # frozen=True requires object.__setattr__ for post-init fixups
        if self.burst_limit == 0:
            object.__setattr__(self, "burst_limit", self.requests_per_minute * 2)

    @property
    def refill_rate(self) -> float:
        """Tokens added per second."""
        return self.requests_per_minute / 60.0


# ---------------------------------------------------------------------------
# Default tier table
# ---------------------------------------------------------------------------

DEFAULT_TIERS: dict[RoleTierName, RateLimitTier] = {
    RoleTierName.ADMIN: RateLimitTier(
        name=RoleTierName.ADMIN, requests_per_minute=300,
    ),
    RoleTierName.SECOPS: RateLimitTier(
        name=RoleTierName.SECOPS, requests_per_minute=200,
    ),
    RoleTierName.VIEWER: RateLimitTier(
        name=RoleTierName.VIEWER, requests_per_minute=100,
    ),
    RoleTierName.ANONYMOUS: RateLimitTier(
        name=RoleTierName.ANONYMOUS, requests_per_minute=60,
    ),
    RoleTierName.SERVICE: RateLimitTier(
        name=RoleTierName.SERVICE, requests_per_minute=500,
    ),
}

# ---------------------------------------------------------------------------
# Paths exempt from rate limiting
# ---------------------------------------------------------------------------

EXEMPT_PATHS: frozenset[str] = frozenset({"/health", "/ready", "/metrics"})

# ---------------------------------------------------------------------------
# Token bucket (per-key)
# ---------------------------------------------------------------------------


@dataclass
class TokenBucket:
    """Thread-safe token-bucket for a single client key.

    The bucket starts full (at ``burst_limit`` tokens) and refills at
    ``refill_rate`` tokens per second, up to ``burst_limit``.
    """

    tier: RateLimitTier
    tokens: float = 0.0
    last_refill: float = 0.0
    total_requests: int = 0
    total_rejected: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        # Start the bucket full
        if self.tokens == 0.0:
            self.tokens = float(self.tier.burst_limit)
        if self.last_refill == 0.0:
            self.last_refill = time.monotonic()

    # -- public API ---------------------------------------------------------

    def consume(self, now: float | None = None) -> bool:
        """Try to consume one token.  Returns True if allowed."""
        with self._lock:
            if now is None:
                now = time.monotonic()
            self._refill(now)
            self.total_requests += 1
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            self.total_rejected += 1
            return False

    def peek(self, now: float | None = None) -> tuple[int, int, float]:
        """Return (limit, remaining, reset_seconds) without consuming.

        ``reset_seconds`` is the time until at least one new token is
        available (0.0 when tokens > 0).
        """
        with self._lock:
            if now is None:
                now = time.monotonic()
            self._refill(now)
            limit = self.tier.requests_per_minute
            remaining = max(0, int(self.tokens))
            if self.tokens >= 1.0:
                reset_seconds = 0.0
            else:
                # Time until next whole token
                deficit = 1.0 - (self.tokens % 1.0) if self.tokens > 0 else 1.0
                reset_seconds = (
                    deficit / self.tier.refill_rate
                    if self.tier.refill_rate > 0
                    else 60.0
                )
            return limit, remaining, reset_seconds

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-serialisable snapshot of the bucket state."""
        with self._lock:
            now = time.monotonic()
            self._refill(now)
            return {
                "tier": self.tier.name.value,
                "tokens_remaining": round(self.tokens, 2),
                "burst_limit": self.tier.burst_limit,
                "requests_per_minute": self.tier.requests_per_minute,
                "total_requests": self.total_requests,
                "total_rejected": self.total_rejected,
            }

    # -- internals ----------------------------------------------------------

    def _refill(self, now: float) -> None:
        """Add tokens accrued since the last refill (caller holds lock)."""
        elapsed = now - self.last_refill
        if elapsed <= 0:
            return
        new_tokens = elapsed * self.tier.refill_rate
        self.tokens = min(self.tokens + new_tokens, float(self.tier.burst_limit))
        self.last_refill = now


# ---------------------------------------------------------------------------
# Adaptive Rate Limiter (singleton)
# ---------------------------------------------------------------------------


class AdaptiveRateLimiter:
    """In-memory, thread-safe, per-role adaptive rate limiter.

    Each unique ``(client_ip, role)`` pair gets its own :class:`TokenBucket`.
    The role determines which :class:`RateLimitTier` governs the bucket.

    Usage::

        limiter = AdaptiveRateLimiter()
        allowed, headers = limiter.check("10.0.0.1", RoleTierName.VIEWER, "/api/v1/events")
        if not allowed:
            return JSONResponse(status_code=429, headers=headers, ...)
    """

    def __init__(
        self,
        tiers: dict[RoleTierName, RateLimitTier] | None = None,
        exempt_paths: frozenset[str] | None = None,
    ) -> None:
        self._tiers: dict[RoleTierName, RateLimitTier] = dict(tiers or DEFAULT_TIERS)
        self._exempt_paths: frozenset[str] = (
            exempt_paths if exempt_paths is not None else EXEMPT_PATHS
        )
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    # -- configuration accessors -------------------------------------------

    @property
    def tiers(self) -> dict[RoleTierName, RateLimitTier]:
        return dict(self._tiers)

    @property
    def exempt_paths(self) -> frozenset[str]:
        return self._exempt_paths

    # -- core API -----------------------------------------------------------

    def _bucket_key(self, client_ip: str, role: RoleTierName) -> str:
        return f"{client_ip}:{role.value}"

    def _get_or_create_bucket(self, client_ip: str, role: RoleTierName) -> TokenBucket:
        key = self._bucket_key(client_ip, role)
        # Fast path (no write lock)
        bucket = self._buckets.get(key)
        if bucket is not None:
            return bucket
        # Slow path — create under write lock
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is not None:
                return bucket
            tier = self._tiers.get(role)
            if tier is None:
                tier = self._tiers[RoleTierName.ANONYMOUS]
            bucket = TokenBucket(tier=tier)
            self._buckets[key] = bucket
            return bucket

    def is_exempt(self, path: str) -> bool:
        """Return True if *path* is exempt from rate limiting."""
        return path in self._exempt_paths

    def check(
        self,
        client_ip: str,
        role: RoleTierName,
        path: str,
    ) -> tuple[bool, dict[str, str]]:
        """Check if the request is allowed.

        Returns:
            (allowed, headers) — *headers* always contains the three
            X-RateLimit-* headers and should be merged into the response
            regardless of whether the request was allowed or rejected.
        """
        # Exempt paths always pass
        if self.is_exempt(path):
            return True, {}

        bucket = self._get_or_create_bucket(client_ip, role)
        now = time.monotonic()
        allowed = bucket.consume(now)
        limit, remaining, reset_seconds = bucket.peek(now)

        headers = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(math.ceil(reset_seconds)),
        }

        if not allowed:
            headers["Retry-After"] = str(math.ceil(reset_seconds))
            logger.warning(
                "Rate limit exceeded for %s (role=%s, path=%s)",
                client_ip,
                role.value,
                path,
            )

        return allowed, headers

    # -- stats / introspection ----------------------------------------------

    def get_usage_stats(self) -> dict[str, Any]:
        """Return per-key usage statistics (for the admin endpoint)."""
        stats: dict[str, Any] = {}
        # Snapshot under the global lock to get a consistent list of keys
        with self._lock:
            keys = list(self._buckets.keys())

        for key in keys:
            bucket = self._buckets.get(key)
            if bucket is not None:
                stats[key] = bucket.snapshot()
        return stats

    def get_config(self) -> dict[str, Any]:
        """Return the current tier configuration as a JSON-friendly dict."""
        return {
            "tiers": {
                name.value: {
                    "requests_per_minute": tier.requests_per_minute,
                    "burst_limit": tier.burst_limit,
                    "refill_rate_per_second": round(tier.refill_rate, 4),
                }
                for name, tier in self._tiers.items()
            },
            "exempt_paths": sorted(self._exempt_paths),
        }

    def reset(self, client_ip: str | None = None) -> int:
        """Reset buckets.  If *client_ip* is given, reset only that IP's
        buckets; otherwise reset all.  Returns the number of buckets cleared.
        """
        with self._lock:
            if client_ip is None:
                count = len(self._buckets)
                self._buckets.clear()
                return count
            to_remove = [k for k in self._buckets if k.startswith(f"{client_ip}:")]
            for k in to_remove:
                del self._buckets[k]
            return len(to_remove)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

adaptive_rate_limiter = AdaptiveRateLimiter()


# ---------------------------------------------------------------------------
# Helper: resolve role from request
# ---------------------------------------------------------------------------


def resolve_role(request: Any) -> RoleTierName:
    """Extract the :class:`RoleTierName` from a FastAPI/Starlette request.

    Falls back to ANONYMOUS if no auth_user is attached.  Recognises the
    ``operator`` role from :mod:`cloud.auth.models` and maps it to SECOPS.
    Also maps the ``SERVICE`` role from internal service tokens.
    """
    user = getattr(getattr(request, "state", None), "auth_user", None)
    if user is None:
        return RoleTierName.ANONYMOUS

    role_value = getattr(user, "role", None)
    if role_value is None:
        return RoleTierName.ANONYMOUS

    # Support both enum and plain string
    role_str = role_value.value if hasattr(role_value, "value") else str(role_value)
    role_str = role_str.lower()

    _ROLE_MAP: dict[str, RoleTierName] = {
        "admin": RoleTierName.ADMIN,
        "secops": RoleTierName.SECOPS,
        "operator": RoleTierName.SECOPS,   # operator → secops tier
        "viewer": RoleTierName.VIEWER,
        "service": RoleTierName.SERVICE,
    }
    return _ROLE_MAP.get(role_str, RoleTierName.ANONYMOUS)


# ---------------------------------------------------------------------------
# GET /api/v1/system/rate-limits — config + per-IP usage stats
# ---------------------------------------------------------------------------


def get_rate_limits_endpoint() -> dict[str, Any]:
    """Handler for ``GET /api/v1/system/rate-limits``.

    Returns the current tier configuration and per-IP bucket usage stats.
    Can be mounted directly as a FastAPI route::

        @app.get("/api/v1/system/rate-limits")
        def rate_limits():
            return get_rate_limits_endpoint()
    """
    config = adaptive_rate_limiter.get_config()
    usage = adaptive_rate_limiter.get_usage_stats()
    return {
        "config": config,
        "usage": usage,
    }
