"""Tests for security middleware: rate limiting, security headers, body size limits."""

from __future__ import annotations

import time
from unittest.mock import patch

from cloud.middleware.security import (
    MAX_BODY_SIZE,
    RATE_LIMIT,
    RATE_WINDOW,
    _check_rate_limit,
    _rate_windows,
)


class TestRateLimiting:

    def setup_method(self):
        """Clear rate limit state between tests."""
        _rate_windows.clear()

    def test_within_limit(self):
        """Requests within limit pass."""
        for _ in range(5):
            assert _check_rate_limit("10.0.0.1") is True

    def test_exceeds_limit(self):
        """Requests exceeding limit are rejected."""
        ip = "10.0.0.99"
        for _ in range(RATE_LIMIT):
            _check_rate_limit(ip)
        assert _check_rate_limit(ip) is False

    def test_different_ips_independent(self):
        """Each IP has its own rate limit window."""
        for _ in range(RATE_LIMIT):
            _check_rate_limit("10.0.0.1")
        # Different IP should still be fine
        assert _check_rate_limit("10.0.0.2") is True

    def test_window_expiry(self):
        """Old entries are pruned — requests succeed after window expires."""
        ip = "10.0.0.50"
        # Fill the window
        for _ in range(RATE_LIMIT):
            _check_rate_limit(ip)
        assert _check_rate_limit(ip) is False

        # Manually expire all entries
        _rate_windows[ip] = [time.monotonic() - RATE_WINDOW - 1]
        assert _check_rate_limit(ip) is True


class TestSecurityHeaders:
    """Test that security middleware adds proper headers to responses."""

    def test_headers_present(self, client):
        """Responses include required security headers."""
        r = client.get("/health")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"
        assert r.headers.get("X-Frame-Options") == "DENY"
        assert r.headers.get("X-XSS-Protection") == "1; mode=block"
        assert r.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert r.headers.get("Cache-Control") == "no-store"

    def test_health_exempt_from_rate_limit(self, client):
        """Health endpoint is exempt from rate limiting."""
        _rate_windows.clear()
        for _ in range(RATE_LIMIT + 10):
            r = client.get("/health")
        assert r.status_code == 200


class TestBodySizeLimit:

    def test_oversized_post_rejected(self, client):
        """POST with Content-Length exceeding limit returns 413."""
        # We send a header claiming a huge body
        r = client.post(
            "/api/v1/events/batch",
            headers={"Content-Length": str(MAX_BODY_SIZE + 1)},
            content=b"{}",
        )
        assert r.status_code == 413

    def test_normal_post_accepted(self, client):
        """POST with normal body size is accepted (may fail validation, but not 413)."""
        r = client.post(
            "/api/v1/events/batch",
            json={"agent_id": "test", "events": []},
        )
        # Should be 200 (accepted) not 413
        assert r.status_code != 413


class TestRateLimitEndpoint:

    def setup_method(self):
        _rate_windows.clear()

    def test_rate_limit_429(self, client):
        """API endpoint returns 429 when rate limited."""
        _rate_windows.clear()
        # Exhaust rate limit by filling the window for testclient IP
        ip = "testclient"
        _rate_windows[ip] = [time.monotonic() for _ in range(RATE_LIMIT)]

        r = client.get("/api/v1/orchestrator/status")
        assert r.status_code == 429
        assert "Rate limit" in r.json()["detail"]
        assert "Retry-After" in r.headers
