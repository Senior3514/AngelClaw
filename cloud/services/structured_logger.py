"""AngelClaw Cloud – Structured JSON Logger with Correlation IDs.

Provides:
  - CorrelationContext: async-safe context variable for request-scoped IDs
  - StructuredJsonFormatter: JSON log formatter with correlation ID injection
  - setup_structured_logging(): configures the root logger
  - correlation_middleware(): FastAPI middleware for correlation ID propagation
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# ---------------------------------------------------------------------------
# Correlation ID context (async-safe)
# ---------------------------------------------------------------------------

_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")
_request_start: ContextVar[float] = ContextVar("request_start", default=0.0)


def get_correlation_id() -> str:
    """Return the current correlation ID (empty string if not in a request)."""
    return _correlation_id.get()


def set_correlation_id(cid: str) -> None:
    """Explicitly set a correlation ID (useful for background tasks)."""
    _correlation_id.set(cid)


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------


class StructuredJsonFormatter(logging.Formatter):
    """Emit log records as single-line JSON objects.

    Fields: timestamp, level, logger, correlation_id, message, + extras.
    """

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        cid = _correlation_id.get()
        if cid:
            entry["correlation_id"] = cid

        if record.exc_info and record.exc_info[1]:
            entry["exception"] = self.formatException(record.exc_info)

        # Merge any extra fields injected via `logger.info("msg", extra={...})`
        for key in (
            "component",
            "agent_id",
            "tenant_id",
            "incident_id",
            "duration_ms",
            "status_code",
            "method",
            "path",
        ):
            val = getattr(record, key, None)
            if val is not None:
                entry[key] = val

        return json.dumps(entry, default=str)


# ---------------------------------------------------------------------------
# Logger setup
# ---------------------------------------------------------------------------

_LOG_FORMAT_ENV = "ANGELCLAW_LOG_FORMAT"


def setup_structured_logging(
    level: int = logging.INFO,
    force_json: bool | None = None,
) -> None:
    """Configure the root logger for structured JSON output.

    Set ANGELCLAW_LOG_FORMAT=text to keep the default text formatter.
    """
    import os

    use_json = force_json
    if use_json is None:
        use_json = os.environ.get(_LOG_FORMAT_ENV, "json").lower() == "json"

    root = logging.getLogger()
    root.setLevel(level)

    # Remove existing handlers to avoid duplicates
    for h in root.handlers[:]:
        root.removeHandler(h)

    handler = logging.StreamHandler()
    if use_json:
        handler.setFormatter(StructuredJsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )

    root.addHandler(handler)

    # Silence noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# FastAPI correlation middleware
# ---------------------------------------------------------------------------

CORRELATION_HEADER = "X-Correlation-ID"


class CorrelationMiddleware(BaseHTTPMiddleware):
    """Injects a correlation ID into every request context.

    Reads X-Correlation-ID from the request header (for upstream tracing)
    or generates a new UUID.  The ID is available via get_correlation_id()
    throughout the request lifecycle and returned in the response header.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        cid = request.headers.get(CORRELATION_HEADER) or str(uuid.uuid4())
        _correlation_id.set(cid)
        _request_start.set(time.monotonic())

        response = await call_next(request)
        response.headers[CORRELATION_HEADER] = cid

        # Log request summary
        duration_ms = round((time.monotonic() - _request_start.get()) * 1000, 1)
        logger = logging.getLogger("angelgrid.cloud.http")
        logger.info(
            "%s %s → %d (%.1fms)",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            extra={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "component": "http",
            },
        )

        return response
