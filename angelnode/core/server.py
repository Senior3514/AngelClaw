"""ANGELGRID – ANGELNODE Local HTTP Server.

Exposes the policy evaluation API on the local loopback interface.
This is the primary entry point for all local consumers — sensors,
AI shield adapters, and CLI tools.

SECURITY NOTE: The server binds to 127.0.0.1 by default.  It must NOT
be exposed to external networks without authentication.
"""

from __future__ import annotations

import logging
import os
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException

from shared.models.decision import EvaluationResponse
from shared.models.event import Event
from shared.models.policy import PolicyAction

from .engine import PolicyEngine
from .structured_logger import DecisionLogger

logger = logging.getLogger("angelnode.server")

# ---------------------------------------------------------------------------
# Configuration via environment variables
# ---------------------------------------------------------------------------
POLICY_FILE = os.environ.get(
    "ANGELNODE_POLICY_FILE",
    str(Path(__file__).resolve().parent.parent / "config" / "default_policy.json"),
)
CATEGORY_DEFAULTS_FILE = os.environ.get(
    "ANGELNODE_CATEGORY_DEFAULTS_FILE",
    str(Path(__file__).resolve().parent.parent / "config" / "category_defaults.json"),
)
LOG_FILE = os.environ.get("ANGELNODE_LOG_FILE", "logs/decisions.jsonl")
AGENT_ID = os.environ.get("ANGELNODE_AGENT_ID", "local-dev-agent")

# Optional bearer token for the /status endpoint.
# SECURITY: If set, /status requires X-ANGELNODE-TOKEN header to match.
# If unset, /status is open (suitable for local-only loopback binding).
STATUS_TOKEN: Optional[str] = os.environ.get("ANGELNODE_STATUS_TOKEN")

# ---------------------------------------------------------------------------
# Module-level singletons (initialized in lifespan)
# ---------------------------------------------------------------------------
engine: PolicyEngine | None = None
decision_logger: DecisionLogger | None = None
_last_policy_sync: datetime | None = None

# Thread-safe evaluation counters for the /status endpoint
_counters_lock = threading.Lock()
_counters = {
    "total_evaluations": 0,
    "allow": 0,
    "block": 0,
    "alert": 0,
    "audit": 0,
}


def _increment_counter(action: PolicyAction) -> None:
    with _counters_lock:
        _counters["total_evaluations"] += 1
        _counters[action.value] += 1


def _get_counters() -> dict:
    with _counters_lock:
        return dict(_counters)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize engine and logger on startup."""
    global engine, decision_logger, _last_policy_sync
    logger.info("Loading policy from %s", POLICY_FILE)
    logger.info("Loading category defaults from %s", CATEGORY_DEFAULTS_FILE)
    engine = PolicyEngine.from_file(POLICY_FILE, CATEGORY_DEFAULTS_FILE)
    decision_logger = DecisionLogger(log_path=LOG_FILE)
    _last_policy_sync = datetime.now(timezone.utc)
    yield


app = FastAPI(
    title="ANGELNODE – Local Policy Agent",
    version="0.2.0",
    lifespan=lifespan,
)

# Mount the AI shield adapter so the full agent exposes both /evaluate
# and /ai/openclaw/evaluate_tool from a single process.
from angelnode.ai_shield.openclaw_adapter import router as openclaw_router  # noqa: E402

app.include_router(openclaw_router)


# ---------------------------------------------------------------------------
# Token auth dependency for /status
# ---------------------------------------------------------------------------

async def _verify_status_token(
    x_angelnode_token: Optional[str] = Header(default=None),
) -> None:
    """If ANGELNODE_STATUS_TOKEN is configured, require a matching header.

    SECURITY NOTE: This is a simple bearer-token check for local use.
    The /status endpoint is bound to 127.0.0.1 by default, so the token
    is a defense-in-depth measure, not the sole access control.
    """
    if STATUS_TOKEN is None:
        # No token configured — allow (loopback only)
        return
    if x_angelnode_token != STATUS_TOKEN:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing X-ANGELNODE-TOKEN",
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    """Liveness probe."""
    return {
        "status": "ok",
        "policy_version": engine.policy_version if engine else None,
    }


@app.get("/status")
async def status(_: None = Depends(_verify_status_token)):
    """Return agent status, counters, and policy metadata.

    SECURITY NOTE: This endpoint is strictly read-only.  It does not
    expose secrets, tokens, database credentials, or policy rule content.
    It is bound to 127.0.0.1 by default and optionally token-protected.
    """
    return {
        "agent_id": AGENT_ID,
        "policy_version": engine.policy_version if engine else None,
        "last_policy_sync": _last_policy_sync.isoformat() if _last_policy_sync else None,
        "health": "ok" if engine else "degraded",
        "counters": _get_counters(),
    }


@app.post("/evaluate", response_model=EvaluationResponse)
async def evaluate(event: Event):
    """Evaluate an event against the active PolicySet.

    Accepts an Event JSON body, runs it through the policy engine, logs the
    decision, and returns the result.
    """
    if engine is None:
        raise HTTPException(status_code=503, detail="Engine not initialized")

    decision = engine.evaluate(event)

    # Track counters for /status
    _increment_counter(decision.action)

    # Log every decision for audit trail
    if decision_logger is not None:
        decision_logger.log(event, decision)

    return EvaluationResponse(event_id=event.id, decision=decision)
