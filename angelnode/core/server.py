"""ANGELGRID – ANGELNODE Local HTTP Server.

Exposes the policy evaluation API on the local loopback interface.
This is the primary entry point for all local consumers — sensors,
AI shield adapters, and CLI tools.

On startup, if ANGELGRID_CLOUD_URL is configured, the server registers
with the Cloud backend, receives an initial PolicySet, and starts a
background polling loop that checks for policy updates every 60 seconds.

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
from shared.models.policy import PolicyAction, PolicySet

from .cloud_sync import CLOUD_URL, TENANT_ID, CloudSyncClient
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
sync_client: CloudSyncClient | None = None
_last_policy_sync: datetime | None = None
_agent_id: str = AGENT_ID

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
# Callbacks for CloudSyncClient
# ---------------------------------------------------------------------------

def _on_policy_update(policy_set: PolicySet) -> None:
    """Hot-reload the engine when Cloud provides a new PolicySet."""
    if engine is not None:
        engine.reload(policy_set)
        logger.info("Policy hot-reloaded from Cloud — version=%s", policy_set.version)


def _on_sync_log(details: dict) -> None:
    """Forward sync log records to the structured JSONL logger."""
    if decision_logger is not None:
        decision_logger.log_sync(details)


def _on_agent_id_update(new_agent_id: str) -> None:
    """Update the agent_id exposed by /status after Cloud registration."""
    global _agent_id
    _agent_id = new_agent_id
    logger.info("Agent ID updated from Cloud registration: %s", new_agent_id)


def _on_sync_timestamp(ts: datetime) -> None:
    """Update the last-sync timestamp exposed by /status."""
    global _last_policy_sync
    _last_policy_sync = ts


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize engine, logger, and cloud sync on startup."""
    global engine, decision_logger, sync_client, _last_policy_sync

    # 1. Load local policy (always available, even without Cloud)
    logger.info("Loading policy from %s", POLICY_FILE)
    logger.info("Loading category defaults from %s", CATEGORY_DEFAULTS_FILE)
    engine = PolicyEngine.from_file(POLICY_FILE, CATEGORY_DEFAULTS_FILE)
    decision_logger = DecisionLogger(log_path=LOG_FILE)
    _last_policy_sync = datetime.now(timezone.utc)

    # 2. If Cloud URL is configured, register and start polling
    if CLOUD_URL:
        logger.info(
            "Cloud sync enabled — url=%s, tenant=%s", CLOUD_URL, TENANT_ID,
        )
        sync_client = CloudSyncClient(
            cloud_url=CLOUD_URL,
            tenant_id=TENANT_ID,
            on_policy_update=_on_policy_update,
            on_sync_log=_on_sync_log,
            on_agent_id_update=_on_agent_id_update,
            on_sync_timestamp=_on_sync_timestamp,
        )
        # Register with Cloud (non-blocking on failure)
        await sync_client.register()
        # Start the background polling loop
        await sync_client.start_polling()
    else:
        logger.info(
            "Cloud sync disabled — set ANGELGRID_CLOUD_URL to enable"
        )

    yield

    # Shutdown: stop polling gracefully
    if sync_client is not None:
        await sync_client.stop()


app = FastAPI(
    title="ANGELNODE – Local Policy Agent",
    version="0.3.0",
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
        "agent_id": _agent_id,
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
