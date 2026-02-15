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
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException

from shared.models.decision import EvaluationResponse
from shared.models.event import Event

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
LOG_FILE = os.environ.get("ANGELNODE_LOG_FILE", "logs/decisions.jsonl")

# ---------------------------------------------------------------------------
# Module-level singletons (initialized in lifespan)
# ---------------------------------------------------------------------------
engine: PolicyEngine | None = None
decision_logger: DecisionLogger | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize engine and logger on startup."""
    global engine, decision_logger
    logger.info("Loading policy from %s", POLICY_FILE)
    engine = PolicyEngine.from_file(POLICY_FILE)
    decision_logger = DecisionLogger(log_path=LOG_FILE)
    yield


app = FastAPI(
    title="ANGELNODE – Local Policy Agent",
    version="0.1.0",
    lifespan=lifespan,
)

# Mount the AI shield adapter so the full agent exposes both /evaluate
# and /ai/openclaw/evaluate_tool from a single process.
from angelnode.ai_shield.openclaw_adapter import router as openclaw_router  # noqa: E402

app.include_router(openclaw_router)


@app.get("/health")
async def health():
    """Liveness probe."""
    return {
        "status": "ok",
        "policy_version": engine.policy_version if engine else None,
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

    # Log every decision for audit trail
    if decision_logger is not None:
        decision_logger.log(event, decision)

    return EvaluationResponse(event_id=event.id, decision=decision)
