"""ANGELGRID – LLM Proxy API routes.

Provides a /api/v1/llm/chat endpoint that proxies requests to a
configured LLM backend (Ollama, OpenAI-compatible) with a mandatory
security-analyst system prompt.

SECURITY NOTES:
- The LLM proxy is disabled by default (LLM_ENABLED=false).
- The system prompt is always injected first and cannot be overridden.
- The proxy is read-only: it never modifies policies, events, or DB state.
- All user prompts and context are scanned and redacted for secrets BEFORE
  being sent to the LLM backend.
- LLM responses are scanned and redacted before being returned to the user.
- All requests and responses are logged for audit.

SECRET PROTECTION PIPELINE:
  User prompt → redact secrets → inject system prompt → send to LLM
  LLM response → redact secrets → return to user
  At no point does a raw secret value reach the LLM or the user.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from shared.security.secret_scanner import contains_secret, redact_dict, redact_secrets

from .config import (
    LLM_BACKEND_URL,
    LLM_ENABLED,
    LLM_MAX_TOKENS,
    LLM_MODEL,
    LLM_SYSTEM_PROMPT,
    LLM_TIMEOUT_SECONDS,
)

logger = logging.getLogger("angelgrid.cloud.llm_proxy")

router = APIRouter(prefix="/api/v1/llm", tags=["LLM Proxy"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class LLMChatRequest(BaseModel):
    """Request body for the LLM chat endpoint."""

    prompt: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="The user's question or analysis request",
    )
    context: Optional[dict[str, Any]] = Field(
        default=None,
        description="Optional read-only context (events, incidents, policies) as structured data",
    )
    options: Optional[dict[str, Any]] = Field(
        default=None,
        description="Optional model parameters (temperature, top_p, etc.)",
    )


class LLMChatResponse(BaseModel):
    """Response from the LLM chat endpoint."""

    answer: str = Field(description="The LLM's response")
    used_model: str = Field(description="Model identifier that generated the response")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Response metadata (latency_ms, token counts, etc.)",
    )


# ---------------------------------------------------------------------------
# POST /api/v1/llm/chat
# ---------------------------------------------------------------------------

@router.post(
    "/chat",
    response_model=LLMChatResponse,
    summary="Chat with ANGELGRID AI security analyst",
    description=(
        "Sends a prompt to the configured LLM backend with an enforced "
        "read-only security-analyst system prompt. All inputs and outputs "
        "are scanned and redacted for secrets. The LLM can analyze events, "
        "explain decisions, and suggest policy tightening — but cannot "
        "modify any state or expose secrets. Disabled by default."
    ),
)
async def llm_chat(req: LLMChatRequest) -> LLMChatResponse:
    if not LLM_ENABLED:
        raise HTTPException(
            status_code=503,
            detail=(
                "LLM proxy is disabled. Set LLM_ENABLED=true and configure "
                "LLM_BACKEND_URL to enable it."
            ),
        )

    # SECURITY: Redact secrets from user prompt before sending to LLM
    safe_prompt = redact_secrets(req.prompt)
    prompt_had_secrets = safe_prompt != req.prompt
    if prompt_had_secrets:
        logger.warning("[LLM PROXY SECRET BLOCK] Secrets detected and redacted from user prompt before sending to LLM")

    # Build the messages array with the mandatory system prompt first
    messages: list[dict[str, str]] = [
        {"role": "system", "content": LLM_SYSTEM_PROMPT},
    ]

    # Inject optional context dict — REDACTED for secrets first
    if req.context:
        import json as _json

        safe_context = redact_dict(req.context)
        if safe_context != req.context:
            logger.warning("Secrets detected and redacted from LLM context")
        context_str = _json.dumps(safe_context, indent=2, default=str)
        messages.append({
            "role": "system",
            "content": f"--- READ-ONLY CONTEXT ---\n{context_str}\n--- END CONTEXT ---",
        })

    messages.append({"role": "user", "content": safe_prompt})

    # Build the request payload (OpenAI-compatible format, works with Ollama)
    payload: dict[str, Any] = {
        "model": LLM_MODEL,
        "messages": messages,
        "stream": False,
        "options": {
            "num_predict": LLM_MAX_TOKENS,
        },
    }

    # Merge caller-provided options (but never override model or system prompt)
    if req.options:
        safe_options = {k: v for k, v in req.options.items() if k not in ("model", "messages", "system")}
        payload["options"].update(safe_options)

    logger.info(
        "LLM request — model=%s, prompt_len=%d, context_len=%d",
        LLM_MODEL,
        len(safe_prompt),
        len(req.context) if req.context else 0,  # number of keys
    )

    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=LLM_TIMEOUT_SECONDS) as client:
            resp = await client.post(
                f"{LLM_BACKEND_URL}/api/chat",
                json=payload,
            )
            resp.raise_for_status()
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail=f"LLM backend timed out after {LLM_TIMEOUT_SECONDS}s",
        )
    except httpx.HTTPStatusError as exc:
        logger.error("LLM backend error: %s %s", exc.response.status_code, exc.response.text[:200])
        raise HTTPException(
            status_code=502,
            detail=f"LLM backend returned {exc.response.status_code}",
        )
    except httpx.ConnectError:
        raise HTTPException(
            status_code=502,
            detail=f"Cannot connect to LLM backend at {LLM_BACKEND_URL}",
        )

    latency_ms = int((time.monotonic() - start) * 1000)
    body = resp.json()

    # Ollama /api/chat response format
    answer = body.get("message", {}).get("content", "")
    if not answer:
        # Fallback for OpenAI-compatible format
        choices = body.get("choices", [])
        if choices:
            answer = choices[0].get("message", {}).get("content", "")

    # SECURITY: Redact any secrets from the LLM response before returning
    safe_answer = redact_secrets(answer or "(empty response from LLM)")
    if safe_answer != answer:
        logger.warning("[LLM PROXY SECRET BLOCK] Secrets detected and redacted from LLM response before returning to user")

    logger.info("LLM response — latency=%dms, answer_len=%d", latency_ms, len(safe_answer))

    return LLMChatResponse(
        answer=safe_answer,
        used_model=LLM_MODEL,
        metadata={
            "latency_ms": latency_ms,
            "backend_url": LLM_BACKEND_URL,
            "llm_enabled": True,
            "secrets_redacted_from_prompt": prompt_had_secrets,
        },
    )
