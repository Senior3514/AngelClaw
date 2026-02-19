"""AngelClaw V5.0 — Transcendence: AI Model Orchestrator.

Multi-model AI orchestration engine that manages a registry of AI models,
routes requests to the best-fit model based on capability matching, and
tracks per-model performance metrics for intelligent load balancing.

Features:
  - Model registry with capability tagging and priority ordering
  - Capability-based request routing with fallback
  - Per-model performance tracking (latency, success/failure counts)
  - Health monitoring and automatic model disabling on failure threshold
  - Per-tenant isolation and analytics
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.ai_orchestrator")

# Maximum consecutive failures before a model is auto-disabled
_MAX_CONSECUTIVE_FAILURES = 5


class AIModel(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    name: str
    model_type: str  # llm, vision, embedding, classification, anomaly, speech
    provider: str  # openai, anthropic, local, huggingface, azure, google
    endpoint: str | None = None
    capabilities: list[str] = []  # e.g. ["text-generation", "summarization", "code"]
    config: dict[str, Any] = {}
    priority: int = 5  # 1 (highest) to 10 (lowest)
    enabled: bool = True
    # Performance metrics
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    consecutive_failures: int = 0
    total_latency_ms: float = 0.0
    avg_latency_ms: float = 0.0
    last_used_at: datetime | None = None
    last_error: str | None = None
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RouteResult(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    model_id: str
    model_name: str
    provider: str
    capability: str
    status: str = "routed"  # routed, success, failed, no_model
    latency_ms: float = 0.0
    payload: dict[str, Any] = {}
    response: dict[str, Any] = {}
    routed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AIOrchestorService:
    """Multi-model AI orchestration with capability-based routing."""

    def __init__(self) -> None:
        self._models: dict[str, AIModel] = {}
        self._tenant_models: dict[str, list[str]] = defaultdict(list)
        self._route_history: dict[str, list[RouteResult]] = defaultdict(list)
        # Capability index: capability -> [model_id, ...]
        self._capability_index: dict[str, list[str]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Model Registry
    # ------------------------------------------------------------------

    def register_model(
        self,
        tenant_id: str,
        name: str,
        model_type: str,
        provider: str,
        endpoint: str | None = None,
        capabilities: list[str] | None = None,
        config: dict | None = None,
        priority: int = 5,
    ) -> dict:
        """Register a new AI model in the orchestrator registry."""
        caps = capabilities or []

        model = AIModel(
            tenant_id=tenant_id,
            name=name,
            model_type=model_type,
            provider=provider,
            endpoint=endpoint,
            capabilities=caps,
            config=config or {},
            priority=max(1, min(10, priority)),
        )

        self._models[model.id] = model
        self._tenant_models[tenant_id].append(model.id)

        # Update capability index
        for cap in caps:
            self._capability_index[cap].append(model.id)

        logger.info(
            "[AI_ORCH] Registered model '%s' (%s/%s) with capabilities %s for %s",
            name, model_type, provider, caps, tenant_id,
        )
        return model.model_dump(mode="json")

    def get_model(self, model_id: str) -> dict | None:
        """Get a single model by ID."""
        model = self._models.get(model_id)
        return model.model_dump(mode="json") if model else None

    def list_models(
        self,
        tenant_id: str,
        model_type: str | None = None,
        capability: str | None = None,
        enabled_only: bool = False,
    ) -> list[dict]:
        """List all models for a tenant with optional filtering."""
        results = []
        for mid in self._tenant_models.get(tenant_id, []):
            model = self._models.get(mid)
            if not model:
                continue
            if model_type and model.model_type != model_type:
                continue
            if capability and capability not in model.capabilities:
                continue
            if enabled_only and not model.enabled:
                continue
            results.append(model.model_dump(mode="json"))
        # Sort by priority (lower = higher priority)
        results.sort(key=lambda m: m.get("priority", 10))
        return results

    def update_model(
        self,
        model_id: str,
        enabled: bool | None = None,
        priority: int | None = None,
        capabilities: list[str] | None = None,
        config: dict | None = None,
        endpoint: str | None = None,
    ) -> dict | None:
        """Update model configuration."""
        model = self._models.get(model_id)
        if not model:
            return None

        if enabled is not None:
            model.enabled = enabled
            if enabled:
                model.consecutive_failures = 0
        if priority is not None:
            model.priority = max(1, min(10, priority))
        if endpoint is not None:
            model.endpoint = endpoint
        if config is not None:
            model.config.update(config)
        if capabilities is not None:
            # Rebuild capability index for this model
            old_caps = set(model.capabilities)
            new_caps = set(capabilities)
            for cap in old_caps - new_caps:
                if model.id in self._capability_index.get(cap, []):
                    self._capability_index[cap].remove(model.id)
            for cap in new_caps - old_caps:
                self._capability_index[cap].append(model.id)
            model.capabilities = capabilities

        logger.info("[AI_ORCH] Updated model '%s'", model.name)
        return model.model_dump(mode="json")

    def remove_model(self, model_id: str) -> dict | None:
        """Remove a model from the registry."""
        model = self._models.get(model_id)
        if not model:
            return None

        # Remove from capability index
        for cap in model.capabilities:
            if model_id in self._capability_index.get(cap, []):
                self._capability_index[cap].remove(model_id)

        # Remove from tenant list
        if model_id in self._tenant_models.get(model.tenant_id, []):
            self._tenant_models[model.tenant_id].remove(model_id)

        del self._models[model_id]
        logger.info("[AI_ORCH] Removed model '%s'", model.name)
        return {"removed": model_id, "name": model.name}

    # ------------------------------------------------------------------
    # Capability-Based Routing
    # ------------------------------------------------------------------

    def route_request(
        self,
        tenant_id: str,
        capability: str,
        payload: dict | None = None,
    ) -> dict:
        """Route a request to the best available model for a capability.

        Selection algorithm:
          1. Filter to tenant's models that have the requested capability
          2. Exclude disabled models
          3. Sort by priority (ascending), then by avg latency (ascending)
          4. Select the top candidate
          5. Record the routing decision and simulate execution
        """
        payload = payload or {}
        candidates = self._find_candidates(tenant_id, capability)

        if not candidates:
            result = RouteResult(
                model_id="",
                model_name="none",
                provider="none",
                capability=capability,
                status="no_model",
                payload=payload,
                response={"error": f"No model available for capability '{capability}'"},
            )
            self._route_history[tenant_id].append(result)
            return result.model_dump(mode="json")

        # Select the best candidate
        selected = candidates[0]
        start_time = time.monotonic()

        # Simulate model execution (in production this would call the actual endpoint)
        response = self._execute_model(selected, capability, payload)
        latency = round((time.monotonic() - start_time) * 1000, 2)

        # Update model metrics
        selected.total_requests += 1
        selected.last_used_at = datetime.now(timezone.utc)
        selected.total_latency_ms += latency

        success = "error" not in response
        if success:
            selected.successful_requests += 1
            selected.consecutive_failures = 0
            status = "success"
        else:
            selected.failed_requests += 1
            selected.consecutive_failures += 1
            selected.last_error = response.get("error", "unknown")
            status = "failed"

            # Auto-disable on too many consecutive failures
            if selected.consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
                selected.enabled = False
                logger.warning(
                    "[AI_ORCH] Auto-disabled model '%s' after %d consecutive failures",
                    selected.name, selected.consecutive_failures,
                )

        # Update average latency
        if selected.total_requests > 0:
            selected.avg_latency_ms = round(
                selected.total_latency_ms / selected.total_requests, 2,
            )

        result = RouteResult(
            model_id=selected.id,
            model_name=selected.name,
            provider=selected.provider,
            capability=capability,
            status=status,
            latency_ms=latency,
            payload=payload,
            response=response,
        )

        self._route_history[tenant_id].append(result)
        # Cap route history
        if len(self._route_history[tenant_id]) > 5000:
            self._route_history[tenant_id] = self._route_history[tenant_id][-5000:]

        logger.info(
            "[AI_ORCH] Routed '%s' request to '%s' (%s) — %s in %.1fms",
            capability, selected.name, selected.provider, status, latency,
        )
        return result.model_dump(mode="json")

    # ------------------------------------------------------------------
    # Stats & Analytics
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return orchestrator statistics for a tenant."""
        models = [
            self._models[mid]
            for mid in self._tenant_models.get(tenant_id, [])
            if mid in self._models
        ]

        by_type: dict[str, int] = defaultdict(int)
        by_provider: dict[str, int] = defaultdict(int)
        total_requests = 0
        total_successful = 0
        total_failed = 0
        latencies: list[float] = []

        for model in models:
            by_type[model.model_type] += 1
            by_provider[model.provider] += 1
            total_requests += model.total_requests
            total_successful += model.successful_requests
            total_failed += model.failed_requests
            if model.avg_latency_ms > 0:
                latencies.append(model.avg_latency_ms)

        active_models = sum(1 for m in models if m.enabled)
        capabilities = set()
        for m in models:
            capabilities.update(m.capabilities)

        return {
            "total_models": len(models),
            "active_models": active_models,
            "by_type": dict(by_type),
            "by_provider": dict(by_provider),
            "total_capabilities": len(capabilities),
            "capabilities": sorted(capabilities),
            "total_requests": total_requests,
            "successful_requests": total_successful,
            "failed_requests": total_failed,
            "success_rate": round(
                total_successful / max(total_requests, 1) * 100, 1,
            ),
            "avg_latency_ms": round(
                sum(latencies) / max(len(latencies), 1), 2,
            ) if latencies else 0.0,
        }

    def get_route_history(
        self,
        tenant_id: str,
        limit: int = 50,
    ) -> list[dict]:
        """Return recent routing decisions for a tenant."""
        history = self._route_history.get(tenant_id, [])
        return [r.model_dump(mode="json") for r in history[-limit:]]

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _find_candidates(
        self,
        tenant_id: str,
        capability: str,
    ) -> list[AIModel]:
        """Find enabled models matching a capability for a tenant.

        Returns models sorted by priority (ascending) then avg latency.
        """
        tenant_model_ids = set(self._tenant_models.get(tenant_id, []))
        capability_model_ids = set(self._capability_index.get(capability, []))

        # Intersection: models that belong to the tenant AND have the capability
        candidate_ids = tenant_model_ids & capability_model_ids

        candidates = []
        for mid in candidate_ids:
            model = self._models.get(mid)
            if model and model.enabled:
                candidates.append(model)

        # Sort by priority (lower = better), then by avg latency
        candidates.sort(key=lambda m: (m.priority, m.avg_latency_ms))
        return candidates

    def _execute_model(
        self,
        model: AIModel,
        capability: str,
        payload: dict,
    ) -> dict:
        """Simulate model execution.

        In production, this would make an HTTP call to the model's endpoint.
        For the orchestration layer, we return a structured response indicating
        the model was selected and the request was routed.
        """
        return {
            "model_id": model.id,
            "model_name": model.name,
            "provider": model.provider,
            "capability": capability,
            "result": "processed",
            "message": (
                f"Request routed to '{model.name}' ({model.provider}) "
                f"for capability '{capability}'"
            ),
            "payload_keys": list(payload.keys()),
        }


# Module-level singleton
ai_orchestrator_service = AIOrchestorService()
