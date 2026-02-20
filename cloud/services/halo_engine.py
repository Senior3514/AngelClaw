"""AngelClaw V5.5 — Convergence: Halo Score Engine.

Computes an organization-wide Halo Score (0-100) from six weighted
security dimensions, providing a single number that represents the
overall security posture of a tenant.

Dimensions and weights:
  - threat_posture   25%
  - compliance       20%
  - vulnerability    20%
  - incident_response 15%
  - endpoint_health  10%
  - policy_coverage  10%

Features:
  - Per-tenant score computation from dimension inputs
  - Score history tracking with timestamps
  - Dimension-level breakdown and trending
  - Weighted aggregation with configurable thresholds
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.halo_engine")

# Dimension weights (must sum to 1.0)
_DIMENSION_WEIGHTS: dict[str, float] = {
    "threat_posture": 0.25,
    "compliance": 0.20,
    "vulnerability": 0.20,
    "incident_response": 0.15,
    "endpoint_health": 0.10,
    "policy_coverage": 0.10,
}

# Score thresholds for classification
_SCORE_THRESHOLDS = {
    "critical": 30,
    "poor": 50,
    "fair": 70,
    "good": 85,
    "excellent": 100,
}


class HaloScore(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    overall_score: float = 0.0
    classification: str = "critical"
    dimensions: dict[str, float] = {}
    weighted_dimensions: dict[str, float] = {}
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DimensionInput(BaseModel):
    name: str
    score: float = 0.0  # 0-100
    details: dict[str, Any] = {}


class HaloScoreEngine:
    """Computes and tracks the organization-wide Halo Score."""

    def __init__(self) -> None:
        self._current_scores: dict[str, HaloScore] = {}
        self._score_history: dict[str, list[HaloScore]] = defaultdict(list)
        self._dimension_cache: dict[str, dict[str, float]] = defaultdict(dict)
        # Max history entries per tenant
        self._max_history = 1000

    # ------------------------------------------------------------------
    # Score Computation
    # ------------------------------------------------------------------

    def compute_score(
        self,
        tenant_id: str,
        dimensions: dict[str, float],
    ) -> dict:
        """Compute a Halo Score from dimension scores.

        Args:
            tenant_id: Tenant identifier.
            dimensions: Mapping of dimension name to score (0-100).
                        Valid keys: threat_posture, compliance, vulnerability,
                        incident_response, endpoint_health, policy_coverage.
        """
        # Clamp each dimension to 0-100 and apply weights
        weighted: dict[str, float] = {}
        raw: dict[str, float] = {}
        total = 0.0

        for dim_name, weight in _DIMENSION_WEIGHTS.items():
            value = max(0.0, min(100.0, dimensions.get(dim_name, 0.0)))
            raw[dim_name] = round(value, 1)
            w = round(value * weight, 2)
            weighted[dim_name] = w
            total += w

        overall = round(total, 1)
        classification = self._classify(overall)

        score = HaloScore(
            tenant_id=tenant_id,
            overall_score=overall,
            classification=classification,
            dimensions=raw,
            weighted_dimensions=weighted,
        )

        # Store current and append history
        self._current_scores[tenant_id] = score
        self._score_history[tenant_id].append(score)
        if len(self._score_history[tenant_id]) > self._max_history:
            self._score_history[tenant_id] = self._score_history[tenant_id][-self._max_history :]

        # Update dimension cache
        self._dimension_cache[tenant_id] = raw

        logger.info(
            "[HALO] Computed score %.1f (%s) for %s",
            overall,
            classification,
            tenant_id,
        )
        return score.model_dump(mode="json")

    # ------------------------------------------------------------------
    # Score Retrieval
    # ------------------------------------------------------------------

    def get_current_score(self, tenant_id: str) -> dict | None:
        """Return the most recently computed Halo Score for a tenant."""
        score = self._current_scores.get(tenant_id)
        return score.model_dump(mode="json") if score else None

    def get_score_history(self, tenant_id: str, limit: int = 50) -> list[dict]:
        """Return recent Halo Score history for a tenant."""
        history = self._score_history.get(tenant_id, [])
        return [s.model_dump(mode="json") for s in history[-limit:]]

    def get_dimension_breakdown(self, tenant_id: str) -> dict:
        """Return a detailed breakdown of each dimension's contribution."""
        score = self._current_scores.get(tenant_id)
        if not score:
            return {
                "tenant_id": tenant_id,
                "overall_score": 0.0,
                "dimensions": [],
                "message": "No score computed yet",
            }

        breakdown = []
        for dim_name, weight in _DIMENSION_WEIGHTS.items():
            raw = score.dimensions.get(dim_name, 0.0)
            weighted = score.weighted_dimensions.get(dim_name, 0.0)
            breakdown.append(
                {
                    "dimension": dim_name,
                    "weight_pct": round(weight * 100),
                    "raw_score": raw,
                    "weighted_contribution": weighted,
                    "classification": self._classify(raw),
                }
            )

        # Sort by weighted contribution descending
        breakdown.sort(key=lambda d: d["weighted_contribution"], reverse=True)

        return {
            "tenant_id": tenant_id,
            "overall_score": score.overall_score,
            "classification": score.classification,
            "dimensions": breakdown,
            "computed_at": score.computed_at.isoformat(),
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return Halo Score engine statistics for a tenant."""
        history = self._score_history.get(tenant_id, [])
        scores = [s.overall_score for s in history]

        current = self._current_scores.get(tenant_id)

        return {
            "current_score": current.overall_score if current else None,
            "current_classification": current.classification if current else None,
            "total_computations": len(history),
            "avg_score": round(sum(scores) / max(len(scores), 1), 1) if scores else 0.0,
            "min_score": round(min(scores), 1) if scores else 0.0,
            "max_score": round(max(scores), 1) if scores else 0.0,
            "dimension_weights": {k: round(v * 100) for k, v in _DIMENSION_WEIGHTS.items()},
        }

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _classify(score: float) -> str:
        """Classify a numeric score into a human-readable tier."""
        for label, threshold in _SCORE_THRESHOLDS.items():
            if score <= threshold:
                return label
        return "excellent"


# Module-level singleton
halo_score_engine = HaloScoreEngine()
