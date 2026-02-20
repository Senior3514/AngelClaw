"""AngelClaw AGI Guardian – Operator Feedback Loop.

Tracks operator decisions on AngelClaw suggestions to improve future behavior:
  - Records accept/reject/ignore/modify actions on suggestions
  - Computes per-tenant suggestion effectiveness
  - Generates adjustment recommendations for thresholds and priorities
  - All adjustments are explainable and revertible

Per-tenant feedback storage with in-memory state and DB persistence hooks.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.feedback_loop")


class FeedbackRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    suggestion_type: str  # policy_change, alert_threshold, scan_config, remediation
    suggestion_id: str = ""
    action: str  # accepted, rejected, ignored, modified
    operator: str = "unknown"
    reason: str = ""
    context: dict[str, Any] = {}
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AdjustmentRecommendation(BaseModel):
    category: str  # alert_threshold, suggestion_priority, verbosity, scan_frequency
    description: str
    current_value: Any = None
    recommended_value: Any = None
    confidence: float = 0.5
    reason: str = ""
    revertible: bool = True


class FeedbackService:
    """Tracks operator feedback and generates improvement recommendations."""

    def __init__(self) -> None:
        # Per-tenant feedback records
        self._records: dict[str, list[FeedbackRecord]] = defaultdict(list)
        # Aggregated counts per suggestion_type per tenant
        self._type_counts: dict[str, dict[str, dict[str, int]]] = defaultdict(
            lambda: defaultdict(lambda: defaultdict(int))
        )

    def record_feedback(
        self,
        tenant_id: str,
        suggestion_type: str,
        action: str,
        operator: str = "unknown",
        suggestion_id: str = "",
        reason: str = "",
        context: dict[str, Any] | None = None,
    ) -> FeedbackRecord:
        """Record an operator's response to a suggestion."""
        valid_actions = {"accepted", "rejected", "ignored", "modified"}
        if action not in valid_actions:
            raise ValueError(f"Invalid action: {action}. Must be one of: {valid_actions}")

        record = FeedbackRecord(
            tenant_id=tenant_id,
            suggestion_type=suggestion_type,
            suggestion_id=suggestion_id,
            action=action,
            operator=operator,
            reason=reason,
            context=context or {},
        )

        self._records[tenant_id].append(record)
        self._type_counts[tenant_id][suggestion_type][action] += 1

        # Cap per-tenant at 1000 records
        if len(self._records[tenant_id]) > 1000:
            self._records[tenant_id] = self._records[tenant_id][-1000:]

        logger.info(
            "[FEEDBACK] tenant=%s type=%s action=%s by=%s",
            tenant_id,
            suggestion_type,
            action,
            operator,
        )
        return record

    def get_tenant_summary(self, tenant_id: str) -> dict:
        """Get feedback summary for a tenant."""
        records = self._records.get(tenant_id, [])
        if not records:
            return {
                "tenant_id": tenant_id,
                "total_feedback": 0,
                "by_type": {},
                "acceptance_rate": 0.0,
                "top_rejected_types": [],
            }

        # Count by action
        action_counts: dict[str, int] = defaultdict(int)
        type_actions: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for r in records:
            action_counts[r.action] += 1
            type_actions[r.suggestion_type][r.action] += 1

        total = len(records)
        accepted = action_counts.get("accepted", 0) + action_counts.get("modified", 0)
        acceptance_rate = accepted / total if total > 0 else 0.0

        # Find most-rejected types
        type_rejection_rates = []
        for stype, actions in type_actions.items():
            t = sum(actions.values())
            rejected = actions.get("rejected", 0) + actions.get("ignored", 0)
            rate = rejected / t if t > 0 else 0.0
            type_rejection_rates.append(
                {
                    "type": stype,
                    "rejection_rate": round(rate, 2),
                    "total": t,
                    "rejected": rejected,
                }
            )
        type_rejection_rates.sort(key=lambda x: x["rejection_rate"], reverse=True)

        return {
            "tenant_id": tenant_id,
            "total_feedback": total,
            "by_action": dict(action_counts),
            "by_type": {stype: dict(actions) for stype, actions in type_actions.items()},
            "acceptance_rate": round(acceptance_rate, 3),
            "top_rejected_types": type_rejection_rates[:5],
        }

    def compute_suggestion_ranking(self, tenant_id: str) -> list[dict]:
        """Rank suggestion types by operator acceptance."""
        records = self._records.get(tenant_id, [])
        if not records:
            return []

        type_stats: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for r in records:
            type_stats[r.suggestion_type][r.action] += 1

        rankings = []
        for stype, actions in type_stats.items():
            total = sum(actions.values())
            accepted = actions.get("accepted", 0) + actions.get("modified", 0)
            rate = accepted / total if total > 0 else 0.0
            rankings.append(
                {
                    "suggestion_type": stype,
                    "acceptance_rate": round(rate, 3),
                    "total_suggestions": total,
                    "accepted": accepted,
                    "rejected": actions.get("rejected", 0),
                    "ignored": actions.get("ignored", 0),
                }
            )

        rankings.sort(key=lambda x: x["acceptance_rate"], reverse=True)
        return rankings

    def get_adjustment_recommendations(self, tenant_id: str) -> list[dict]:
        """Generate recommendations based on feedback patterns."""
        summary = self.get_tenant_summary(tenant_id)
        recommendations: list[AdjustmentRecommendation] = []

        if summary["total_feedback"] < 5:
            return []

        # If most suggestions are rejected, suggest reducing verbosity
        if summary["acceptance_rate"] < 0.3:
            recommendations.append(
                AdjustmentRecommendation(
                    category="verbosity",
                    description="Operators reject most suggestions — reduce suggestion frequency",
                    current_value="normal",
                    recommended_value="quiet",
                    confidence=0.7,
                    reason=f"Only {summary['acceptance_rate']:.0%} of suggestions accepted",
                )
            )

        # If alert_threshold type is mostly rejected, suggest raising thresholds
        for rejected_type in summary.get("top_rejected_types", []):
            if rejected_type["rejection_rate"] > 0.6 and rejected_type["total"] >= 3:
                stype = rejected_type["type"]
                recommendations.append(
                    AdjustmentRecommendation(
                        category="alert_threshold",
                        description=(
                            f"'{stype}' suggestions are often"
                            " rejected — raise alert threshold"
                        ),
                        current_value="default",
                        recommended_value="raised",
                        confidence=min(0.9, 0.5 + rejected_type["rejection_rate"] * 0.3),
                        reason=(
                            f"{rejected_type['rejected']}/{rejected_type['total']} "
                            f"'{stype}' suggestions rejected/ignored"
                        ),
                    )
                )

        # If acceptance rate is high, suggest increasing autonomy
        if summary["acceptance_rate"] > 0.8 and summary["total_feedback"] >= 10:
            recommendations.append(
                AdjustmentRecommendation(
                    category="suggestion_priority",
                    description="High acceptance rate — consider increasing autonomy level",
                    current_value="suggest",
                    recommended_value="assist",
                    confidence=0.6,
                    reason=(
                        f"{summary['acceptance_rate']:.0%}"
                        " acceptance rate across"
                        f" {summary['total_feedback']} suggestions"
                    ),
                )
            )

        return [r.model_dump(mode="json") for r in recommendations]

    def get_recent_feedback(
        self,
        tenant_id: str,
        limit: int = 20,
        hours: int = 24,
    ) -> list[dict]:
        """Get recent feedback records."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        records = self._records.get(tenant_id, [])
        recent = [r for r in records if r.created_at >= cutoff]
        recent.sort(key=lambda r: r.created_at, reverse=True)
        return [r.model_dump(mode="json") for r in recent[:limit]]

    def get_all_tenant_ids(self) -> list[str]:
        """Return all tenant IDs with feedback data."""
        return list(self._records.keys())


# Module-level singleton
feedback_service = FeedbackService()
