"""AngelClaw – Self-Learning Reflection Log.

Records incident outcomes, response effectiveness, and detection accuracy.
Uses this data to improve future detection thresholds and playbook selection.

The reflection log is append-only JSONL stored in the database.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from cloud.db.models import GuardianAlertRow

logger = logging.getLogger("angelgrid.cloud.guardian.learning")


class ReflectionEntry(BaseModel):
    """A single learning reflection from an incident lifecycle."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    incident_id: str = ""
    category: str  # detection_accuracy, response_effectiveness, false_positive, threshold_adjustment
    lesson: str
    details: dict[str, Any] = {}
    applied: bool = False  # Whether this lesson was acted on


class LearningEngine:
    """Collects reflections and applies learned thresholds."""

    def __init__(self) -> None:
        self._reflections: list[ReflectionEntry] = []
        self._false_positive_patterns: dict[str, int] = {}  # pattern_name → count
        self._effective_playbooks: dict[str, int] = {}  # playbook_name → success_count
        self._ineffective_playbooks: dict[str, int] = {}  # playbook_name → fail_count

    def record_detection_outcome(
        self,
        incident_id: str,
        pattern_name: str,
        was_true_positive: bool,
        confidence: float,
        details: dict | None = None,
    ) -> ReflectionEntry:
        """Record whether a detection was accurate or a false positive."""
        if was_true_positive:
            entry = ReflectionEntry(
                incident_id=incident_id,
                category="detection_accuracy",
                lesson=f"Pattern '{pattern_name}' correctly detected threat (confidence: {confidence:.0%})",
                details={"pattern": pattern_name, "confidence": confidence, "true_positive": True, **(details or {})},
            )
        else:
            self._false_positive_patterns[pattern_name] = self._false_positive_patterns.get(pattern_name, 0) + 1
            fp_count = self._false_positive_patterns[pattern_name]
            entry = ReflectionEntry(
                incident_id=incident_id,
                category="false_positive",
                lesson=(
                    f"Pattern '{pattern_name}' was a false positive "
                    f"(confidence: {confidence:.0%}, total FPs: {fp_count})"
                ),
                details={"pattern": pattern_name, "confidence": confidence, "true_positive": False,
                         "fp_count": fp_count, **(details or {})},
            )
            if fp_count >= 3:
                logger.warning(
                    "[LEARNING] Pattern '%s' has %d false positives — consider threshold adjustment",
                    pattern_name, fp_count,
                )

        self._reflections.append(entry)
        logger.info("[LEARNING] %s", entry.lesson)
        return entry

    def record_response_outcome(
        self,
        incident_id: str,
        playbook_name: str,
        success: bool,
        resolution_time_seconds: float = 0,
        details: dict | None = None,
    ) -> ReflectionEntry:
        """Record whether a response playbook was effective."""
        if success:
            self._effective_playbooks[playbook_name] = self._effective_playbooks.get(playbook_name, 0) + 1
            entry = ReflectionEntry(
                incident_id=incident_id,
                category="response_effectiveness",
                lesson=f"Playbook '{playbook_name}' resolved incident in {resolution_time_seconds:.0f}s",
                details={"playbook": playbook_name, "success": True,
                         "resolution_seconds": resolution_time_seconds, **(details or {})},
            )
        else:
            self._ineffective_playbooks[playbook_name] = self._ineffective_playbooks.get(playbook_name, 0) + 1
            entry = ReflectionEntry(
                incident_id=incident_id,
                category="response_effectiveness",
                lesson=f"Playbook '{playbook_name}' failed to resolve incident",
                details={"playbook": playbook_name, "success": False, **(details or {})},
            )

        self._reflections.append(entry)
        logger.info("[LEARNING] %s", entry.lesson)
        return entry

    def suggest_threshold_adjustment(self, pattern_name: str) -> dict | None:
        """Suggest confidence threshold adjustment based on false positive data."""
        fp_count = self._false_positive_patterns.get(pattern_name, 0)
        if fp_count < 3:
            return None

        # Suggest raising the threshold proportionally to FP count
        current_threshold = 0.7  # Default
        suggested = min(0.95, current_threshold + (fp_count * 0.05))
        return {
            "pattern": pattern_name,
            "current_threshold": current_threshold,
            "suggested_threshold": suggested,
            "false_positive_count": fp_count,
            "reason": f"{fp_count} false positives detected — raising threshold to reduce noise",
        }

    def get_playbook_ranking(self) -> list[dict]:
        """Rank playbooks by effectiveness."""
        all_playbooks = set(self._effective_playbooks.keys()) | set(self._ineffective_playbooks.keys())
        rankings = []
        for pb in all_playbooks:
            success = self._effective_playbooks.get(pb, 0)
            fail = self._ineffective_playbooks.get(pb, 0)
            total = success + fail
            rate = success / total if total > 0 else 0
            rankings.append({
                "playbook": pb,
                "success_count": success,
                "fail_count": fail,
                "success_rate": round(rate, 2),
            })
        rankings.sort(key=lambda r: r["success_rate"], reverse=True)
        return rankings

    def get_reflections(self, limit: int = 50, category: str | None = None) -> list[dict]:
        """Return recent reflections, optionally filtered by category."""
        entries = self._reflections
        if category:
            entries = [e for e in entries if e.category == category]
        return [e.model_dump(mode="json") for e in entries[-limit:]]

    def summary(self) -> dict:
        """Summary of learning state."""
        return {
            "total_reflections": len(self._reflections),
            "false_positive_patterns": dict(self._false_positive_patterns),
            "effective_playbooks": dict(self._effective_playbooks),
            "ineffective_playbooks": dict(self._ineffective_playbooks),
            "threshold_suggestions": [
                self.suggest_threshold_adjustment(p)
                for p in self._false_positive_patterns
                if self.suggest_threshold_adjustment(p) is not None
            ],
            "playbook_ranking": self.get_playbook_ranking(),
        }


# Module-level singleton
learning_engine = LearningEngine()
