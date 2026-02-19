"""AngelClaw – Self-Learning Reflection Log.

Records incident outcomes, response effectiveness, and detection accuracy.
Uses this data to improve future detection thresholds and playbook selection.

The reflection log is append-only JSONL stored in the database.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelgrid.cloud.guardian.learning")


class ReflectionEntry(BaseModel):
    """A single learning reflection from an incident lifecycle."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    incident_id: str = ""
    category: (
        str  # detection_accuracy, response_effectiveness, false_positive, threshold_adjustment
    )
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
        # V2.1 — expanded learning state
        self._pattern_true_positives: dict[str, int] = {}  # pattern_name → TP count
        self._resolution_times: dict[str, list[float]] = {}  # playbook → resolution seconds
        self._severity_trend: list[str] = []  # recent incident severities
        self._pattern_confidence_overrides: dict[str, float] = {}  # learned threshold overrides

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
                lesson=(
                    f"Pattern '{pattern_name}' correctly detected"
                    f" threat (confidence: {confidence:.0%})"
                ),
                details={
                    "pattern": pattern_name,
                    "confidence": confidence,
                    "true_positive": True,
                    **(details or {}),
                },
            )
        else:
            self._false_positive_patterns[pattern_name] = (
                self._false_positive_patterns.get(pattern_name, 0) + 1
            )
            fp_count = self._false_positive_patterns[pattern_name]
            entry = ReflectionEntry(
                incident_id=incident_id,
                category="false_positive",
                lesson=(
                    f"Pattern '{pattern_name}' was a false positive "
                    f"(confidence: {confidence:.0%}, total FPs: {fp_count})"
                ),
                details={
                    "pattern": pattern_name,
                    "confidence": confidence,
                    "true_positive": False,
                    "fp_count": fp_count,
                    **(details or {}),
                },
            )
            if fp_count >= 3:
                logger.warning(
                    "[LEARNING] Pattern '%s' has %d false positives"
                    " — consider threshold adjustment",
                    pattern_name,
                    fp_count,
                )

        # V2.1 — track true positive counts for precision scoring
        if was_true_positive:
            self._pattern_true_positives[pattern_name] = (
                self._pattern_true_positives.get(pattern_name, 0) + 1
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
            self._effective_playbooks[playbook_name] = (
                self._effective_playbooks.get(playbook_name, 0) + 1
            )
            # V2.1 — track resolution times for trend analysis
            self._resolution_times.setdefault(playbook_name, []).append(
                resolution_time_seconds
            )
            entry = ReflectionEntry(
                incident_id=incident_id,
                category="response_effectiveness",
                lesson=(
                    f"Playbook '{playbook_name}' resolved"
                    f" incident in {resolution_time_seconds:.0f}s"
                ),
                details={
                    "playbook": playbook_name,
                    "success": True,
                    "resolution_seconds": resolution_time_seconds,
                    **(details or {}),
                },
            )
        else:
            self._ineffective_playbooks[playbook_name] = (
                self._ineffective_playbooks.get(playbook_name, 0) + 1
            )
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
        all_playbooks = set(self._effective_playbooks.keys()) | set(
            self._ineffective_playbooks.keys()
        )
        rankings = []
        for pb in all_playbooks:
            success = self._effective_playbooks.get(pb, 0)
            fail = self._ineffective_playbooks.get(pb, 0)
            total = success + fail
            rate = success / total if total > 0 else 0
            rankings.append(
                {
                    "playbook": pb,
                    "success_count": success,
                    "fail_count": fail,
                    "success_rate": round(rate, 2),
                }
            )
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
            # V2.1 additions
            "pattern_precision": self.get_pattern_precision(),
            "avg_resolution_times": self.get_avg_resolution_times(),
            "severity_trend": self._severity_trend[-20:],
            "confidence_overrides": dict(self._pattern_confidence_overrides),
        }

    # ------------------------------------------------------------------
    # V2.1 — Pattern precision tracking
    # ------------------------------------------------------------------

    def get_pattern_precision(self) -> dict[str, dict]:
        """Return precision (TP / (TP+FP)) for each pattern."""
        all_patterns = set(self._pattern_true_positives.keys()) | set(
            self._false_positive_patterns.keys()
        )
        result: dict[str, dict] = {}
        for p in all_patterns:
            tp = self._pattern_true_positives.get(p, 0)
            fp = self._false_positive_patterns.get(p, 0)
            total = tp + fp
            precision = tp / total if total > 0 else 0.0
            result[p] = {
                "true_positives": tp,
                "false_positives": fp,
                "precision": round(precision, 3),
            }
        return result

    # ------------------------------------------------------------------
    # V2.1 — Average resolution time per playbook
    # ------------------------------------------------------------------

    def get_avg_resolution_times(self) -> dict[str, float]:
        """Return average resolution time (seconds) per playbook."""
        result: dict[str, float] = {}
        for pb, times in self._resolution_times.items():
            if times:
                result[pb] = round(sum(times) / len(times), 1)
        return result

    # ------------------------------------------------------------------
    # V2.1 — Severity trend tracking
    # ------------------------------------------------------------------

    def record_incident_severity(self, severity: str) -> None:
        """Track incident severity for trend analysis."""
        self._severity_trend.append(severity)
        # Keep last 100
        if len(self._severity_trend) > 100:
            self._severity_trend = self._severity_trend[-100:]

    def get_severity_trend_score(self) -> float:
        """Return a 0.0-1.0 score indicating recent severity escalation.

        0.0 = all recent incidents are low/info
        1.0 = all recent incidents are critical
        """
        if not self._severity_trend:
            return 0.0
        sev_map = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        recent = self._severity_trend[-20:]
        scores = [sev_map.get(s, 0) for s in recent]
        return round(sum(scores) / (len(scores) * 4), 3)

    # ------------------------------------------------------------------
    # V2.1 — Adaptive confidence overrides
    # ------------------------------------------------------------------

    def compute_confidence_override(self, pattern_name: str) -> float | None:
        """Compute an adaptive confidence threshold for a pattern.

        High false-positive patterns get higher thresholds (harder to trigger).
        High true-positive patterns get lower thresholds (easier to trigger).
        Returns None if insufficient data.
        """
        tp = self._pattern_true_positives.get(pattern_name, 0)
        fp = self._false_positive_patterns.get(pattern_name, 0)
        total = tp + fp
        if total < 5:
            return None

        precision = tp / total
        # Map precision to threshold: low precision → raise threshold
        if precision >= 0.9:
            threshold = 0.5  # very reliable, low threshold
        elif precision >= 0.7:
            threshold = 0.65
        elif precision >= 0.5:
            threshold = 0.75
        else:
            threshold = min(0.95, 0.7 + (fp * 0.03))

        self._pattern_confidence_overrides[pattern_name] = threshold
        logger.info(
            "[LEARNING] Adaptive threshold for '%s': %.2f (precision=%.0f%%, %d samples)",
            pattern_name,
            threshold,
            precision * 100,
            total,
        )
        return threshold

    def get_confidence_threshold(self, pattern_name: str, default: float = 0.7) -> float:
        """Get the effective confidence threshold for a pattern."""
        return self._pattern_confidence_overrides.get(pattern_name, default)

    # ------------------------------------------------------------------
    # V2.2 — Pattern decay (reduce FP weight over time)
    # ------------------------------------------------------------------

    def apply_decay(self, decay_factor: float = 0.9) -> int:
        """Apply decay to false positive counts.

        Older false positives become less relevant over time. Call periodically
        (e.g., every 24h) to prevent stale FP data from over-suppressing patterns.
        Returns the number of patterns decayed.
        """
        decayed = 0
        for pattern_name in list(self._false_positive_patterns.keys()):
            old_count = self._false_positive_patterns[pattern_name]
            new_count = max(0, int(old_count * decay_factor))
            if new_count != old_count:
                self._false_positive_patterns[pattern_name] = new_count
                decayed += 1
                if new_count == 0:
                    del self._false_positive_patterns[pattern_name]
        if decayed:
            logger.info("[LEARNING] Decayed %d false positive pattern(s)", decayed)
        return decayed

    # ------------------------------------------------------------------
    # V2.2 — Pattern correlation tracking
    # ------------------------------------------------------------------

    def record_pattern_correlation(
        self,
        pattern_a: str,
        pattern_b: str,
    ) -> None:
        """Record that two patterns co-occurred in the same incident.

        Used to discover attack chains and multi-pattern correlations.
        """
        key = tuple(sorted([pattern_a, pattern_b]))
        if not hasattr(self, "_pattern_correlations"):
            self._pattern_correlations: dict[tuple, int] = {}
        self._pattern_correlations[key] = self._pattern_correlations.get(key, 0) + 1

    def get_correlated_patterns(self, min_occurrences: int = 2) -> list[dict]:
        """Return pattern pairs that frequently co-occur."""
        correlations = getattr(self, "_pattern_correlations", {})
        results = []
        for (a, b), count in correlations.items():
            if count >= min_occurrences:
                results.append({
                    "pattern_a": a,
                    "pattern_b": b,
                    "co_occurrences": count,
                })
        results.sort(key=lambda r: r["co_occurrences"], reverse=True)
        return results

    # ------------------------------------------------------------------
    # V2.2 — Detection effectiveness scoring
    # ------------------------------------------------------------------

    def detection_effectiveness_score(self) -> float:
        """Compute overall detection effectiveness (0.0-1.0).

        Combines precision across all patterns and playbook success rates.
        """
        precision_data = self.get_pattern_precision()
        if not precision_data:
            return 0.5  # No data yet

        # Weighted average precision (weight by total detections)
        total_weight = 0
        weighted_precision = 0.0
        for p_data in precision_data.values():
            weight = p_data["true_positives"] + p_data["false_positives"]
            weighted_precision += p_data["precision"] * weight
            total_weight += weight

        avg_precision = weighted_precision / max(total_weight, 1)

        # Factor in playbook success rate
        rankings = self.get_playbook_ranking()
        if rankings:
            avg_playbook_rate = sum(r["success_rate"] for r in rankings) / len(rankings)
        else:
            avg_playbook_rate = 0.5

        # Combined score: 70% detection precision, 30% response effectiveness
        return round(avg_precision * 0.7 + avg_playbook_rate * 0.3, 3)

    # ------------------------------------------------------------------
    # V2.1 — Playbook recommendation engine
    # ------------------------------------------------------------------

    def recommend_playbook(self, severity: str, pattern_name: str) -> str | None:
        """Recommend the best playbook based on historical effectiveness.

        Considers severity, pattern match history, and playbook success rates.
        """
        rankings = self.get_playbook_ranking()
        if not rankings:
            return None

        # Filter to playbooks with >= 50% success rate
        viable = [r for r in rankings if r["success_rate"] >= 0.5]
        if not viable:
            return None

        # For critical severity, prefer aggressive playbooks
        critical_playbooks = {"quarantine_agent", "block_source", "revoke_token"}
        if severity in ("critical", "high"):
            for r in viable:
                if r["playbook"] in critical_playbooks:
                    return r["playbook"]

        # Return the highest-success-rate playbook
        return viable[0]["playbook"]


    # ------------------------------------------------------------------
    # V3.0 — Prediction calibration for predictive engine
    # ------------------------------------------------------------------

    def get_prediction_calibration(self) -> dict[str, float]:
        """Return confidence adjustments for all known prediction patterns.

        Based on historical precision data. Used by predictive.py to suppress
        low-precision predictions.
        """
        calibrations: dict[str, float] = {}
        precision_data = self.get_pattern_precision()
        for pattern_name, data in precision_data.items():
            total = data["true_positives"] + data["false_positives"]
            if total >= 3:
                precision = data["precision"]
                if precision >= 0.8:
                    calibrations[pattern_name] = 0.3  # Very reliable, low bar
                elif precision >= 0.5:
                    calibrations[pattern_name] = 0.5
                else:
                    calibrations[pattern_name] = 0.7  # Unreliable, high bar
        return calibrations

    # ------------------------------------------------------------------
    # V3.0 — Trend analysis for severity escalation
    # ------------------------------------------------------------------

    def get_escalation_rate(self, window: int = 20) -> dict:
        """Analyze rate of severity escalation over recent incidents."""
        if len(self._severity_trend) < 4:
            return {"rate": 0.0, "direction": "stable", "samples": len(self._severity_trend)}

        recent = self._severity_trend[-window:]
        sev_map = {"info": 0, "low": 1, "warn": 2, "medium": 2, "high": 3, "critical": 4}
        scores = [sev_map.get(s, 0) for s in recent]

        half = len(scores) // 2
        first_avg = sum(scores[:half]) / max(half, 1)
        second_avg = sum(scores[half:]) / max(len(scores) - half, 1)
        rate = second_avg - first_avg

        direction = "escalating" if rate > 0.3 else ("declining" if rate < -0.3 else "stable")
        return {
            "rate": round(rate, 2),
            "direction": direction,
            "first_half_avg": round(first_avg, 2),
            "second_half_avg": round(second_avg, 2),
            "samples": len(recent),
        }


# Module-level singleton
learning_engine = LearningEngine()
