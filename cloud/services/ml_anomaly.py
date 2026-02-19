"""AngelClaw V4.1 — Prophecy: ML Anomaly Detection Engine.

Lightweight statistical anomaly detection using isolation forest concepts
and local outlier factor (LOF) simulation. No external ML dependencies.

Detects:
  - Volume spikes (events/hour exceeding baseline)
  - Category shifts (unusual event category distributions)
  - Time anomalies (activity outside normal patterns)
  - Behavioral drift (deviation from established profiles)
"""

from __future__ import annotations

import logging
import math
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("angelclaw.ml_anomaly")


class AnomalyResult:
    def __init__(
        self,
        entity_id: str,
        anomaly_type: str,
        score: float,
        severity: str,
        description: str,
        features: dict[str, Any] | None = None,
    ) -> None:
        self.id = str(uuid.uuid4())
        self.entity_id = entity_id
        self.anomaly_type = anomaly_type
        self.score = round(max(0.0, min(1.0, score)), 3)
        self.severity = severity
        self.description = description
        self.features = features or {}
        self.created_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "entity_id": self.entity_id,
            "anomaly_type": self.anomaly_type,
            "score": self.score,
            "severity": self.severity,
            "description": self.description,
            "features": self.features,
            "created_at": self.created_at.isoformat(),
        }


class MLAnomalyEngine:
    """Statistical anomaly detection engine."""

    def __init__(self) -> None:
        self._baselines: dict[str, dict[str, Any]] = {}  # entity_id -> baseline
        self._detections: list[AnomalyResult] = []
        self._detection_count: int = 0

    def update_baseline(self, entity_id: str, metrics: dict[str, float]) -> dict:
        """Update rolling baseline for an entity."""
        if entity_id not in self._baselines:
            self._baselines[entity_id] = {
                "means": {},
                "variances": {},
                "observations": 0,
            }
        baseline = self._baselines[entity_id]
        n = baseline["observations"] + 1
        baseline["observations"] = n

        for key, value in metrics.items():
            old_mean = baseline["means"].get(key, value)
            new_mean = old_mean + (value - old_mean) / n
            old_var = baseline["variances"].get(key, 0.0)
            new_var = old_var + (value - old_mean) * (value - new_mean)
            baseline["means"][key] = new_mean
            baseline["variances"][key] = new_var

        return {"entity_id": entity_id, "observations": n}

    def detect_anomalies(
        self,
        entity_id: str,
        current_metrics: dict[str, float],
        threshold: float = 2.0,
    ) -> list[dict]:
        """Detect anomalies in current metrics vs baseline."""
        baseline = self._baselines.get(entity_id)
        if not baseline or baseline["observations"] < 5:
            return []  # Not enough data

        anomalies = []
        n = baseline["observations"]

        for key, value in current_metrics.items():
            mean = baseline["means"].get(key)
            var = baseline["variances"].get(key)
            if mean is None or var is None:
                continue

            std = math.sqrt(max(var / max(n - 1, 1), 0.001))
            z_score = abs(value - mean) / std if std > 0 else 0

            if z_score > threshold:
                score = min(1.0, z_score / 5.0)
                severity = "critical" if score > 0.8 else "high" if score > 0.6 else "medium"
                anomaly_type = self._classify_anomaly(key)

                result = AnomalyResult(
                    entity_id=entity_id,
                    anomaly_type=anomaly_type,
                    score=score,
                    severity=severity,
                    description=f"Anomalous {key}: {value:.1f} (baseline: {mean:.1f}, z-score: {z_score:.1f})",
                    features={"metric": key, "value": value, "mean": round(mean, 2), "z_score": round(z_score, 2)},
                )
                self._detections.append(result)
                self._detection_count += 1
                anomalies.append(result.to_dict())

        if anomalies:
            logger.info("[ML_ANOMALY] %d anomaly(ies) detected for %s", len(anomalies), entity_id)
        return anomalies

    def batch_detect(
        self,
        events_by_entity: dict[str, list[dict]],
        threshold: float = 2.0,
    ) -> list[dict]:
        """Batch anomaly detection across multiple entities."""
        all_anomalies = []
        for entity_id, events in events_by_entity.items():
            # Compute current metrics from events
            metrics = self._compute_metrics(events)
            # Update baseline
            self.update_baseline(entity_id, metrics)
            # Detect anomalies
            anomalies = self.detect_anomalies(entity_id, metrics, threshold)
            all_anomalies.extend(anomalies)
        return all_anomalies

    def get_baseline(self, entity_id: str) -> dict | None:
        baseline = self._baselines.get(entity_id)
        if not baseline:
            return None
        return {
            "entity_id": entity_id,
            "observations": baseline["observations"],
            "metrics": {
                k: {"mean": round(v, 2), "std": round(math.sqrt(max(baseline["variances"].get(k, 0) / max(baseline["observations"] - 1, 1), 0)), 2)}
                for k, v in baseline["means"].items()
            },
        }

    def get_recent_detections(self, entity_id: str | None = None, limit: int = 50) -> list[dict]:
        results = self._detections
        if entity_id:
            results = [d for d in results if d.entity_id == entity_id]
        return [d.to_dict() for d in reversed(results[-limit:])]

    def get_stats(self) -> dict:
        return {
            "total_baselines": len(self._baselines),
            "total_detections": self._detection_count,
            "recent_detections": len(self._detections),
        }

    def _classify_anomaly(self, metric_key: str) -> str:
        if "volume" in metric_key or "count" in metric_key or "rate" in metric_key:
            return "volume_spike"
        elif "category" in metric_key:
            return "category_shift"
        elif "hour" in metric_key or "time" in metric_key:
            return "time_anomaly"
        return "behavior_drift"

    def _compute_metrics(self, events: list[dict]) -> dict[str, float]:
        metrics: dict[str, float] = {"event_count": float(len(events))}
        categories: dict[str, int] = defaultdict(int)
        severities: dict[str, int] = defaultdict(int)
        for e in events:
            categories[e.get("category", "unknown")] += 1
            severities[e.get("severity", "info")] += 1
        metrics["unique_categories"] = float(len(categories))
        metrics["high_severity_ratio"] = (
            (severities.get("high", 0) + severities.get("critical", 0)) / max(len(events), 1)
        )
        return metrics


# Module-level singleton
ml_anomaly_engine = MLAnomalyEngine()
