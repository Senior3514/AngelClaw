"""AngelClaw V4.1 — Prophecy: Risk Forecasting Engine.

Predicts future risk levels based on trend analysis, event velocity,
and historical patterns. Generates forecasts for configurable time windows.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger("angelclaw.risk_forecast")


class RiskForecast:
    def __init__(
        self,
        tenant_id: str,
        forecast_type: str,
        time_horizon_hours: int,
        predicted_value: str,
        confidence: float,
        contributing_factors: list[str] | None = None,
    ) -> None:
        self.id = str(uuid.uuid4())
        self.tenant_id = tenant_id
        self.forecast_type = forecast_type
        self.time_horizon_hours = time_horizon_hours
        self.predicted_value = predicted_value
        self.confidence = round(max(0.0, min(1.0, confidence)), 2)
        self.contributing_factors = contributing_factors or []
        self.actual_value: str | None = None
        self.accuracy: float | None = None
        self.created_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "forecast_type": self.forecast_type,
            "time_horizon_hours": self.time_horizon_hours,
            "predicted_value": self.predicted_value,
            "confidence": self.confidence,
            "contributing_factors": self.contributing_factors,
            "actual_value": self.actual_value,
            "accuracy": self.accuracy,
            "created_at": self.created_at.isoformat(),
        }


class RiskForecastEngine:
    """Risk forecasting with trend analysis."""

    def __init__(self) -> None:
        self._forecasts: list[RiskForecast] = []
        self._event_history: dict[str, list[dict]] = defaultdict(list)  # tenant -> event summaries

    def record_observation(self, tenant_id: str, summary: dict) -> None:
        """Record a periodic observation for trend analysis."""
        summary["timestamp"] = datetime.now(timezone.utc).isoformat()
        self._event_history[tenant_id].append(summary)
        # Keep last 168 observations (7 days of hourly data)
        if len(self._event_history[tenant_id]) > 168:
            self._event_history[tenant_id] = self._event_history[tenant_id][-168:]

    def generate_forecasts(
        self,
        tenant_id: str,
        horizons: list[int] | None = None,
    ) -> list[dict]:
        """Generate risk forecasts for specified time horizons."""
        horizons = horizons or [1, 6, 24]
        history = self._event_history.get(tenant_id, [])
        if len(history) < 3:
            return []

        forecasts = []

        for horizon in horizons:
            # Incident volume forecast
            vol_forecast = self._forecast_volume(history, horizon)
            forecasts.append(vol_forecast)

            # Severity trend forecast
            sev_forecast = self._forecast_severity_trend(history, horizon)
            forecasts.append(sev_forecast)

            # Attack likelihood forecast
            attack_forecast = self._forecast_attack_likelihood(history, horizon)
            forecasts.append(attack_forecast)

        for f_dict in forecasts:
            forecast = RiskForecast(
                tenant_id=tenant_id,
                forecast_type=f_dict["type"],
                time_horizon_hours=f_dict["horizon"],
                predicted_value=str(f_dict["value"]),
                confidence=f_dict["confidence"],
                contributing_factors=f_dict.get("factors", []),
            )
            self._forecasts.append(forecast)

        logger.info("[FORECAST] Generated %d forecasts for %s", len(forecasts), tenant_id)
        return forecasts

    def get_forecasts(self, tenant_id: str, forecast_type: str | None = None, limit: int = 50) -> list[dict]:
        results = [f for f in self._forecasts if f.tenant_id == tenant_id]
        if forecast_type:
            results = [f for f in results if f.forecast_type == forecast_type]
        results.sort(key=lambda f: f.created_at, reverse=True)
        return [f.to_dict() for f in results[:limit]]

    def record_actual(self, forecast_id: str, actual_value: str) -> dict | None:
        """Record the actual outcome for a forecast to compute accuracy."""
        for f in self._forecasts:
            if f.id == forecast_id:
                f.actual_value = actual_value
                try:
                    predicted = float(f.predicted_value)
                    actual = float(actual_value)
                    if predicted > 0:
                        f.accuracy = round(max(0, 1 - abs(predicted - actual) / predicted), 2)
                    else:
                        f.accuracy = 1.0 if actual == 0 else 0.0
                except (ValueError, ZeroDivisionError):
                    f.accuracy = 1.0 if f.predicted_value == actual_value else 0.0
                return f.to_dict()
        return None

    def get_accuracy_report(self, tenant_id: str) -> dict:
        evaluated = [f for f in self._forecasts if f.tenant_id == tenant_id and f.accuracy is not None]
        if not evaluated:
            return {"forecasts_evaluated": 0, "avg_accuracy": None}
        avg_acc = sum(f.accuracy for f in evaluated) / len(evaluated)
        return {
            "forecasts_evaluated": len(evaluated),
            "avg_accuracy": round(avg_acc, 2),
            "by_type": self._accuracy_by_type(evaluated),
        }

    def _forecast_volume(self, history: list[dict], horizon: int) -> dict:
        volumes = [h.get("event_count", 0) for h in history[-24:]]
        if not volumes:
            return {"type": "incident_volume", "horizon": horizon, "value": 0, "confidence": 0.1}
        trend = (volumes[-1] - volumes[0]) / max(len(volumes), 1) if len(volumes) > 1 else 0
        predicted = max(0, volumes[-1] + trend * horizon)
        confidence = min(0.9, 0.5 + 0.1 * min(len(volumes), 4))
        return {
            "type": "incident_volume",
            "horizon": horizon,
            "value": round(predicted),
            "confidence": round(confidence, 2),
            "factors": ["event_velocity", "historical_trend"],
        }

    def _forecast_severity_trend(self, history: list[dict], horizon: int) -> dict:
        high_ratios = [
            h.get("high_severity_ratio", 0) for h in history[-24:]
        ]
        if not high_ratios:
            return {"type": "severity_trend", "horizon": horizon, "value": "stable", "confidence": 0.1}
        avg = sum(high_ratios) / len(high_ratios)
        recent = sum(high_ratios[-3:]) / max(len(high_ratios[-3:]), 1)
        if recent > avg * 1.5:
            trend = "escalating"
        elif recent < avg * 0.5:
            trend = "improving"
        else:
            trend = "stable"
        return {
            "type": "severity_trend",
            "horizon": horizon,
            "value": trend,
            "confidence": round(min(0.85, 0.4 + len(high_ratios) * 0.02), 2),
            "factors": ["severity_ratio_trend", "recent_vs_average"],
        }

    def _forecast_attack_likelihood(self, history: list[dict], horizon: int) -> dict:
        indicators = [h.get("threat_indicators", 0) for h in history[-24:]]
        if not indicators:
            return {"type": "attack_likelihood", "horizon": horizon, "value": "low", "confidence": 0.2}
        avg = sum(indicators) / len(indicators)
        if avg > 5:
            level = "critical"
        elif avg > 2:
            level = "high"
        elif avg > 0.5:
            level = "medium"
        else:
            level = "low"
        return {
            "type": "attack_likelihood",
            "horizon": horizon,
            "value": level,
            "confidence": round(min(0.8, 0.3 + len(indicators) * 0.02), 2),
            "factors": ["indicator_density", "trend_velocity"],
        }

    def _accuracy_by_type(self, evaluated: list[RiskForecast]) -> dict:
        by_type: dict[str, list[float]] = defaultdict(list)
        for f in evaluated:
            if f.accuracy is not None:
                by_type[f.forecast_type].append(f.accuracy)
        return {t: round(sum(v) / len(v), 2) for t, v in by_type.items()}


# Module-level singleton
risk_forecast_engine = RiskForecastEngine()
