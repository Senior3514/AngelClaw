"""AngelClaw – Warden Agent.

Real-time anomaly detection and pattern matching.  The Warden is the
eyes and ears of ANGEL — it observes events and emits ThreatIndicators
for the Orchestrator.
"""

from __future__ import annotations

import logging

from cloud.db.models import EventRow
from cloud.guardian.base_agent import SubAgent
from cloud.guardian.detection.anomaly import anomaly_detector
from cloud.guardian.detection.correlator import correlation_engine
from cloud.guardian.detection.patterns import pattern_detector
from cloud.guardian.models import (
    AgentResult,
    AgentTask,
    AgentType,
    Permission,
    ThreatIndicator,
)

logger = logging.getLogger("angelgrid.cloud.guardian.warden")


class WardenAgent(SubAgent):
    """Watches events and detects threats via patterns, anomalies, and correlation."""

    def __init__(self) -> None:
        super().__init__(
            agent_type=AgentType.WARDEN,
            permissions={Permission.READ_EVENTS, Permission.READ_AGENTS},
        )

    async def handle_task(self, task: AgentTask) -> AgentResult:
        """Process a detection task.

        Expected task payload:
            events: list[dict]  — serialized EventRow objects
            window_seconds: int — detection window (default 300)
        """
        self.require_permission(Permission.READ_EVENTS)

        events_data = task.payload.get("events", [])
        window = task.payload.get("window_seconds", 300)

        if not events_data:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type.value,
                result_data={"indicators": [], "anomaly_scores": []},
            )

        # Reconstruct EventRow-like objects for detection
        events = _deserialize_events(events_data)

        all_indicators: list[ThreatIndicator] = []

        # 1. Pattern matching (immediate)
        pattern_indicators = pattern_detector.detect(events, window)
        all_indicators.extend(pattern_indicators)

        # 2. Anomaly scoring (behavioral baseline)
        anomaly_scores = anomaly_detector.score_events(events)
        anomaly_indicators = anomaly_detector.scores_to_indicators(anomaly_scores)
        all_indicators.extend(anomaly_indicators)

        # 3. Correlation (cross-event chains)
        chains = correlation_engine.correlate(events)
        correlation_indicators = correlation_engine.chains_to_indicators(chains)
        all_indicators.extend(correlation_indicators)

        # Deduplicate by pattern_name + agent combo
        seen = set()
        unique: list[ThreatIndicator] = []
        for ind in all_indicators:
            key = (ind.pattern_name, tuple(sorted(ind.related_agent_ids)))
            if key not in seen:
                seen.add(key)
                unique.append(ind)

        logger.info(
            "[WARDEN] Analyzed %d events → %d indicators "
            "(patterns=%d, anomalies=%d, correlations=%d)",
            len(events),
            len(unique),
            len(pattern_indicators),
            len(anomaly_indicators),
            len(correlation_indicators),
        )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            agent_type=self.agent_type.value,
            result_data={
                "indicators": [ind.model_dump(mode="json") for ind in unique],
                "anomaly_scores": [s.model_dump(mode="json") for s in anomaly_scores],
                "stats": {
                    "events_analyzed": len(events),
                    "patterns_found": len(pattern_indicators),
                    "anomalies_found": len(anomaly_indicators),
                    "correlations_found": len(correlation_indicators),
                },
            },
        )


def _deserialize_events(events_data: list[dict]) -> list[EventRow]:
    """Convert dicts back into EventRow-like objects for detection."""
    from datetime import datetime, timezone

    rows: list[EventRow] = []
    for d in events_data:
        row = EventRow(
            id=d.get("id", ""),
            agent_id=d.get("agent_id", ""),
            type=d.get("type", ""),
            severity=d.get("severity", "low"),
            details=d.get("details", {}),
            source=d.get("source", ""),
        )
        # Handle timestamp
        ts = d.get("timestamp")
        if isinstance(ts, str):
            try:
                row.timestamp = datetime.fromisoformat(ts)
            except (ValueError, TypeError):
                row.timestamp = datetime.now(timezone.utc)
        elif isinstance(ts, datetime):
            row.timestamp = ts
        else:
            row.timestamp = datetime.now(timezone.utc)

        rows.append(row)
    return rows
