"""AngelClaw – Chronicle (Timeline Sentinel).

Focuses on temporal correlation and event sequencing.  Detects multi-agent
coordinated activity, kill chain progression, and time-window anomalies.
Composes the existing CorrelationEngine while adding multi-agent timeline
analysis.  Part of the Angel Legion.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone

from cloud.guardian.base_agent import SubAgent
from cloud.guardian.models import (
    AgentResult,
    AgentTask,
    AgentType,
    Permission,
    ThreatIndicator,
)

logger = logging.getLogger("angelgrid.cloud.guardian.timeline_sentinel")

# Thresholds
_RAPID_SUCCESSION_SECONDS = 2.0    # events closer than this from different agents
_COORDINATED_MIN_AGENTS = 2        # minimum agents for coordinated detection
_COORDINATED_MIN_EVENTS = 3        # minimum events in window
_SEQUENCE_SUSPICIOUS_PATTERNS = [
    ["reconnaissance", "initial_access", "execution"],
    ["credential_access", "lateral_movement"],
    ["execution", "persistence", "exfiltration"],
]


class TimelineSentinel(SubAgent):
    """Chronicle — temporal correlation and event sequencing analysis."""

    def __init__(self) -> None:
        super().__init__(
            agent_type=AgentType.TIMELINE,
            permissions={Permission.READ_EVENTS, Permission.READ_TIMELINE},
        )

    async def handle_task(self, task: AgentTask) -> AgentResult:
        """Analyze events for temporal patterns.

        Expected payload:
            events: list[dict] — serialized events with timestamps
            window_seconds: int
        """
        self.require_permission(Permission.READ_TIMELINE)

        events_data = task.payload.get("events", [])
        if not events_data:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type.value,
                result_data={"indicators": []},
            )

        indicators: list[ThreatIndicator] = []

        # 1. Detect coordinated multi-agent activity
        indicators.extend(_detect_coordinated_activity(events_data))

        # 2. Detect rapid event succession across agents
        indicators.extend(_detect_rapid_succession(events_data))

        # 3. Detect suspicious event sequences (kill chain patterns)
        indicators.extend(_detect_sequence_patterns(events_data))

        # 4. Detect time clustering (burst of activity then silence)
        indicators.extend(_detect_time_clustering(events_data))

        logger.info(
            "[CHRONICLE] Analyzed %d events → %d temporal indicators",
            len(events_data),
            len(indicators),
        )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            agent_type=self.agent_type.value,
            result_data={
                "indicators": [ind.model_dump(mode="json") for ind in indicators],
                "stats": {
                    "total_events": len(events_data),
                    "indicators_found": len(indicators),
                },
            },
        )


def _parse_timestamp(ts_val: str | datetime | None) -> datetime | None:
    """Parse a timestamp value to datetime."""
    if isinstance(ts_val, datetime):
        return ts_val
    if isinstance(ts_val, str):
        try:
            return datetime.fromisoformat(ts_val)
        except (ValueError, TypeError):
            return None
    return None


def _detect_coordinated_activity(events: list[dict]) -> list[ThreatIndicator]:
    """Detect multiple agents performing similar actions near-simultaneously."""
    # Group by event type
    by_type: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        by_type[e.get("type", "")].append(e)

    indicators: list[ThreatIndicator] = []
    for event_type, type_events in by_type.items():
        if not event_type or len(type_events) < _COORDINATED_MIN_EVENTS:
            continue

        agents = {e.get("agent_id", "") for e in type_events if e.get("agent_id")}
        if len(agents) < _COORDINATED_MIN_AGENTS:
            continue

        # Check temporal proximity
        timestamps = []
        for e in type_events:
            ts = _parse_timestamp(e.get("timestamp"))
            if ts:
                timestamps.append(ts)

        if len(timestamps) < 2:
            continue

        timestamps.sort()
        span = (timestamps[-1] - timestamps[0]).total_seconds()
        if span <= 60:  # all within 1 minute
            indicators.append(
                ThreatIndicator(
                    indicator_type="temporal_correlation",
                    pattern_name="coordinated_activity",
                    severity="high",
                    confidence=0.8,
                    description=(
                        f"Coordinated '{event_type}' from {len(agents)} agents "
                        f"within {span:.0f}s"
                    ),
                    related_event_ids=[e.get("id", "") for e in type_events[:20]],
                    related_agent_ids=list(agents)[:10],
                    suggested_playbook="escalate_to_human",
                    mitre_tactic="lateral_movement",
                )
            )

    return indicators


def _detect_rapid_succession(events: list[dict]) -> list[ThreatIndicator]:
    """Detect events from different agents arriving in rapid succession."""
    timed_events: list[tuple[datetime, dict]] = []
    for e in events:
        ts = _parse_timestamp(e.get("timestamp"))
        if ts:
            timed_events.append((ts, e))

    if len(timed_events) < 2:
        return []

    timed_events.sort(key=lambda x: x[0])
    indicators: list[ThreatIndicator] = []
    rapid_groups: list[list[dict]] = []
    current_group: list[dict] = [timed_events[0][1]]

    for i in range(1, len(timed_events)):
        gap = (timed_events[i][0] - timed_events[i - 1][0]).total_seconds()
        if gap <= _RAPID_SUCCESSION_SECONDS:
            current_group.append(timed_events[i][1])
        else:
            if len(current_group) >= 3:
                rapid_groups.append(current_group)
            current_group = [timed_events[i][1]]

    if len(current_group) >= 3:
        rapid_groups.append(current_group)

    for group in rapid_groups:
        agents = {e.get("agent_id", "") for e in group if e.get("agent_id")}
        if len(agents) >= 2:
            indicators.append(
                ThreatIndicator(
                    indicator_type="temporal_correlation",
                    pattern_name="rapid_multi_agent_burst",
                    severity="high",
                    confidence=0.75,
                    description=(
                        f"Rapid event burst: {len(group)} events from "
                        f"{len(agents)} agents within {_RAPID_SUCCESSION_SECONDS}s"
                    ),
                    related_event_ids=[e.get("id", "") for e in group[:20]],
                    related_agent_ids=list(agents)[:10],
                    suggested_playbook="escalate_to_human",
                )
            )

    return indicators


def _detect_sequence_patterns(events: list[dict]) -> list[ThreatIndicator]:
    """Detect suspicious event sequences matching known kill chain patterns."""
    from cloud.guardian.detection.correlator import _infer_tactic, _TACTIC_HINTS  # noqa: F401

    # Build per-agent tactic sequences
    per_agent: dict[str, list[str]] = defaultdict(list)
    per_agent_events: dict[str, list[str]] = defaultdict(list)

    for e in events:
        agent_id = e.get("agent_id", "")
        if not agent_id:
            continue
        event_type = (e.get("type", "") or "").lower()
        for hint, tactic in _TACTIC_HINTS.items():
            if hint in event_type:
                if not per_agent[agent_id] or per_agent[agent_id][-1] != tactic:
                    per_agent[agent_id].append(tactic)
                    per_agent_events[agent_id].append(e.get("id", ""))
                break

    indicators: list[ThreatIndicator] = []
    for agent_id, tactics in per_agent.items():
        for pattern in _SEQUENCE_SUSPICIOUS_PATTERNS:
            if _is_subsequence(pattern, tactics):
                indicators.append(
                    ThreatIndicator(
                        indicator_type="temporal_correlation",
                        pattern_name="kill_chain_sequence",
                        severity="critical",
                        confidence=0.85,
                        description=(
                            f"Kill chain sequence detected on agent {agent_id[:8]}: "
                            f"{' → '.join(pattern)}"
                        ),
                        related_event_ids=per_agent_events[agent_id][:20],
                        related_agent_ids=[agent_id],
                        suggested_playbook="quarantine_agent",
                        mitre_tactic=pattern[-1],
                    )
                )
                break  # one indicator per agent

    return indicators


def _is_subsequence(pattern: list[str], sequence: list[str]) -> bool:
    """Check if pattern appears as a subsequence of sequence."""
    it = iter(sequence)
    return all(item in it for item in pattern)


def _detect_time_clustering(events: list[dict]) -> list[ThreatIndicator]:
    """Detect unusual time clustering — burst then silence pattern."""
    timed: list[tuple[datetime, dict]] = []
    for e in events:
        ts = _parse_timestamp(e.get("timestamp"))
        if ts:
            timed.append((ts, e))

    if len(timed) < 5:
        return []

    timed.sort(key=lambda x: x[0])
    total_span = (timed[-1][0] - timed[0][0]).total_seconds()
    if total_span <= 0:
        return []

    # Check if 80%+ of events cluster in <20% of the time span
    window = total_span * 0.2
    max_in_window = 0
    for i, (ts_i, _) in enumerate(timed):
        count = sum(
            1 for ts_j, _ in timed[i:]
            if (ts_j - ts_i).total_seconds() <= window
        )
        max_in_window = max(max_in_window, count)

    indicators: list[ThreatIndicator] = []
    if max_in_window >= len(timed) * 0.8 and len(timed) >= 10:
        agents = {e.get("agent_id", "") for _, e in timed if e.get("agent_id")}
        indicators.append(
            ThreatIndicator(
                indicator_type="temporal_correlation",
                pattern_name="burst_then_silence",
                severity="medium",
                confidence=0.65,
                description=(
                    f"Time clustering: {max_in_window}/{len(timed)} events in "
                    f"{window:.0f}s of {total_span:.0f}s span"
                ),
                related_agent_ids=list(agents)[:10],
                suggested_playbook="escalate_to_human",
            )
        )

    return indicators
