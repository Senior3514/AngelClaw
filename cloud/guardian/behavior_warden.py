"""AngelClaw – Drift Watcher (Behavior Warden).

Builds and monitors per-agent behavioral baselines, detecting deviation,
drift, and peer anomalies.  Composes the existing AnomalyDetector for
scoring while adding agent-profiling and peer-comparison logic.
Part of the Angel Legion.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict

from cloud.guardian.base_agent import SubAgent
from cloud.guardian.detection.anomaly import AnomalyDetector, anomaly_detector
from cloud.guardian.models import (
    AgentResult,
    AgentTask,
    AgentType,
    Permission,
    ThreatIndicator,
)

logger = logging.getLogger("angelgrid.cloud.guardian.behavior_warden")

# Thresholds
_ANOMALY_ALERT_THRESHOLD = 0.65  # score above which we alert
_PEER_DEVIATION_THRESHOLD = 3.0  # times above peer average


class BehaviorWarden(SubAgent):
    """Drift Watcher — monitors behavioral baselines and peer deviation."""

    def __init__(self, detector: AnomalyDetector | None = None) -> None:
        super().__init__(
            agent_type=AgentType.BEHAVIOR,
            permissions={Permission.READ_EVENTS, Permission.READ_AGENTS},
        )
        self._detector = detector or anomaly_detector

    async def handle_task(self, task: AgentTask) -> AgentResult:
        """Analyze events for behavioral anomalies.

        Expected payload:
            events: list[dict] — serialized events
            window_seconds: int
        """
        self.require_permission(Permission.READ_EVENTS)

        events_data = task.payload.get("events", [])
        if not events_data:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type.value,
                result_data={"indicators": []},
            )

        indicators: list[ThreatIndicator] = []

        # 1. Per-agent behavioral profiling
        per_agent = _group_by_agent(events_data)
        profiles = _build_profiles(per_agent)

        # 2. Peer comparison — agents of the same perceived role should behave similarly
        peer_indicators = _detect_peer_deviation(profiles, per_agent)
        indicators.extend(peer_indicators)

        # 3. Sudden behavior change detection
        change_indicators = _detect_sudden_change(events_data)
        indicators.extend(change_indicators)

        # 4. Category anomaly — agent suddenly using event categories it never used
        novelty_indicators = _detect_category_novelty(events_data)
        indicators.extend(novelty_indicators)

        # V2.1 — expanded behavior detection
        # 5. Time-of-day anomaly
        indicators.extend(_detect_time_of_day_anomaly(events_data))

        # 6. Dormant agent activation
        indicators.extend(_detect_dormant_agent_activation(events_data))

        logger.info(
            "[DRIFT WATCHER] Analyzed %d events from %d agents → %d indicators",
            len(events_data),
            len(per_agent),
            len(indicators),
        )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            agent_type=self.agent_type.value,
            result_data={
                "indicators": [ind.model_dump(mode="json") for ind in indicators],
                "profiles": {aid: p for aid, p in profiles.items()},
                "stats": {
                    "agents_profiled": len(profiles),
                    "total_events": len(events_data),
                    "indicators_found": len(indicators),
                },
            },
        )


def _group_by_agent(events: list[dict]) -> dict[str, list[dict]]:
    """Group events by agent_id."""
    per_agent: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        agent_id = e.get("agent_id", "")
        if agent_id:
            per_agent[agent_id].append(e)
    return per_agent


def _build_profiles(per_agent: dict[str, list[dict]]) -> dict[str, dict]:
    """Build a behavioral profile for each agent."""
    profiles: dict[str, dict] = {}
    for agent_id, events in per_agent.items():
        type_dist = Counter(e.get("type", "") for e in events)
        sev_dist = Counter(e.get("severity", "info") for e in events)
        profiles[agent_id] = {
            "event_count": len(events),
            "type_distribution": dict(type_dist.most_common(10)),
            "severity_distribution": dict(sev_dist),
            "high_critical_ratio": (
                (sev_dist.get("high", 0) + sev_dist.get("critical", 0))
                / max(len(events), 1)
            ),
        }
    return profiles


def _detect_peer_deviation(
    profiles: dict[str, dict],
    per_agent: dict[str, list[dict]],
) -> list[ThreatIndicator]:
    """Detect agents deviating significantly from their peers."""
    if len(profiles) < 2:
        return []

    avg_count = sum(p["event_count"] for p in profiles.values()) / len(profiles)
    avg_hc_ratio = sum(p["high_critical_ratio"] for p in profiles.values()) / len(profiles)

    indicators: list[ThreatIndicator] = []
    for agent_id, profile in profiles.items():
        # Event volume deviation
        if avg_count > 0 and profile["event_count"] > avg_count * _PEER_DEVIATION_THRESHOLD:
            indicators.append(
                ThreatIndicator(
                    indicator_type="behavioral_anomaly",
                    pattern_name="peer_volume_deviation",
                    severity="high",
                    confidence=0.75,
                    description=(
                        f"Agent {agent_id[:8]} has {profile['event_count']} events "
                        f"({profile['event_count'] / avg_count:.1f}x peer average)"
                    ),
                    related_event_ids=[
                        e.get("id", "")
                        for e in per_agent.get(agent_id, [])[:10]
                    ],
                    related_agent_ids=[agent_id],
                    suggested_playbook="throttle_agent",
                )
            )

        # High-severity ratio deviation
        if (
            avg_hc_ratio < 0.3
            and profile["high_critical_ratio"] > 0.5
            and profile["event_count"] >= 5
        ):
            indicators.append(
                ThreatIndicator(
                    indicator_type="behavioral_anomaly",
                    pattern_name="peer_severity_deviation",
                    severity="high",
                    confidence=0.8,
                    description=(
                        f"Agent {agent_id[:8]} severity ratio "
                        f"{profile['high_critical_ratio']:.0%} vs peer avg "
                        f"{avg_hc_ratio:.0%}"
                    ),
                    related_agent_ids=[agent_id],
                    suggested_playbook="escalate_to_human",
                )
            )

    return indicators


def _detect_sudden_change(events: list[dict]) -> list[ThreatIndicator]:
    """Detect sudden severity escalation within a single batch."""
    indicators: list[ThreatIndicator] = []
    sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    per_agent: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        per_agent[e.get("agent_id", "")].append(e)

    for agent_id, agent_events in per_agent.items():
        if not agent_id or len(agent_events) < 4:
            continue
        severities = [sev_order.get(e.get("severity", "info"), 0) for e in agent_events]
        # Check if severity trend is sharply increasing
        first_half = severities[: len(severities) // 2]
        second_half = severities[len(severities) // 2:]
        avg_first = sum(first_half) / max(len(first_half), 1)
        avg_second = sum(second_half) / max(len(second_half), 1)
        if avg_second - avg_first >= 2.0:
            indicators.append(
                ThreatIndicator(
                    indicator_type="behavioral_anomaly",
                    pattern_name="severity_escalation",
                    severity="high",
                    confidence=0.7,
                    description=(
                        f"Sharp severity escalation on agent {agent_id[:8]}: "
                        f"avg {avg_first:.1f} → {avg_second:.1f}"
                    ),
                    related_agent_ids=[agent_id],
                    suggested_playbook="escalate_to_human",
                )
            )
    return indicators


def _detect_category_novelty(events: list[dict]) -> list[ThreatIndicator]:
    """Flag agents using event categories for the first time (in this batch context)."""
    # In a real deployment this would compare against stored baselines.
    # Here we detect agents with very unusual category mix.
    indicators: list[ThreatIndicator] = []
    per_agent: dict[str, Counter] = defaultdict(Counter)
    for e in events:
        agent_id = e.get("agent_id", "")
        if agent_id:
            cat = (e.get("type", "").split(".")[0] if "." in e.get("type", "") else e.get("type", ""))
            per_agent[agent_id][cat] += 1

    for agent_id, cats in per_agent.items():
        if len(cats) >= 5:  # agent touching many different categories
            indicators.append(
                ThreatIndicator(
                    indicator_type="behavioral_anomaly",
                    pattern_name="broad_category_usage",
                    severity="medium",
                    confidence=0.6,
                    description=(
                        f"Agent {agent_id[:8]} active across {len(cats)} categories: "
                        f"{', '.join(cats.keys())}"
                    ),
                    related_agent_ids=[agent_id],
                    suggested_playbook="escalate_to_human",
                )
            )
    return indicators


def _detect_time_of_day_anomaly(events: list[dict]) -> list[ThreatIndicator]:
    """V2.1 — Detect agents active at unusual hours (potential compromise)."""
    from datetime import datetime

    per_agent_hours: dict[str, list[int]] = defaultdict(list)
    for e in events:
        agent_id = e.get("agent_id", "")
        if not agent_id:
            continue
        ts = e.get("timestamp")
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts)
            except (ValueError, TypeError):
                continue
        elif not isinstance(ts, datetime):
            continue
        per_agent_hours[agent_id].append(ts.hour)

    indicators: list[ThreatIndicator] = []
    # Off-hours: midnight to 5 AM
    off_hours = set(range(0, 6))
    for agent_id, hours in per_agent_hours.items():
        off_count = sum(1 for h in hours if h in off_hours)
        if off_count >= 3 and off_count / max(len(hours), 1) > 0.5:
            indicators.append(
                ThreatIndicator(
                    indicator_type="behavioral_anomaly",
                    pattern_name="off_hours_activity",
                    severity="medium",
                    confidence=0.65,
                    description=(
                        f"Off-hours activity: agent {agent_id[:8]} has "
                        f"{off_count}/{len(hours)} events between midnight-5AM"
                    ),
                    related_agent_ids=[agent_id],
                    suggested_playbook="escalate_to_human",
                )
            )
    return indicators


def _detect_dormant_agent_activation(events: list[dict]) -> list[ThreatIndicator]:
    """V2.1 — Detect sudden activation of previously dormant agents."""
    per_agent: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        agent_id = e.get("agent_id", "")
        if agent_id:
            per_agent[agent_id].append(e)

    indicators: list[ThreatIndicator] = []
    for agent_id, agent_events in per_agent.items():
        # Check if agent has high-severity events but was previously unknown
        high_sev_count = sum(
            1 for e in agent_events if e.get("severity") in ("high", "critical")
        )
        if high_sev_count >= 3 and len(agent_events) <= high_sev_count + 2:
            indicators.append(
                ThreatIndicator(
                    indicator_type="behavioral_anomaly",
                    pattern_name="dormant_agent_activation",
                    severity="high",
                    confidence=0.70,
                    description=(
                        f"Dormant agent activation: {agent_id[:8]} suddenly produced "
                        f"{high_sev_count} high-severity events"
                    ),
                    related_event_ids=[e.get("id", "") for e in agent_events[:10]],
                    related_agent_ids=[agent_id],
                    suggested_playbook="escalate_to_human",
                )
            )
    return indicators
