"""AngelClaw – Behavioral anomaly detection.

Builds per-agent baselines over a rolling window and scores new events
against them.  An anomaly score of 0.0 = perfectly normal, 1.0 = extreme
deviation.
"""

from __future__ import annotations

import logging
import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from cloud.db.models import EventRow
from cloud.guardian.models import AnomalyScore, MitreTactic, ThreatIndicator

logger = logging.getLogger("angelgrid.cloud.guardian.detection.anomaly")


class AgentBaseline:
    """Rolling behavioral baseline for a single agent."""

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        self.event_count: int = 0
        self.window_hours: float = 24.0
        self.category_dist: Counter[str] = Counter()
        self.severity_dist: Counter[str] = Counter()
        self.type_dist: Counter[str] = Counter()
        self.updated_at: datetime = datetime.now(timezone.utc)

    @property
    def event_rate_per_hour(self) -> float:
        if self.window_hours <= 0:
            return 0.0
        return self.event_count / self.window_hours


class AnomalyDetector:
    """Maintains per-agent baselines and scores incoming events."""

    def __init__(self, baseline_window_hours: float = 24.0) -> None:
        self.baseline_window_hours = baseline_window_hours
        self._baselines: dict[str, AgentBaseline] = {}

    # ------------------------------------------------------------------
    # Baseline management
    # ------------------------------------------------------------------

    def build_baselines(self, historical_events: list[EventRow]) -> int:
        """Build baselines from a batch of historical events.

        Returns the number of agent baselines created/updated.
        """
        per_agent: dict[str, list[EventRow]] = defaultdict(list)
        for e in historical_events:
            per_agent[e.agent_id].append(e)

        for agent_id, events in per_agent.items():
            bl = AgentBaseline(agent_id)
            bl.event_count = len(events)
            bl.window_hours = self.baseline_window_hours

            for e in events:
                if e.type:
                    cat = e.type.split(".")[0] if "." in e.type else e.type
                    bl.category_dist[cat] += 1
                    bl.type_dist[e.type] += 1
                if e.severity:
                    bl.severity_dist[e.severity] += 1

            self._baselines[agent_id] = bl

        logger.info(
            "Built baselines for %d agents from %d events",
            len(per_agent), len(historical_events),
        )
        return len(per_agent)

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score_events(
        self, events: list[EventRow],
    ) -> list[AnomalyScore]:
        """Score a batch of new events against baselines.

        Returns one AnomalyScore per agent that appears in the batch.
        """
        per_agent: dict[str, list[EventRow]] = defaultdict(list)
        for e in events:
            per_agent[e.agent_id].append(e)

        scores: list[AnomalyScore] = []
        for agent_id, agent_events in per_agent.items():
            baseline = self._baselines.get(agent_id)
            score = self._score_agent(agent_id, agent_events, baseline)
            scores.append(score)

        return scores

    def _score_agent(
        self,
        agent_id: str,
        events: list[EventRow],
        baseline: AgentBaseline | None,
    ) -> AnomalyScore:
        """Compute anomaly score for one agent's events vs. baseline."""
        # No baseline → new agent, moderate anomaly
        if baseline is None or baseline.event_count == 0:
            return AnomalyScore(
                agent_id=agent_id,
                score=0.4,
                current_event_rate=float(len(events)),
                top_anomalous_types=[e.type for e in events[:3] if e.type],
            )

        sub_scores: list[float] = []

        # 1. Event rate deviation
        expected_rate = baseline.event_rate_per_hour
        # Estimate current rate from batch size (assume batch = 5 min window)
        current_rate = len(events) * 12.0  # extrapolate to hourly
        if expected_rate > 0:
            rate_ratio = current_rate / expected_rate
            rate_score = min(1.0, max(0.0, (rate_ratio - 1.0) / 4.0))
        else:
            rate_score = 0.5 if len(events) > 0 else 0.0
        sub_scores.append(rate_score)

        # 2. Category distribution deviation (Jensen-Shannon-like)
        current_cats: Counter[str] = Counter()
        for e in events:
            if e.type:
                cat = e.type.split(".")[0] if "." in e.type else e.type
                current_cats[cat] += 1
        cat_deviation = self._distribution_divergence(
            baseline.category_dist, current_cats,
        )
        sub_scores.append(cat_deviation)

        # 3. Severity escalation
        current_sev: Counter[str] = Counter()
        for e in events:
            if e.severity:
                current_sev[e.severity] += 1
        high_ratio_baseline = (
            (baseline.severity_dist.get("high", 0) + baseline.severity_dist.get("critical", 0))
            / max(baseline.event_count, 1)
        )
        high_ratio_current = (
            (current_sev.get("high", 0) + current_sev.get("critical", 0))
            / max(len(events), 1)
        )
        sev_score = min(1.0, max(0.0, high_ratio_current - high_ratio_baseline) * 2)
        sub_scores.append(sev_score)

        # 4. Novel event types
        known_types = set(baseline.type_dist.keys())
        novel = [e.type for e in events if e.type and e.type not in known_types]
        novelty_score = min(1.0, len(novel) / max(len(events), 1))
        sub_scores.append(novelty_score)

        # Weighted average
        weights = [0.3, 0.25, 0.25, 0.2]
        final_score = sum(s * w for s, w in zip(sub_scores, weights))

        # Per-category deviation detail
        cat_detail = {}
        all_cats = set(baseline.category_dist.keys()) | set(current_cats.keys())
        for cat in all_cats:
            bl_pct = baseline.category_dist.get(cat, 0) / max(baseline.event_count, 1)
            cur_pct = current_cats.get(cat, 0) / max(len(events), 1)
            cat_detail[cat] = round(cur_pct - bl_pct, 3)

        return AnomalyScore(
            agent_id=agent_id,
            score=round(min(1.0, max(0.0, final_score)), 3),
            baseline_event_rate=round(expected_rate, 2),
            current_event_rate=round(current_rate, 2),
            category_deviation=cat_detail,
            top_anomalous_types=novel[:5],
        )

    @staticmethod
    def _distribution_divergence(
        baseline: Counter, current: Counter,
    ) -> float:
        """Simple distribution divergence score between two counters."""
        if not baseline and not current:
            return 0.0
        if not baseline:
            return 0.5

        bl_total = sum(baseline.values()) or 1
        cur_total = sum(current.values()) or 1
        all_keys = set(baseline.keys()) | set(current.keys())

        divergence = 0.0
        for key in all_keys:
            bl_pct = baseline.get(key, 0) / bl_total
            cur_pct = current.get(key, 0) / cur_total
            divergence += abs(bl_pct - cur_pct)

        # Normalize: max divergence = 2.0 (all mass shifted)
        return min(1.0, divergence / 2.0)

    # ------------------------------------------------------------------
    # Threat indicators from anomaly scores
    # ------------------------------------------------------------------

    def scores_to_indicators(
        self, scores: list[AnomalyScore],
    ) -> list[ThreatIndicator]:
        """Convert high anomaly scores into ThreatIndicators."""
        indicators = []
        for s in scores:
            if s.score >= 0.7:
                severity = "critical" if s.score >= 0.9 else "high"
                indicators.append(ThreatIndicator(
                    indicator_type="anomaly",
                    pattern_name="behavioral_anomaly",
                    severity=severity,
                    confidence=round(s.score, 2),
                    description=(
                        f"Behavioral anomaly for agent {s.agent_id[:8]}: "
                        f"score={s.score:.2f}, rate={s.current_event_rate:.0f}/h "
                        f"(baseline {s.baseline_event_rate:.0f}/h)"
                    ),
                    related_agent_ids=[s.agent_id],
                    suggested_playbook="throttle_agent" if s.score < 0.9 else "quarantine_agent",
                    metadata={"anomaly_score": s.score},
                ))

                logger.warning(
                    "[ANOMALY] agent=%s score=%.2f severity=%s",
                    s.agent_id[:8], s.score, severity,
                )
        return indicators


# Module-level singleton
anomaly_detector = AnomalyDetector()
