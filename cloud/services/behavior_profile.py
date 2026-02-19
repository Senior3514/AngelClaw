"""AngelClaw V4.1 — Prophecy: Behavioral Profiling Service.

Builds and maintains behavioral baselines for agents, users, and services.
Detects deviations from established patterns with configurable thresholds.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("angelclaw.behavior_profile")


class BehaviorProfile:
    def __init__(self, tenant_id: str, entity_type: str, entity_id: str) -> None:
        self.id = str(uuid.uuid4())
        self.tenant_id = tenant_id
        self.entity_type = entity_type  # agent, user, service
        self.entity_id = entity_id
        self.baseline_data: dict[str, Any] = {
            "avg_events_per_hour": 0.0,
            "common_categories": {},
            "common_event_types": {},
            "active_hours": [],
            "severity_distribution": {},
        }
        self.anomaly_threshold = 2.0
        self.last_updated = datetime.now(timezone.utc)
        self.profile_age_days = 0
        self.total_observations = 0
        self.status = "learning"  # learning, active, stale
        self.created_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "baseline_data": self.baseline_data,
            "anomaly_threshold": self.anomaly_threshold,
            "last_updated": self.last_updated.isoformat(),
            "profile_age_days": self.profile_age_days,
            "total_observations": self.total_observations,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
        }


class BehaviorProfileService:
    """Behavioral profiling with baseline management."""

    def __init__(self) -> None:
        self._profiles: dict[str, BehaviorProfile] = {}  # entity_id -> profile
        self._tenant_profiles: dict[str, list[str]] = defaultdict(list)

    def get_or_create_profile(self, tenant_id: str, entity_type: str, entity_id: str) -> dict:
        if entity_id in self._profiles:
            return self._profiles[entity_id].to_dict()
        profile = BehaviorProfile(tenant_id, entity_type, entity_id)
        self._profiles[entity_id] = profile
        self._tenant_profiles[tenant_id].append(entity_id)
        logger.info("[BEHAVIOR] Created profile for %s:%s", entity_type, entity_id[:8])
        return profile.to_dict()

    def update_profile(self, entity_id: str, events: list[dict]) -> dict | None:
        profile = self._profiles.get(entity_id)
        if not profile:
            return None

        profile.total_observations += len(events)
        profile.last_updated = datetime.now(timezone.utc)

        # Update baseline metrics
        cat_counts: dict[str, int] = defaultdict(int)
        sev_counts: dict[str, int] = defaultdict(int)
        type_counts: dict[str, int] = defaultdict(int)
        for e in events:
            cat_counts[e.get("category", "unknown")] += 1
            sev_counts[e.get("severity", "info")] += 1
            type_counts[e.get("type", "unknown")] += 1

        # Exponential moving average
        alpha = 0.3
        bl = profile.baseline_data
        bl["avg_events_per_hour"] = bl["avg_events_per_hour"] * (1 - alpha) + len(events) * alpha

        for cat, count in cat_counts.items():
            old = bl["common_categories"].get(cat, 0)
            bl["common_categories"][cat] = old * (1 - alpha) + count * alpha

        for sev, count in sev_counts.items():
            old = bl["severity_distribution"].get(sev, 0)
            bl["severity_distribution"][sev] = old * (1 - alpha) + count * alpha

        # Transition to active after enough observations
        if profile.total_observations >= 50 and profile.status == "learning":
            profile.status = "active"

        return profile.to_dict()

    def check_deviation(self, entity_id: str, current_metrics: dict) -> list[dict]:
        """Check if current behavior deviates from profile baseline."""
        profile = self._profiles.get(entity_id)
        if not profile or profile.status != "active":
            return []

        deviations = []
        bl = profile.baseline_data
        threshold = profile.anomaly_threshold

        # Check event volume
        current_vol = current_metrics.get("event_count", 0)
        expected_vol = bl.get("avg_events_per_hour", 0)
        if expected_vol > 0 and current_vol > expected_vol * threshold:
            deviations.append({
                "type": "volume_spike",
                "description": f"Event volume {current_vol} exceeds baseline {expected_vol:.1f} by {threshold}x",
                "severity": "high" if current_vol > expected_vol * 3 else "medium",
                "current": current_vol,
                "baseline": round(expected_vol, 1),
            })

        # Check new categories
        current_cats = set(current_metrics.get("categories", []))
        known_cats = set(bl.get("common_categories", {}).keys())
        new_cats = current_cats - known_cats
        if new_cats and len(known_cats) > 3:
            deviations.append({
                "type": "category_novelty",
                "description": f"New event categories observed: {', '.join(new_cats)}",
                "severity": "medium",
                "new_categories": list(new_cats),
            })

        # Check severity escalation
        current_high = current_metrics.get("high_severity_count", 0)
        baseline_high = bl.get("severity_distribution", {}).get("high", 0) + bl.get("severity_distribution", {}).get("critical", 0)
        if baseline_high > 0 and current_high > baseline_high * threshold:
            deviations.append({
                "type": "severity_escalation",
                "description": f"High/critical events ({current_high}) exceeds baseline ({baseline_high:.1f})",
                "severity": "high",
            })

        return deviations

    def list_profiles(self, tenant_id: str, status: str | None = None) -> list[dict]:
        results = []
        for eid in self._tenant_profiles.get(tenant_id, []):
            profile = self._profiles.get(eid)
            if not profile:
                continue
            if status and profile.status != status:
                continue
            results.append(profile.to_dict())
        return results

    def set_threshold(self, entity_id: str, threshold: float) -> dict | None:
        profile = self._profiles.get(entity_id)
        if not profile:
            return None
        profile.anomaly_threshold = max(1.0, min(10.0, threshold))
        return profile.to_dict()

    def get_stats(self, tenant_id: str) -> dict:
        profiles = [self._profiles[e] for e in self._tenant_profiles.get(tenant_id, []) if e in self._profiles]
        by_status: dict[str, int] = defaultdict(int)
        for p in profiles:
            by_status[p.status] += 1
        return {
            "total_profiles": len(profiles),
            "by_status": dict(by_status),
            "total_observations": sum(p.total_observations for p in profiles),
        }


# Module-level singleton
behavior_profile_service = BehaviorProfileService()
