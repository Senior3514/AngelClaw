"""AngelClaw V5.5 — Convergence: Real-Time Defense Engine.

Event streaming aggregation with live dashboard metrics, per-tenant
real-time counters, sliding window statistics, and WebSocket broadcast
registry for push-based UI updates.

Features:
  - Ingest security events with type/severity classification
  - Live metrics computation (events/sec, active threats, blocked/sec)
  - Sliding window statistics (1min, 5min, 15min)
  - WebSocket subscriber registry for real-time push
  - Per-tenant isolation with automatic counter management
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.realtime_engine")

# Sliding window durations in seconds
_WINDOW_SIZES = {"1min": 60, "5min": 300, "15min": 900}


class RealTimeEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    event_type: str  # alert, threat, block, auth, anomaly, scan, policy
    severity: str = "medium"  # info, low, medium, high, critical
    source: str = ""
    details: dict[str, Any] = {}
    timestamp: float = Field(default_factory=time.time)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Subscriber(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    subscriber_id: str
    connected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_heartbeat: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    active: bool = True
    filters: dict[str, Any] = {}


class RealTimeEngine:
    """Event streaming aggregation with live metrics and sliding windows."""

    def __init__(self) -> None:
        # Per-tenant event buffer (bounded deque for memory safety)
        self._events: dict[str, deque[RealTimeEvent]] = defaultdict(
            lambda: deque(maxlen=10000),
        )
        # Per-tenant counters
        self._total_counts: dict[str, int] = defaultdict(int)
        self._type_counts: dict[str, dict[str, int]] = defaultdict(
            lambda: defaultdict(int),
        )
        self._severity_counts: dict[str, dict[str, int]] = defaultdict(
            lambda: defaultdict(int),
        )
        # WebSocket subscribers
        self._subscribers: dict[str, dict[str, Subscriber]] = defaultdict(dict)

    # ------------------------------------------------------------------
    # Event Ingestion
    # ------------------------------------------------------------------

    def ingest_event(
        self,
        tenant_id: str,
        event_type: str,
        severity: str = "medium",
        source: str = "",
        details: dict | None = None,
    ) -> dict:
        """Ingest a real-time security event."""
        event = RealTimeEvent(
            tenant_id=tenant_id,
            event_type=event_type,
            severity=severity,
            source=source,
            details=details or {},
        )

        self._events[tenant_id].append(event)
        self._total_counts[tenant_id] += 1
        self._type_counts[tenant_id][event_type] += 1
        self._severity_counts[tenant_id][severity] += 1

        logger.debug(
            "[RT_ENGINE] Ingested event type=%s severity=%s for %s",
            event_type, severity, tenant_id,
        )
        return event.model_dump(mode="json")

    # ------------------------------------------------------------------
    # Live Metrics
    # ------------------------------------------------------------------

    def get_live_metrics(self, tenant_id: str) -> dict:
        """Compute live dashboard metrics for a tenant."""
        now = time.time()
        events = list(self._events.get(tenant_id, []))

        # Events in the last 60 seconds for rate calculation
        recent = [e for e in events if now - e.timestamp <= 60]
        elapsed = min(60.0, max(now - events[0].timestamp, 1.0)) if events else 1.0

        events_per_sec = round(len(recent) / elapsed, 2) if recent else 0.0
        threats = [e for e in recent if e.event_type == "threat"]
        blocks = [e for e in recent if e.event_type == "block"]
        blocked_per_sec = round(len(blocks) / elapsed, 2) if blocks else 0.0

        return {
            "tenant_id": tenant_id,
            "events_per_sec": events_per_sec,
            "active_threats": len(threats),
            "blocked_per_sec": blocked_per_sec,
            "total_events": self._total_counts[tenant_id],
            "by_type": dict(self._type_counts.get(tenant_id, {})),
            "by_severity": dict(self._severity_counts.get(tenant_id, {})),
            "subscriber_count": sum(
                1 for s in self._subscribers.get(tenant_id, {}).values()
                if s.active
            ),
            "computed_at": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Sliding Window Statistics
    # ------------------------------------------------------------------

    def get_sliding_window(self, tenant_id: str, window: str = "5min") -> dict:
        """Return event statistics for a sliding time window.

        Args:
            tenant_id: Tenant identifier.
            window: One of '1min', '5min', '15min'.
        """
        window_sec = _WINDOW_SIZES.get(window, 300)
        now = time.time()
        events = list(self._events.get(tenant_id, []))
        windowed = [e for e in events if now - e.timestamp <= window_sec]

        by_type: dict[str, int] = defaultdict(int)
        by_severity: dict[str, int] = defaultdict(int)
        sources: dict[str, int] = defaultdict(int)
        for evt in windowed:
            by_type[evt.event_type] += 1
            by_severity[evt.severity] += 1
            if evt.source:
                sources[evt.source] += 1

        return {
            "window": window,
            "window_seconds": window_sec,
            "event_count": len(windowed),
            "events_per_sec": round(len(windowed) / max(window_sec, 1), 2),
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
            "top_sources": dict(
                sorted(sources.items(), key=lambda x: x[1], reverse=True)[:10],
            ),
            "computed_at": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # WebSocket Subscriber Registry
    # ------------------------------------------------------------------

    def register_subscriber(
        self,
        tenant_id: str,
        subscriber_id: str,
        filters: dict | None = None,
    ) -> dict:
        """Register a WebSocket subscriber for real-time event push."""
        sub = Subscriber(
            tenant_id=tenant_id,
            subscriber_id=subscriber_id,
            filters=filters or {},
        )
        self._subscribers[tenant_id][subscriber_id] = sub
        logger.info(
            "[RT_ENGINE] Registered subscriber '%s' for %s",
            subscriber_id, tenant_id,
        )
        return sub.model_dump(mode="json")

    def unregister_subscriber(self, tenant_id: str, subscriber_id: str) -> bool:
        """Remove a WebSocket subscriber."""
        subs = self._subscribers.get(tenant_id, {})
        if subscriber_id in subs:
            del subs[subscriber_id]
            logger.info(
                "[RT_ENGINE] Unregistered subscriber '%s' for %s",
                subscriber_id, tenant_id,
            )
            return True
        return False

    def list_subscribers(self, tenant_id: str) -> list[dict]:
        """List all active subscribers for a tenant."""
        return [
            s.model_dump(mode="json")
            for s in self._subscribers.get(tenant_id, {}).values()
            if s.active
        ]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return aggregate real-time engine statistics for a tenant."""
        events = list(self._events.get(tenant_id, []))
        now = time.time()
        last_min = [e for e in events if now - e.timestamp <= 60]
        active_subs = sum(
            1 for s in self._subscribers.get(tenant_id, {}).values()
            if s.active
        )

        return {
            "total_events_ingested": self._total_counts[tenant_id],
            "buffer_size": len(events),
            "events_last_minute": len(last_min),
            "by_type": dict(self._type_counts.get(tenant_id, {})),
            "by_severity": dict(self._severity_counts.get(tenant_id, {})),
            "active_subscribers": active_subs,
            "windows_available": list(_WINDOW_SIZES.keys()),
        }


# Module-level singleton
realtime_engine_service = RealTimeEngine()
