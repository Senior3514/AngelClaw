"""Tests for V5.5 Convergence.

RealTimeEngine, HaloScoreEngine, FleetOrchestrator, DashboardAggregator.
"""

from __future__ import annotations

import pytest

from cloud.services.dashboard_aggregator import DashboardAggregator
from cloud.services.fleet_orchestrator import FleetOrchestrator
from cloud.services.halo_engine import HaloScoreEngine
from cloud.services.realtime_engine import RealTimeEngine

TENANT = "test-tenant"


# ===========================================================================
# RealTimeEngine — Event Ingestion
# ===========================================================================


class TestRealTimeEngineIngest:
    """Ingest events and verify counters / buffers."""

    def test_ingest_single_event(self):
        svc = RealTimeEngine()
        evt = svc.ingest_event(TENANT, event_type="alert", severity="high")
        assert evt["tenant_id"] == TENANT
        assert evt["event_type"] == "alert"
        assert evt["severity"] == "high"
        assert "id" in evt

    def test_ingest_default_severity(self):
        svc = RealTimeEngine()
        evt = svc.ingest_event(TENANT, event_type="scan")
        assert evt["severity"] == "medium"

    def test_ingest_with_source_and_details(self):
        svc = RealTimeEngine()
        evt = svc.ingest_event(
            TENANT,
            event_type="threat",
            severity="critical",
            source="firewall-01",
            details={"rule": "drop-all"},
        )
        assert evt["source"] == "firewall-01"
        assert evt["details"]["rule"] == "drop-all"

    def test_ingest_increments_total_count(self):
        svc = RealTimeEngine()
        for _ in range(5):
            svc.ingest_event(TENANT, event_type="alert")
        stats = svc.get_stats(TENANT)
        assert stats["total_events_ingested"] == 5

    def test_ingest_increments_type_counts(self):
        svc = RealTimeEngine()
        svc.ingest_event(TENANT, event_type="alert")
        svc.ingest_event(TENANT, event_type="alert")
        svc.ingest_event(TENANT, event_type="block")
        stats = svc.get_stats(TENANT)
        assert stats["by_type"]["alert"] == 2
        assert stats["by_type"]["block"] == 1

    def test_ingest_increments_severity_counts(self):
        svc = RealTimeEngine()
        svc.ingest_event(TENANT, event_type="alert", severity="high")
        svc.ingest_event(TENANT, event_type="alert", severity="high")
        svc.ingest_event(TENANT, event_type="alert", severity="low")
        stats = svc.get_stats(TENANT)
        assert stats["by_severity"]["high"] == 2
        assert stats["by_severity"]["low"] == 1

    @pytest.mark.parametrize(
        "etype", ["alert", "threat", "block", "auth", "anomaly", "scan", "policy"]
    )
    def test_ingest_all_event_types(self, etype):
        svc = RealTimeEngine()
        evt = svc.ingest_event(TENANT, event_type=etype)
        assert evt["event_type"] == etype

    @pytest.mark.parametrize("sev", ["info", "low", "medium", "high", "critical"])
    def test_ingest_all_severities(self, sev):
        svc = RealTimeEngine()
        evt = svc.ingest_event(TENANT, event_type="alert", severity=sev)
        assert evt["severity"] == sev

    def test_ingest_event_has_timestamp(self):
        svc = RealTimeEngine()
        evt = svc.ingest_event(TENANT, event_type="alert")
        assert "timestamp" in evt
        assert isinstance(evt["timestamp"], (int, float))

    def test_ingest_tenant_isolation(self):
        svc = RealTimeEngine()
        svc.ingest_event("tenant-a", event_type="alert")
        svc.ingest_event("tenant-b", event_type="block")
        assert svc.get_stats("tenant-a")["total_events_ingested"] == 1
        assert svc.get_stats("tenant-b")["total_events_ingested"] == 1

    def test_buffer_size_matches_ingested(self):
        svc = RealTimeEngine()
        for _ in range(10):
            svc.ingest_event(TENANT, event_type="alert")
        stats = svc.get_stats(TENANT)
        assert stats["buffer_size"] == 10


# ===========================================================================
# RealTimeEngine — Live Metrics
# ===========================================================================


class TestRealTimeEngineLiveMetrics:
    """Live metric computation (events/sec, threats, etc.)."""

    def test_metrics_empty_tenant(self):
        svc = RealTimeEngine()
        m = svc.get_live_metrics(TENANT)
        assert m["total_events"] == 0
        assert m["events_per_sec"] == 0.0

    def test_metrics_after_ingestion(self):
        svc = RealTimeEngine()
        svc.ingest_event(TENANT, event_type="threat")
        svc.ingest_event(TENANT, event_type="block")
        m = svc.get_live_metrics(TENANT)
        assert m["total_events"] == 2
        assert m["active_threats"] >= 1

    def test_metrics_contains_expected_keys(self):
        svc = RealTimeEngine()
        svc.ingest_event(TENANT, event_type="alert")
        m = svc.get_live_metrics(TENANT)
        for key in (
            "tenant_id",
            "events_per_sec",
            "active_threats",
            "blocked_per_sec",
            "total_events",
            "by_type",
            "by_severity",
            "subscriber_count",
            "computed_at",
        ):
            assert key in m

    def test_metrics_subscriber_count_zero_when_none(self):
        svc = RealTimeEngine()
        svc.ingest_event(TENANT, event_type="alert")
        m = svc.get_live_metrics(TENANT)
        assert m["subscriber_count"] == 0

    def test_metrics_subscriber_count_reflects_registrations(self):
        svc = RealTimeEngine()
        svc.ingest_event(TENANT, event_type="alert")
        svc.register_subscriber(TENANT, "ws-1")
        svc.register_subscriber(TENANT, "ws-2")
        m = svc.get_live_metrics(TENANT)
        assert m["subscriber_count"] == 2


# ===========================================================================
# RealTimeEngine — Sliding Window
# ===========================================================================


class TestRealTimeEngineSlidingWindow:
    """Sliding window statistics across 1min, 5min, 15min."""

    def test_window_empty_tenant(self):
        svc = RealTimeEngine()
        w = svc.get_sliding_window(TENANT, window="1min")
        assert w["event_count"] == 0

    def test_window_counts_recent_events(self):
        svc = RealTimeEngine()
        for _ in range(3):
            svc.ingest_event(TENANT, event_type="alert")
        w = svc.get_sliding_window(TENANT, window="1min")
        assert w["event_count"] == 3

    @pytest.mark.parametrize("window,seconds", [("1min", 60), ("5min", 300), ("15min", 900)])
    def test_window_seconds_value(self, window, seconds):
        svc = RealTimeEngine()
        w = svc.get_sliding_window(TENANT, window=window)
        assert w["window_seconds"] == seconds

    def test_window_by_type_breakdown(self):
        svc = RealTimeEngine()
        svc.ingest_event(TENANT, event_type="alert")
        svc.ingest_event(TENANT, event_type="threat")
        w = svc.get_sliding_window(TENANT, window="5min")
        assert w["by_type"]["alert"] == 1
        assert w["by_type"]["threat"] == 1

    def test_window_top_sources(self):
        svc = RealTimeEngine()
        svc.ingest_event(TENANT, event_type="alert", source="fw-01")
        svc.ingest_event(TENANT, event_type="alert", source="fw-01")
        svc.ingest_event(TENANT, event_type="alert", source="ids-02")
        w = svc.get_sliding_window(TENANT, window="5min")
        assert w["top_sources"]["fw-01"] == 2

    def test_window_default_is_5min(self):
        svc = RealTimeEngine()
        w = svc.get_sliding_window(TENANT)
        assert w["window"] == "5min"

    def test_window_unknown_defaults_to_300(self):
        svc = RealTimeEngine()
        w = svc.get_sliding_window(TENANT, window="unknown")
        assert w["window_seconds"] == 300


# ===========================================================================
# RealTimeEngine — Subscriber Registry
# ===========================================================================


class TestRealTimeEngineSubscribers:
    """WebSocket subscriber registration, listing, removal."""

    def test_register_subscriber(self):
        svc = RealTimeEngine()
        sub = svc.register_subscriber(TENANT, "ws-client-1")
        assert sub["subscriber_id"] == "ws-client-1"
        assert sub["active"] is True

    def test_register_subscriber_with_filters(self):
        svc = RealTimeEngine()
        sub = svc.register_subscriber(TENANT, "ws-2", filters={"severity": "high"})
        assert sub["filters"]["severity"] == "high"

    def test_list_subscribers(self):
        svc = RealTimeEngine()
        svc.register_subscriber(TENANT, "a")
        svc.register_subscriber(TENANT, "b")
        subs = svc.list_subscribers(TENANT)
        assert len(subs) == 2
        ids = {s["subscriber_id"] for s in subs}
        assert ids == {"a", "b"}

    def test_list_subscribers_empty(self):
        svc = RealTimeEngine()
        assert svc.list_subscribers(TENANT) == []

    def test_unregister_subscriber(self):
        svc = RealTimeEngine()
        svc.register_subscriber(TENANT, "ws-1")
        assert svc.unregister_subscriber(TENANT, "ws-1") is True
        assert svc.list_subscribers(TENANT) == []

    def test_unregister_nonexistent(self):
        svc = RealTimeEngine()
        assert svc.unregister_subscriber(TENANT, "no-such") is False

    def test_unregister_wrong_tenant(self):
        svc = RealTimeEngine()
        svc.register_subscriber("tenant-a", "ws-1")
        assert svc.unregister_subscriber("tenant-b", "ws-1") is False

    def test_subscriber_overwrites_same_id(self):
        svc = RealTimeEngine()
        svc.register_subscriber(TENANT, "ws-1", filters={"a": 1})
        svc.register_subscriber(TENANT, "ws-1", filters={"b": 2})
        subs = svc.list_subscribers(TENANT)
        assert len(subs) == 1
        assert subs[0]["filters"] == {"b": 2}


# ===========================================================================
# RealTimeEngine — Stats
# ===========================================================================


class TestRealTimeEngineStats:
    """get_stats method coverage."""

    def test_stats_empty(self):
        svc = RealTimeEngine()
        s = svc.get_stats(TENANT)
        assert s["total_events_ingested"] == 0
        assert s["buffer_size"] == 0
        assert s["active_subscribers"] == 0

    def test_stats_windows_available(self):
        svc = RealTimeEngine()
        s = svc.get_stats(TENANT)
        assert set(s["windows_available"]) == {"1min", "5min", "15min"}

    def test_stats_reflects_subscribers(self):
        svc = RealTimeEngine()
        svc.register_subscriber(TENANT, "s1")
        s = svc.get_stats(TENANT)
        assert s["active_subscribers"] == 1


# ===========================================================================
# HaloScoreEngine — Score Computation
# ===========================================================================


class TestHaloScoreCompute:
    """compute_score and classification logic."""

    def test_compute_all_dimensions_full(self):
        svc = HaloScoreEngine()
        dims = {
            "threat_posture": 100,
            "compliance": 100,
            "vulnerability": 100,
            "incident_response": 100,
            "endpoint_health": 100,
            "policy_coverage": 100,
        }
        result = svc.compute_score(TENANT, dims)
        assert result["overall_score"] == 100.0
        assert result["classification"] == "excellent"

    def test_compute_all_dimensions_zero(self):
        svc = HaloScoreEngine()
        dims = {
            k: 0
            for k in [
                "threat_posture",
                "compliance",
                "vulnerability",
                "incident_response",
                "endpoint_health",
                "policy_coverage",
            ]
        }
        result = svc.compute_score(TENANT, dims)
        assert result["overall_score"] == 0.0
        assert result["classification"] == "critical"

    def test_compute_partial_dimensions(self):
        svc = HaloScoreEngine()
        result = svc.compute_score(TENANT, {"threat_posture": 80})
        # Only threat_posture contributes: 80 * 0.25 = 20.0
        assert result["overall_score"] == 20.0

    def test_compute_clamps_above_100(self):
        svc = HaloScoreEngine()
        result = svc.compute_score(TENANT, {"threat_posture": 200})
        assert result["dimensions"]["threat_posture"] == 100.0

    def test_compute_clamps_below_zero(self):
        svc = HaloScoreEngine()
        result = svc.compute_score(TENANT, {"compliance": -50})
        assert result["dimensions"]["compliance"] == 0.0

    @pytest.mark.parametrize(
        "score,expected_class",
        [
            (10, "critical"),
            (30, "critical"),
            (40, "poor"),
            (50, "poor"),
            (60, "fair"),
            (70, "fair"),
            (80, "good"),
            (85, "good"),
            (90, "excellent"),
            (100, "excellent"),
        ],
    )
    def test_classification_thresholds(self, score, expected_class):
        svc = HaloScoreEngine()
        # Set all dimensions to the same value so overall = value
        dims = {
            k: score
            for k in [
                "threat_posture",
                "compliance",
                "vulnerability",
                "incident_response",
                "endpoint_health",
                "policy_coverage",
            ]
        }
        result = svc.compute_score(TENANT, dims)
        assert result["classification"] == expected_class

    def test_compute_returns_weighted_dimensions(self):
        svc = HaloScoreEngine()
        dims = {"threat_posture": 80, "compliance": 60}
        result = svc.compute_score(TENANT, dims)
        # threat_posture: 80 * 0.25 = 20.0
        assert result["weighted_dimensions"]["threat_posture"] == 20.0
        # compliance: 60 * 0.20 = 12.0
        assert result["weighted_dimensions"]["compliance"] == 12.0

    def test_compute_stores_current_score(self):
        svc = HaloScoreEngine()
        svc.compute_score(TENANT, {"threat_posture": 70})
        current = svc.get_current_score(TENANT)
        assert current is not None
        assert current["overall_score"] == 70 * 0.25

    def test_compute_empty_dimensions(self):
        svc = HaloScoreEngine()
        result = svc.compute_score(TENANT, {})
        assert result["overall_score"] == 0.0

    def test_compute_ignores_unknown_dimensions(self):
        svc = HaloScoreEngine()
        result = svc.compute_score(TENANT, {"made_up_dimension": 100})
        assert result["overall_score"] == 0.0


# ===========================================================================
# HaloScoreEngine — Score Retrieval
# ===========================================================================


class TestHaloScoreRetrieval:
    """get_current_score, get_score_history, get_dimension_breakdown."""

    def test_get_current_score_none(self):
        svc = HaloScoreEngine()
        assert svc.get_current_score(TENANT) is None

    def test_get_current_score_after_compute(self):
        svc = HaloScoreEngine()
        svc.compute_score(TENANT, {"compliance": 90})
        current = svc.get_current_score(TENANT)
        assert current is not None
        assert current["tenant_id"] == TENANT

    def test_score_history_grows(self):
        svc = HaloScoreEngine()
        svc.compute_score(TENANT, {"compliance": 50})
        svc.compute_score(TENANT, {"compliance": 70})
        svc.compute_score(TENANT, {"compliance": 90})
        history = svc.get_score_history(TENANT)
        assert len(history) == 3

    def test_score_history_limit(self):
        svc = HaloScoreEngine()
        for i in range(10):
            svc.compute_score(TENANT, {"compliance": float(i * 10)})
        history = svc.get_score_history(TENANT, limit=3)
        assert len(history) == 3

    def test_score_history_empty(self):
        svc = HaloScoreEngine()
        assert svc.get_score_history(TENANT) == []

    def test_dimension_breakdown_no_score(self):
        svc = HaloScoreEngine()
        bd = svc.get_dimension_breakdown(TENANT)
        assert bd["overall_score"] == 0.0
        assert bd["dimensions"] == []
        assert bd["message"] == "No score computed yet"

    def test_dimension_breakdown_after_compute(self):
        svc = HaloScoreEngine()
        svc.compute_score(TENANT, {"threat_posture": 90, "compliance": 60})
        bd = svc.get_dimension_breakdown(TENANT)
        assert bd["overall_score"] > 0
        assert len(bd["dimensions"]) == 6
        dim_names = {d["dimension"] for d in bd["dimensions"]}
        assert "threat_posture" in dim_names
        assert "compliance" in dim_names

    def test_dimension_breakdown_sorted_desc(self):
        svc = HaloScoreEngine()
        svc.compute_score(
            TENANT,
            {
                "threat_posture": 100,
                "compliance": 10,
                "vulnerability": 50,
                "incident_response": 80,
                "endpoint_health": 30,
                "policy_coverage": 20,
            },
        )
        bd = svc.get_dimension_breakdown(TENANT)
        contributions = [d["weighted_contribution"] for d in bd["dimensions"]]
        assert contributions == sorted(contributions, reverse=True)


# ===========================================================================
# HaloScoreEngine — Stats
# ===========================================================================


class TestHaloScoreStats:
    """get_stats method coverage."""

    def test_stats_empty(self):
        svc = HaloScoreEngine()
        s = svc.get_stats(TENANT)
        assert s["current_score"] is None
        assert s["total_computations"] == 0
        assert s["avg_score"] == 0.0
        assert s["min_score"] == 0.0
        assert s["max_score"] == 0.0

    def test_stats_after_computations(self):
        svc = HaloScoreEngine()
        svc.compute_score(TENANT, {"threat_posture": 80, "compliance": 60})
        s = svc.get_stats(TENANT)
        assert s["current_score"] is not None
        assert s["total_computations"] == 1
        assert s["current_classification"] is not None

    def test_stats_dimension_weights(self):
        svc = HaloScoreEngine()
        s = svc.get_stats(TENANT)
        assert s["dimension_weights"]["threat_posture"] == 25
        assert s["dimension_weights"]["compliance"] == 20

    def test_stats_min_max(self):
        svc = HaloScoreEngine()
        # All dims = 40 => overall 40.0; All dims = 80 => overall 80.0
        svc.compute_score(
            TENANT,
            {
                k: 40
                for k in [
                    "threat_posture",
                    "compliance",
                    "vulnerability",
                    "incident_response",
                    "endpoint_health",
                    "policy_coverage",
                ]
            },
        )
        svc.compute_score(
            TENANT,
            {
                k: 80
                for k in [
                    "threat_posture",
                    "compliance",
                    "vulnerability",
                    "incident_response",
                    "endpoint_health",
                    "policy_coverage",
                ]
            },
        )
        s = svc.get_stats(TENANT)
        assert s["min_score"] == 40.0
        assert s["max_score"] == 80.0


# ===========================================================================
# FleetOrchestrator — Node Registration
# ===========================================================================


class TestFleetOrchestratorRegister:
    """register_node, remove_node, basic lifecycle."""

    def test_register_node(self):
        svc = FleetOrchestrator()
        node = svc.register_node(TENANT, hostname="node-1", os_type="linux", version="22.04")
        assert node["hostname"] == "node-1"
        assert node["os_type"] == "linux"
        assert node["version"] == "22.04"
        assert node["status"] == "online"
        assert node["health_pct"] == 100.0

    def test_register_node_lowercase_os(self):
        svc = FleetOrchestrator()
        node = svc.register_node(TENANT, hostname="n", os_type="WINDOWS")
        assert node["os_type"] == "windows"

    def test_register_with_tags(self):
        svc = FleetOrchestrator()
        node = svc.register_node(TENANT, hostname="n", os_type="linux", tags=["prod", "web"])
        assert node["tags"] == ["prod", "web"]

    def test_register_default_tags_empty(self):
        svc = FleetOrchestrator()
        node = svc.register_node(TENANT, hostname="n", os_type="linux")
        assert node["tags"] == []

    def test_remove_node(self):
        svc = FleetOrchestrator()
        node = svc.register_node(TENANT, hostname="n", os_type="linux")
        assert svc.remove_node(TENANT, node["id"]) is True
        status = svc.get_fleet_status(TENANT)
        assert status["total_nodes"] == 0

    def test_remove_node_wrong_tenant(self):
        svc = FleetOrchestrator()
        node = svc.register_node("tenant-a", hostname="n", os_type="linux")
        assert svc.remove_node("tenant-b", node["id"]) is False

    def test_remove_nonexistent_node(self):
        svc = FleetOrchestrator()
        assert svc.remove_node(TENANT, "no-such-id") is False

    @pytest.mark.parametrize("os_type", ["windows", "linux", "macos", "freebsd"])
    def test_register_various_os_types(self, os_type):
        svc = FleetOrchestrator()
        node = svc.register_node(TENANT, hostname="n", os_type=os_type)
        assert node["os_type"] == os_type


# ===========================================================================
# FleetOrchestrator — Node Health
# ===========================================================================


class TestFleetOrchestratorHealth:
    """update_node_health and status derivation."""

    def test_update_health(self):
        svc = FleetOrchestrator()
        node = svc.register_node(TENANT, hostname="n", os_type="linux")
        updated = svc.update_node_health(TENANT, node["id"], health_pct=75.0)
        assert updated is not None
        assert updated["health_pct"] == 75.0
        assert updated["status"] == "online"

    def test_health_status_degraded(self):
        svc = FleetOrchestrator()
        node = svc.register_node(TENANT, hostname="n", os_type="linux")
        updated = svc.update_node_health(TENANT, node["id"], health_pct=50.0)
        assert updated["status"] == "degraded"

    def test_health_status_critical(self):
        svc = FleetOrchestrator()
        node = svc.register_node(TENANT, hostname="n", os_type="linux")
        updated = svc.update_node_health(TENANT, node["id"], health_pct=10.0)
        assert updated["status"] == "critical"

    def test_health_status_online(self):
        svc = FleetOrchestrator()
        node = svc.register_node(TENANT, hostname="n", os_type="linux")
        updated = svc.update_node_health(TENANT, node["id"], health_pct=90.0)
        assert updated["status"] == "online"

    def test_health_clamp_above_100(self):
        svc = FleetOrchestrator()
        node = svc.register_node(TENANT, hostname="n", os_type="linux")
        updated = svc.update_node_health(TENANT, node["id"], health_pct=150.0)
        assert updated["health_pct"] == 100.0

    def test_health_clamp_below_zero(self):
        svc = FleetOrchestrator()
        node = svc.register_node(TENANT, hostname="n", os_type="linux")
        updated = svc.update_node_health(TENANT, node["id"], health_pct=-20.0)
        assert updated["health_pct"] == 0.0

    def test_health_wrong_tenant_returns_none(self):
        svc = FleetOrchestrator()
        node = svc.register_node("tenant-a", hostname="n", os_type="linux")
        assert svc.update_node_health("tenant-b", node["id"], health_pct=50.0) is None

    def test_health_nonexistent_node_returns_none(self):
        svc = FleetOrchestrator()
        assert svc.update_node_health(TENANT, "no-such", health_pct=50.0) is None

    def test_health_with_metrics(self):
        svc = FleetOrchestrator()
        node = svc.register_node(TENANT, hostname="n", os_type="linux")
        updated = svc.update_node_health(
            TENANT,
            node["id"],
            health_pct=85.0,
            metrics={"cpu": 45, "mem": 60},
        )
        assert updated["metrics"]["cpu"] == 45
        assert updated["metrics"]["mem"] == 60

    @pytest.mark.parametrize(
        "health,expected_status",
        [
            (0, "critical"),
            (24, "critical"),
            (25, "degraded"),
            (59, "degraded"),
            (60, "online"),
            (80, "online"),
            (100, "online"),
        ],
    )
    def test_health_threshold_boundaries(self, health, expected_status):
        svc = FleetOrchestrator()
        node = svc.register_node(TENANT, hostname="n", os_type="linux")
        updated = svc.update_node_health(TENANT, node["id"], health_pct=float(health))
        assert updated["status"] == expected_status


# ===========================================================================
# FleetOrchestrator — Fleet Status & Analytics
# ===========================================================================


class TestFleetOrchestratorStatus:
    """Fleet-level status aggregation and OS distribution."""

    def test_fleet_status_empty(self):
        svc = FleetOrchestrator()
        status = svc.get_fleet_status(TENANT)
        assert status["total_nodes"] == 0
        assert status["avg_health_pct"] == 0.0

    def test_fleet_status_multiple_nodes(self):
        svc = FleetOrchestrator()
        svc.register_node(TENANT, hostname="n1", os_type="linux")
        svc.register_node(TENANT, hostname="n2", os_type="windows")
        status = svc.get_fleet_status(TENANT)
        assert status["total_nodes"] == 2
        assert status["online"] == 2

    def test_fleet_status_mixed_health(self):
        svc = FleetOrchestrator()
        n1 = svc.register_node(TENANT, hostname="n1", os_type="linux")
        n2 = svc.register_node(TENANT, hostname="n2", os_type="linux")
        svc.update_node_health(TENANT, n1["id"], health_pct=80.0)
        svc.update_node_health(TENANT, n2["id"], health_pct=20.0)
        status = svc.get_fleet_status(TENANT)
        assert status["online"] == 1
        assert status["critical"] == 1
        assert status["avg_health_pct"] == 50.0

    def test_os_distribution(self):
        svc = FleetOrchestrator()
        svc.register_node(TENANT, hostname="n1", os_type="linux", version="22.04")
        svc.register_node(TENANT, hostname="n2", os_type="linux", version="22.04")
        svc.register_node(TENANT, hostname="n3", os_type="windows", version="11")
        dist = svc.get_os_distribution(TENANT)
        assert dist["by_os"]["linux"] == 2
        assert dist["by_os"]["windows"] == 1
        assert dist["by_version"]["linux/22.04"] == 2

    def test_os_distribution_empty(self):
        svc = FleetOrchestrator()
        dist = svc.get_os_distribution(TENANT)
        assert dist["total_nodes"] == 0
        assert dist["by_os"] == {}

    def test_fleet_status_tenant_isolation(self):
        svc = FleetOrchestrator()
        svc.register_node("tenant-a", hostname="n1", os_type="linux")
        svc.register_node("tenant-b", hostname="n2", os_type="linux")
        assert svc.get_fleet_status("tenant-a")["total_nodes"] == 1
        assert svc.get_fleet_status("tenant-b")["total_nodes"] == 1


# ===========================================================================
# FleetOrchestrator — Command Dispatch
# ===========================================================================


class TestFleetOrchestratorDispatch:
    """Batch command dispatch and result tracking."""

    def test_dispatch_single_node(self):
        svc = FleetOrchestrator()
        node = svc.register_node(TENANT, hostname="n1", os_type="linux")
        cmd = svc.dispatch_command(TENANT, [node["id"]], command="scan")
        assert cmd["command"] == "scan"
        assert cmd["status"] == "dispatched"
        assert node["id"] in cmd["results"]

    def test_dispatch_multiple_nodes(self):
        svc = FleetOrchestrator()
        n1 = svc.register_node(TENANT, hostname="n1", os_type="linux")
        n2 = svc.register_node(TENANT, hostname="n2", os_type="linux")
        cmd = svc.dispatch_command(TENANT, [n1["id"], n2["id"]], command="update")
        assert len(cmd["target_node_ids"]) == 2

    def test_dispatch_with_params(self):
        svc = FleetOrchestrator()
        node = svc.register_node(TENANT, hostname="n1", os_type="linux")
        cmd = svc.dispatch_command(
            TENANT,
            [node["id"]],
            command="scan",
            params={"deep": True},
        )
        assert cmd["params"]["deep"] is True

    def test_dispatch_invalid_nodes(self):
        svc = FleetOrchestrator()
        cmd = svc.dispatch_command(TENANT, ["fake-id"], command="scan")
        assert "error" in cmd

    def test_dispatch_mixed_valid_invalid(self):
        svc = FleetOrchestrator()
        node = svc.register_node(TENANT, hostname="n1", os_type="linux")
        cmd = svc.dispatch_command(TENANT, [node["id"], "fake-id"], command="scan")
        assert len(cmd["target_node_ids"]) == 1

    def test_dispatch_wrong_tenant_nodes(self):
        svc = FleetOrchestrator()
        node = svc.register_node("other-tenant", hostname="n1", os_type="linux")
        cmd = svc.dispatch_command(TENANT, [node["id"]], command="scan")
        assert "error" in cmd

    def test_dispatch_result_has_hostname(self):
        svc = FleetOrchestrator()
        node = svc.register_node(TENANT, hostname="server-01", os_type="linux")
        cmd = svc.dispatch_command(TENANT, [node["id"]], command="scan")
        assert cmd["results"][node["id"]]["hostname"] == "server-01"


# ===========================================================================
# FleetOrchestrator — Stats
# ===========================================================================


class TestFleetOrchestratorStats:
    """get_stats method coverage."""

    def test_stats_empty(self):
        svc = FleetOrchestrator()
        s = svc.get_stats(TENANT)
        assert s["total_nodes"] == 0
        assert s["total_commands"] == 0

    def test_stats_after_registration(self):
        svc = FleetOrchestrator()
        svc.register_node(TENANT, hostname="n1", os_type="linux")
        svc.register_node(TENANT, hostname="n2", os_type="windows")
        s = svc.get_stats(TENANT)
        assert s["total_nodes"] == 2
        assert s["by_os"]["linux"] == 1
        assert s["by_os"]["windows"] == 1

    def test_stats_avg_health(self):
        svc = FleetOrchestrator()
        n1 = svc.register_node(TENANT, hostname="n1", os_type="linux")
        n2 = svc.register_node(TENANT, hostname="n2", os_type="linux")
        svc.update_node_health(TENANT, n1["id"], health_pct=60.0)
        svc.update_node_health(TENANT, n2["id"], health_pct=80.0)
        s = svc.get_stats(TENANT)
        assert s["avg_health_pct"] == 70.0

    def test_stats_commands_count(self):
        svc = FleetOrchestrator()
        node = svc.register_node(TENANT, hostname="n1", os_type="linux")
        svc.dispatch_command(TENANT, [node["id"]], command="scan")
        svc.dispatch_command(TENANT, [node["id"]], command="update")
        s = svc.get_stats(TENANT)
        assert s["total_commands"] == 2


# ===========================================================================
# DashboardAggregator — Data Ingestion
# ===========================================================================


class TestDashboardAggregatorIngestion:
    """update_halo_score, update_wingspan, update_threat_data, etc."""

    def test_update_halo_score(self):
        svc = DashboardAggregator()
        svc.update_halo_score(TENANT, 85.0)
        cc = svc.get_command_center(TENANT)
        assert cc["halo_score"] == 85.0

    def test_update_halo_score_clamp_above(self):
        svc = DashboardAggregator()
        svc.update_halo_score(TENANT, 150.0)
        cc = svc.get_command_center(TENANT)
        assert cc["halo_score"] == 100.0

    def test_update_halo_score_clamp_below(self):
        svc = DashboardAggregator()
        svc.update_halo_score(TENANT, -10.0)
        cc = svc.get_command_center(TENANT)
        assert cc["halo_score"] == 0.0

    def test_update_wingspan(self):
        svc = DashboardAggregator()
        svc.update_wingspan(TENANT, {"total_nodes": 10, "online_nodes": 8, "coverage_pct": 80.0})
        ws = svc.get_wingspan_stats(TENANT)
        assert ws["total_nodes"] == 10
        assert ws["online_nodes"] == 8

    def test_update_threat_data(self):
        svc = DashboardAggregator()
        svc.update_threat_data(TENANT, {"total_threats": 5, "total_alerts": 20})
        tl = svc.get_threat_landscape(TENANT)
        assert tl["total_threats"] == 5
        assert tl["total_alerts"] == 20

    def test_update_compliance(self):
        svc = DashboardAggregator()
        svc.update_compliance(TENANT, {"overall_pct": 92.0, "frameworks": ["SOC2", "HIPAA"]})
        cc = svc.get_command_center(TENANT)
        assert cc["compliance_status"]["overall_pct"] == 92.0
        assert "SOC2" in cc["compliance_status"]["frameworks"]

    def test_push_event(self):
        svc = DashboardAggregator()
        svc.push_event(TENANT, {"type": "alert", "msg": "Intrusion detected"})
        cc = svc.get_command_center(TENANT)
        assert len(cc["recent_events"]) == 1
        assert cc["recent_events"][0]["type"] == "alert"

    def test_push_event_has_timestamp(self):
        svc = DashboardAggregator()
        svc.push_event(TENANT, {"type": "alert"})
        cc = svc.get_command_center(TENANT)
        assert "timestamp" in cc["recent_events"][0]

    def test_push_event_caps_at_200(self):
        svc = DashboardAggregator()
        for i in range(210):
            svc.push_event(TENANT, {"idx": i})
        s = svc.get_stats(TENANT)
        assert s["recent_events_count"] == 200


# ===========================================================================
# DashboardAggregator — Dashboard Payloads
# ===========================================================================


class TestDashboardAggregatorPayloads:
    """get_command_center, get_wingspan_stats, get_threat_landscape, get_predictive_stats."""

    def test_command_center_empty(self):
        svc = DashboardAggregator()
        cc = svc.get_command_center(TENANT)
        assert cc["tenant_id"] == TENANT
        assert cc["halo_score"] == 0.0
        assert cc["wingspan"]["total_nodes"] == 0
        assert cc["threat_count"] == 0

    def test_command_center_keys(self):
        svc = DashboardAggregator()
        cc = svc.get_command_center(TENANT)
        for key in (
            "tenant_id",
            "halo_score",
            "wingspan",
            "threat_count",
            "alert_count",
            "active_wardens",
            "top_threats",
            "compliance_status",
            "recent_events",
            "generated_at",
        ):
            assert key in cc

    def test_command_center_recent_events_max_20(self):
        svc = DashboardAggregator()
        for i in range(30):
            svc.push_event(TENANT, {"idx": i})
        cc = svc.get_command_center(TENANT)
        assert len(cc["recent_events"]) == 20

    def test_wingspan_stats_empty(self):
        svc = DashboardAggregator()
        ws = svc.get_wingspan_stats(TENANT)
        assert ws["total_nodes"] == 0
        assert ws["coverage_pct"] == 0.0

    def test_wingspan_stats_populated(self):
        svc = DashboardAggregator()
        svc.update_wingspan(
            TENANT,
            {
                "total_nodes": 50,
                "online_nodes": 45,
                "offline_nodes": 3,
                "degraded_nodes": 2,
                "coverage_pct": 90.0,
                "active_wardens": 5,
                "os_distribution": {"linux": 30, "windows": 20},
            },
        )
        ws = svc.get_wingspan_stats(TENANT)
        assert ws["total_nodes"] == 50
        assert ws["online_nodes"] == 45
        assert ws["os_distribution"]["linux"] == 30

    def test_threat_landscape_empty(self):
        svc = DashboardAggregator()
        tl = svc.get_threat_landscape(TENANT)
        assert tl["total_threats"] == 0
        assert tl["by_severity"] == {}

    def test_threat_landscape_populated(self):
        svc = DashboardAggregator()
        svc.update_threat_data(
            TENANT,
            {
                "total_threats": 12,
                "total_alerts": 100,
                "by_severity": {"high": 3, "medium": 9},
                "by_category": {"malware": 5, "phishing": 7},
                "top_threats": [{"name": "ransomware"}, {"name": "apt"}],
                "active_incidents": 2,
                "mttd_minutes": 15,
                "mttr_minutes": 45,
            },
        )
        tl = svc.get_threat_landscape(TENANT)
        assert tl["total_threats"] == 12
        assert tl["by_severity"]["high"] == 3
        assert tl["mean_time_to_detect"] == 15
        assert tl["mean_time_to_respond"] == 45

    def test_predictive_stats_empty(self):
        svc = DashboardAggregator()
        ps = svc.get_predictive_stats(TENANT)
        assert ps["threat_trend"] == "stable"
        assert ps["risk_forecast"] == "moderate"

    def test_predictive_stats_populated(self):
        svc = DashboardAggregator()
        svc.update_threat_data(
            TENANT,
            {
                "threat_trend": "increasing",
                "risk_forecast": "high",
                "predicted_incidents_24h": 7,
                "recommended_actions": ["patch", "isolate"],
            },
        )
        ps = svc.get_predictive_stats(TENANT)
        assert ps["threat_trend"] == "increasing"
        assert ps["risk_forecast"] == "high"
        assert ps["predicted_incidents_24h"] == 7
        assert len(ps["recommended_actions"]) == 2

    def test_predictive_halo_trend_stable_no_history(self):
        svc = DashboardAggregator()
        ps = svc.get_predictive_stats(TENANT)
        assert ps["halo_score_trend"] == "stable"

    def test_predictive_halo_trend_improving(self):
        svc = DashboardAggregator()
        # Generate command_center snapshots with increasing halo_score
        for score in [50.0, 55.0, 60.0]:
            svc.update_halo_score(TENANT, score)
            svc.get_command_center(TENANT)
        ps = svc.get_predictive_stats(TENANT)
        assert ps["halo_score_trend"] == "improving"

    def test_predictive_halo_trend_declining(self):
        svc = DashboardAggregator()
        for score in [80.0, 75.0, 70.0]:
            svc.update_halo_score(TENANT, score)
            svc.get_command_center(TENANT)
        ps = svc.get_predictive_stats(TENANT)
        assert ps["halo_score_trend"] == "declining"


# ===========================================================================
# DashboardAggregator — Snapshot Recording
# ===========================================================================


class TestDashboardAggregatorSnapshots:
    """Verify snapshot recording and history."""

    def test_snapshot_recorded_on_command_center(self):
        svc = DashboardAggregator()
        svc.get_command_center(TENANT)
        s = svc.get_stats(TENANT)
        assert s["total_snapshots"] >= 1
        assert s["by_section"]["command_center"] >= 1

    def test_snapshot_recorded_on_wingspan(self):
        svc = DashboardAggregator()
        svc.get_wingspan_stats(TENANT)
        s = svc.get_stats(TENANT)
        assert s["by_section"]["wingspan"] >= 1

    def test_snapshot_recorded_on_threat_landscape(self):
        svc = DashboardAggregator()
        svc.get_threat_landscape(TENANT)
        s = svc.get_stats(TENANT)
        assert s["by_section"]["threat_landscape"] >= 1

    def test_snapshot_recorded_on_predictive(self):
        svc = DashboardAggregator()
        svc.get_predictive_stats(TENANT)
        s = svc.get_stats(TENANT)
        assert s["by_section"]["predictive"] >= 1

    def test_multiple_snapshots_accumulate(self):
        svc = DashboardAggregator()
        svc.get_command_center(TENANT)
        svc.get_command_center(TENANT)
        svc.get_wingspan_stats(TENANT)
        s = svc.get_stats(TENANT)
        assert s["total_snapshots"] == 3


# ===========================================================================
# DashboardAggregator — Stats
# ===========================================================================


class TestDashboardAggregatorStats:
    """get_stats method coverage."""

    def test_stats_empty(self):
        svc = DashboardAggregator()
        s = svc.get_stats(TENANT)
        assert s["total_snapshots"] == 0
        assert s["cached_halo_score"] == 0.0
        assert s["recent_events_count"] == 0
        assert s["widgets_configured"] == 0

    def test_stats_after_halo_update(self):
        svc = DashboardAggregator()
        svc.update_halo_score(TENANT, 77.0)
        s = svc.get_stats(TENANT)
        assert s["cached_halo_score"] == 77.0

    def test_stats_after_events(self):
        svc = DashboardAggregator()
        svc.push_event(TENANT, {"type": "alert"})
        svc.push_event(TENANT, {"type": "block"})
        s = svc.get_stats(TENANT)
        assert s["recent_events_count"] == 2

    def test_stats_tenant_isolation(self):
        svc = DashboardAggregator()
        svc.update_halo_score("tenant-a", 90.0)
        svc.update_halo_score("tenant-b", 30.0)
        assert svc.get_stats("tenant-a")["cached_halo_score"] == 90.0
        assert svc.get_stats("tenant-b")["cached_halo_score"] == 30.0


# ===========================================================================
# DashboardAggregator — Edge Cases
# ===========================================================================


class TestDashboardAggregatorEdgeCases:
    """Edge cases and integration-like scenarios."""

    def test_top_threats_capped_at_5_in_command_center(self):
        svc = DashboardAggregator()
        svc.update_threat_data(
            TENANT,
            {
                "top_threats": [{"name": f"t{i}"} for i in range(10)],
            },
        )
        cc = svc.get_command_center(TENANT)
        assert len(cc["top_threats"]) == 5

    def test_top_threats_capped_at_10_in_landscape(self):
        svc = DashboardAggregator()
        svc.update_threat_data(
            TENANT,
            {
                "top_threats": [{"name": f"t{i}"} for i in range(20)],
            },
        )
        tl = svc.get_threat_landscape(TENANT)
        assert len(tl["top_threats"]) == 10

    def test_command_center_full_integration(self):
        svc = DashboardAggregator()
        svc.update_halo_score(TENANT, 88.0)
        svc.update_wingspan(
            TENANT,
            {"total_nodes": 100, "online_nodes": 95, "coverage_pct": 95.0, "active_wardens": 3},
        )
        svc.update_threat_data(TENANT, {"total_threats": 5, "total_alerts": 50})
        svc.update_compliance(TENANT, {"overall_pct": 97.0, "frameworks": ["SOC2"]})
        svc.push_event(TENANT, {"type": "alert", "msg": "test"})
        cc = svc.get_command_center(TENANT)
        assert cc["halo_score"] == 88.0
        assert cc["wingspan"]["total_nodes"] == 100
        assert cc["threat_count"] == 5
        assert cc["compliance_status"]["overall_pct"] == 97.0
        assert len(cc["recent_events"]) == 1

    def test_overwrite_wingspan(self):
        svc = DashboardAggregator()
        svc.update_wingspan(TENANT, {"total_nodes": 10})
        svc.update_wingspan(TENANT, {"total_nodes": 20})
        ws = svc.get_wingspan_stats(TENANT)
        assert ws["total_nodes"] == 20
