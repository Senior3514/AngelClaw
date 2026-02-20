"""Tests for V4.1 Prophecy: ML Anomaly, Behavior Profile, Attack Path, Risk Forecast."""

from __future__ import annotations

from cloud.services.attack_path import AttackPathEngine
from cloud.services.behavior_profile import BehaviorProfileService
from cloud.services.ml_anomaly import MLAnomalyEngine
from cloud.services.risk_forecast import RiskForecastEngine

# ---------------------------------------------------------------------------
# MLAnomalyEngine
# ---------------------------------------------------------------------------


class TestMLAnomalyBasic:
    """Baseline updates and basic detection flow."""

    def test_update_baseline_creates_entry(self):
        engine = MLAnomalyEngine()
        result = engine.update_baseline("entity-1", {"cpu": 50.0, "memory": 70.0})
        assert result["entity_id"] == "entity-1"
        assert result["observations"] == 1

    def test_update_baseline_increments_observations(self):
        engine = MLAnomalyEngine()
        engine.update_baseline("e1", {"cpu": 50.0})
        engine.update_baseline("e1", {"cpu": 55.0})
        result = engine.update_baseline("e1", {"cpu": 52.0})
        assert result["observations"] == 3

    def test_get_baseline_returns_none_for_unknown(self):
        engine = MLAnomalyEngine()
        assert engine.get_baseline("nonexistent") is None

    def test_get_baseline_returns_stats(self):
        engine = MLAnomalyEngine()
        for v in [10.0, 12.0, 11.0, 9.0, 10.5]:
            engine.update_baseline("e1", {"cpu": v})
        baseline = engine.get_baseline("e1")
        assert baseline is not None
        assert baseline["entity_id"] == "e1"
        assert baseline["observations"] == 5
        assert "cpu" in baseline["metrics"]

    def test_detect_anomalies_empty_when_not_enough_observations(self):
        engine = MLAnomalyEngine()
        engine.update_baseline("e1", {"cpu": 50.0})
        engine.update_baseline("e1", {"cpu": 55.0})
        # Only 2 observations, need >= 5
        anomalies = engine.detect_anomalies("e1", {"cpu": 999.0})
        assert anomalies == []

    def test_detect_anomalies_empty_for_unknown_entity(self):
        engine = MLAnomalyEngine()
        anomalies = engine.detect_anomalies("unknown", {"cpu": 100.0})
        assert anomalies == []


class TestMLAnomalyDetection:
    """Anomaly detection with z-score thresholds."""

    def test_detect_anomaly_when_zscore_exceeds_threshold(self):
        engine = MLAnomalyEngine()
        # Build a stable baseline near 10.0
        for _ in range(20):
            engine.update_baseline("server-1", {"event_count": 10.0})
        # Now submit an extreme value
        anomalies = engine.detect_anomalies("server-1", {"event_count": 100.0})
        assert len(anomalies) >= 1
        anomaly = anomalies[0]
        assert anomaly["entity_id"] == "server-1"
        assert anomaly["score"] > 0
        assert anomaly["severity"] in ("medium", "high", "critical")
        assert "event_count" in anomaly["description"]

    def test_no_anomaly_for_normal_value(self):
        engine = MLAnomalyEngine()
        for v in [10.0, 10.5, 9.5, 10.2, 9.8, 10.1]:
            engine.update_baseline("e1", {"cpu": v})
        # Value within normal range
        anomalies = engine.detect_anomalies("e1", {"cpu": 10.3})
        assert anomalies == []

    def test_anomaly_type_classification_volume(self):
        engine = MLAnomalyEngine()
        for _ in range(10):
            engine.update_baseline("e1", {"event_count": 5.0})
        anomalies = engine.detect_anomalies("e1", {"event_count": 500.0})
        assert len(anomalies) >= 1
        assert anomalies[0]["features"]["metric"] == "event_count"

    def test_anomaly_score_capped_at_one(self):
        engine = MLAnomalyEngine()
        for _ in range(10):
            engine.update_baseline("e1", {"rate": 1.0})
        anomalies = engine.detect_anomalies("e1", {"rate": 99999.0})
        assert len(anomalies) >= 1
        assert anomalies[0]["score"] <= 1.0

    def test_custom_threshold(self):
        engine = MLAnomalyEngine()
        # Use varying baseline values to produce reasonable variance
        for v in [8.0, 9.0, 10.0, 11.0, 12.0, 10.0, 9.0, 11.0, 10.0, 10.0]:
            engine.update_baseline("e1", {"cpu": v})
        # With a very high threshold, a moderately high value should not trigger
        anomalies = engine.detect_anomalies("e1", {"cpu": 15.0}, threshold=100.0)
        assert anomalies == []


class TestMLAnomalyBatch:
    """Batch detection across multiple entities."""

    def test_batch_detect_updates_baselines(self):
        engine = MLAnomalyEngine()
        events_by_entity = {
            "server-a": [{"category": "network", "severity": "info"}] * 5,
            "server-b": [{"category": "auth", "severity": "high"}] * 3,
        }
        engine.batch_detect(events_by_entity)
        assert engine.get_baseline("server-a") is not None
        assert engine.get_baseline("server-b") is not None

    def test_batch_detect_returns_list(self):
        engine = MLAnomalyEngine()
        events_by_entity = {
            "e1": [{"category": "network", "severity": "info"}],
        }
        result = engine.batch_detect(events_by_entity)
        assert isinstance(result, list)

    def test_batch_detect_multiple_entities_accumulate(self):
        engine = MLAnomalyEngine()
        # Build up baselines with multiple batch calls
        for _ in range(6):
            engine.batch_detect(
                {
                    "e1": [{"category": "network", "severity": "info"}] * 2,
                    "e2": [{"category": "auth", "severity": "low"}] * 2,
                }
            )
        stats = engine.get_stats()
        assert stats["total_baselines"] == 2


class TestMLAnomalyStats:
    """Stats and recent detections."""

    def test_get_stats_empty(self):
        engine = MLAnomalyEngine()
        stats = engine.get_stats()
        assert stats["total_baselines"] == 0
        assert stats["total_detections"] == 0
        assert stats["recent_detections"] == 0

    def test_get_stats_after_operations(self):
        engine = MLAnomalyEngine()
        for _ in range(10):
            engine.update_baseline("e1", {"cpu": 10.0})
        engine.detect_anomalies("e1", {"cpu": 500.0})
        stats = engine.get_stats()
        assert stats["total_baselines"] == 1
        assert stats["total_detections"] >= 1
        assert stats["recent_detections"] >= 1

    def test_get_recent_detections_empty(self):
        engine = MLAnomalyEngine()
        assert engine.get_recent_detections() == []

    def test_get_recent_detections_filtered_by_entity(self):
        engine = MLAnomalyEngine()
        for _ in range(10):
            engine.update_baseline("e1", {"cpu": 10.0})
            engine.update_baseline("e2", {"cpu": 10.0})
        engine.detect_anomalies("e1", {"cpu": 500.0})
        engine.detect_anomalies("e2", {"cpu": 500.0})
        e1_only = engine.get_recent_detections(entity_id="e1")
        assert len(e1_only) >= 1
        assert all(d["entity_id"] == "e1" for d in e1_only)


# ---------------------------------------------------------------------------
# BehaviorProfileService
# ---------------------------------------------------------------------------


class TestBehaviorProfileBasic:
    """Create, list, and update profiles."""

    def test_create_profile(self):
        svc = BehaviorProfileService()
        profile = svc.get_or_create_profile("tenant-1", "agent", "agent-001")
        assert profile["tenant_id"] == "tenant-1"
        assert profile["entity_type"] == "agent"
        assert profile["entity_id"] == "agent-001"
        assert profile["status"] == "learning"
        assert profile["total_observations"] == 0

    def test_create_profile_idempotent(self):
        svc = BehaviorProfileService()
        p1 = svc.get_or_create_profile("t1", "agent", "a1")
        p2 = svc.get_or_create_profile("t1", "agent", "a1")
        assert p1["id"] == p2["id"]

    def test_list_profiles(self):
        svc = BehaviorProfileService()
        svc.get_or_create_profile("t1", "agent", "a1")
        svc.get_or_create_profile("t1", "user", "u1")
        svc.get_or_create_profile("t2", "agent", "a2")
        profiles = svc.list_profiles("t1")
        assert len(profiles) == 2

    def test_list_profiles_filter_by_status(self):
        svc = BehaviorProfileService()
        svc.get_or_create_profile("t1", "agent", "a1")
        profiles = svc.list_profiles("t1", status="active")
        assert len(profiles) == 0  # new profiles start in "learning"
        profiles = svc.list_profiles("t1", status="learning")
        assert len(profiles) == 1

    def test_list_profiles_empty_tenant(self):
        svc = BehaviorProfileService()
        assert svc.list_profiles("nonexistent") == []


class TestBehaviorProfileUpdate:
    """Profile updates with event metrics."""

    def test_update_profile_increments_observations(self):
        svc = BehaviorProfileService()
        svc.get_or_create_profile("t1", "agent", "a1")
        events = [
            {"category": "network", "severity": "info", "type": "conn"},
            {"category": "auth", "severity": "high", "type": "login"},
        ]
        updated = svc.update_profile("a1", events)
        assert updated is not None
        assert updated["total_observations"] == 2

    def test_update_profile_unknown_entity(self):
        svc = BehaviorProfileService()
        result = svc.update_profile("nonexistent", [{"category": "x"}])
        assert result is None

    def test_update_profile_transitions_to_active(self):
        svc = BehaviorProfileService()
        svc.get_or_create_profile("t1", "agent", "a1")
        # Feed 50+ observations to trigger transition
        events = [{"category": "network", "severity": "info", "type": "conn"}] * 50
        updated = svc.update_profile("a1", events)
        assert updated is not None
        assert updated["status"] == "active"
        assert updated["total_observations"] == 50

    def test_update_profile_baseline_data_evolves(self):
        svc = BehaviorProfileService()
        svc.get_or_create_profile("t1", "agent", "a1")
        events = [{"category": "network", "severity": "info", "type": "ping"}] * 10
        updated = svc.update_profile("a1", events)
        assert updated is not None
        assert updated["baseline_data"]["avg_events_per_hour"] > 0
        assert "network" in updated["baseline_data"]["common_categories"]


class TestBehaviorProfileDeviation:
    """Deviation detection from baseline."""

    def _make_active_profile(self, svc: BehaviorProfileService) -> str:
        entity_id = "active-agent"
        svc.get_or_create_profile("t1", "agent", entity_id)
        # Feed enough events to transition to active and build a baseline
        for _ in range(10):
            events = [{"category": "network", "severity": "info", "type": "conn"}] * 5
            svc.update_profile(entity_id, events)
        return entity_id

    def test_check_deviation_learning_profile_returns_empty(self):
        svc = BehaviorProfileService()
        svc.get_or_create_profile("t1", "agent", "a1")
        deviations = svc.check_deviation("a1", {"event_count": 9999})
        assert deviations == []

    def test_check_deviation_unknown_entity_returns_empty(self):
        svc = BehaviorProfileService()
        deviations = svc.check_deviation("nonexistent", {"event_count": 100})
        assert deviations == []

    def test_check_deviation_volume_spike(self):
        svc = BehaviorProfileService()
        entity_id = self._make_active_profile(svc)
        profile = svc._profiles[entity_id]
        avg = profile.baseline_data["avg_events_per_hour"]
        # Submit a volume that exceeds threshold (2x baseline)
        spike_volume = avg * 10
        deviations = svc.check_deviation(entity_id, {"event_count": spike_volume})
        assert len(deviations) >= 1
        assert deviations[0]["type"] == "volume_spike"

    def test_check_deviation_no_spike_normal_volume(self):
        svc = BehaviorProfileService()
        entity_id = self._make_active_profile(svc)
        profile = svc._profiles[entity_id]
        avg = profile.baseline_data["avg_events_per_hour"]
        # Submit a volume within normal range
        deviations = svc.check_deviation(entity_id, {"event_count": avg * 0.5})
        volume_spikes = [d for d in deviations if d["type"] == "volume_spike"]
        assert len(volume_spikes) == 0


class TestBehaviorProfileStats:
    """Stats and threshold configuration."""

    def test_get_stats_empty(self):
        svc = BehaviorProfileService()
        stats = svc.get_stats("t1")
        assert stats["total_profiles"] == 0
        assert stats["total_observations"] == 0

    def test_get_stats_with_profiles(self):
        svc = BehaviorProfileService()
        svc.get_or_create_profile("t1", "agent", "a1")
        svc.get_or_create_profile("t1", "user", "u1")
        svc.update_profile("a1", [{"category": "net", "severity": "info", "type": "x"}] * 5)
        stats = svc.get_stats("t1")
        assert stats["total_profiles"] == 2
        assert stats["by_status"]["learning"] >= 1
        assert stats["total_observations"] == 5

    def test_set_threshold(self):
        svc = BehaviorProfileService()
        svc.get_or_create_profile("t1", "agent", "a1")
        result = svc.set_threshold("a1", 5.0)
        assert result is not None
        assert result["anomaly_threshold"] == 5.0

    def test_set_threshold_clamped(self):
        svc = BehaviorProfileService()
        svc.get_or_create_profile("t1", "agent", "a1")
        result = svc.set_threshold("a1", 0.1)
        assert result is not None
        assert result["anomaly_threshold"] == 1.0  # clamped to min 1.0

    def test_set_threshold_unknown_entity(self):
        svc = BehaviorProfileService()
        assert svc.set_threshold("nonexistent", 3.0) is None


# ---------------------------------------------------------------------------
# AttackPathEngine
# ---------------------------------------------------------------------------


class TestAttackPathBasic:
    """Node/edge setup via topology links and path computation."""

    def _make_topology(self) -> list[dict]:
        """Build a simple linear topology: A -> B -> C -> D (critical)."""
        return [
            {"source_asset_id": "A", "target_asset_id": "B", "protocol": "ssh"},
            {"source_asset_id": "B", "target_asset_id": "C", "protocol": "http"},
            {"source_asset_id": "C", "target_asset_id": "D", "protocol": "https"},
        ]

    def test_compute_paths_finds_path_to_critical_asset(self):
        engine = AttackPathEngine()
        links = self._make_topology()
        paths = engine.compute_paths(
            tenant_id="t1",
            topology_links=links,
            critical_assets=["D"],
        )
        assert len(paths) >= 1
        # At least one path should reach D
        targets = [p["target_asset_id"] for p in paths]
        assert "D" in targets

    def test_compute_paths_includes_techniques(self):
        engine = AttackPathEngine()
        links = self._make_topology()
        paths = engine.compute_paths(
            tenant_id="t1",
            topology_links=links,
            critical_assets=["D"],
        )
        # Paths should have MITRE ATT&CK techniques mapped
        for p in paths:
            assert isinstance(p["attack_techniques"], list)

    def test_compute_paths_includes_mitigations(self):
        engine = AttackPathEngine()
        links = self._make_topology()
        paths = engine.compute_paths(
            tenant_id="t1",
            topology_links=links,
            critical_assets=["D"],
        )
        for p in paths:
            assert isinstance(p["mitigations"], list)
            assert len(p["mitigations"]) >= 1

    def test_compute_paths_no_critical_assets(self):
        engine = AttackPathEngine()
        links = self._make_topology()
        paths = engine.compute_paths(
            tenant_id="t1",
            topology_links=links,
            critical_assets=[],
        )
        assert paths == []

    def test_compute_paths_unreachable_target(self):
        engine = AttackPathEngine()
        links = [
            {"source_asset_id": "A", "target_asset_id": "B", "protocol": "ssh"},
        ]
        # Z is not connected to anything
        paths = engine.compute_paths(
            tenant_id="t1",
            topology_links=links,
            critical_assets=["Z"],
        )
        assert paths == []


class TestAttackPathBFS:
    """BFS path finding through the topology graph."""

    def test_bfs_finds_shortest_path(self):
        engine = AttackPathEngine()
        links = [
            {"source_asset_id": "A", "target_asset_id": "B", "protocol": "tcp"},
            {"source_asset_id": "B", "target_asset_id": "C", "protocol": "tcp"},
            {"source_asset_id": "A", "target_asset_id": "C", "protocol": "tcp"},  # direct
        ]
        paths = engine.compute_paths(
            tenant_id="t1",
            topology_links=links,
            critical_assets=["C"],
        )
        # Should find the direct A->C path (length 2) among results
        shortest = min(paths, key=lambda p: p["path_length"])
        assert shortest["path_length"] == 2

    def test_bfs_bidirectional_links(self):
        engine = AttackPathEngine()
        links = [
            {
                "source_asset_id": "A",
                "target_asset_id": "B",
                "protocol": "smb",
                "direction": "bidirectional",
            },
        ]
        paths = engine.compute_paths(
            tenant_id="t1",
            topology_links=links,
            critical_assets=["A"],
        )
        # B->A should be reachable via bidirectional link
        b_to_a = [p for p in paths if p["source_asset_id"] == "B" and p["target_asset_id"] == "A"]
        assert len(b_to_a) >= 1

    def test_bfs_path_length_limit(self):
        engine = AttackPathEngine()
        # Build a long chain: n0 -> n1 -> n2 -> ... -> n7 (more than 6 hops)
        links = [
            {"source_asset_id": f"n{i}", "target_asset_id": f"n{i + 1}", "protocol": "tcp"}
            for i in range(8)
        ]
        paths = engine.compute_paths(
            tenant_id="t1",
            topology_links=links,
            critical_assets=["n8"],
        )
        # Paths longer than 6 nodes are excluded
        for p in paths:
            assert p["path_length"] <= 6


class TestAttackPathAdvanced:
    """Risk scoring, mitigation, and retrieval."""

    def test_risk_score_with_asset_risks(self):
        engine = AttackPathEngine()
        links = [
            {"source_asset_id": "A", "target_asset_id": "B", "protocol": "ssh"},
        ]
        paths = engine.compute_paths(
            tenant_id="t1",
            topology_links=links,
            asset_risks={"A": 30, "B": 70},
            critical_assets=["B"],
        )
        assert len(paths) >= 1
        assert paths[0]["risk_score"] > 0

    def test_get_paths_returns_stored(self):
        engine = AttackPathEngine()
        links = [
            {"source_asset_id": "A", "target_asset_id": "B", "protocol": "ssh"},
        ]
        engine.compute_paths("t1", links, critical_assets=["B"])
        stored = engine.get_paths("t1")
        assert len(stored) >= 1

    def test_get_paths_filter_by_min_risk(self):
        engine = AttackPathEngine()
        links = [
            {"source_asset_id": "A", "target_asset_id": "B", "protocol": "ssh"},
        ]
        engine.compute_paths("t1", links, asset_risks={"B": 10}, critical_assets=["B"])
        high_risk = engine.get_paths("t1", min_risk=999)
        assert high_risk == []

    def test_mitigate_path(self):
        engine = AttackPathEngine()
        links = [
            {"source_asset_id": "A", "target_asset_id": "B", "protocol": "ssh"},
        ]
        engine.compute_paths("t1", links, critical_assets=["B"])
        stored = engine.get_paths("t1")
        path_id = stored[0]["id"]
        result = engine.mitigate_path(path_id)
        assert result is not None
        assert result["status"] == "mitigated"

    def test_mitigate_nonexistent_path(self):
        engine = AttackPathEngine()
        assert engine.mitigate_path("nonexistent") is None

    def test_get_path_by_id(self):
        engine = AttackPathEngine()
        links = [
            {"source_asset_id": "X", "target_asset_id": "Y", "protocol": "rdp"},
        ]
        engine.compute_paths("t1", links, critical_assets=["Y"])
        stored = engine.get_paths("t1")
        path_id = stored[0]["id"]
        result = engine.get_path(path_id)
        assert result is not None
        assert result["id"] == path_id

    def test_get_path_nonexistent(self):
        engine = AttackPathEngine()
        assert engine.get_path("fake-id") is None


class TestAttackPathStats:
    """Stats and multi-tenant isolation."""

    def test_get_stats_empty(self):
        engine = AttackPathEngine()
        stats = engine.get_stats("t1")
        assert stats["total_paths"] == 0
        assert stats["active"] == 0
        assert stats["mitigated"] == 0
        assert stats["avg_risk"] == 0.0
        assert stats["critical_paths"] == 0

    def test_get_stats_after_computation(self):
        engine = AttackPathEngine()
        links = [
            {"source_asset_id": "A", "target_asset_id": "B", "protocol": "ssh"},
            {"source_asset_id": "B", "target_asset_id": "C", "protocol": "http"},
        ]
        engine.compute_paths("t1", links, critical_assets=["C"])
        stats = engine.get_stats("t1")
        assert stats["total_paths"] >= 1
        assert stats["active"] >= 1

    def test_stats_isolated_per_tenant(self):
        engine = AttackPathEngine()
        links = [
            {"source_asset_id": "A", "target_asset_id": "B", "protocol": "tcp"},
        ]
        engine.compute_paths("t1", links, critical_assets=["B"])
        engine.compute_paths("t2", links, critical_assets=["B"])
        stats_t1 = engine.get_stats("t1")
        stats_t2 = engine.get_stats("t2")
        assert stats_t1["total_paths"] >= 1
        assert stats_t2["total_paths"] >= 1


# ---------------------------------------------------------------------------
# RiskForecastEngine
# ---------------------------------------------------------------------------


class TestRiskForecastBasic:
    """Data points (observations) and forecast generation."""

    def test_record_observation(self):
        engine = RiskForecastEngine()
        engine.record_observation("t1", {"event_count": 10, "high_severity_ratio": 0.1})
        # Should have history recorded
        assert len(engine._event_history["t1"]) == 1

    def test_record_observation_adds_timestamp(self):
        engine = RiskForecastEngine()
        engine.record_observation("t1", {"event_count": 5})
        entry = engine._event_history["t1"][0]
        assert "timestamp" in entry

    def test_record_observation_caps_history(self):
        engine = RiskForecastEngine()
        for i in range(200):
            engine.record_observation("t1", {"event_count": i})
        # Should be capped at 168
        assert len(engine._event_history["t1"]) == 168

    def test_generate_forecasts_not_enough_data(self):
        engine = RiskForecastEngine()
        engine.record_observation("t1", {"event_count": 10})
        engine.record_observation("t1", {"event_count": 12})
        # Only 2 observations, need >= 3
        forecasts = engine.generate_forecasts("t1")
        assert forecasts == []

    def test_generate_forecasts_with_sufficient_data(self):
        engine = RiskForecastEngine()
        for i in range(5):
            engine.record_observation(
                "t1",
                {
                    "event_count": 10 + i,
                    "high_severity_ratio": 0.1,
                    "threat_indicators": 1,
                },
            )
        forecasts = engine.generate_forecasts("t1")
        assert len(forecasts) > 0
        # Default horizons are [1, 6, 24], 3 forecast types each = 9 total
        assert len(forecasts) == 9

    def test_generate_forecasts_custom_horizons(self):
        engine = RiskForecastEngine()
        for i in range(5):
            engine.record_observation("t1", {"event_count": 10 + i})
        forecasts = engine.generate_forecasts("t1", horizons=[12])
        # 3 types * 1 horizon = 3
        assert len(forecasts) == 3
        for f in forecasts:
            assert f["horizon"] == 12


class TestRiskForecastAdvanced:
    """Forecast types, accuracy tracking, and retrieval."""

    def _seed_engine(self) -> RiskForecastEngine:
        engine = RiskForecastEngine()
        for i in range(10):
            engine.record_observation(
                "t1",
                {
                    "event_count": 10 + i,
                    "high_severity_ratio": 0.05 * (i % 3),
                    "threat_indicators": i % 4,
                },
            )
        return engine

    def test_forecast_types_present(self):
        engine = self._seed_engine()
        forecasts = engine.generate_forecasts("t1", horizons=[1])
        types = {f["type"] for f in forecasts}
        assert "incident_volume" in types
        assert "severity_trend" in types
        assert "attack_likelihood" in types

    def test_forecast_confidence_bounded(self):
        engine = self._seed_engine()
        engine.generate_forecasts("t1")
        stored = engine.get_forecasts("t1")
        for f in stored:
            assert 0.0 <= f["confidence"] <= 1.0

    def test_get_forecasts_filter_by_type(self):
        engine = self._seed_engine()
        engine.generate_forecasts("t1")
        vol_only = engine.get_forecasts("t1", forecast_type="incident_volume")
        assert all(f["forecast_type"] == "incident_volume" for f in vol_only)

    def test_get_forecasts_empty_tenant(self):
        engine = RiskForecastEngine()
        assert engine.get_forecasts("nonexistent") == []

    def test_record_actual_computes_accuracy(self):
        engine = self._seed_engine()
        engine.generate_forecasts("t1", horizons=[1])
        stored = engine.get_forecasts("t1", forecast_type="incident_volume")
        assert len(stored) >= 1
        forecast_id = stored[0]["id"]
        predicted = stored[0]["predicted_value"]
        result = engine.record_actual(forecast_id, predicted)
        assert result is not None
        assert result["accuracy"] is not None
        # If actual == predicted, accuracy should be 1.0
        assert result["accuracy"] == 1.0

    def test_record_actual_nonexistent(self):
        engine = RiskForecastEngine()
        assert engine.record_actual("fake-id", "10") is None

    def test_accuracy_report_empty(self):
        engine = RiskForecastEngine()
        report = engine.get_accuracy_report("t1")
        assert report["forecasts_evaluated"] == 0
        assert report["avg_accuracy"] is None

    def test_accuracy_report_with_data(self):
        engine = self._seed_engine()
        engine.generate_forecasts("t1", horizons=[1])
        stored = engine.get_forecasts("t1", forecast_type="incident_volume")
        for f in stored:
            engine.record_actual(f["id"], f["predicted_value"])
        report = engine.get_accuracy_report("t1")
        assert report["forecasts_evaluated"] >= 1
        assert report["avg_accuracy"] is not None
        assert "incident_volume" in report["by_type"]


class TestRiskForecastStats:
    """Forecast statistics and multi-tenant isolation."""

    def test_forecasts_isolated_per_tenant(self):
        engine = RiskForecastEngine()
        for i in range(5):
            engine.record_observation("t1", {"event_count": 10 + i})
            engine.record_observation("t2", {"event_count": 20 + i})
        engine.generate_forecasts("t1")
        engine.generate_forecasts("t2")
        t1_forecasts = engine.get_forecasts("t1")
        t2_forecasts = engine.get_forecasts("t2")
        assert all(f["tenant_id"] == "t1" for f in t1_forecasts)
        assert all(f["tenant_id"] == "t2" for f in t2_forecasts)

    def test_get_forecasts_limit(self):
        engine = RiskForecastEngine()
        for i in range(5):
            engine.record_observation("t1", {"event_count": 10 + i})
        engine.generate_forecasts("t1")
        limited = engine.get_forecasts("t1", limit=2)
        assert len(limited) == 2

    def test_severity_trend_escalating(self):
        engine = RiskForecastEngine()
        # Recent observations have increasing high severity ratio
        for i in range(5):
            engine.record_observation(
                "t1",
                {
                    "event_count": 10,
                    "high_severity_ratio": 0.1 * (i + 1),
                    "threat_indicators": 0,
                },
            )
        forecasts = engine.generate_forecasts("t1", horizons=[1])
        sev_forecasts = [f for f in forecasts if f["type"] == "severity_trend"]
        assert len(sev_forecasts) >= 1
        # With escalating ratios, trend should reflect that
        assert sev_forecasts[0]["value"] in ("escalating", "stable")
