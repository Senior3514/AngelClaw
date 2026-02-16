"""Tests for the guardian detection layer."""

from datetime import datetime, timezone

from cloud.guardian.detection.patterns import PatternDetector
from cloud.guardian.detection.anomaly import AnomalyDetector
from cloud.guardian.detection.correlator import CorrelationEngine


class FakeEvent:
    """Minimal event-like object for testing."""
    def __init__(self, **kwargs):
        self.id = kwargs.get("id", "evt-1")
        self.agent_id = kwargs.get("agent_id", "agent-1")
        self.type = kwargs.get("type", "test_event")
        self.severity = kwargs.get("severity", "info")
        self.category = kwargs.get("category", "system")
        self.details = kwargs.get("details", {})
        self.source = kwargs.get("source", "test")
        self.timestamp = kwargs.get("timestamp", datetime.now(timezone.utc))


def test_pattern_detector_no_threats():
    """Empty events should produce no indicators."""
    detector = PatternDetector()
    indicators = detector.detect([])
    assert indicators == []


def test_pattern_detector_secret_exfil():
    """Two secret-access events should trigger repeated_secret_exfil."""
    events = [
        FakeEvent(id="e1", details={"accesses_secrets": True}),
        FakeEvent(id="e2", details={"accesses_secrets": True}),
    ]
    detector = PatternDetector()
    indicators = detector.detect(events)
    names = [i.pattern_name for i in indicators]
    assert "repeated_secret_exfil" in names


def test_pattern_detector_burst():
    """Five high-severity events from one agent should trigger high_severity_burst."""
    events = [
        FakeEvent(id=f"e{i}", severity="critical", agent_id="agent-x")
        for i in range(5)
    ]
    detector = PatternDetector()
    indicators = detector.detect(events)
    names = [i.pattern_name for i in indicators]
    assert "high_severity_burst" in names


def test_anomaly_detector_empty():
    """No events should produce empty scores."""
    detector = AnomalyDetector()
    scores = detector.score_events([])
    assert scores == []


def test_correlation_engine_empty():
    """No events should produce no chains."""
    engine = CorrelationEngine()
    chains = engine.correlate([])
    assert chains == []


def test_correlation_engine_chain():
    """Multiple high-severity events with different tactics should produce a chain."""
    events = [
        FakeEvent(id="e1", agent_id="a1", type="auth_failure", category="auth",
                  severity="high",
                  timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)),
        FakeEvent(id="e2", agent_id="a1", type="file_write", category="file_system",
                  severity="high",
                  timestamp=datetime(2024, 1, 1, 0, 1, 0, tzinfo=timezone.utc)),
        FakeEvent(id="e3", agent_id="a1", type="shell_exec", category="shell",
                  severity="high",
                  timestamp=datetime(2024, 1, 1, 0, 2, 0, tzinfo=timezone.utc)),
    ]
    engine = CorrelationEngine()
    chains = engine.correlate(events)
    # Should produce at least one chain with multiple tactics
    assert len(chains) >= 1
