"""Tests for self-audit and learning engine."""

import pytest

from cloud.guardian.learning import LearningEngine, ReflectionEntry
from cloud.guardian.models import AuditReport


def test_learning_engine_init():
    engine = LearningEngine()
    assert engine._reflections == []
    assert engine.summary()["total_reflections"] == 0


def test_learning_record_true_positive():
    engine = LearningEngine()
    entry = engine.record_detection_outcome(
        incident_id="inc-1",
        pattern_name="repeated_secret_exfil",
        was_true_positive=True,
        confidence=0.85,
    )
    assert entry.category == "detection_accuracy"
    assert "correctly detected" in entry.lesson


def test_learning_record_false_positive():
    engine = LearningEngine()
    for i in range(3):
        entry = engine.record_detection_outcome(
            incident_id=f"inc-{i}",
            pattern_name="test_pattern",
            was_true_positive=False,
            confidence=0.6,
        )
    assert entry.category == "false_positive"
    assert engine._false_positive_patterns["test_pattern"] == 3

    # Should suggest threshold adjustment
    suggestion = engine.suggest_threshold_adjustment("test_pattern")
    assert suggestion is not None
    assert suggestion["suggested_threshold"] > 0.7


def test_learning_playbook_ranking():
    engine = LearningEngine()
    engine.record_response_outcome("i1", "quarantine_agent", success=True, resolution_time_seconds=30)
    engine.record_response_outcome("i2", "quarantine_agent", success=True, resolution_time_seconds=45)
    engine.record_response_outcome("i3", "throttle_agent", success=False)

    ranking = engine.get_playbook_ranking()
    assert len(ranking) == 2
    assert ranking[0]["playbook"] == "quarantine_agent"
    assert ranking[0]["success_rate"] == 1.0


def test_learning_reflections():
    engine = LearningEngine()
    engine.record_detection_outcome("i1", "p1", True, 0.9)
    engine.record_response_outcome("i1", "pb1", True, 60)

    reflections = engine.get_reflections()
    assert len(reflections) == 2

    filtered = engine.get_reflections(category="detection_accuracy")
    assert len(filtered) == 1
