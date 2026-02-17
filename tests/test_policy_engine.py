"""Tests for the ANGELNODE PolicyEngine — the critical decision path.

Covers: rule matching (category, type, source_pattern, detail_conditions),
extended operators (_pattern, _in, _gt), burst detection, category defaults,
fail-closed fallback, disabled rules, hot-reload, and BurstTracker.
"""

from __future__ import annotations

import pytest

from angelnode.core.engine import BurstTracker, PolicyEngine
from shared.models.decision import Decision
from shared.models.event import Event, EventCategory, Severity
from shared.models.policy import (
    PolicyAction,
    PolicyMatch,
    PolicyRule,
    PolicySet,
    RiskLevel,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _event(**kwargs) -> Event:
    """Create an Event with sensible defaults."""
    defaults = {
        "agent_id": "agent-test",
        "category": EventCategory.SHELL,
        "type": "exec",
        "severity": Severity.INFO,
        "details": {},
        "source": "test-process",
    }
    defaults.update(kwargs)
    return Event(**defaults)


def _rule(
    *,
    action: PolicyAction = PolicyAction.BLOCK,
    categories: list[str] | None = None,
    types: list[str] | None = None,
    source_pattern: str | None = None,
    detail_conditions: dict | None = None,
    risk_level: RiskLevel = RiskLevel.HIGH,
    enabled: bool = True,
    description: str = "test rule",
) -> PolicyRule:
    return PolicyRule(
        match=PolicyMatch(
            categories=categories,
            types=types,
            source_pattern=source_pattern,
            detail_conditions=detail_conditions,
        ),
        action=action,
        risk_level=risk_level,
        enabled=enabled,
        description=description,
    )


def _engine(*rules: PolicyRule, category_defaults: dict | None = None) -> PolicyEngine:
    ps = PolicySet(name="test-policy", rules=list(rules))
    return PolicyEngine(ps, category_defaults or {})


# ---------------------------------------------------------------------------
# Basic matching
# ---------------------------------------------------------------------------


class TestPolicyEngineBasicMatching:
    def test_category_match(self):
        """Rule with categories=['shell'] matches a shell event."""
        engine = _engine(_rule(categories=["shell"], action=PolicyAction.BLOCK))
        decision = engine.evaluate(_event(category=EventCategory.SHELL))
        assert decision.action == PolicyAction.BLOCK

    def test_category_no_match(self):
        """Rule with categories=['network'] does not match a shell event."""
        engine = _engine(
            _rule(categories=["network"], action=PolicyAction.BLOCK),
        )
        decision = engine.evaluate(_event(category=EventCategory.SHELL))
        # No rule matches, no category default → fail-closed BLOCK
        assert decision.action == PolicyAction.BLOCK

    def test_type_match(self):
        """Rule with types=['exec'] matches an exec event."""
        engine = _engine(_rule(types=["exec"], action=PolicyAction.ALERT))
        decision = engine.evaluate(_event(type="exec"))
        assert decision.action == PolicyAction.ALERT

    def test_type_no_match(self):
        """Rule with types=['read'] does not match an exec event."""
        engine = _engine(_rule(types=["read"]))
        decision = engine.evaluate(_event(type="exec"))
        # Falls through to fail-closed
        assert decision.action == PolicyAction.BLOCK

    def test_source_pattern_match(self):
        """Source pattern regex matches event.source."""
        engine = _engine(_rule(source_pattern=r"^ollama.*", action=PolicyAction.ALLOW))
        decision = engine.evaluate(_event(source="ollama-runner"))
        assert decision.action == PolicyAction.ALLOW

    def test_source_pattern_no_match(self):
        """Source pattern regex does not match different source."""
        engine = _engine(_rule(source_pattern=r"^ollama.*", action=PolicyAction.ALLOW))
        decision = engine.evaluate(_event(source="claude-agent"))
        assert decision.action == PolicyAction.BLOCK

    def test_source_pattern_none_source(self):
        """Source pattern does not match when event.source is None."""
        engine = _engine(_rule(source_pattern=r".*", action=PolicyAction.ALLOW))
        decision = engine.evaluate(_event(source=None))
        assert decision.action == PolicyAction.BLOCK

    def test_combined_category_and_type(self):
        """Rule requiring both category and type matches when both match."""
        engine = _engine(
            _rule(
                categories=["shell"],
                types=["exec"],
                action=PolicyAction.BLOCK,
            )
        )
        decision = engine.evaluate(_event(category=EventCategory.SHELL, type="exec"))
        assert decision.action == PolicyAction.BLOCK

    def test_combined_mismatch(self):
        """Rule requiring both category and type fails if type mismatches."""
        engine = _engine(
            _rule(
                categories=["shell"],
                types=["read"],
                action=PolicyAction.BLOCK,
            )
        )
        # Falls through
        decision = engine.evaluate(_event(category=EventCategory.SHELL, type="exec"))
        assert decision.matched_rule_id is None

    def test_wildcard_rule_matches_everything(self):
        """A rule with no conditions matches any event."""
        engine = _engine(_rule(action=PolicyAction.ALLOW))
        decision = engine.evaluate(_event(category=EventCategory.NETWORK))
        assert decision.action == PolicyAction.ALLOW


# ---------------------------------------------------------------------------
# Detail conditions
# ---------------------------------------------------------------------------


class TestDetailConditions:
    def test_exact_match(self):
        """Exact detail condition: 'command': 'rm -rf /'."""
        engine = _engine(
            _rule(
                detail_conditions={"command": "rm -rf /"},
                action=PolicyAction.BLOCK,
            )
        )
        decision = engine.evaluate(_event(details={"command": "rm -rf /"}))
        assert decision.action == PolicyAction.BLOCK

    def test_exact_no_match(self):
        """Exact detail condition does not match different value."""
        engine = _engine(
            _rule(
                detail_conditions={"command": "rm -rf /"},
                action=PolicyAction.BLOCK,
            )
        )
        decision = engine.evaluate(_event(details={"command": "ls -la"}))
        assert decision.matched_rule_id is None

    def test_pattern_match(self):
        """Regex pattern: 'command_pattern': 'rm\\s+-rf'."""
        engine = _engine(
            _rule(
                detail_conditions={"command_pattern": r"rm\s+-rf"},
                action=PolicyAction.BLOCK,
            )
        )
        decision = engine.evaluate(_event(details={"command": "rm -rf /tmp/test"}))
        assert decision.action == PolicyAction.BLOCK

    def test_pattern_no_match(self):
        """Regex pattern does not match safe command."""
        engine = _engine(
            _rule(
                detail_conditions={"command_pattern": r"rm\s+-rf"},
                action=PolicyAction.BLOCK,
            )
        )
        decision = engine.evaluate(_event(details={"command": "ls -la"}))
        assert decision.matched_rule_id is None

    def test_pattern_missing_key(self):
        """Pattern condition fails when base key is missing from details."""
        engine = _engine(
            _rule(
                detail_conditions={"command_pattern": r".*"},
                action=PolicyAction.BLOCK,
            )
        )
        decision = engine.evaluate(_event(details={}))
        assert decision.matched_rule_id is None

    def test_in_match(self):
        """List membership: 'method_in': ['DELETE', 'DROP']."""
        engine = _engine(
            _rule(
                detail_conditions={"method_in": ["DELETE", "DROP"]},
                action=PolicyAction.BLOCK,
            )
        )
        decision = engine.evaluate(_event(details={"method": "DELETE"}))
        assert decision.action == PolicyAction.BLOCK

    def test_in_no_match(self):
        """List membership fails for unlisted value."""
        engine = _engine(
            _rule(
                detail_conditions={"method_in": ["DELETE", "DROP"]},
                action=PolicyAction.BLOCK,
            )
        )
        decision = engine.evaluate(_event(details={"method": "SELECT"}))
        assert decision.matched_rule_id is None

    def test_in_missing_key(self):
        """List membership fails when key is missing."""
        engine = _engine(
            _rule(
                detail_conditions={"method_in": ["DELETE"]},
                action=PolicyAction.BLOCK,
            )
        )
        decision = engine.evaluate(_event(details={}))
        assert decision.matched_rule_id is None

    def test_gt_match(self):
        """Numeric GT: 'payload_size_gt': 1000000."""
        engine = _engine(
            _rule(
                detail_conditions={"payload_size_gt": 1000000},
                action=PolicyAction.BLOCK,
            )
        )
        decision = engine.evaluate(_event(details={"payload_size": 5000000}))
        assert decision.action == PolicyAction.BLOCK

    def test_gt_no_match(self):
        """Numeric GT fails for value below threshold."""
        engine = _engine(
            _rule(
                detail_conditions={"payload_size_gt": 1000000},
                action=PolicyAction.BLOCK,
            )
        )
        decision = engine.evaluate(_event(details={"payload_size": 500}))
        assert decision.matched_rule_id is None

    def test_gt_equal_no_match(self):
        """Numeric GT fails for value equal to threshold (strict >)."""
        engine = _engine(
            _rule(
                detail_conditions={"payload_size_gt": 1000},
                action=PolicyAction.BLOCK,
            )
        )
        decision = engine.evaluate(_event(details={"payload_size": 1000}))
        assert decision.matched_rule_id is None

    def test_gt_missing_key(self):
        """Numeric GT fails when key is missing."""
        engine = _engine(
            _rule(
                detail_conditions={"payload_size_gt": 100},
                action=PolicyAction.BLOCK,
            )
        )
        decision = engine.evaluate(_event(details={}))
        assert decision.matched_rule_id is None

    def test_gt_non_numeric(self):
        """Numeric GT fails gracefully for non-numeric values."""
        engine = _engine(
            _rule(
                detail_conditions={"payload_size_gt": 100},
                action=PolicyAction.BLOCK,
            )
        )
        decision = engine.evaluate(_event(details={"payload_size": "not-a-number"}))
        assert decision.matched_rule_id is None


# ---------------------------------------------------------------------------
# Rule ordering & disabled rules
# ---------------------------------------------------------------------------


class TestRuleOrdering:
    def test_first_match_wins(self):
        """First matching rule wins — order matters."""
        engine = _engine(
            _rule(categories=["shell"], action=PolicyAction.ALLOW, description="allow-shell"),
            _rule(categories=["shell"], action=PolicyAction.BLOCK, description="block-shell"),
        )
        decision = engine.evaluate(_event(category=EventCategory.SHELL))
        assert decision.action == PolicyAction.ALLOW

    def test_disabled_rule_skipped(self):
        """Disabled rules are skipped even if they would match."""
        engine = _engine(
            _rule(categories=["shell"], action=PolicyAction.ALLOW, enabled=False),
            _rule(categories=["shell"], action=PolicyAction.BLOCK),
        )
        decision = engine.evaluate(_event(category=EventCategory.SHELL))
        assert decision.action == PolicyAction.BLOCK


# ---------------------------------------------------------------------------
# Category defaults & fail-closed
# ---------------------------------------------------------------------------


class TestCategoryDefaults:
    def test_category_default_allow(self):
        """Low-risk category falls back to its default ALLOW action."""
        defaults = {
            "logging": Decision(
                action=PolicyAction.ALLOW,
                reason="Logging is always safe",
                risk_level=RiskLevel.NONE,
            ),
        }
        engine = _engine(category_defaults=defaults)  # No rules
        decision = engine.evaluate(_event(category=EventCategory.LOGGING))
        assert decision.action == PolicyAction.ALLOW

    def test_category_default_block(self):
        """High-risk category falls back to its default BLOCK action."""
        defaults = {
            "shell": Decision(
                action=PolicyAction.BLOCK,
                reason="Shell is blocked by default",
                risk_level=RiskLevel.HIGH,
            ),
        }
        engine = _engine(category_defaults=defaults)
        decision = engine.evaluate(_event(category=EventCategory.SHELL))
        assert decision.action == PolicyAction.BLOCK

    def test_fail_closed_no_default(self):
        """Category with no rule and no default → BLOCK (fail-closed)."""
        engine = _engine()  # No rules, no defaults
        decision = engine.evaluate(_event(category=EventCategory.AI_TOOL))
        assert decision.action == PolicyAction.BLOCK
        assert decision.risk_level == RiskLevel.HIGH
        assert "fail-closed" in decision.reason

    def test_rule_overrides_default(self):
        """Explicit rule takes priority over category default."""
        defaults = {
            "shell": Decision(
                action=PolicyAction.BLOCK,
                reason="Shell is blocked by default",
                risk_level=RiskLevel.HIGH,
            ),
        }
        engine = _engine(
            _rule(categories=["shell"], types=["echo"], action=PolicyAction.ALLOW),
            category_defaults=defaults,
        )
        decision = engine.evaluate(_event(category=EventCategory.SHELL, type="echo"))
        assert decision.action == PolicyAction.ALLOW


# ---------------------------------------------------------------------------
# Hot-reload
# ---------------------------------------------------------------------------


class TestHotReload:
    def test_reload_changes_policy(self):
        """Hot-reload replaces the active policy set."""
        engine = _engine(_rule(categories=["shell"], action=PolicyAction.BLOCK))
        decision = engine.evaluate(_event(category=EventCategory.SHELL))
        assert decision.action == PolicyAction.BLOCK

        new_ps = PolicySet(
            name="reloaded",
            rules=[
                _rule(categories=["shell"], action=PolicyAction.ALLOW),
            ],
        )
        engine.reload(new_ps)
        decision = engine.evaluate(_event(category=EventCategory.SHELL))
        assert decision.action == PolicyAction.ALLOW

    def test_policy_version_updates(self):
        """Reload updates the policy version hash."""
        engine = _engine(_rule(action=PolicyAction.ALLOW))
        v1 = engine.policy_version

        new_ps = PolicySet(
            name="v2",
            rules=[
                _rule(action=PolicyAction.BLOCK),
            ],
        )
        engine.reload(new_ps)
        v2 = engine.policy_version
        assert v1 != v2


# ---------------------------------------------------------------------------
# BurstTracker
# ---------------------------------------------------------------------------


class TestBurstTracker:
    def test_below_threshold(self):
        """Events below threshold do not trigger burst."""
        tracker = BurstTracker()
        for _ in range(3):
            result = tracker.record_and_check("shell", "exec", window_seconds=60, threshold=5)
        assert result is False

    def test_above_threshold(self):
        """Events above threshold trigger burst detection."""
        tracker = BurstTracker()
        results = []
        for _ in range(10):
            results.append(
                tracker.record_and_check("shell", "exec", window_seconds=60, threshold=5)
            )
        assert any(results)  # At least one True after threshold exceeded

    def test_different_keys_independent(self):
        """Different category:type keys are tracked independently."""
        tracker = BurstTracker()
        for _ in range(10):
            tracker.record_and_check("shell", "exec", window_seconds=60, threshold=5)
        result = tracker.record_and_check("network", "connect", window_seconds=60, threshold=5)
        assert result is False  # Only 1 event for network:connect


# ---------------------------------------------------------------------------
# Burst detection via policy rules
# ---------------------------------------------------------------------------


class TestBurstDetectionIntegration:
    def test_burst_rule_triggers(self):
        """Rule with burst_window_seconds+burst_threshold triggers after enough events."""
        engine = _engine(
            _rule(
                categories=["shell"],
                types=["exec"],
                detail_conditions={
                    "burst_window_seconds": 60,
                    "burst_threshold": 3,
                },
                action=PolicyAction.BLOCK,
                description="Burst shell exec",
            )
        )
        # First 3 events: threshold not yet exceeded
        for _ in range(3):
            decision = engine.evaluate(_event(category=EventCategory.SHELL, type="exec"))

        # 4th event should trigger (count > 3)
        decision = engine.evaluate(_event(category=EventCategory.SHELL, type="exec"))
        assert decision.action == PolicyAction.BLOCK
        assert "Burst" in decision.reason


# ---------------------------------------------------------------------------
# Factory: from_file
# ---------------------------------------------------------------------------


class TestFromFile:
    def test_from_file_missing(self):
        """from_file raises FileNotFoundError for missing policy file."""
        with pytest.raises(FileNotFoundError):
            PolicyEngine.from_file("/nonexistent/policy.json")

    def test_from_file_loads_default_policy(self):
        """from_file loads the shipped default_policy.json."""
        import os

        policy_path = os.path.join(
            os.path.dirname(__file__), "..", "angelnode", "config", "default_policy.json"
        )
        if not os.path.exists(policy_path):
            pytest.skip("default_policy.json not found")
        engine = PolicyEngine.from_file(policy_path)
        assert len(engine._policy_set.rules) > 0
        assert engine.policy_version
