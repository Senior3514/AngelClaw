"""Tests for V3.0 services: AntiTamper, FeedbackLoop, SelfHardening.

Covers basic CRUD, edge cases, mode transitions, multi-tenant isolation,
heartbeat/checksum detection, feedback-driven recommendations, hardening
cycles, and action apply/revert lifecycle.
"""

from __future__ import annotations

import pytest

from cloud.services.anti_tamper import AntiTamperService
from cloud.services.feedback_loop import FeedbackService
from cloud.services.self_hardening import SelfHardeningEngine


# ---------------------------------------------------------------------------
# AntiTamperService
# ---------------------------------------------------------------------------

class TestAntiTamperBasic:
    """Basic enable/disable/status operations."""

    def test_initial_status(self):
        svc = AntiTamperService()
        s = svc.status()
        assert s["enabled"] is False
        assert s["mode"] == "off"

    def test_enable(self):
        svc = AntiTamperService()
        result = svc.enable()
        assert result["enabled"] is True
        assert result["mode"] == "monitor"

    def test_disable(self):
        svc = AntiTamperService()
        svc.enable()
        result = svc.disable()
        assert result["enabled"] is False
        assert result["mode"] == "off"

    def test_check_status_active(self):
        svc = AntiTamperService()
        svc.enable()
        cs = svc.check_status()
        assert cs["active"] is True
        assert cs["enabled"] is True
        assert cs["mode"] == "monitor"

    def test_check_status_inactive(self):
        svc = AntiTamperService()
        cs = svc.check_status()
        assert cs["active"] is False
        assert cs["enabled"] is False


class TestAntiTamperConfigure:
    """Simple and full configure() API."""

    def test_simple_configure_monitor(self):
        svc = AntiTamperService()
        result = svc.configure("monitor", enabled=True)
        assert result["configured"] is True
        assert result["mode"] == "monitor"
        assert result["enabled"] is True

    def test_simple_configure_enforce(self):
        svc = AntiTamperService()
        result = svc.configure("enforce", enabled=True)
        assert result["configured"] is True
        assert result["mode"] == "enforce"

    def test_simple_configure_off(self):
        svc = AntiTamperService()
        svc.enable()
        result = svc.configure("off")
        assert result["configured"] is True
        assert result["mode"] == "off"

    def test_simple_configure_invalid_mode(self):
        svc = AntiTamperService()
        result = svc.configure("invalid_mode")
        assert result["configured"] is False
        assert "error" in result

    def test_full_configure_returns_config_object(self):
        svc = AntiTamperService()
        config = svc.configure("tenant-a", mode="enforce", agent_id="agent-1")
        assert config.tenant_id == "tenant-a"
        assert config.mode.value == "enforce"
        assert config.agent_id == "agent-1"

    def test_full_configure_invalid_mode_raises(self):
        svc = AntiTamperService()
        with pytest.raises(ValueError, match="Invalid mode"):
            svc.configure("tenant-a", mode="bad_mode")


class TestAntiTamperEvents:
    """record_event, get_events, filtering."""

    def test_record_event_monitor_not_blocked(self):
        svc = AntiTamperService()
        svc.configure("monitor", enabled=True)
        ev = svc.record_event("agent-1", "config_change")
        assert ev["blocked"] is False
        assert ev["mode"] == "monitor"
        assert ev["agent_id"] == "agent-1"
        assert "id" in ev

    def test_record_event_enforce_blocked(self):
        svc = AntiTamperService()
        svc.configure("enforce", enabled=True)
        ev = svc.record_event("agent-2", "config_change")
        assert ev["blocked"] is True
        assert ev["mode"] == "enforce"

    def test_record_event_with_details(self):
        svc = AntiTamperService()
        svc.enable()
        details = {"file": "/etc/angelclaw.conf", "changed_by": "root"}
        ev = svc.record_event("agent-1", "config_change", details=details)
        assert ev["details"]["file"] == "/etc/angelclaw.conf"

    def test_get_events_empty(self):
        svc = AntiTamperService()
        events = svc.get_events()
        assert events == []

    def test_get_events_returns_recorded(self):
        svc = AntiTamperService()
        svc.enable()
        svc.record_event("agent-1", "config_change", tenant_id="t1")
        svc.record_event("agent-2", "process_death", tenant_id="t2")
        all_events = svc.get_events()
        assert len(all_events) == 2

    def test_get_events_filter_by_tenant(self):
        svc = AntiTamperService()
        svc.enable()
        svc.record_event("a1", "config_change", tenant_id="t1")
        svc.record_event("a2", "config_change", tenant_id="t2")
        filtered = svc.get_events(tenant_id="t1")
        assert len(filtered) == 1
        assert filtered[0]["agent_id"] == "a1"

    def test_get_events_filter_by_agent(self):
        svc = AntiTamperService()
        svc.enable()
        svc.record_event("a1", "config_change", tenant_id="t1")
        svc.record_event("a2", "config_change", tenant_id="t1")
        filtered = svc.get_events(agent_id="a1")
        assert len(filtered) == 1

    def test_get_events_limit(self):
        svc = AntiTamperService()
        svc.enable()
        for i in range(10):
            svc.record_event(f"a{i}", "config_change")
        limited = svc.get_events(limit=3)
        assert len(limited) == 3


class TestAntiTamperTamperEvent:
    """Full tamper-event API: record_tamper_event, is_protected, resolve."""

    def test_record_tamper_event_when_protected(self):
        svc = AntiTamperService()
        svc.configure("tenant-x", mode="monitor")
        ev = svc.record_tamper_event("tenant-x", "agent-1", "config_change", "changed")
        assert ev is not None
        assert ev.tenant_id == "tenant-x"
        assert ev.agent_id == "agent-1"

    def test_record_tamper_event_when_off(self):
        svc = AntiTamperService()
        # No config => mode=OFF by default
        ev = svc.record_tamper_event("tenant-x", "agent-1", "config_change")
        assert ev is None

    def test_is_protected_true(self):
        svc = AntiTamperService()
        svc.configure("t1", mode="enforce")
        assert svc.is_protected("t1") is True

    def test_is_protected_false(self):
        svc = AntiTamperService()
        assert svc.is_protected("t-unknown") is False

    def test_resolve_event(self):
        svc = AntiTamperService()
        svc.configure("t1", mode="monitor")
        ev = svc.record_tamper_event("t1", "a1", "config_change")
        assert ev is not None
        assert svc.resolve_event(ev.id, "admin") is True

    def test_resolve_nonexistent_event(self):
        svc = AntiTamperService()
        assert svc.resolve_event("nonexistent-id", "admin") is False


class TestAntiTamperHeartbeat:
    """Heartbeat recording and timeout detection."""

    def test_record_heartbeat(self):
        svc = AntiTamperService()
        svc.record_heartbeat("agent-hb")
        assert "agent-hb" in svc._agent_heartbeats

    def test_heartbeat_no_timeout(self):
        svc = AntiTamperService()
        svc.configure("t1", mode="monitor", heartbeat_timeout_seconds=300)
        svc.record_heartbeat("a1")
        ev = svc.check_heartbeat("t1", "a1")
        assert ev is None  # just recorded, not timed out

    def test_heartbeat_timeout_detected(self):
        from datetime import datetime, timedelta, timezone
        svc = AntiTamperService()
        svc.configure("t1", mode="monitor", heartbeat_timeout_seconds=60)
        # Simulate a heartbeat far in the past
        svc._agent_heartbeats["a1"] = datetime.now(timezone.utc) - timedelta(seconds=120)
        ev = svc.check_heartbeat("t1", "a1")
        assert ev is not None
        assert ev.event_type.value == "heartbeat_miss"

    def test_heartbeat_off_mode_ignored(self):
        from datetime import datetime, timedelta, timezone
        svc = AntiTamperService()
        # No config => OFF
        svc._agent_heartbeats["a1"] = datetime.now(timezone.utc) - timedelta(seconds=9999)
        ev = svc.check_heartbeat("t-none", "a1")
        assert ev is None

    def test_heartbeat_no_prior_heartbeat(self):
        svc = AntiTamperService()
        svc.configure("t1", mode="monitor")
        ev = svc.check_heartbeat("t1", "a-new")
        assert ev is None  # no heartbeat recorded yet


class TestAntiTamperChecksum:
    """Checksum mismatch detection."""

    def test_first_checksum_no_event(self):
        svc = AntiTamperService()
        ev = svc.update_checksum("a1", "abc123")
        assert ev is None

    def test_same_checksum_no_event(self):
        svc = AntiTamperService()
        svc.update_checksum("a1", "abc123")
        ev = svc.update_checksum("a1", "abc123")
        assert ev is None

    def test_checksum_mismatch_creates_event(self):
        svc = AntiTamperService()
        svc.configure("dev-tenant", mode="monitor")
        svc.update_checksum("a1", "abc123")
        ev = svc.update_checksum("a1", "xyz789")
        assert ev is not None
        assert ev.event_type.value == "checksum_mismatch"
        assert ev.severity == "critical"


class TestAntiTamperGetStatus:
    """get_status overview."""

    def test_get_status_empty(self):
        svc = AntiTamperService()
        status = svc.get_status()
        assert status["enforced_count"] == 0
        assert status["monitored_count"] == 0
        assert status["tamper_events_24h"] == 0

    def test_get_status_with_configs_and_events(self):
        svc = AntiTamperService()
        svc.configure("t1", mode="enforce")
        svc.configure("t1", mode="monitor", agent_id="a1")
        svc.record_tamper_event("t1", "a1", "config_change")
        status = svc.get_status(tenant_id="t1")
        assert status["enforced_count"] == 1
        assert status["monitored_count"] == 1
        assert status["tamper_events_24h"] >= 1
        assert "a1" in status["agents_with_issues"]


class TestAntiTamperMultiTenant:
    """Multi-tenant isolation."""

    def test_configs_isolated_per_tenant(self):
        svc = AntiTamperService()
        svc.configure("t1", mode="enforce")
        svc.configure("t2", mode="monitor")
        c1 = svc.get_config("t1")
        c2 = svc.get_config("t2")
        assert c1.mode.value == "enforce"
        assert c2.mode.value == "monitor"

    def test_events_filtered_per_tenant(self):
        svc = AntiTamperService()
        svc.configure("t1", mode="monitor")
        svc.configure("t2", mode="monitor")
        svc.record_tamper_event("t1", "a1", "config_change")
        svc.record_tamper_event("t2", "a2", "process_death")
        t1_events = svc.get_events(tenant_id="t1")
        t2_events = svc.get_events(tenant_id="t2")
        assert len(t1_events) == 1
        assert len(t2_events) == 1
        assert t1_events[0]["agent_id"] == "a1"
        assert t2_events[0]["agent_id"] == "a2"

    def test_agent_config_overrides_tenant_default(self):
        svc = AntiTamperService()
        svc.configure("t1", mode="monitor")
        svc.configure("t1", mode="enforce", agent_id="special-agent")
        default_cfg = svc.get_config("t1", agent_id="normal-agent")
        special_cfg = svc.get_config("t1", agent_id="special-agent")
        assert default_cfg.mode.value == "monitor"
        assert special_cfg.mode.value == "enforce"


# ---------------------------------------------------------------------------
# FeedbackService
# ---------------------------------------------------------------------------

class TestFeedbackBasic:
    """Record feedback and query."""

    def test_record_accepted(self):
        svc = FeedbackService()
        rec = svc.record_feedback("t1", "policy_change", "accepted", operator="alice")
        assert rec.tenant_id == "t1"
        assert rec.action == "accepted"
        assert rec.operator == "alice"

    def test_record_rejected(self):
        svc = FeedbackService()
        rec = svc.record_feedback("t1", "alert_threshold", "rejected")
        assert rec.action == "rejected"

    def test_record_modified(self):
        svc = FeedbackService()
        rec = svc.record_feedback("t1", "scan_config", "modified", reason="changed params")
        assert rec.action == "modified"
        assert rec.reason == "changed params"

    def test_record_ignored(self):
        svc = FeedbackService()
        rec = svc.record_feedback("t1", "remediation", "ignored")
        assert rec.action == "ignored"

    def test_invalid_action_raises(self):
        svc = FeedbackService()
        with pytest.raises(ValueError, match="Invalid action"):
            svc.record_feedback("t1", "policy_change", "deleted")

    def test_record_with_context(self):
        svc = FeedbackService()
        ctx = {"severity": "high", "source": "scan"}
        rec = svc.record_feedback("t1", "alert_threshold", "accepted", context=ctx)
        assert rec.context["severity"] == "high"


class TestFeedbackSummary:
    """Tenant summary and ranking."""

    def test_empty_summary(self):
        svc = FeedbackService()
        summary = svc.get_tenant_summary("empty-tenant")
        assert summary["total_feedback"] == 0
        assert summary["acceptance_rate"] == 0.0
        assert summary["by_type"] == {}

    def test_summary_counts(self):
        svc = FeedbackService()
        svc.record_feedback("t1", "policy_change", "accepted")
        svc.record_feedback("t1", "policy_change", "rejected")
        svc.record_feedback("t1", "alert_threshold", "accepted")
        summary = svc.get_tenant_summary("t1")
        assert summary["total_feedback"] == 3
        # 2 accepted out of 3
        assert abs(summary["acceptance_rate"] - 0.667) < 0.01

    def test_acceptance_rate_includes_modified(self):
        svc = FeedbackService()
        svc.record_feedback("t1", "policy_change", "modified")
        svc.record_feedback("t1", "policy_change", "rejected")
        summary = svc.get_tenant_summary("t1")
        # 1 modified counts as accepted, 1 rejected => 0.5
        assert summary["acceptance_rate"] == 0.5

    def test_top_rejected_types(self):
        svc = FeedbackService()
        for _ in range(5):
            svc.record_feedback("t1", "noisy_type", "rejected")
        svc.record_feedback("t1", "good_type", "accepted")
        summary = svc.get_tenant_summary("t1")
        assert len(summary["top_rejected_types"]) >= 1
        top = summary["top_rejected_types"][0]
        assert top["type"] == "noisy_type"
        assert top["rejection_rate"] == 1.0

    def test_suggestion_ranking(self):
        svc = FeedbackService()
        svc.record_feedback("t1", "good", "accepted")
        svc.record_feedback("t1", "good", "accepted")
        svc.record_feedback("t1", "bad", "rejected")
        svc.record_feedback("t1", "bad", "rejected")
        ranking = svc.compute_suggestion_ranking("t1")
        assert len(ranking) == 2
        # 'good' should be ranked first (acceptance_rate=1.0)
        assert ranking[0]["suggestion_type"] == "good"
        assert ranking[0]["acceptance_rate"] == 1.0
        assert ranking[1]["suggestion_type"] == "bad"
        assert ranking[1]["acceptance_rate"] == 0.0

    def test_ranking_empty_tenant(self):
        svc = FeedbackService()
        assert svc.compute_suggestion_ranking("no-data") == []


class TestFeedbackRecommendations:
    """Adjustment recommendations based on feedback patterns."""

    def test_no_recommendations_below_threshold(self):
        svc = FeedbackService()
        # Only 3 records, need 5+ for recommendations
        for _ in range(3):
            svc.record_feedback("t1", "policy_change", "rejected")
        recs = svc.get_adjustment_recommendations("t1")
        assert recs == []

    def test_verbosity_recommendation_low_acceptance(self):
        svc = FeedbackService()
        # 6 records, all rejected => acceptance_rate < 0.3
        for _ in range(6):
            svc.record_feedback("t1", "policy_change", "rejected")
        recs = svc.get_adjustment_recommendations("t1")
        categories = [r["category"] for r in recs]
        assert "verbosity" in categories

    def test_alert_threshold_recommendation_high_rejection(self):
        svc = FeedbackService()
        # 5 records of same type, 4 rejected => rejection_rate > 0.6
        for _ in range(4):
            svc.record_feedback("t1", "scan_config", "rejected")
        svc.record_feedback("t1", "scan_config", "accepted")
        recs = svc.get_adjustment_recommendations("t1")
        categories = [r["category"] for r in recs]
        assert "alert_threshold" in categories

    def test_autonomy_recommendation_high_acceptance(self):
        svc = FeedbackService()
        # 12 records, all accepted => acceptance_rate > 0.8 with 10+ records
        for _ in range(12):
            svc.record_feedback("t1", "policy_change", "accepted")
        recs = svc.get_adjustment_recommendations("t1")
        categories = [r["category"] for r in recs]
        assert "suggestion_priority" in categories

    def test_no_autonomy_rec_under_10_records(self):
        svc = FeedbackService()
        # 8 records, all accepted — has > 0.8 acceptance but < 10 records
        for _ in range(8):
            svc.record_feedback("t1", "policy_change", "accepted")
        recs = svc.get_adjustment_recommendations("t1")
        categories = [r["category"] for r in recs]
        assert "suggestion_priority" not in categories


class TestFeedbackRecent:
    """Recent feedback and tenant listing."""

    def test_get_recent_feedback(self):
        svc = FeedbackService()
        svc.record_feedback("t1", "policy_change", "accepted")
        svc.record_feedback("t1", "alert_threshold", "rejected")
        recent = svc.get_recent_feedback("t1", limit=10, hours=24)
        assert len(recent) == 2

    def test_get_recent_feedback_limit(self):
        svc = FeedbackService()
        for i in range(5):
            svc.record_feedback("t1", f"type_{i}", "accepted")
        recent = svc.get_recent_feedback("t1", limit=2)
        assert len(recent) == 2

    def test_get_recent_feedback_empty(self):
        svc = FeedbackService()
        assert svc.get_recent_feedback("no-data") == []

    def test_get_all_tenant_ids(self):
        svc = FeedbackService()
        svc.record_feedback("t1", "a", "accepted")
        svc.record_feedback("t2", "b", "rejected")
        ids = svc.get_all_tenant_ids()
        assert "t1" in ids
        assert "t2" in ids

    def test_get_all_tenant_ids_empty(self):
        svc = FeedbackService()
        assert svc.get_all_tenant_ids() == []


class TestFeedbackMultiTenant:
    """Multi-tenant isolation."""

    def test_feedback_isolated_per_tenant(self):
        svc = FeedbackService()
        svc.record_feedback("t1", "policy_change", "accepted")
        svc.record_feedback("t2", "policy_change", "rejected")
        s1 = svc.get_tenant_summary("t1")
        s2 = svc.get_tenant_summary("t2")
        assert s1["total_feedback"] == 1
        assert s2["total_feedback"] == 1
        assert s1["acceptance_rate"] == 1.0
        assert s2["acceptance_rate"] == 0.0


# ---------------------------------------------------------------------------
# SelfHardeningEngine
# ---------------------------------------------------------------------------

class TestSelfHardeningCycle:
    """run_hardening_cycle with various contexts."""

    def test_empty_context_no_actions(self):
        engine = SelfHardeningEngine()
        actions = engine.run_hardening_cycle("t1", "suggest", context={})
        assert actions == []

    def test_scan_failures_trigger(self):
        engine = SelfHardeningEngine()
        actions = engine.run_hardening_cycle("t1", "suggest", context={"scan_failures": 5})
        types = [a["action_type"] for a in actions]
        assert "increase_scan_freq" in types

    def test_scan_failures_below_threshold(self):
        engine = SelfHardeningEngine()
        actions = engine.run_hardening_cycle("t1", "suggest", context={"scan_failures": 2})
        types = [a["action_type"] for a in actions]
        assert "increase_scan_freq" not in types

    def test_loose_allowlist_any(self):
        engine = SelfHardeningEngine()
        actions = engine.run_hardening_cycle(
            "t1", "suggest",
            context={"network_allowlist": ["ANY"], "known_safe_destinations": ["10.0.0.1"]},
        )
        types = [a["action_type"] for a in actions]
        assert "tighten_allowlist" in types

    def test_loose_allowlist_wildcard(self):
        engine = SelfHardeningEngine()
        actions = engine.run_hardening_cycle(
            "t1", "suggest",
            context={"network_allowlist": ["*"]},
        )
        types = [a["action_type"] for a in actions]
        assert "tighten_allowlist" in types

    def test_logging_disabled(self):
        engine = SelfHardeningEngine()
        actions = engine.run_hardening_cycle("t1", "suggest", context={"logging_enabled": False})
        types = [a["action_type"] for a in actions]
        assert "enable_logging" in types

    def test_auth_issues(self):
        engine = SelfHardeningEngine()
        actions = engine.run_hardening_cycle(
            "t1", "suggest", context={"auth_issues": ["weak_password", "no_mfa"]},
        )
        types = [a["action_type"] for a in actions]
        assert types.count("strengthen_auth") == 2

    def test_unprotected_agents(self):
        engine = SelfHardeningEngine()
        actions = engine.run_hardening_cycle(
            "t1", "suggest", context={"unprotected_high_risk_agents": ["a1", "a2"]},
        )
        types = [a["action_type"] for a in actions]
        assert "enable_anti_tamper" in types

    def test_repeated_misconfig(self):
        engine = SelfHardeningEngine()
        actions = engine.run_hardening_cycle("t1", "suggest", context={"misconfig_count": 7})
        types = [a["action_type"] for a in actions]
        assert "propose_stronger_defaults" in types

    def test_misconfig_below_threshold(self):
        engine = SelfHardeningEngine()
        actions = engine.run_hardening_cycle("t1", "suggest", context={"misconfig_count": 3})
        types = [a["action_type"] for a in actions]
        assert "propose_stronger_defaults" not in types

    def test_multiple_issues_combined(self):
        engine = SelfHardeningEngine()
        actions = engine.run_hardening_cycle("t1", "suggest", context={
            "scan_failures": 5,
            "logging_enabled": False,
            "misconfig_count": 10,
        })
        types = [a["action_type"] for a in actions]
        assert "increase_scan_freq" in types
        assert "enable_logging" in types
        assert "propose_stronger_defaults" in types


class TestSelfHardeningAutonomyModes:
    """Autonomy mode behavior: observe, suggest, auto_apply."""

    def test_suggest_mode_proposes_action(self):
        engine = SelfHardeningEngine()
        engine.run_hardening_cycle("t1", "suggest", context={"scan_failures": 3})
        proposed = engine.get_proposed_actions()
        assert len(proposed) >= 1
        assert proposed[0]["applied"] is False

    def test_auto_apply_mode_applies_immediately(self):
        engine = SelfHardeningEngine()
        actions = engine.run_hardening_cycle("t1", "auto_apply", context={"scan_failures": 3})
        assert len(actions) >= 1
        assert actions[0]["applied"] is True
        # Should not be in proposed list
        proposed = engine.get_proposed_actions()
        assert len(proposed) == 0

    def test_assist_mode_applies_immediately(self):
        engine = SelfHardeningEngine()
        actions = engine.run_hardening_cycle("t1", "assist", context={"logging_enabled": False})
        assert len(actions) >= 1
        assert actions[0]["applied"] is True

    def test_observe_mode_no_apply_no_propose(self):
        engine = SelfHardeningEngine()
        actions = engine.run_hardening_cycle("t1", "observe", context={"scan_failures": 5})
        assert len(actions) >= 1
        # Actions returned but neither applied nor proposed
        proposed = engine.get_proposed_actions()
        assert len(proposed) == 0
        log = engine.get_hardening_log()
        # observe mode actions are not stored in _actions or _proposed
        # only auto_apply goes to _actions, suggest goes to _proposed
        applied_ids = [a["id"] for a in log]
        for action in actions:
            assert action["id"] not in applied_ids


class TestSelfHardeningActionLifecycle:
    """Apply/revert lifecycle for proposed actions."""

    def test_apply_proposed_action(self):
        engine = SelfHardeningEngine()
        engine.run_hardening_cycle("t1", "suggest", context={"scan_failures": 3})
        proposed = engine.get_proposed_actions()
        assert len(proposed) >= 1
        action_id = proposed[0]["id"]
        result = engine.apply_action(action_id, applied_by="admin")
        assert result is not None
        assert result["applied"] is True
        assert result["applied_by"] == "admin"
        # No longer proposed
        assert len(engine.get_proposed_actions()) == 0

    def test_apply_nonexistent_action(self):
        engine = SelfHardeningEngine()
        result = engine.apply_action("nonexistent-id")
        assert result is None

    def test_revert_applied_action(self):
        engine = SelfHardeningEngine()
        engine.run_hardening_cycle("t1", "suggest", context={"logging_enabled": False})
        proposed = engine.get_proposed_actions()
        action_id = proposed[0]["id"]
        engine.apply_action(action_id, applied_by="admin")
        result = engine.revert_action(action_id, reverted_by="admin")
        assert result is not None
        assert result["reverted"] is True
        assert result["reverted_by"] == "admin"

    def test_revert_non_revertible_action(self):
        engine = SelfHardeningEngine()
        engine.run_hardening_cycle("t1", "auto_apply", context={"auth_issues": ["no_mfa"]})
        log = engine.get_hardening_log()
        auth_action = next(a for a in log if a["action_type"] == "strengthen_auth")
        result = engine.revert_action(auth_action["id"])
        assert result is not None
        assert "error" in result

    def test_revert_already_reverted(self):
        engine = SelfHardeningEngine()
        engine.run_hardening_cycle("t1", "suggest", context={"scan_failures": 3})
        proposed = engine.get_proposed_actions()
        action_id = proposed[0]["id"]
        engine.apply_action(action_id)
        engine.revert_action(action_id)
        result = engine.revert_action(action_id)
        assert result is not None
        assert "error" in result

    def test_revert_nonexistent_action(self):
        engine = SelfHardeningEngine()
        result = engine.revert_action("fake-id")
        assert result is None


class TestSelfHardeningLog:
    """Hardening log and issue summary."""

    def test_hardening_log_empty(self):
        engine = SelfHardeningEngine()
        assert engine.get_hardening_log() == []

    def test_hardening_log_includes_applied_and_proposed(self):
        engine = SelfHardeningEngine()
        engine.run_hardening_cycle("t1", "suggest", context={"scan_failures": 3})
        engine.run_hardening_cycle("t1", "auto_apply", context={"logging_enabled": False})
        log = engine.get_hardening_log()
        assert len(log) == 2
        types = [a["action_type"] for a in log]
        assert "increase_scan_freq" in types
        assert "enable_logging" in types

    def test_hardening_log_filter_by_tenant(self):
        engine = SelfHardeningEngine()
        engine.run_hardening_cycle("t1", "suggest", context={"scan_failures": 3})
        engine.run_hardening_cycle("t2", "suggest", context={"logging_enabled": False})
        log_t1 = engine.get_hardening_log(tenant_id="t1")
        log_t2 = engine.get_hardening_log(tenant_id="t2")
        assert len(log_t1) == 1
        assert len(log_t2) == 1

    def test_hardening_log_limit(self):
        engine = SelfHardeningEngine()
        engine.run_hardening_cycle("t1", "suggest", context={
            "scan_failures": 5,
            "logging_enabled": False,
            "misconfig_count": 10,
        })
        log = engine.get_hardening_log(limit=2)
        assert len(log) == 2

    def test_issue_summary_empty(self):
        engine = SelfHardeningEngine()
        summary = engine.get_issue_summary()
        assert summary["total_issues"] == 0
        assert summary["actions_applied"] == 0
        assert summary["actions_proposed"] == 0
        assert summary["actions_reverted"] == 0

    def test_issue_summary_tracks_counts(self):
        engine = SelfHardeningEngine()
        engine.run_hardening_cycle("t1", "suggest", context={"scan_failures": 5})
        engine.run_hardening_cycle("t1", "auto_apply", context={"logging_enabled": False})
        summary = engine.get_issue_summary()
        assert summary["total_issues"] >= 2
        assert summary["actions_applied"] >= 1
        assert summary["actions_proposed"] >= 1

    def test_issue_summary_after_revert(self):
        engine = SelfHardeningEngine()
        engine.run_hardening_cycle("t1", "suggest", context={"scan_failures": 3})
        proposed = engine.get_proposed_actions()
        action_id = proposed[0]["id"]
        engine.apply_action(action_id)
        engine.revert_action(action_id)
        summary = engine.get_issue_summary()
        assert summary["actions_reverted"] == 1
        # Applied but reverted should not count as active applied
        assert summary["actions_applied"] == 0


class TestSelfHardeningMultiTenant:
    """Multi-tenant isolation in hardening engine."""

    def test_proposed_actions_filtered_by_tenant(self):
        engine = SelfHardeningEngine()
        engine.run_hardening_cycle("t1", "suggest", context={"scan_failures": 3})
        engine.run_hardening_cycle("t2", "suggest", context={"logging_enabled": False})
        t1 = engine.get_proposed_actions(tenant_id="t1")
        t2 = engine.get_proposed_actions(tenant_id="t2")
        assert len(t1) == 1
        assert len(t2) == 1
        assert t1[0]["tenant_id"] == "t1"
        assert t2[0]["tenant_id"] == "t2"
