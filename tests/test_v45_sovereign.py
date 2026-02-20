"""Tests for V4.5 Sovereign.

Microsegmentation, Identity Policy, Device Trust, Session Risk, Adaptive Auth.
"""

from __future__ import annotations

from cloud.services.adaptive_auth import AdaptiveAuthService
from cloud.services.device_trust import DeviceTrustService
from cloud.services.identity_policy import IdentityPolicyService
from cloud.services.microsegmentation import MicrosegmentationEngine
from cloud.services.session_risk import SessionRiskService

TENANT = "test-tenant"


# ---------------------------------------------------------------------------
# MicrosegmentationEngine
# ---------------------------------------------------------------------------


class TestMicrosegmentationBasic:
    """Create, list, and delete segment operations."""

    def test_create_segment(self):
        svc = MicrosegmentationEngine()
        seg = svc.create_segment(
            tenant_id=TENANT,
            name="web-to-api",
            source_criteria={"zone": "web"},
            target_criteria={"zone": "api"},
            allowed_protocols=["https"],
        )
        assert seg["name"] == "web-to-api"
        assert seg["enabled"] is True
        assert seg["action"] == "allow"
        assert seg["hit_count"] == 0

    def test_list_segments(self):
        svc = MicrosegmentationEngine()
        svc.create_segment(
            tenant_id=TENANT,
            name="seg-a",
            source_criteria={"zone": "a"},
            target_criteria={"zone": "b"},
            allowed_protocols=["tcp"],
            priority=10,
        )
        svc.create_segment(
            tenant_id=TENANT,
            name="seg-b",
            source_criteria={"zone": "c"},
            target_criteria={"zone": "d"},
            allowed_protocols=["udp"],
            priority=5,
        )
        segments = svc.list_segments(TENANT)
        assert len(segments) == 2
        # Sorted by priority ascending — seg-b (priority 5) first
        assert segments[0]["name"] == "seg-b"
        assert segments[1]["name"] == "seg-a"

    def test_delete_segment(self):
        svc = MicrosegmentationEngine()
        seg = svc.create_segment(
            tenant_id=TENANT,
            name="temp-seg",
            source_criteria={"zone": "x"},
            target_criteria={"zone": "y"},
            allowed_protocols=["ssh"],
        )
        assert svc.delete_segment(TENANT, seg["id"]) is True
        assert svc.list_segments(TENANT) == []

    def test_delete_segment_wrong_tenant(self):
        svc = MicrosegmentationEngine()
        seg = svc.create_segment(
            tenant_id=TENANT,
            name="owned",
            source_criteria={},
            target_criteria={},
            allowed_protocols=["*"],
        )
        assert svc.delete_segment("other-tenant", seg["id"]) is False


class TestMicrosegmentationEvaluation:
    """Evaluate access decisions and zero-trust defaults."""

    def test_evaluate_access_matching_segment_returns_allow(self):
        svc = MicrosegmentationEngine()
        svc.create_segment(
            tenant_id=TENANT,
            name="allow-https",
            source_criteria={"zone": "web"},
            target_criteria={"zone": "api"},
            allowed_protocols=["https"],
            action="allow",
        )
        result = svc.evaluate_access(
            tenant_id=TENANT,
            source={"zone": "web"},
            target={"zone": "api"},
            protocol="https",
        )
        assert result["decision"] == "allow"
        assert result["matched_segment_name"] == "allow-https"

    def test_evaluate_access_no_match_returns_deny(self):
        svc = MicrosegmentationEngine()
        # No segments at all — zero trust
        result = svc.evaluate_access(
            tenant_id=TENANT,
            source={"zone": "web"},
            target={"zone": "db"},
            protocol="tcp",
        )
        assert result["decision"] == "deny"
        assert result["matched_segment_id"] is None
        assert result["reason"] == "no_matching_segment"

    def test_evaluate_access_wrong_protocol_denied(self):
        svc = MicrosegmentationEngine()
        svc.create_segment(
            tenant_id=TENANT,
            name="only-https",
            source_criteria={"zone": "web"},
            target_criteria={"zone": "api"},
            allowed_protocols=["https"],
        )
        result = svc.evaluate_access(
            tenant_id=TENANT,
            source={"zone": "web"},
            target={"zone": "api"},
            protocol="ssh",
        )
        assert result["decision"] == "deny"


class TestMicrosegmentationStats:
    """Statistics reporting."""

    def test_get_stats(self):
        svc = MicrosegmentationEngine()
        svc.create_segment(
            tenant_id=TENANT,
            name="seg-1",
            source_criteria={"zone": "a"},
            target_criteria={"zone": "b"},
            allowed_protocols=["https"],
        )
        svc.evaluate_access(
            tenant_id=TENANT,
            source={"zone": "a"},
            target={"zone": "b"},
            protocol="https",
        )
        stats = svc.get_stats(TENANT)
        assert stats["total_segments"] == 1
        assert stats["enabled"] == 1
        assert stats["total_hits"] == 1
        assert stats["total_evaluations"] == 1
        assert stats["by_action"]["allow"] == 1


# ---------------------------------------------------------------------------
# IdentityPolicyService
# ---------------------------------------------------------------------------


class TestIdentityPolicyBasic:
    """Create and list identity policies."""

    def test_create_policy(self):
        svc = IdentityPolicyService()
        policy = svc.create_policy(
            tenant_id=TENANT,
            name="admin-billing",
            identity_type="user",
            identity_pattern="admin-*",
            resource_pattern="/api/billing/*",
            decision="allow",
        )
        assert policy["name"] == "admin-billing"
        assert policy["decision"] == "allow"
        assert policy["identity_type"] == "user"

    def test_list_policies(self):
        svc = IdentityPolicyService()
        svc.create_policy(
            tenant_id=TENANT,
            name="p1",
            identity_type="user",
            identity_pattern="*",
            resource_pattern="*",
            priority=50,
        )
        svc.create_policy(
            tenant_id=TENANT,
            name="p2",
            identity_type="service",
            identity_pattern="svc-*",
            resource_pattern="/internal/*",
            priority=10,
        )
        policies = svc.list_policies(TENANT)
        assert len(policies) == 2
        # Sorted by priority ascending
        assert policies[0]["name"] == "p2"
        assert policies[1]["name"] == "p1"


class TestIdentityPolicyEvaluation:
    """Evaluate access and zero-trust defaults."""

    def test_evaluate_access_matching_policy(self):
        svc = IdentityPolicyService()
        svc.create_policy(
            tenant_id=TENANT,
            name="allow-admins",
            identity_type="user",
            identity_pattern="admin-*",
            resource_pattern="/api/*",
            decision="allow",
        )
        result = svc.evaluate_access(
            tenant_id=TENANT,
            identity_type="user",
            identity_name="admin-bob",
            resource="/api/users",
        )
        assert result["decision"] == "allow"
        assert result["reason"] == "policy_match"
        assert len(result["matched_policies"]) == 1

    def test_evaluate_access_deny_policy(self):
        svc = IdentityPolicyService()
        svc.create_policy(
            tenant_id=TENANT,
            name="deny-guests",
            identity_type="user",
            identity_pattern="guest-*",
            resource_pattern="/admin/*",
            decision="deny",
        )
        result = svc.evaluate_access(
            tenant_id=TENANT,
            identity_type="user",
            identity_name="guest-alice",
            resource="/admin/settings",
        )
        assert result["decision"] == "deny"

    def test_evaluate_access_no_match_returns_deny(self):
        svc = IdentityPolicyService()
        # No policies — zero trust
        result = svc.evaluate_access(
            tenant_id=TENANT,
            identity_type="user",
            identity_name="random-user",
            resource="/secret/data",
        )
        assert result["decision"] == "deny"
        assert result["reason"] == "no_matching_policy"


class TestIdentityPolicyStats:
    """Statistics reporting."""

    def test_get_stats(self):
        svc = IdentityPolicyService()
        svc.create_policy(
            tenant_id=TENANT,
            name="p1",
            identity_type="user",
            identity_pattern="*",
            resource_pattern="*",
            decision="allow",
        )
        svc.create_policy(
            tenant_id=TENANT,
            name="p2",
            identity_type="service",
            identity_pattern="svc-*",
            resource_pattern="/internal/*",
            decision="deny",
        )
        stats = svc.get_stats(TENANT)
        assert stats["total_policies"] == 2
        assert stats["enabled"] == 2
        assert stats["by_decision"]["allow"] == 1
        assert stats["by_decision"]["deny"] == 1
        assert stats["by_identity_type"]["user"] == 1
        assert stats["by_identity_type"]["service"] == 1


# ---------------------------------------------------------------------------
# DeviceTrustService
# ---------------------------------------------------------------------------


class TestDeviceTrustBasic:
    """Assess device trust with different posture configurations."""

    def test_assess_device_all_flags_true_high_score(self):
        svc = DeviceTrustService()
        result = svc.assess_device(
            tenant_id=TENANT,
            device_id="dev-001",
            os_family="windows",
            os_version="11",
            patch_level="current",
            encryption_enabled=True,
            antivirus_active=True,
            firewall_enabled=True,
        )
        # os_supported=20 + patch_current=25 + encryption=20 + antivirus=20 + firewall=15 = 100
        assert result["trust_score"] == 100
        assert result["risk_level"] == "trusted"

    def test_assess_device_all_flags_false_low_score(self):
        svc = DeviceTrustService()
        result = svc.assess_device(
            tenant_id=TENANT,
            device_id="dev-002",
            os_family="unknown",
            os_version="unknown",
            patch_level="outdated",
            encryption_enabled=False,
            antivirus_active=False,
            firewall_enabled=False,
        )
        # os=0 + patch_outdated=0 + enc=0 + av=0 + fw=0 = 0
        assert result["trust_score"] == 0
        assert result["risk_level"] == "critical"

    def test_assess_device_partial_flags_moderate(self):
        svc = DeviceTrustService()
        result = svc.assess_device(
            tenant_id=TENANT,
            device_id="dev-003",
            os_family="linux",
            os_version="ubuntu-22",
            patch_level="behind_1",
            encryption_enabled=True,
            antivirus_active=False,
            firewall_enabled=False,
        )
        # os_supported=20 + patch_behind_1=18 + encryption=20 = 58
        assert result["trust_score"] == 58
        assert result["risk_level"] == "low_trust"


class TestDeviceTrustCRUD:
    """List, get, and update operations."""

    def test_list_devices(self):
        svc = DeviceTrustService()
        svc.assess_device(TENANT, "dev-a")
        svc.assess_device(TENANT, "dev-b")
        devices = svc.list_devices(TENANT)
        assert len(devices) == 2

    def test_get_device_trust(self):
        svc = DeviceTrustService()
        svc.assess_device(TENANT, "dev-x", encryption_enabled=True)
        result = svc.get_device_trust("dev-x")
        assert result is not None
        assert result["device_id"] == "dev-x"
        assert result["encryption_enabled"] is True

    def test_get_device_trust_not_found(self):
        svc = DeviceTrustService()
        result = svc.get_device_trust("nonexistent")
        assert result is None

    def test_update_assessment(self):
        svc = DeviceTrustService()
        svc.assess_device(
            TENANT,
            "dev-z",
            os_family="windows",
            os_version="11",
            patch_level="current",
            encryption_enabled=True,
            antivirus_active=True,
            firewall_enabled=True,
        )
        result = svc.update_assessment("dev-z", encryption_enabled=False)
        assert result is not None
        assert result["encryption_enabled"] is False
        assert result["trust_score"] < 100


class TestDeviceTrustStats:
    """Statistics reporting."""

    def test_get_stats(self):
        svc = DeviceTrustService()
        svc.assess_device(
            TENANT,
            "dev-1",
            os_family="windows",
            os_version="11",
            patch_level="current",
            encryption_enabled=True,
            antivirus_active=True,
            firewall_enabled=True,
        )
        svc.assess_device(
            TENANT,
            "dev-2",
            os_family="unknown",
            os_version="unknown",
            patch_level="outdated",
        )
        stats = svc.get_stats(TENANT)
        assert stats["total_devices"] == 2
        assert stats["by_risk_level"]["trusted"] == 1
        assert stats["by_risk_level"]["critical"] == 1


# ---------------------------------------------------------------------------
# SessionRiskService
# ---------------------------------------------------------------------------


class TestSessionRiskBasic:
    """Assess sessions with different geo signals."""

    def test_assess_session_known_geo_low_risk(self):
        svc = SessionRiskService()
        result = svc.assess_session(
            tenant_id=TENANT,
            session_id="sess-001",
            user_id="user-a",
            device_id="dev-a",
            geo_location="us-east",
        )
        # Known geo -> no geo_anomaly (0 pts)
        assert "geo_anomaly" not in result["risk_factors"]
        # Score depends on device known status and off-hours, but geo is clean
        assert result["session_id"] == "sess-001"

    def test_assess_session_unknown_geo_higher_risk(self):
        svc = SessionRiskService()
        result = svc.assess_session(
            tenant_id=TENANT,
            session_id="sess-002",
            user_id="user-b",
            device_id="dev-b",
            geo_location="unknown-region",
        )
        assert "geo_anomaly" in result["risk_factors"]
        assert result["risk_score"] >= 30  # At minimum geo_anomaly contributes 30


class TestSessionRiskAdvanced:
    """Reassess, terminate, and list operations."""

    def test_reassess_session_increments_count(self):
        svc = SessionRiskService()
        svc.assess_session(TENANT, "sess-r", "user-r", "dev-r", "us-east")
        r1 = svc.reassess_session(TENANT, "sess-r")
        assert r1 is not None
        assert r1["reassessment_count"] == 1
        r2 = svc.reassess_session(TENANT, "sess-r")
        assert r2["reassessment_count"] == 2

    def test_terminate_session(self):
        svc = SessionRiskService()
        svc.assess_session(TENANT, "sess-t", "user-t", "dev-t", "us-east")
        result = svc.terminate_session(TENANT, "sess-t")
        assert result is not None
        assert result["terminated"] is True
        assert result["recommended_action"] == "terminate"

    def test_terminate_session_wrong_tenant(self):
        svc = SessionRiskService()
        svc.assess_session(TENANT, "sess-w", "user-w", "dev-w")
        result = svc.terminate_session("other-tenant", "sess-w")
        assert result is None

    def test_list_sessions(self):
        svc = SessionRiskService()
        svc.assess_session(TENANT, "sess-1", "user-1", "dev-1")
        svc.assess_session(TENANT, "sess-2", "user-2", "dev-2")
        sessions = svc.list_sessions(TENANT)
        assert len(sessions) == 2


class TestSessionRiskStats:
    """Statistics reporting."""

    def test_get_stats(self):
        svc = SessionRiskService()
        svc.assess_session(TENANT, "sess-s1", "user-s1", "dev-s1", "us-east")
        svc.assess_session(TENANT, "sess-s2", "user-s2", "dev-s2", "unknown-land")
        stats = svc.get_stats(TENANT)
        assert stats["total_sessions"] == 2
        assert stats["total_reassessments"] == 0
        assert isinstance(stats["avg_risk_score"], float)


# ---------------------------------------------------------------------------
# AdaptiveAuthService
# ---------------------------------------------------------------------------


class TestAdaptiveAuthBasic:
    """Evaluate auth requirements and list decisions."""

    def test_evaluate_auth_requirement_returns_decision(self):
        svc = AdaptiveAuthService()
        result = svc.evaluate_auth_requirement(
            tenant_id=TENANT,
            session_id="sess-auth-1",
            user_id="user-auth",
            resource="/api/data",
            device_id="dev-auth",
        )
        assert "required_auth_level" in result
        assert result["required_auth_level"] in {
            "password",
            "mfa",
            "biometric",
            "impossible_travel_block",
        }
        assert "risk_score" in result
        assert result["tenant_id"] == TENANT

    def test_list_decisions(self):
        svc = AdaptiveAuthService()
        svc.evaluate_auth_requirement(TENANT, "s1", "u1", "/r1", "d1")
        svc.evaluate_auth_requirement(TENANT, "s2", "u2", "/r2", "d2")
        decisions = svc.list_decisions(TENANT)
        assert len(decisions) == 2

    def test_list_decisions_empty_tenant(self):
        svc = AdaptiveAuthService()
        decisions = svc.list_decisions("nonexistent-tenant")
        assert decisions == []


class TestAdaptiveAuthStats:
    """Statistics reporting."""

    def test_get_stats(self):
        svc = AdaptiveAuthService()
        svc.evaluate_auth_requirement(TENANT, "s-stat", "u-stat", "/res", "d-stat")
        stats = svc.get_stats(TENANT)
        assert stats["total_evaluations"] == 1
        assert isinstance(stats["by_auth_level"], dict)
        assert isinstance(stats["average_risk_score"], float)

    def test_get_stats_empty(self):
        svc = AdaptiveAuthService()
        stats = svc.get_stats(TENANT)
        assert stats["total_evaluations"] == 0
