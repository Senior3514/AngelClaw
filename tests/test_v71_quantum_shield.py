"""Tests for V7.1.0 Quantum Shield: Advanced Behavioral Analytics."""

from __future__ import annotations

from cloud.services.threat_scoring import ThreatScoringService
from cloud.services.ueba import UEBAService

TENANT = "test-tenant"


class TestUEBAService:
    """UEBAService tests."""

    def test_profile_user(self):
        svc = UEBAService()
        result = svc.profile_user(TENANT, "user-1", [{"action": "login"}])
        assert "id" in result
        assert result["tenant_id"] == TENANT

    def test_detect_anomaly(self):
        svc = UEBAService()
        result = svc.detect_anomaly(TENANT, "user-1", {"ip": "10.0.0.1"})
        assert "id" in result
        assert result["tenant_id"] == TENANT

    def test_get_user_risk(self):
        svc = UEBAService()
        result = svc.get_user_risk(TENANT, "user-1")
        assert isinstance(result, (dict, list))

    def test_list_profiles_empty(self):
        svc = UEBAService()
        result = svc.list_profiles(TENANT)
        assert isinstance(result, list)

    def test_get_insider_threats_empty(self):
        svc = UEBAService()
        result = svc.get_insider_threats(TENANT)
        assert isinstance(result, list)

    def test_status(self):
        svc = UEBAService()
        result = svc.status(TENANT)
        assert result["tenant_id"] == TENANT
        assert result["service"] == "UEBAService"
        assert result["version"] == "7.1.0"


class TestThreatScoringService:
    """ThreatScoringService tests."""

    def test_score_threat(self):
        svc = ThreatScoringService()
        result = svc.score_threat(TENANT, {"type": "test", "value": "test-data"})
        assert "id" in result
        assert result["tenant_id"] == TENANT

    def test_batch_score_empty(self):
        svc = ThreatScoringService()
        result = svc.batch_score(TENANT, [{"type": "malware"}])
        assert isinstance(result, list)

    def test_get_priority_queue_empty(self):
        svc = ThreatScoringService()
        result = svc.get_priority_queue(TENANT)
        assert isinstance(result, list)

    def test_explain_score(self):
        svc = ThreatScoringService()
        result = svc.explain_score(TENANT, "test-target")
        assert "id" in result
        assert result["tenant_id"] == TENANT

    def test_status(self):
        svc = ThreatScoringService()
        result = svc.status(TENANT)
        assert result["tenant_id"] == TENANT
        assert result["service"] == "ThreatScoringService"
        assert result["version"] == "7.1.0"
