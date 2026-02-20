"""Tests for V7.2.0 Neural Mesh: AI-Enhanced Network Intelligence."""

from __future__ import annotations

import pytest

from cloud.services.traffic_analysis import TrafficAnalysisService
from cloud.services.dns_security import DNSSecurityService


TENANT = "test-tenant"


class TestTrafficAnalysisService:
    """TrafficAnalysisService tests."""

    def test_analyze_flow(self):
        svc = TrafficAnalysisService()
        result = svc.analyze_flow(TENANT, {"type": "test", "value": "test-data"})
        assert "id" in result
        assert result["tenant_id"] == TENANT

    def test_detect_beaconing_empty(self):
        svc = TrafficAnalysisService()
        result = svc.detect_beaconing(TENANT, [{"dst": "c2.evil.com"}])
        assert isinstance(result, list)

    def test_detect_exfiltration_empty(self):
        svc = TrafficAnalysisService()
        result = svc.detect_exfiltration(TENANT, [{"bytes": 100000}])
        assert isinstance(result, list)

    def test_detect_lateral_movement_empty(self):
        svc = TrafficAnalysisService()
        result = svc.detect_lateral_movement(TENANT, [{"src": "10.0.0.1"}])
        assert isinstance(result, list)

    def test_status(self):
        svc = TrafficAnalysisService()
        result = svc.status(TENANT)
        assert result["tenant_id"] == TENANT
        assert result["service"] == "TrafficAnalysisService"
        assert result["version"] == "7.2.0"

class TestDNSSecurityService:
    """DNSSecurityService tests."""

    def test_analyze_query(self):
        svc = DNSSecurityService()
        result = svc.analyze_query(TENANT, "test-target")
        assert "id" in result
        assert result["tenant_id"] == TENANT

    def test_detect_dga_empty(self):
        svc = DNSSecurityService()
        result = svc.detect_dga(TENANT, ["xkwqr.com"])
        assert isinstance(result, list)

    def test_detect_tunneling_empty(self):
        svc = DNSSecurityService()
        result = svc.detect_tunneling(TENANT, [{"query": "data.evil.com"}])
        assert isinstance(result, list)

    def test_get_sinkhole_list_empty(self):
        svc = DNSSecurityService()
        result = svc.get_sinkhole_list(TENANT)
        assert isinstance(result, list)

    def test_status(self):
        svc = DNSSecurityService()
        result = svc.status(TENANT)
        assert result["tenant_id"] == TENANT
        assert result["service"] == "DNSSecurityService"
        assert result["version"] == "7.2.0"

