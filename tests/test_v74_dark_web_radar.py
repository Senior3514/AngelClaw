"""Tests for V7.4.0 Dark Web Radar: Extended Threat Intelligence & Dark Web Monitoring."""

from __future__ import annotations

import pytest

from cloud.services.darkweb_monitor import DarkWebMonitorService
from cloud.services.supply_chain import SupplyChainService


TENANT = "test-tenant"


class TestDarkWebMonitorService:
    """DarkWebMonitorService tests."""

    def test_scan_credentials_empty(self):
        svc = DarkWebMonitorService()
        result = svc.scan_credentials(TENANT, ["example.com"])
        assert isinstance(result, list)

    def test_add_watchlist(self):
        svc = DarkWebMonitorService()
        result = svc.add_watchlist(TENANT, {"name": "test-item", "type": "test"})
        assert "id" in result
        assert result["tenant_id"] == TENANT
        assert result["status"] == "active"

    def test_add_watchlist_creates_unique_ids(self):
        svc = DarkWebMonitorService()
        r1 = svc.add_watchlist(TENANT, {"name": "item-1"})
        r2 = svc.add_watchlist(TENANT, {"name": "item-2"})
        assert r1["id"] != r2["id"]

    def test_get_alerts_empty(self):
        svc = DarkWebMonitorService()
        result = svc.get_alerts(TENANT)
        assert isinstance(result, list)

    def test_track_actor(self):
        svc = DarkWebMonitorService()
        result = svc.track_actor(TENANT, "actor-001")
        assert isinstance(result, (dict, list))

    def test_status(self):
        svc = DarkWebMonitorService()
        result = svc.status(TENANT)
        assert result["tenant_id"] == TENANT
        assert result["service"] == "DarkWebMonitorService"
        assert result["version"] == "7.4.0"

class TestSupplyChainService:
    """SupplyChainService tests."""

    def test_analyze_sbom(self):
        svc = SupplyChainService()
        result = svc.analyze_sbom(TENANT, {"type": "test", "value": "test-data"})
        assert "id" in result
        assert result["tenant_id"] == TENANT

    def test_scan_dependencies_empty(self):
        svc = SupplyChainService()
        result = svc.scan_dependencies(TENANT, [{"name": "lodash"}])
        assert isinstance(result, list)

    def test_assess_vendor(self):
        svc = SupplyChainService()
        result = svc.assess_vendor(TENANT, "vendor-x", {"tier": "critical"})
        assert isinstance(result, (dict, list))

    def test_get_risk_report(self):
        svc = SupplyChainService()
        result = svc.get_risk_report(TENANT)
        assert isinstance(result, (dict, list))

    def test_status(self):
        svc = SupplyChainService()
        result = svc.status(TENANT)
        assert result["tenant_id"] == TENANT
        assert result["service"] == "SupplyChainService"
        assert result["version"] == "7.4.0"

