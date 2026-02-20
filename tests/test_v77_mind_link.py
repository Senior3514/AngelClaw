"""Tests for V7.7.0 Mind Link: Collaborative Intelligence & Reporting."""

from __future__ import annotations

import pytest

from cloud.services.intel_marketplace import IntelMarketplaceService
from cloud.services.report_generator import ReportGeneratorService


TENANT = "test-tenant"


class TestIntelMarketplaceService:
    """IntelMarketplaceService tests."""

    def test_publish_intel(self):
        svc = IntelMarketplaceService()
        result = svc.publish_intel(TENANT, {"name": "test-item", "type": "test"})
        assert "id" in result
        assert result["tenant_id"] == TENANT
        assert result["status"] == "active"

    def test_publish_intel_creates_unique_ids(self):
        svc = IntelMarketplaceService()
        r1 = svc.publish_intel(TENANT, {"name": "item-1"})
        r2 = svc.publish_intel(TENANT, {"name": "item-2"})
        assert r1["id"] != r2["id"]

    def test_search_intel_empty(self):
        svc = IntelMarketplaceService()
        result = svc.search_intel(TENANT, "ransomware")
        assert isinstance(result, list)

    def test_download_intel(self):
        svc = IntelMarketplaceService()
        result = svc.download_intel(TENANT, "listing-1")
        assert isinstance(result, (dict, list))

    def test_get_listings_empty(self):
        svc = IntelMarketplaceService()
        result = svc.get_listings(TENANT)
        assert isinstance(result, list)

    def test_status(self):
        svc = IntelMarketplaceService()
        result = svc.status(TENANT)
        assert result["tenant_id"] == TENANT
        assert result["service"] == "IntelMarketplaceService"
        assert result["version"] == "7.7.0"

class TestReportGeneratorService:
    """ReportGeneratorService tests."""

    def test_generate_executive(self):
        svc = ReportGeneratorService()
        result = svc.generate_executive(TENANT)
        assert isinstance(result, (dict, list))

    def test_generate_technical(self):
        svc = ReportGeneratorService()
        result = svc.generate_technical(TENANT, "INC-001")
        assert isinstance(result, (dict, list))

    def test_generate_compliance(self):
        svc = ReportGeneratorService()
        result = svc.generate_compliance(TENANT)
        assert isinstance(result, (dict, list))

    def test_list_reports_empty(self):
        svc = ReportGeneratorService()
        result = svc.list_reports(TENANT)
        assert isinstance(result, list)

    def test_status(self):
        svc = ReportGeneratorService()
        result = svc.status(TENANT)
        assert result["tenant_id"] == TENANT
        assert result["service"] == "ReportGeneratorService"
        assert result["version"] == "7.7.0"

