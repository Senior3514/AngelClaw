"""Tests for V7.5.0 Iron Vault: Data Protection & Privacy."""

from __future__ import annotations

from cloud.services.data_classification import DataClassificationService
from cloud.services.dlp_engine import DLPService

TENANT = "test-tenant"


class TestDLPService:
    """DLPService tests."""

    def test_scan_content(self):
        svc = DLPService()
        result = svc.scan_content(TENANT, "test-target")
        assert "id" in result
        assert result["tenant_id"] == TENANT

    def test_add_policy(self):
        svc = DLPService()
        result = svc.add_policy(TENANT, {"name": "test-item", "type": "test"})
        assert "id" in result
        assert result["tenant_id"] == TENANT
        assert result["status"] == "active"

    def test_add_policy_creates_unique_ids(self):
        svc = DLPService()
        r1 = svc.add_policy(TENANT, {"name": "item-1"})
        r2 = svc.add_policy(TENANT, {"name": "item-2"})
        assert r1["id"] != r2["id"]

    def test_get_violations_empty(self):
        svc = DLPService()
        result = svc.get_violations(TENANT)
        assert isinstance(result, list)

    def test_get_policies_empty(self):
        svc = DLPService()
        result = svc.get_policies(TENANT)
        assert isinstance(result, list)

    def test_status(self):
        svc = DLPService()
        result = svc.status(TENANT)
        assert result["tenant_id"] == TENANT
        assert result["service"] == "DLPService"
        assert result["version"] == "7.5.0"


class TestDataClassificationService:
    """DataClassificationService tests."""

    def test_classify_data(self):
        svc = DataClassificationService()
        result = svc.classify_data(TENANT, {"type": "test", "value": "test-data"})
        assert "id" in result
        assert result["tenant_id"] == TENANT

    def test_discover_sensitive_empty(self):
        svc = DataClassificationService()
        result = svc.discover_sensitive(TENANT, "/data/uploads")
        assert isinstance(result, list)

    def test_get_inventory_empty(self):
        svc = DataClassificationService()
        result = svc.get_inventory(TENANT)
        assert isinstance(result, list)

    def test_get_lineage(self):
        svc = DataClassificationService()
        result = svc.get_lineage(TENANT, "asset-1")
        assert isinstance(result, (dict, list))

    def test_status(self):
        svc = DataClassificationService()
        result = svc.status(TENANT)
        assert result["tenant_id"] == TENANT
        assert result["service"] == "DataClassificationService"
        assert result["version"] == "7.5.0"
