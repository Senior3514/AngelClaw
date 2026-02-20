"""Tests for V7.9.0 Apex Predator: Automated Offensive Security & Validation."""

from __future__ import annotations

import pytest

from cloud.services.pentest_auto import PentestAutoService
from cloud.services.red_team import RedTeamService


TENANT = "test-tenant"


class TestPentestAutoService:
    """PentestAutoService tests."""

    def test_start_pentest(self):
        svc = PentestAutoService()
        result = svc.start_pentest(TENANT, {"name": "test-item", "type": "test"})
        assert "id" in result
        assert result["tenant_id"] == TENANT
        assert result["status"] == "active"

    def test_start_pentest_creates_unique_ids(self):
        svc = PentestAutoService()
        r1 = svc.start_pentest(TENANT, {"name": "item-1"})
        r2 = svc.start_pentest(TENANT, {"name": "item-2"})
        assert r1["id"] != r2["id"]

    def test_get_findings_empty(self):
        svc = PentestAutoService()
        result = svc.get_findings(TENANT, "run-1")
        assert isinstance(result, list)

    def test_verify_remediation(self):
        svc = PentestAutoService()
        result = svc.verify_remediation(TENANT, "finding-1")
        assert isinstance(result, (dict, list))

    def test_list_runs_empty(self):
        svc = PentestAutoService()
        result = svc.list_runs(TENANT)
        assert isinstance(result, list)

    def test_status(self):
        svc = PentestAutoService()
        result = svc.status(TENANT)
        assert result["tenant_id"] == TENANT
        assert result["service"] == "PentestAutoService"
        assert result["version"] == "7.9.0"

class TestRedTeamService:
    """RedTeamService tests."""

    def test_create_campaign(self):
        svc = RedTeamService()
        result = svc.create_campaign(TENANT, {"name": "test-item", "type": "test"})
        assert "id" in result
        assert result["tenant_id"] == TENANT
        assert result["status"] == "active"

    def test_create_campaign_creates_unique_ids(self):
        svc = RedTeamService()
        r1 = svc.create_campaign(TENANT, {"name": "item-1"})
        r2 = svc.create_campaign(TENANT, {"name": "item-2"})
        assert r1["id"] != r2["id"]

    def test_execute_phase(self):
        svc = RedTeamService()
        result = svc.execute_phase(TENANT, "campaign-1")
        assert isinstance(result, (dict, list))

    def test_get_gaps_empty(self):
        svc = RedTeamService()
        result = svc.get_gaps(TENANT, "campaign-1")
        assert isinstance(result, list)

    def test_list_campaigns_empty(self):
        svc = RedTeamService()
        result = svc.list_campaigns(TENANT)
        assert isinstance(result, list)

    def test_status(self):
        svc = RedTeamService()
        result = svc.status(TENANT)
        assert result["tenant_id"] == TENANT
        assert result["service"] == "RedTeamService"
        assert result["version"] == "7.9.0"

