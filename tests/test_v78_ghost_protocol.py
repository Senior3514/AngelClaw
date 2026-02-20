"""Tests for V7.8.0 Ghost Protocol: Stealth Defense & Active Deception."""

from __future__ import annotations

import pytest

from cloud.services.deception_depth import DeceptionDepthService
from cloud.services.moving_target import MovingTargetService


TENANT = "test-tenant"


class TestDeceptionDepthService:
    """DeceptionDepthService tests."""

    def test_deploy_honeypot(self):
        svc = DeceptionDepthService()
        result = svc.deploy_honeypot(TENANT, {"name": "test-item", "type": "test"})
        assert "id" in result
        assert result["tenant_id"] == TENANT
        assert result["status"] == "active"

    def test_deploy_honeypot_creates_unique_ids(self):
        svc = DeceptionDepthService()
        r1 = svc.deploy_honeypot(TENANT, {"name": "item-1"})
        r2 = svc.deploy_honeypot(TENANT, {"name": "item-2"})
        assert r1["id"] != r2["id"]

    def test_get_interactions_empty(self):
        svc = DeceptionDepthService()
        result = svc.get_interactions(TENANT, "hp-1")
        assert isinstance(result, list)

    def test_create_campaign(self):
        svc = DeceptionDepthService()
        result = svc.create_campaign(TENANT, {"name": "test-item", "type": "test"})
        assert "id" in result
        assert result["tenant_id"] == TENANT
        assert result["status"] == "active"

    def test_create_campaign_creates_unique_ids(self):
        svc = DeceptionDepthService()
        r1 = svc.create_campaign(TENANT, {"name": "item-1"})
        r2 = svc.create_campaign(TENANT, {"name": "item-2"})
        assert r1["id"] != r2["id"]

    def test_list_honeypots_empty(self):
        svc = DeceptionDepthService()
        result = svc.list_honeypots(TENANT)
        assert isinstance(result, list)

    def test_status(self):
        svc = DeceptionDepthService()
        result = svc.status(TENANT)
        assert result["tenant_id"] == TENANT
        assert result["service"] == "DeceptionDepthService"
        assert result["version"] == "7.8.0"

class TestMovingTargetService:
    """MovingTargetService tests."""

    def test_create_policy(self):
        svc = MovingTargetService()
        result = svc.create_policy(TENANT, {"name": "test-item", "type": "test"})
        assert "id" in result
        assert result["tenant_id"] == TENANT
        assert result["status"] == "active"

    def test_create_policy_creates_unique_ids(self):
        svc = MovingTargetService()
        r1 = svc.create_policy(TENANT, {"name": "item-1"})
        r2 = svc.create_policy(TENANT, {"name": "item-2"})
        assert r1["id"] != r2["id"]

    def test_execute_mutation(self):
        svc = MovingTargetService()
        result = svc.execute_mutation(TENANT, "policy-1")
        assert isinstance(result, (dict, list))

    def test_get_effectiveness(self):
        svc = MovingTargetService()
        result = svc.get_effectiveness(TENANT)
        assert isinstance(result, (dict, list))

    def test_list_policies_empty(self):
        svc = MovingTargetService()
        result = svc.list_policies(TENANT)
        assert isinstance(result, list)

    def test_status(self):
        svc = MovingTargetService()
        result = svc.status(TENANT)
        assert result["tenant_id"] == TENANT
        assert result["service"] == "MovingTargetService"
        assert result["version"] == "7.8.0"

