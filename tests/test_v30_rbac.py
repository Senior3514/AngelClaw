"""Tests for V3.0 Custom RBAC."""

from __future__ import annotations

import pytest

from cloud.auth.custom_roles import CustomRoleService
from cloud.db.models import CustomRoleRow


@pytest.fixture
def role_service():
    return CustomRoleService()


class TestCustomRoleService:
    def test_create_role(self, db, role_service):
        result = role_service.create_role(
            db, "dev-tenant",
            name="security-analyst",
            description="Can view events and alerts",
            permissions=["read_events", "read_alerts"],
        )
        assert result is not None
        assert "id" in result or "name" in result

    def test_list_roles(self, db, role_service):
        role_service.create_role(
            db, "dev-tenant", name="test-role",
            permissions=["read_events"],
        )
        roles = role_service.list_roles(db, "dev-tenant")
        assert len(roles) >= 1

    def test_get_role(self, db, role_service):
        role_service.create_role(
            db, "dev-tenant", name="get-role",
            permissions=["read_events"],
        )
        role = role_service.get_role(db, "dev-tenant", "get-role")
        assert role is not None

    def test_update_role(self, db, role_service):
        created = role_service.create_role(
            db, "dev-tenant", name="update-role",
            permissions=["read_events"],
        )
        role_id = created["id"]
        result = role_service.update_role(
            db, "dev-tenant", role_id,
            permissions=["read_events", "read_alerts", "read_agents"],
        )
        assert result is not None

    def test_delete_role(self, db, role_service):
        created = role_service.create_role(
            db, "dev-tenant", name="delete-role",
            permissions=["read_events"],
        )
        role_id = created["id"]
        result = role_service.delete_role(db, "dev-tenant", role_id)
        assert result is True

    def test_role_db_record(self, db, role_service):
        role_service.create_role(
            db, "dev-tenant", name="db-role",
            permissions=["read_events"],
        )
        record = db.query(CustomRoleRow).filter_by(name="db-role").first()
        assert record is not None
        assert record.tenant_id == "dev-tenant"

    def test_role_permissions_stored(self, db, role_service):
        created = role_service.create_role(
            db, "dev-tenant", name="perm-role",
            permissions=["read_events", "read_alerts"],
        )
        role_id = created.get("id")
        if role_id:
            row = db.query(CustomRoleRow).filter_by(id=role_id).first()
            assert row is not None
            assert len(row.permissions) == 2
