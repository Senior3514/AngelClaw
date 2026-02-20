"""AngelClaw Cloud – Custom RBAC Role Service (V3.0 Dominion).

Provides user-defined roles with granular permissions on top of the
built-in system roles.  System roles (admin, secops, viewer, auditor,
service) cannot be modified or deleted.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from cloud.db.models import CustomRoleRow

logger = logging.getLogger("angelgrid.cloud.auth.custom_roles")

# ---------------------------------------------------------------------------
# System (predefined) roles -- immutable
# ---------------------------------------------------------------------------

SYSTEM_ROLES: dict[str, dict[str, Any]] = {
    "admin": {
        "permissions": ["*"],
        "description": "Full system access",
    },
    "secops": {
        "permissions": [
            "read_events",
            "read_agents",
            "read_policies",
            "read_alerts",
            "write_incidents",
            "run_scans",
            "manage_quarantine",
            "chat",
        ],
        "description": "Security operations",
    },
    "viewer": {
        "permissions": [
            "read_events",
            "read_agents",
            "read_policies",
            "read_alerts",
            "chat",
        ],
        "description": "Read-only access",
    },
    "auditor": {
        "permissions": [
            "read_events",
            "read_alerts",
            "read_audit_trail",
            "export_data",
        ],
        "description": "Compliance auditor",
    },
    "service": {
        "permissions": [
            "ingest_events",
            "read_policies",
        ],
        "description": "Service-to-service integration",
    },
}

# ---------------------------------------------------------------------------
# Granular permission catalogue
# ---------------------------------------------------------------------------

GRANULAR_PERMISSIONS: list[str] = [
    "read_events",
    "read_agents",
    "read_policies",
    "read_alerts",
    "read_audit_trail",
    "write_incidents",
    "write_policies",
    "write_agents",
    "run_scans",
    "manage_quarantine",
    "manage_notifications",
    "manage_plugins",
    "manage_api_keys",
    "manage_roles",
    "manage_backups",
    "export_data",
    "ingest_events",
    "chat",
    "admin_system",
    "*",
]


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class CustomRoleService:
    """Manage system and user-defined RBAC roles."""

    # -- Create ---------------------------------------------------------------

    def create_role(
        self,
        db: Any,
        tenant_id: str,
        name: str,
        permissions: list[str],
        description: str = "",
        created_by: str = "system",
    ) -> dict:
        """Create a new custom role after validating permissions.

        Raises ``ValueError`` if the name collides with a system role or if
        any permission string is not in :data:`GRANULAR_PERMISSIONS`.
        """
        if name.lower() in SYSTEM_ROLES:
            raise ValueError(f"Cannot create role with reserved system name '{name}'")

        invalid = self.validate_permissions(permissions)
        if invalid:
            raise ValueError(f"Invalid permissions: {', '.join(invalid)}")

        # Prevent duplicate custom-role names within the same tenant
        existing = (
            db.query(CustomRoleRow)
            .filter(
                CustomRoleRow.tenant_id == tenant_id,
                CustomRoleRow.name == name,
            )
            .first()
        )
        if existing:
            raise ValueError(f"Custom role '{name}' already exists for this tenant")

        row = CustomRoleRow(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            name=name,
            description=description,
            permissions=permissions,
            is_system="false",
            created_by=created_by,
            created_at=datetime.now(timezone.utc),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        logger.info(
            "Created custom role '%s' (tenant=%s, perms=%d)",
            name,
            tenant_id,
            len(permissions),
        )
        return self._row_to_dict(row)

    # -- Read -----------------------------------------------------------------

    def get_role(self, db: Any, tenant_id: str, name: str) -> dict | None:
        """Return a role by name, checking system roles first."""
        lower = name.lower()
        if lower in SYSTEM_ROLES:
            return {
                "id": lower,
                "tenant_id": tenant_id,
                "name": lower,
                "description": SYSTEM_ROLES[lower]["description"],
                "permissions": SYSTEM_ROLES[lower]["permissions"],
                "is_system": True,
                "created_by": "system",
                "created_at": None,
            }

        row = (
            db.query(CustomRoleRow)
            .filter(
                CustomRoleRow.tenant_id == tenant_id,
                CustomRoleRow.name == name,
            )
            .first()
        )
        if row:
            return self._row_to_dict(row)
        return None

    def list_roles(self, db: Any, tenant_id: str) -> list[dict]:
        """Return all roles visible to *tenant_id* (system + custom)."""
        roles: list[dict] = []

        # System roles first
        for name, meta in SYSTEM_ROLES.items():
            roles.append(
                {
                    "id": name,
                    "tenant_id": tenant_id,
                    "name": name,
                    "description": meta["description"],
                    "permissions": meta["permissions"],
                    "is_system": True,
                    "created_by": "system",
                    "created_at": None,
                }
            )

        # Custom roles
        rows = (
            db.query(CustomRoleRow)
            .filter(CustomRoleRow.tenant_id == tenant_id)
            .order_by(CustomRoleRow.created_at.asc())
            .all()
        )
        for row in rows:
            roles.append(self._row_to_dict(row))

        return roles

    # -- Update ---------------------------------------------------------------

    def update_role(
        self,
        db: Any,
        tenant_id: str,
        role_id: str,
        permissions: list[str] | None = None,
        description: str | None = None,
    ) -> dict | None:
        """Update a custom role.  System roles cannot be updated.

        Returns the updated role dict or ``None`` if not found.
        Raises ``ValueError`` for system roles or invalid permissions.
        """
        if role_id.lower() in SYSTEM_ROLES:
            raise ValueError(f"Cannot update system role '{role_id}'")

        row = (
            db.query(CustomRoleRow)
            .filter(
                CustomRoleRow.id == role_id,
                CustomRoleRow.tenant_id == tenant_id,
            )
            .first()
        )
        if not row:
            return None

        if permissions is not None:
            invalid = self.validate_permissions(permissions)
            if invalid:
                raise ValueError(f"Invalid permissions: {', '.join(invalid)}")
            row.permissions = permissions

        if description is not None:
            row.description = description

        db.commit()
        db.refresh(row)
        logger.info("Updated custom role '%s' (id=%s)", row.name, role_id)
        return self._row_to_dict(row)

    # -- Delete ---------------------------------------------------------------

    def delete_role(self, db: Any, tenant_id: str, role_id: str) -> bool:
        """Delete a custom role.  System roles cannot be deleted.

        Returns ``True`` if a row was deleted, ``False`` if not found.
        Raises ``ValueError`` for system roles.
        """
        if role_id.lower() in SYSTEM_ROLES:
            raise ValueError(f"Cannot delete system role '{role_id}'")

        row = (
            db.query(CustomRoleRow)
            .filter(
                CustomRoleRow.id == role_id,
                CustomRoleRow.tenant_id == tenant_id,
            )
            .first()
        )
        if not row:
            return False

        db.delete(row)
        db.commit()
        logger.info("Deleted custom role '%s' (id=%s)", row.name, role_id)
        return True

    # -- Permission checks ----------------------------------------------------

    def check_permission(
        self,
        db: Any,
        tenant_id: str,
        role_name: str,
        required_permission: str,
    ) -> bool:
        """Return ``True`` if *role_name* grants *required_permission*.

        The wildcard ``*`` permission grants access to everything.
        """
        role = self.get_role(db, tenant_id, role_name)
        if role is None:
            return False

        perms: list[str] = role.get("permissions", [])
        if "*" in perms:
            return True
        return required_permission in perms

    # -- Validation -----------------------------------------------------------

    @staticmethod
    def validate_permissions(permissions: list[str]) -> list[str]:
        """Return a list of permission names that are **not** recognised."""
        return [p for p in permissions if p not in GRANULAR_PERMISSIONS]

    # -- Helpers --------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: CustomRoleRow) -> dict:
        return {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "name": row.name,
            "description": row.description or "",
            "permissions": row.permissions or [],
            "is_system": row.is_system == "true",
            "created_by": row.created_by or "system",
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

role_service = CustomRoleService()
