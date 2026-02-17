"""AngelClaw – Tenant-Scoped Preferences.

Controls how AngelClaw behaves: autonomy level, scan frequency,
reporting verbosity. Persisted per-tenant in the database and
modifiable via API, chat, or UI.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field
from sqlalchemy import JSON, Column, DateTime, Integer, String
from sqlalchemy.orm import Session

from cloud.db.models import Base

logger = logging.getLogger("angelclaw.preferences")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AutonomyLevel(str, Enum):
    OBSERVE_ONLY = "observe_only"  # Watch and report, never suggest
    SUGGEST_ONLY = "suggest_only"  # Suggest actions, never auto-apply
    ASSIST = "assist"  # Suggest + apply with operator confirmation
    AUTONOMOUS = "autonomous_apply"  # Auto-apply safe actions (future)


class ReportingLevel(str, Enum):
    QUIET = "quiet"  # Only critical findings
    NORMAL = "normal"  # Standard reporting
    VERBOSE = "verbose"  # Detailed reporting with context


# ---------------------------------------------------------------------------
# DB Model
# ---------------------------------------------------------------------------


class AngelClawPreferencesRow(Base):
    __tablename__ = "angelclaw_preferences"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(64), nullable=False, unique=True, index=True)
    autonomy_level = Column(String(32), default=AutonomyLevel.SUGGEST_ONLY.value)
    scan_frequency_minutes = Column(Integer, default=10)
    reporting_level = Column(String(16), default=ReportingLevel.NORMAL.value)
    custom_settings = Column(JSON, default=dict)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_by = Column(String(128), default="system")


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class Preferences(BaseModel):
    tenant_id: str = "dev-tenant"
    autonomy_level: AutonomyLevel = AutonomyLevel.SUGGEST_ONLY
    scan_frequency_minutes: int = Field(default=10, ge=1, le=1440)
    reporting_level: ReportingLevel = ReportingLevel.NORMAL
    custom_settings: dict = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_by: str = "system"


class PreferencesUpdate(BaseModel):
    autonomy_level: AutonomyLevel | None = None
    scan_frequency_minutes: int | None = Field(default=None, ge=1, le=1440)
    reporting_level: ReportingLevel | None = None
    custom_settings: dict | None = None


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


def get_preferences(db: Session, tenant_id: str = "dev-tenant") -> Preferences:
    """Get preferences for a tenant, creating defaults if needed."""
    row = db.query(AngelClawPreferencesRow).filter_by(tenant_id=tenant_id).first()
    if not row:
        return Preferences(tenant_id=tenant_id)
    return Preferences(
        tenant_id=row.tenant_id,
        autonomy_level=AutonomyLevel(row.autonomy_level),
        scan_frequency_minutes=row.scan_frequency_minutes,
        reporting_level=ReportingLevel(row.reporting_level),
        custom_settings=row.custom_settings or {},
        updated_at=row.updated_at,
        updated_by=row.updated_by,
    )


def update_preferences(
    db: Session,
    tenant_id: str,
    update: PreferencesUpdate,
    updated_by: str = "operator",
) -> Preferences:
    """Update preferences, creating the row if it doesn't exist."""
    row = db.query(AngelClawPreferencesRow).filter_by(tenant_id=tenant_id).first()
    if not row:
        row = AngelClawPreferencesRow(tenant_id=tenant_id)
        db.add(row)

    changes = []
    if update.autonomy_level is not None:
        old = row.autonomy_level
        row.autonomy_level = update.autonomy_level.value
        if old != row.autonomy_level:
            changes.append(f"autonomy_level: {old} -> {row.autonomy_level}")

    if update.scan_frequency_minutes is not None:
        old = row.scan_frequency_minutes
        row.scan_frequency_minutes = update.scan_frequency_minutes
        if old != row.scan_frequency_minutes:
            changes.append(f"scan_frequency: {old}min -> {row.scan_frequency_minutes}min")

    if update.reporting_level is not None:
        old = row.reporting_level
        row.reporting_level = update.reporting_level.value
        if old != row.reporting_level:
            changes.append(f"reporting_level: {old} -> {row.reporting_level}")

    if update.custom_settings is not None:
        row.custom_settings = {**(row.custom_settings or {}), **update.custom_settings}
        changes.append("custom_settings updated")

    row.updated_at = datetime.now(timezone.utc)
    row.updated_by = updated_by
    db.commit()

    if changes:
        logger.info("[PREFERENCES] %s updated by %s: %s", tenant_id, updated_by, "; ".join(changes))

    return get_preferences(db, tenant_id)
