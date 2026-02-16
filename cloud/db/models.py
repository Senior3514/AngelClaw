"""AngelClaw Cloud – SQLAlchemy ORM models.

These models mirror the shared Pydantic schemas but are mapped to relational
tables for persistent storage.  SQLite is used by default; switch the
connection string to PostgreSQL for production.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Column, DateTime, Enum, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class AgentNodeRow(Base):
    """Persisted ANGELNODE registration."""

    __tablename__ = "agent_nodes"

    id = Column(String(36), primary_key=True)
    type = Column(String(32), nullable=False)
    os = Column(String(32), nullable=False)
    hostname = Column(String(255), nullable=False)
    tags = Column(JSON, default=list)
    policy_version = Column(String(64), default="0")
    status = Column(String(32), default="pending")
    version = Column(String(32), default="0.1.0")
    registered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen_at = Column(DateTime, nullable=True)


class EventRow(Base):
    """Persisted event from agent telemetry."""

    __tablename__ = "events"

    id = Column(String(36), primary_key=True)
    agent_id = Column(String(36), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    category = Column(String(32), nullable=False)
    type = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False)
    details = Column(JSON, default=dict)
    source = Column(String(255), nullable=True)


class PolicySetRow(Base):
    """Persisted policy set distributed to agents."""

    __tablename__ = "policy_sets"

    id = Column(String(36), primary_key=True)
    name = Column(String(128), nullable=False)
    description = Column(Text, default="")
    rules_json = Column(JSON, nullable=False)
    version_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class IncidentRow(Base):
    """Persisted incident record."""

    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True)
    event_ids = Column(JSON, default=list)
    status = Column(String(32), default="open")
    classification = Column(String(64), default="unknown")
    severity = Column(String(16), default="warn")
    recommended_actions = Column(JSON, default=list)
    summary = Column(Text, default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class GuardianReportRow(Base):
    """Periodic heartbeat summary of fleet health."""

    __tablename__ = "guardian_reports"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    agents_total = Column(Integer, default=0)
    agents_active = Column(Integer, default=0)
    agents_degraded = Column(Integer, default=0)
    agents_offline = Column(Integer, default=0)
    incidents_total = Column(Integer, default=0)
    incidents_by_severity = Column(JSON, default=dict)
    policy_changes_since_last = Column(Integer, default=0)
    anomalies = Column(JSON, default=list)
    summary = Column(Text, default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class GuardianAlertRow(Base):
    """Event-driven critical notification."""

    __tablename__ = "guardian_alerts"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    alert_type = Column(String(64), nullable=False)
    title = Column(String(512), nullable=False)
    severity = Column(String(16), nullable=False)
    details = Column(JSON, default=dict)
    related_event_ids = Column(JSON, default=list)
    related_agent_ids = Column(JSON, default=list)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class GuardianChangeRow(Base):
    """Policy/config change record."""

    __tablename__ = "guardian_changes"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    change_type = Column(String(64), nullable=False)
    description = Column(Text, default="")
    before_snapshot = Column(String(64), nullable=True)
    after_snapshot = Column(String(64), nullable=True)
    changed_by = Column(String(128), default="system")
    details = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
