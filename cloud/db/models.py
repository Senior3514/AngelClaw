"""AngelClaw Cloud – SQLAlchemy ORM models.

These models mirror the shared Pydantic schemas but are mapped to relational
tables for persistent storage.  SQLite is used by default; switch the
connection string to PostgreSQL for production.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Column, DateTime, Integer, String, Text
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


# ---------------------------------------------------------------------------
# V2.4 — Fortress models
# ---------------------------------------------------------------------------


class PolicySnapshotRow(Base):
    """Named snapshot of a policy set for rollback."""

    __tablename__ = "policy_snapshots"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    description = Column(Text, default="")
    policy_set_id = Column(String(36), nullable=False)
    rules_json = Column(JSON, nullable=False)
    version_hash = Column(String(64), nullable=False)
    rule_count = Column(Integer, default=0)
    created_by = Column(String(128), default="system")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class QuarantineRecordRow(Base):
    """Agent quarantine record with timed release."""

    __tablename__ = "quarantine_records"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    agent_id = Column(String(36), nullable=False, index=True)
    reason = Column(Text, default="")
    quarantined_by = Column(String(128), default="system")
    quarantined_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    release_at = Column(DateTime, nullable=True)
    released_at = Column(DateTime, nullable=True)
    released_by = Column(String(128), nullable=True)
    status = Column(String(16), default="active")
    suppressed_events = Column(Integer, default=0)


class NotificationChannelRow(Base):
    """Configured notification channel (Slack/Discord/Webhook)."""

    __tablename__ = "notification_channels"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    channel_type = Column(String(32), nullable=False)
    config = Column(JSON, nullable=False)
    enabled = Column(String(8), default="true")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class NotificationRuleRow(Base):
    """Routing rule: severity/type -> notification channel."""

    __tablename__ = "notification_rules"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    channel_id = Column(String(36), nullable=False)
    min_severity = Column(String(16), default="high")
    alert_types = Column(JSON, default=list)
    enabled = Column(String(8), default="true")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# V2.5 — Ascension models
# ---------------------------------------------------------------------------


class PluginRegistrationRow(Base):
    """Registered warden plugin."""

    __tablename__ = "plugin_registrations"

    id = Column(String(36), primary_key=True)
    name = Column(String(128), nullable=False, unique=True)
    version = Column(String(32), nullable=False)
    agent_type = Column(String(32), nullable=False)
    entry_point = Column(String(256), nullable=False)
    permissions = Column(JSON, default=list)
    status = Column(String(16), default="loaded")
    loaded_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    error = Column(Text, nullable=True)


class ApiKeyRow(Base):
    """Service-to-service API key (hashed)."""

    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    key_hash = Column(String(64), nullable=False, unique=True, index=True)
    key_prefix = Column(String(12), nullable=False)
    scopes = Column(JSON, default=list)
    created_by = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    revoked = Column(String(8), default="false")
    revoked_at = Column(DateTime, nullable=True)


class BackupRecordRow(Base):
    """System backup metadata."""

    __tablename__ = "backup_records"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    filename = Column(String(256), nullable=False)
    size_bytes = Column(Integer, default=0)
    tables_included = Column(JSON, default=list)
    created_by = Column(String(128), default="system")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    status = Column(String(16), default="completed")


# ---------------------------------------------------------------------------
# V3.0 — Dominion models
# ---------------------------------------------------------------------------


class CustomRoleRow(Base):
    """User-defined RBAC role with granular permissions."""

    __tablename__ = "custom_roles"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    name = Column(String(64), nullable=False)
    description = Column(Text, default="")
    permissions = Column(JSON, default=list)
    is_system = Column(String(8), default="false")
    created_by = Column(String(128), default="system")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class EventReplayRow(Base):
    """Event replay session record."""

    __tablename__ = "event_replays"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    status = Column(String(16), default="pending")
    event_count = Column(Integer, default=0)
    indicators_found = Column(Integer, default=0)
    source_filter = Column(JSON, default=dict)
    results = Column(JSON, default=dict)
    created_by = Column(String(128), default="system")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class RemediationWorkflowRow(Base):
    """Automated multi-step remediation workflow definition."""

    __tablename__ = "remediation_workflows"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    description = Column(Text, default="")
    trigger_conditions = Column(JSON, default=dict)
    steps = Column(JSON, default=list)
    rollback_steps = Column(JSON, default=list)
    enabled = Column(String(8), default="true")
    executions = Column(Integer, default=0)
    last_executed_at = Column(DateTime, nullable=True)
    created_by = Column(String(128), default="system")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ThreatHuntQueryRow(Base):
    """Saved threat hunting query."""

    __tablename__ = "threat_hunt_queries"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    description = Column(Text, default="")
    query_dsl = Column(JSON, nullable=False)
    last_result_count = Column(Integer, default=0)
    last_run_at = Column(DateTime, nullable=True)
    created_by = Column(String(128), default="system")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# V2.3.0 — Admin Console models
# ---------------------------------------------------------------------------


class TenantRow(Base):
    """Organization tenant for multi-tenant management."""

    __tablename__ = "tenants"

    id = Column(String(64), primary_key=True)
    name = Column(String(256), nullable=False)
    description = Column(Text, default="")
    contact_email = Column(String(256), nullable=True)
    tier = Column(String(32), default="standard")  # free, standard, enterprise
    max_agents = Column(Integer, default=100)
    halo_score = Column(Integer, default=100)  # 0-100 security posture score
    wingspan = Column(Integer, default=0)  # coverage metric (% of assets monitored)
    status = Column(String(32), default="active")  # active, suspended, archived
    settings = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AntiTamperConfigRow(Base):
    """Per-agent or per-tenant anti-tamper configuration."""

    __tablename__ = "anti_tamper_configs"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    agent_id = Column(String(36), nullable=True, index=True)  # NULL = tenant-wide
    mode = Column(String(16), default="monitor")  # off, monitor, enforce
    check_binary_integrity = Column(String(8), default="true")
    check_config_changes = Column(String(8), default="true")
    check_process_health = Column(String(8), default="true")
    check_heartbeat = Column(String(8), default="true")
    heartbeat_timeout_seconds = Column(Integer, default=300)
    enabled_by = Column(String(128), default="system")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AntiTamperEventRow(Base):
    """Recorded tamper detection event."""

    __tablename__ = "anti_tamper_events"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    agent_id = Column(String(36), nullable=False, index=True)
    event_type = Column(String(64), nullable=False)  # config_change, process_death, checksum_mismatch, heartbeat_miss, unauthorized_uninstall
    severity = Column(String(16), default="high")
    description = Column(Text, default="")
    details = Column(JSON, default=dict)
    resolved = Column(String(8), default="false")
    resolved_by = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class FeedbackRecordRow(Base):
    """Operator feedback on AngelClaw suggestions."""

    __tablename__ = "feedback_records"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    suggestion_type = Column(String(64), nullable=False)  # policy_change, alert_threshold, scan_config, remediation
    suggestion_id = Column(String(36), nullable=True)
    action = Column(String(16), nullable=False)  # accepted, rejected, ignored, modified
    operator = Column(String(128), nullable=False)
    reason = Column(Text, default="")
    context = Column(JSON, default=dict)  # what was shown, what was decided
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class SelfHardeningLogRow(Base):
    """Log of autonomous hardening actions taken by AngelClaw."""

    __tablename__ = "self_hardening_logs"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    action_type = Column(String(64), nullable=False)  # tighten_allowlist, enable_logging, increase_scan_freq, block_source
    description = Column(Text, default="")
    reason = Column(Text, default="")
    before_state = Column(JSON, default=dict)
    after_state = Column(JSON, default=dict)
    revertible = Column(String(8), default="true")
    reverted = Column(String(8), default="false")
    reverted_at = Column(DateTime, nullable=True)
    reverted_by = Column(String(128), nullable=True)
    autonomy_mode = Column(String(16), default="suggest")
    applied_by = Column(String(128), default="system")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
