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


# ---------------------------------------------------------------------------
# V3.5 — Sentinel models (Threat Intelligence)
# ---------------------------------------------------------------------------


class ThreatIntelFeedRow(Base):
    """Threat intelligence feed subscription."""

    __tablename__ = "threat_intel_feeds"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    feed_type = Column(String(32), nullable=False)  # stix, taxii, csv, json, misp
    url = Column(String(512), nullable=True)
    enabled = Column(String(8), default="true")
    poll_interval_minutes = Column(Integer, default=60)
    last_polled_at = Column(DateTime, nullable=True)
    ioc_count = Column(Integer, default=0)
    error = Column(Text, nullable=True)
    config = Column(JSON, default=dict)
    created_by = Column(String(128), default="system")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class IOCEntryRow(Base):
    """Indicator of Compromise entry from threat intel."""

    __tablename__ = "ioc_entries"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    feed_id = Column(String(36), nullable=False, index=True)
    ioc_type = Column(String(32), nullable=False)  # ip, domain, hash_md5, hash_sha256, url, email, cve
    value = Column(String(512), nullable=False, index=True)
    severity = Column(String(16), default="medium")
    confidence = Column(Integer, default=50)  # 0-100
    tags = Column(JSON, default=list)
    context = Column(JSON, default=dict)  # STIX metadata, source info
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=True)
    active = Column(String(8), default="true")


class ReputationEntryRow(Base):
    """IP/domain/hash reputation score."""

    __tablename__ = "reputation_entries"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    entity_type = Column(String(32), nullable=False)  # ip, domain, hash, email
    entity_value = Column(String(512), nullable=False, index=True)
    score = Column(Integer, default=50)  # 0=malicious, 100=clean
    category = Column(String(64), nullable=True)  # malware, phishing, c2, spam, clean
    sources = Column(JSON, default=list)
    last_checked = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class IOCMatchRow(Base):
    """Record of an IOC match against live events."""

    __tablename__ = "ioc_matches"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    ioc_id = Column(String(36), nullable=False, index=True)
    event_id = Column(String(36), nullable=False, index=True)
    agent_id = Column(String(36), nullable=True)
    match_field = Column(String(64), nullable=False)  # source_ip, dest_ip, domain, hash
    matched_value = Column(String(512), nullable=False)
    severity = Column(String(16), default="high")
    acknowledged = Column(String(8), default="false")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# V4.0 — Omniscience models (Situational Awareness)
# ---------------------------------------------------------------------------


class AssetRow(Base):
    """Discovered or registered asset in the environment."""

    __tablename__ = "assets"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    asset_type = Column(String(32), nullable=False)  # server, workstation, container, cloud_instance, network_device, iot
    name = Column(String(256), nullable=False)
    hostname = Column(String(255), nullable=True)
    ip_address = Column(String(64), nullable=True)
    os = Column(String(64), nullable=True)
    agent_id = Column(String(36), nullable=True, index=True)
    classification = Column(String(32), default="standard")  # critical, high_value, standard, low_value
    owner = Column(String(128), nullable=True)
    tags = Column(JSON, default=list)
    risk_score = Column(Integer, default=0)  # 0-100
    last_scan_at = Column(DateTime, nullable=True)
    status = Column(String(32), default="active")  # active, decommissioned, unknown
    asset_metadata = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class TopologyLinkRow(Base):
    """Network topology link between two assets."""

    __tablename__ = "topology_links"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    source_asset_id = Column(String(36), nullable=False, index=True)
    target_asset_id = Column(String(36), nullable=False, index=True)
    link_type = Column(String(32), nullable=False)  # network, dependency, trust, data_flow
    protocol = Column(String(16), nullable=True)  # tcp, udp, http, https, ssh
    port = Column(Integer, nullable=True)
    direction = Column(String(16), default="bidirectional")  # inbound, outbound, bidirectional
    risk_score = Column(Integer, default=0)
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class VulnerabilityRow(Base):
    """Vulnerability finding linked to an asset."""

    __tablename__ = "vulnerabilities"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    asset_id = Column(String(36), nullable=False, index=True)
    cve_id = Column(String(32), nullable=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, default="")
    severity = Column(String(16), nullable=False)  # critical, high, medium, low, info
    cvss_score = Column(String(8), nullable=True)  # e.g. "9.8"
    status = Column(String(32), default="open")  # open, mitigated, accepted, false_positive
    remediation = Column(Text, default="")
    scanner_source = Column(String(64), default="angelclaw")
    found_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    resolved_at = Column(DateTime, nullable=True)


class SOARPlaybookRow(Base):
    """SOAR playbook definition with trigger-action chains."""

    __tablename__ = "soar_playbooks"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    description = Column(Text, default="")
    trigger_type = Column(String(64), nullable=False)  # alert, event_pattern, schedule, manual, ioc_match
    trigger_config = Column(JSON, default=dict)
    actions = Column(JSON, default=list)  # ordered list of action steps
    enabled = Column(String(8), default="true")
    priority = Column(Integer, default=5)  # 1=highest, 10=lowest
    max_executions_per_hour = Column(Integer, default=10)
    executions_total = Column(Integer, default=0)
    last_executed_at = Column(DateTime, nullable=True)
    created_by = Column(String(128), default="system")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class SLAConfigRow(Base):
    """SLA configuration for incident response times."""

    __tablename__ = "sla_configs"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    severity = Column(String(16), nullable=False)  # critical, high, medium, low
    response_time_minutes = Column(Integer, nullable=False)  # max time to first response
    resolution_time_minutes = Column(Integer, nullable=False)  # max time to resolution
    escalation_contacts = Column(JSON, default=list)
    enabled = Column(String(8), default="true")
    breaches_total = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class IncidentTimelineRow(Base):
    """Incident timeline entry for visualization."""

    __tablename__ = "incident_timeline"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    incident_id = Column(String(36), nullable=False, index=True)
    entry_type = Column(String(32), nullable=False)  # event, action, comment, escalation, resolution
    timestamp = Column(DateTime, nullable=False, index=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, default="")
    actor = Column(String(128), default="system")  # who/what performed this
    details = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# V4.1 — Prophecy models (Predictive ML)
# ---------------------------------------------------------------------------


class BehaviorProfileRow(Base):
    """Behavioral baseline profile for an agent or user."""

    __tablename__ = "behavior_profiles"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    entity_type = Column(String(32), nullable=False)  # agent, user, service
    entity_id = Column(String(64), nullable=False, index=True)
    baseline_data = Column(JSON, default=dict)  # avg events/hr, common categories, time patterns
    anomaly_threshold = Column(String(8), default="2.0")  # standard deviations
    last_updated = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    profile_age_days = Column(Integer, default=0)
    total_observations = Column(Integer, default=0)
    status = Column(String(16), default="learning")  # learning, active, stale
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AnomalyDetectionRow(Base):
    """ML anomaly detection result."""

    __tablename__ = "anomaly_detections"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    profile_id = Column(String(36), nullable=False, index=True)
    entity_id = Column(String(64), nullable=False)
    anomaly_type = Column(String(64), nullable=False)  # volume_spike, category_shift, time_anomaly, behavior_drift
    score = Column(String(8), nullable=False)  # 0.0-1.0 anomaly score
    severity = Column(String(16), default="medium")
    description = Column(Text, default="")
    features = Column(JSON, default=dict)  # feature values that triggered the anomaly
    acknowledged = Column(String(8), default="false")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AttackPathRow(Base):
    """Computed attack path between assets."""

    __tablename__ = "attack_paths"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    name = Column(String(256), nullable=False)
    source_asset_id = Column(String(36), nullable=False)
    target_asset_id = Column(String(36), nullable=False)
    path_nodes = Column(JSON, default=list)  # ordered list of asset IDs in the path
    attack_techniques = Column(JSON, default=list)  # MITRE ATT&CK techniques
    risk_score = Column(Integer, default=0)  # 0-100
    likelihood = Column(String(8), default="0.5")  # 0.0-1.0
    mitigations = Column(JSON, default=list)
    status = Column(String(16), default="active")  # active, mitigated, accepted
    computed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class RiskForecastRow(Base):
    """Risk forecast prediction for future time windows."""

    __tablename__ = "risk_forecasts"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    forecast_type = Column(String(64), nullable=False)  # incident_volume, severity_trend, attack_likelihood
    time_horizon_hours = Column(Integer, nullable=False)  # how far ahead
    predicted_value = Column(String(32), nullable=False)
    confidence = Column(String(8), nullable=False)  # 0.0-1.0
    contributing_factors = Column(JSON, default=list)
    actual_value = Column(String(32), nullable=True)  # filled in after the period
    accuracy = Column(String(8), nullable=True)  # computed after actual
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# V4.2 — Nexus models (Integration Hub)
# ---------------------------------------------------------------------------


class SIEMConnectorRow(Base):
    """Universal SIEM connector configuration."""

    __tablename__ = "siem_connectors"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    siem_type = Column(String(32), nullable=False)  # splunk, elastic, qradar, arcsight, sentinel, wazuh
    connection_config = Column(JSON, nullable=False)  # host, port, credentials (encrypted ref)
    sync_direction = Column(String(16), default="push")  # push, pull, bidirectional
    event_filter = Column(JSON, default=dict)  # which events to sync
    enabled = Column(String(8), default="true")
    last_sync_at = Column(DateTime, nullable=True)
    events_synced = Column(Integer, default=0)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ContainerScanRow(Base):
    """Container image or runtime security scan result."""

    __tablename__ = "container_scans"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    image_name = Column(String(256), nullable=False)
    image_tag = Column(String(64), nullable=True)
    image_digest = Column(String(128), nullable=True)
    scan_type = Column(String(32), nullable=False)  # image, runtime, config
    vulnerabilities_found = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    findings = Column(JSON, default=list)
    policy_violations = Column(JSON, default=list)
    status = Column(String(16), default="completed")  # pending, scanning, completed, failed
    scanned_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class IaCScanRow(Base):
    """Infrastructure-as-Code security scan result."""

    __tablename__ = "iac_scans"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    source_type = Column(String(32), nullable=False)  # terraform, cloudformation, kubernetes, ansible, dockerfile
    source_path = Column(String(512), nullable=False)
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    findings = Column(JSON, default=list)
    passed_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)
    status = Column(String(16), default="completed")
    scanned_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class CICDGateRow(Base):
    """CI/CD pipeline security gate check result."""

    __tablename__ = "cicd_gates"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    pipeline_name = Column(String(256), nullable=False)
    pipeline_run_id = Column(String(128), nullable=True)
    gate_type = Column(String(32), nullable=False)  # pre_deploy, post_build, pre_merge, runtime
    decision = Column(String(16), nullable=False)  # pass, fail, warn
    checks_passed = Column(Integer, default=0)
    checks_failed = Column(Integer, default=0)
    findings = Column(JSON, default=list)
    policy_id = Column(String(36), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# V4.5 — Sovereign models (Zero Trust Architecture)
# ---------------------------------------------------------------------------


class MicrosegmentRow(Base):
    """Microsegmentation policy segment."""

    __tablename__ = "microsegments"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    description = Column(Text, default="")
    segment_type = Column(String(32), nullable=False)  # network, application, data, identity
    source_criteria = Column(JSON, default=dict)  # asset tags, IPs, identities
    target_criteria = Column(JSON, default=dict)
    allowed_protocols = Column(JSON, default=list)  # tcp:443, udp:53, etc.
    action = Column(String(16), default="allow")  # allow, deny, monitor
    priority = Column(Integer, default=100)
    enabled = Column(String(8), default="true")
    hit_count = Column(Integer, default=0)
    created_by = Column(String(128), default="system")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class IdentityPolicyRow(Base):
    """Identity-based zero-trust access policy."""

    __tablename__ = "identity_policies"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    identity_type = Column(String(32), nullable=False)  # user, service_account, api_key, agent
    identity_pattern = Column(String(256), nullable=False)  # regex or exact match
    resource_pattern = Column(String(256), nullable=False)
    conditions = Column(JSON, default=dict)  # time_of_day, geo, device_trust_min, risk_max
    action = Column(String(16), default="allow")  # allow, deny, mfa_required, step_up
    priority = Column(Integer, default=100)
    enabled = Column(String(8), default="true")
    evaluations = Column(Integer, default=0)
    last_matched_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class DeviceTrustRow(Base):
    """Device trust assessment record."""

    __tablename__ = "device_trust"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    device_id = Column(String(128), nullable=False, index=True)
    agent_id = Column(String(36), nullable=True)
    trust_score = Column(Integer, default=50)  # 0-100
    os_version = Column(String(64), nullable=True)
    patch_level = Column(String(32), nullable=True)
    encryption_enabled = Column(String(8), default="unknown")
    antivirus_active = Column(String(8), default="unknown")
    firewall_enabled = Column(String(8), default="unknown")
    compliance_status = Column(String(16), default="unknown")  # compliant, non_compliant, unknown
    risk_factors = Column(JSON, default=list)
    last_assessed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class SessionRiskRow(Base):
    """Real-time session risk assessment."""

    __tablename__ = "session_risks"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    session_id = Column(String(128), nullable=False, index=True)
    user_id = Column(String(128), nullable=False)
    device_id = Column(String(128), nullable=True)
    risk_score = Column(Integer, default=0)  # 0-100
    risk_factors = Column(JSON, default=list)  # geo_anomaly, time_anomaly, behavior_anomaly, etc.
    auth_level = Column(String(16), default="standard")  # standard, mfa, step_up
    action_taken = Column(String(32), default="none")  # none, mfa_challenge, block, monitor
    geo_location = Column(String(128), nullable=True)
    assessed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=True)


# ---------------------------------------------------------------------------
# V5.0 — Transcendence models (AGI Empyrion)
# ---------------------------------------------------------------------------


class AIModelRegistryRow(Base):
    """Registered AI model for multi-model orchestration."""

    __tablename__ = "ai_model_registry"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    model_type = Column(String(32), nullable=False)  # llm, classifier, anomaly, embeddings, vision
    provider = Column(String(64), nullable=False)  # ollama, openai, anthropic, local, huggingface
    endpoint = Column(String(512), nullable=True)
    capabilities = Column(JSON, default=list)  # summarize, classify, detect, generate, embed
    config = Column(JSON, default=dict)
    priority = Column(Integer, default=5)
    enabled = Column(String(8), default="true")
    requests_total = Column(Integer, default=0)
    avg_latency_ms = Column(Integer, default=0)
    error_rate = Column(String(8), default="0.0")
    last_used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class NLPolicyRow(Base):
    """Natural language authored security policy."""

    __tablename__ = "nl_policies"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    natural_language = Column(Text, nullable=False)  # "Block all SSH from external IPs after hours"
    compiled_rules = Column(JSON, default=list)  # machine-readable rules generated from NL
    confidence = Column(String(8), default="0.0")  # AI confidence in compilation
    status = Column(String(16), default="draft")  # draft, review, active, disabled
    review_notes = Column(Text, default="")
    compiled_by = Column(String(64), default="angelclaw_brain")
    approved_by = Column(String(128), nullable=True)
    created_by = Column(String(128), default="system")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class DeceptionTokenRow(Base):
    """Honey token / honey pot deployment."""

    __tablename__ = "deception_tokens"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    token_type = Column(String(32), nullable=False)  # honey_credential, honey_file, honey_endpoint, honey_dns, canary_token
    name = Column(String(128), nullable=False)
    deployment_location = Column(String(256), nullable=False)
    token_value = Column(String(512), nullable=True)  # the bait value (not a real secret)
    triggered = Column(String(8), default="false")
    trigger_count = Column(Integer, default=0)
    last_triggered_at = Column(DateTime, nullable=True)
    last_triggered_by = Column(String(256), nullable=True)  # IP, agent, user that triggered it
    enabled = Column(String(8), default="true")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ForensicCaseRow(Base):
    """Digital forensics investigation case."""

    __tablename__ = "forensic_cases"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, default="")
    incident_id = Column(String(36), nullable=True, index=True)
    status = Column(String(16), default="open")  # open, investigating, evidence_collected, closed
    priority = Column(String(16), default="medium")
    assigned_to = Column(String(128), nullable=True)
    evidence_items = Column(JSON, default=list)  # list of evidence references
    findings = Column(JSON, default=list)
    timeline = Column(JSON, default=list)  # forensic timeline entries
    chain_of_custody = Column(JSON, default=list)
    created_by = Column(String(128), default="system")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    closed_at = Column(DateTime, nullable=True)


class ComplianceRuleRow(Base):
    """Compliance-as-code rule definition."""

    __tablename__ = "compliance_rules"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    framework = Column(String(32), nullable=False)  # gdpr, hipaa, pci_dss, soc2, nist, iso27001, cis
    control_id = Column(String(64), nullable=False)  # e.g. "GDPR-Art.32", "PCI-DSS-3.4"
    title = Column(String(256), nullable=False)
    description = Column(Text, default="")
    check_type = Column(String(32), nullable=False)  # policy, config, event_pattern, manual
    check_config = Column(JSON, default=dict)  # automated check parameters
    severity = Column(String(16), default="medium")
    status = Column(String(16), default="active")  # active, disabled, draft
    last_check_result = Column(String(16), nullable=True)  # pass, fail, error, not_checked
    last_checked_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class EvolvingRuleRow(Base):
    """Self-evolving detection rule managed by AI."""

    __tablename__ = "evolving_rules"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    description = Column(Text, default="")
    rule_type = Column(String(32), nullable=False)  # pattern, threshold, anomaly, composite
    rule_config = Column(JSON, nullable=False)
    generation = Column(Integer, default=1)  # evolution generation counter
    parent_rule_id = Column(String(36), nullable=True)  # rule this evolved from
    fitness_score = Column(String(8), default="0.5")  # 0.0-1.0 effectiveness
    true_positives = Column(Integer, default=0)
    false_positives = Column(Integer, default=0)
    total_evaluations = Column(Integer, default=0)
    auto_evolved = Column(String(8), default="false")  # was this auto-generated?
    enabled = Column(String(8), default="true")
    evolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# V5.5 — Convergence (Real-Time Defense Fabric)
# ---------------------------------------------------------------------------


class RealtimeEventRow(Base):
    """Real-time event stream entry for live dashboard metrics."""

    __tablename__ = "realtime_events"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    event_type = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False)
    source = Column(String(128), default="")
    details = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class HaloScoreRow(Base):
    """Historical Halo Score snapshots for trend analysis."""

    __tablename__ = "halo_scores"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    score = Column(Integer, nullable=False)
    dimensions = Column(JSON, nullable=False)
    computed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class FleetNodeRow(Base):
    """ANGELNODE fleet node registry for fleet orchestration."""

    __tablename__ = "fleet_nodes"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    hostname = Column(String(256), nullable=False)
    os_type = Column(String(32), nullable=False)
    version = Column(String(16), default="10.0.0")
    health_pct = Column(Integer, default=100)
    status = Column(String(16), default="active")  # active, degraded, offline
    tags = Column(JSON, default=list)
    metrics = Column(JSON, default=dict)
    last_seen_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    registered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# V6.0 — Omniguard (Multi-Cloud Defense Fabric)
# ---------------------------------------------------------------------------


class CloudConnectorRow(Base):
    """Multi-cloud connector configuration."""

    __tablename__ = "cloud_connectors"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    cloud_provider = Column(String(32), nullable=False)  # aws, azure, gcp, oci, alibaba
    name = Column(String(128), nullable=False)
    config = Column(JSON, default=dict)
    regions = Column(JSON, default=list)
    status = Column(String(16), default="active")
    last_sync_at = Column(DateTime, nullable=True)
    resources_synced = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class CSPMFindingRow(Base):
    """Cloud Security Posture Management finding."""

    __tablename__ = "cspm_findings"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    connector_id = Column(String(36), nullable=False)
    provider = Column(String(32), nullable=False)
    benchmark = Column(String(32), nullable=False)
    severity = Column(String(16), nullable=False)
    resource_type = Column(String(64), default="")
    title = Column(String(256), nullable=False)
    description = Column(Text, default="")
    status = Column(String(16), default="open")  # open, remediated, suppressed
    remediation = Column(Text, default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class SaaSAppRow(Base):
    """SaaS application registry for protection monitoring."""

    __tablename__ = "saas_apps"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    app_name = Column(String(128), nullable=False)
    app_type = Column(String(32), nullable=False)
    auth_method = Column(String(32), default="oauth")
    config = Column(JSON, default=dict)
    risk_score = Column(Integer, default=0)
    is_shadow = Column(String(8), default="false")
    status = Column(String(16), default="active")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class HybridEnvironmentRow(Base):
    """Hybrid deployment environment registry."""

    __tablename__ = "hybrid_environments"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    env_name = Column(String(128), nullable=False)
    env_type = Column(String(32), nullable=False)  # on_prem, cloud, edge, hybrid
    endpoint = Column(String(256), default="")
    config = Column(JSON, default=dict)
    status = Column(String(16), default="active")
    federated = Column(String(8), default="false")
    last_sync_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# V6.5 — Prometheus (Autonomous Threat Hunting)
# ---------------------------------------------------------------------------


class ThreatHuntRow(Base):
    """Autonomous threat hunting campaign."""

    __tablename__ = "threat_hunts"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    hypothesis = Column(Text, nullable=False)
    hunt_type = Column(String(32), nullable=False)
    config = Column(JSON, default=dict)
    status = Column(String(16), default="created")  # created, running, completed, failed
    findings_count = Column(Integer, default=0)
    results = Column(JSON, default=dict)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class MitreMappingRow(Base):
    """MITRE ATT&CK technique mapping record."""

    __tablename__ = "mitre_mappings"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    technique_id = Column(String(16), nullable=False)
    tactic = Column(String(64), nullable=False)
    name = Column(String(128), nullable=False)
    description = Column(Text, default="")
    event_count = Column(Integer, default=0)
    last_seen_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AdversaryScenarioRow(Base):
    """Adversary simulation scenario for purple team exercises."""

    __tablename__ = "adversary_scenarios"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    attack_type = Column(String(64), nullable=False)
    mitre_techniques = Column(JSON, default=list)
    config = Column(JSON, default=dict)
    status = Column(String(16), default="created")
    results = Column(JSON, default=dict)
    defense_score = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class IntelCorrelationRow(Base):
    """Intelligence correlation record linking events/indicators."""

    __tablename__ = "intel_correlations"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    correlation_type = Column(String(32), nullable=False)
    event_ids = Column(JSON, default=list)
    confidence = Column(String(8), nullable=False)
    campaign_id = Column(String(64), nullable=True)
    findings = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# V7.0 — Empyrion (Full AGI Autonomous Defense)
# ---------------------------------------------------------------------------


class AGIDefenseRuleRow(Base):
    """AGI-generated defense rule."""

    __tablename__ = "agi_defense_rules"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    analysis_id = Column(String(36), nullable=False)
    name = Column(String(128), nullable=False)
    rule_logic = Column(JSON, nullable=False)
    confidence = Column(String(8), nullable=False)
    status = Column(String(16), default="generated")  # generated, validated, deployed, disabled
    validation_results = Column(JSON, default=dict)
    deployed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AutonomousResponseRow(Base):
    """Autonomous incident response record."""

    __tablename__ = "autonomous_responses"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    incident_id = Column(String(36), nullable=False)
    response_type = Column(String(32), nullable=False)
    status = Column(String(16), default="triggered")  # triggered, containing, eradicating, recovering, completed, overridden
    containment_at = Column(DateTime, nullable=True)
    eradication_at = Column(DateTime, nullable=True)
    recovery_at = Column(DateTime, nullable=True)
    overridden_by = Column(String(64), nullable=True)
    override_reason = Column(Text, nullable=True)
    timeline = Column(JSON, default=list)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ThreatFederationRow(Base):
    """Cross-org threat federation membership."""

    __tablename__ = "threat_federation"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    org_name = Column(String(128), nullable=False)
    trust_level = Column(String(8), nullable=False)
    status = Column(String(16), default="active")
    indicators_shared = Column(Integer, default=0)
    indicators_consumed = Column(Integer, default=0)
    joined_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class SOCTriageRow(Base):
    """SOC autopilot triage record."""

    __tablename__ = "soc_triage"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    alert_id = Column(String(36), nullable=False)
    priority = Column(String(16), nullable=False)
    category = Column(String(64), default="")
    assigned_analyst = Column(String(64), nullable=True)
    status = Column(String(16), default="triaged")  # triaged, investigating, resolved, escalated
    investigation_id = Column(String(36), nullable=True)
    triage_data = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
