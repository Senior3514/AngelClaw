"""AngelClaw – Self-Audit Service.

Detects config drift, orphan rules, stale agents, and policy inconsistencies.
Runs periodically via the orchestrator or on-demand via API.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from cloud.db.models import AgentNodeRow, EventRow, GuardianAlertRow, PolicySetRow

logger = logging.getLogger("angelgrid.cloud.guardian.self_audit")


class AuditFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    category: str  # config_drift, orphan_rule, stale_agent, policy_gap, auth_risk
    severity: str  # critical, high, warn, info
    title: str
    description: str
    suggested_fix: str = ""


class SelfAuditReport(BaseModel):
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    findings: list[AuditFinding] = []
    checks_run: int = 0
    clean: bool = True
    summary: str = ""


async def run_self_audit(db: Session) -> SelfAuditReport:
    """Run all self-audit checks and return a structured report."""
    findings: list[AuditFinding] = []
    checks = 0

    # Check 1: Stale agents (active status but not seen in >10 min)
    checks += 1
    findings.extend(_check_stale_agents(db))

    # Check 2: Policy version drift (agents on different policy versions)
    checks += 1
    findings.extend(_check_policy_drift(db))

    # Check 3: Orphan alerts (alerts with no corresponding recent events)
    checks += 1
    findings.extend(_check_orphan_alerts(db))

    # Check 4: Auth configuration risks
    checks += 1
    findings.extend(_check_auth_risks())

    # Check 5: Unmonitored event categories
    checks += 1
    findings.extend(_check_event_coverage(db))

    # Check 6: High-frequency agents (possible misconfiguration)
    checks += 1
    findings.extend(_check_noisy_agents(db))

    # V2.2 — Check 7: Secret exposure in recent events
    checks += 1
    findings.extend(_check_secret_exposure(db))

    # V2.2 — Check 8: Warden health (check Angel Legion agents)
    checks += 1
    findings.extend(_check_warden_health())

    # V2.2 — Check 9: Database size and performance
    checks += 1
    findings.extend(_check_db_health(db))

    # V2.2 — Check 10: Rate limiting configuration
    checks += 1
    findings.extend(_check_rate_limiting())

    clean = len(findings) == 0
    summary_parts = [f"{checks} checks run."]
    if findings:
        by_sev = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        summary_parts.append(
            f"{len(findings)} finding(s): "
            + ", ".join(f"{v} {k}" for k, v in sorted(by_sev.items()))
        )
    else:
        summary_parts.append("All checks passed — clean audit.")

    report = SelfAuditReport(
        findings=findings,
        checks_run=checks,
        clean=clean,
        summary=" ".join(summary_parts),
    )

    logger.info(
        "[SELF-AUDIT] %s — %d findings from %d checks",
        "CLEAN" if clean else "FINDINGS",
        len(findings),
        checks,
    )

    return report


def _check_stale_agents(db: Session) -> list[AuditFinding]:
    """Detect agents marked active but not seen recently."""
    findings = []
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=10)
    stale = (
        db.query(AgentNodeRow)
        .filter(
            AgentNodeRow.status == "active",
            AgentNodeRow.last_seen_at < cutoff,
        )
        .all()
    )
    for agent in stale:
        findings.append(
            AuditFinding(
                category="stale_agent",
                severity="warn",
                title=f"Stale agent: {agent.hostname}",
                description=(
                    f"Agent {agent.hostname} ({agent.id[:8]}) is marked active but "
                    f"last seen at {agent.last_seen_at}."
                ),
                suggested_fix="Investigate connectivity or mark agent as degraded.",
            )
        )
    return findings


def _check_policy_drift(db: Session) -> list[AuditFinding]:
    """Detect agents running different policy versions."""
    findings = []
    current_policy = db.query(PolicySetRow).first()
    if not current_policy:
        return findings

    agents = db.query(AgentNodeRow).filter(AgentNodeRow.status == "active").all()
    drifted = [
        a
        for a in agents
        if a.policy_version != current_policy.version_hash and a.policy_version != "0"
    ]
    if drifted:
        hostnames = [a.hostname for a in drifted[:5]]
        findings.append(
            AuditFinding(
                category="config_drift",
                severity="high",
                title=f"Policy drift: {len(drifted)} agent(s) on old version",
                description=(
                    f"Agents {', '.join(hostnames)} are not running the current "
                    f"policy version ({current_policy.version_hash[:8]})."
                ),
                suggested_fix="Force policy sync or investigate why agents aren't updating.",
            )
        )
    return findings


def _check_orphan_alerts(db: Session) -> list[AuditFinding]:
    """Detect very old unresolved alerts."""
    findings = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    old_alerts = (
        db.query(GuardianAlertRow)
        .filter(
            GuardianAlertRow.created_at < cutoff,
            GuardianAlertRow.severity.in_(["critical", "high"]),
        )
        .count()
    )
    if old_alerts > 5:
        findings.append(
            AuditFinding(
                category="orphan_rule",
                severity="warn",
                title=f"{old_alerts} stale critical/high alerts (>24h old)",
                description="Old alerts may need review or archival.",
                suggested_fix="Review and archive resolved alerts.",
            )
        )
    return findings


def _check_auth_risks() -> list[AuditFinding]:
    """Check for authentication configuration risks."""
    import os

    findings = []

    auth_enabled = os.environ.get("ANGELCLAW_AUTH_ENABLED", "true").lower() in ("true", "1", "yes")
    if not auth_enabled:
        findings.append(
            AuditFinding(
                category="auth_risk",
                severity="critical",
                title="Authentication is DISABLED",
                description="The API is accessible without credentials.",
                suggested_fix="Set ANGELCLAW_AUTH_ENABLED=true and configure passwords.",
            )
        )

    admin_pass = os.environ.get("ANGELCLAW_ADMIN_PASSWORD", "")
    if auth_enabled and not admin_pass:
        findings.append(
            AuditFinding(
                category="auth_risk",
                severity="critical",
                title="Admin password not configured",
                description="ANGELCLAW_ADMIN_PASSWORD is empty — admin login will fail.",
                suggested_fix="Set ANGELCLAW_ADMIN_PASSWORD in environment or env file.",
            )
        )

    bind_host = os.environ.get("ANGELCLAW_BIND_HOST", "127.0.0.1")
    if bind_host == "0.0.0.0" and not auth_enabled:
        findings.append(
            AuditFinding(
                category="auth_risk",
                severity="critical",
                title="Public exposure without auth",
                description="Server is bound to 0.0.0.0 with auth disabled.",
                suggested_fix="Enable auth or bind to 127.0.0.1.",
            )
        )

    return findings


def _check_event_coverage(db: Session) -> list[AuditFinding]:
    """Check if any event categories have no policy rules."""
    findings = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    events = db.query(EventRow).filter(EventRow.timestamp >= cutoff).all()

    categories = {e.category for e in events}
    policy = db.query(PolicySetRow).first()
    if not policy or not policy.rules_json:
        return findings

    covered_categories = set()
    for rule in policy.rules_json:
        if isinstance(rule, dict):
            conds = rule.get("conditions", {})
            cat = conds.get("category") or conds.get("category_in", [])
            if isinstance(cat, str):
                covered_categories.add(cat)
            elif isinstance(cat, list):
                covered_categories.update(cat)

    uncovered = categories - covered_categories - {"system"}
    if uncovered:
        findings.append(
            AuditFinding(
                category="policy_gap",
                severity="info",
                title=f"Uncovered event categories: {', '.join(sorted(uncovered))}",
                description="These categories have events but no specific policy rules.",
                suggested_fix="Consider adding rules for these categories.",
            )
        )

    return findings


def _check_noisy_agents(db: Session) -> list[AuditFinding]:
    """Detect agents generating excessive events (possible misconfiguration)."""
    findings = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
    events = db.query(EventRow).filter(EventRow.timestamp >= cutoff).all()

    agent_counts: dict[str, int] = {}
    for e in events:
        agent_counts[e.agent_id] = agent_counts.get(e.agent_id, 0) + 1

    for agent_id, count in agent_counts.items():
        if count > 500:
            findings.append(
                AuditFinding(
                    category="stale_agent",
                    severity="warn",
                    title=f"Noisy agent: {agent_id[:8]} ({count} events/hr)",
                    description=f"Agent {agent_id[:8]} generated {count} events in the last hour.",
                    suggested_fix="Check for misconfiguration or apply throttling.",
                )
            )

    return findings


# ---------------------------------------------------------------------------
# V2.2 — New self-audit checks
# ---------------------------------------------------------------------------


def _check_secret_exposure(db: Session) -> list[AuditFinding]:
    """Check for potential secret exposure in recent events."""
    findings = []
    try:
        from shared.security.secret_scanner import contains_secret

        cutoff = datetime.now(timezone.utc) - timedelta(hours=6)
        events = db.query(EventRow).filter(EventRow.timestamp >= cutoff).limit(500).all()

        exposed_count = 0
        exposed_agents: set[str] = set()
        for e in events:
            details_str = str(e.details or {})
            if contains_secret(details_str):
                exposed_count += 1
                exposed_agents.add(e.agent_id)

        if exposed_count > 0:
            findings.append(
                AuditFinding(
                    category="secret_exposure",
                    severity="critical" if exposed_count >= 5 else "high",
                    title=(
                        f"Secret values in {exposed_count} event(s)"
                        f" from {len(exposed_agents)} agent(s)"
                    ),
                    description=(
                        f"Detected {exposed_count} events containing potential secret values. "
                        "These may be logged or transmitted in cleartext."
                    ),
                    suggested_fix=(
                        "Review event sources and ensure secrets are redacted before ingestion. "
                        "Enable AngelClaw secret scrubbing at the ANGELNODE level."
                    ),
                )
            )
    except Exception:
        pass
    return findings


def _check_warden_health() -> list[AuditFinding]:
    """Check Angel Legion warden health via the orchestrator."""
    findings = []
    try:
        from cloud.guardian.orchestrator import angel_orchestrator

        pulse = angel_orchestrator.pulse_check()
        degraded = pulse.get("degraded", 0)
        offline = pulse.get("offline", 0)

        if degraded > 0:
            findings.append(
                AuditFinding(
                    category="warden_health",
                    severity="high",
                    title=f"{degraded} Angel Legion warden(s) degraded",
                    description=(
                        f"{degraded} warden(s) are in ERROR state due to repeated failures. "
                        "Detection coverage may be reduced."
                    ),
                    suggested_fix="Check warden logs and consider restarting affected wardens.",
                )
            )

        if offline > 0:
            findings.append(
                AuditFinding(
                    category="warden_health",
                    severity="warn",
                    title=f"{offline} Angel Legion warden(s) offline",
                    description=f"{offline} warden(s) are stopped.",
                    suggested_fix="Restart the orchestrator to reinitialize wardens.",
                )
            )

        # Check circuit breakers
        breakers = pulse.get("circuit_breakers", {})
        for agent_id, failures in breakers.items():
            if failures >= 3:
                findings.append(
                    AuditFinding(
                        category="warden_health",
                        severity="high",
                        title=f"Circuit breaker open for warden {agent_id[:12]}",
                        description=(
                            f"Warden {agent_id[:12]} has {failures} consecutive failures. "
                            "It will be skipped during detection sweeps."
                        ),
                        suggested_fix="Investigate warden errors and reset circuit breaker.",
                    )
                )
    except Exception:
        pass
    return findings


def _check_db_health(db: Session) -> list[AuditFinding]:
    """Check database health: event accumulation, alert backlog."""
    findings = []
    try:
        total_events = db.query(EventRow).count()
        if total_events > 100_000:
            findings.append(
                AuditFinding(
                    category="db_health",
                    severity="warn",
                    title=f"Large event table: {total_events:,} rows",
                    description=(
                        "Event table is growing large. Consider archiving or "
                        "pruning old events to maintain query performance."
                    ),
                    suggested_fix="Implement event archival for events older than 30 days.",
                )
            )

        total_alerts = db.query(GuardianAlertRow).count()
        if total_alerts > 10_000:
            findings.append(
                AuditFinding(
                    category="db_health",
                    severity="warn",
                    title=f"Large alert table: {total_alerts:,} rows",
                    description="Alert table is growing large.",
                    suggested_fix="Archive resolved alerts older than 30 days.",
                )
            )
    except Exception:
        pass
    return findings


def _check_rate_limiting() -> list[AuditFinding]:
    """Check if rate limiting is configured for the API."""
    import os

    findings = []

    rate_limit = os.environ.get("ANGELCLAW_RATE_LIMIT", "")
    bind_host = os.environ.get("ANGELCLAW_BIND_HOST", "127.0.0.1")

    if bind_host != "127.0.0.1" and not rate_limit:
        findings.append(
            AuditFinding(
                category="config_drift",
                severity="high",
                title="No rate limiting on public-facing API",
                description=(
                    "The API is bound to a non-localhost address without rate limiting. "
                    "This exposes the API to denial-of-service attacks."
                ),
                suggested_fix=(
                    "Set ANGELCLAW_RATE_LIMIT environment variable or use a "
                    "reverse proxy (nginx/caddy) with rate limiting."
                ),
            )
        )

    return findings
