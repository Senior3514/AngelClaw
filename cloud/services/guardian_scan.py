"""AngelClaw Cloud – Guardian Scan Service.

Aggregates system exposures and returns structured risk assessments
with hardening suggestions. Called from Guardian Chat when the user
asks for a security scan.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from cloud.db.models import AgentNodeRow, EventRow, GuardianAlertRow, GuardianReportRow

logger = logging.getLogger("angelgrid.cloud.guardian_scan")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class ScanRisk(BaseModel):
    id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low
    affected_agents: list[str] = Field(default_factory=list)
    suggested_fix: str = ""


class HardeningSuggestion(BaseModel):
    action: str
    rule_id: str = ""
    scope: str = "all_agents"
    description: str = ""


class GuardianScanResult(BaseModel):
    top_risks: list[ScanRisk] = Field(default_factory=list)
    hardening_suggestions: list[HardeningSuggestion] = Field(default_factory=list)
    scanned_at: datetime
    total_checks: int = 0
    summary: str = ""


# ---------------------------------------------------------------------------
# Scan logic
# ---------------------------------------------------------------------------

async def run_guardian_scan(
    db: Session,
    tenant_id: str = "dev-tenant",
) -> GuardianScanResult:
    """Aggregate system exposures and return structured results."""
    risks: list[ScanRisk] = []
    suggestions: list[HardeningSuggestion] = []
    now = datetime.now(timezone.utc)
    total_checks = 0

    # 1. Check stale/outdated agents
    total_checks += 1
    agents = db.query(AgentNodeRow).all()
    stale_cutoff = now - timedelta(minutes=10)
    stale_agents = [
        a for a in agents
        if a.status == "active" and a.last_seen_at and a.last_seen_at < stale_cutoff
    ]
    if stale_agents:
        risks.append(ScanRisk(
            id="stale-agents",
            title=f"{len(stale_agents)} agent(s) may be offline",
            description=(
                f"These agents are marked active but haven't reported in >10 minutes: "
                f"{', '.join(a.hostname for a in stale_agents[:5])}"
            ),
            severity="high",
            affected_agents=[a.hostname for a in stale_agents],
            suggested_fix="Check agent connectivity and restart if needed.",
        ))

    # 2. Check for repeated secret access attempts
    total_checks += 1
    secret_cutoff = now - timedelta(hours=24)
    secret_events = (
        db.query(EventRow)
        .filter(
            EventRow.timestamp >= secret_cutoff,
            EventRow.type.like("%secret%"),
        )
        .all()
    )
    # Also check events with accesses_secrets in details
    all_recent = db.query(EventRow).filter(EventRow.timestamp >= secret_cutoff).all()
    secret_access_events = [
        e for e in all_recent
        if (e.details or {}).get("accesses_secrets") is True
    ]
    total_secret = len(secret_events) + len(secret_access_events)
    if total_secret > 0:
        risks.append(ScanRisk(
            id="secret-access-attempts",
            title=f"{total_secret} secret access attempt(s) in last 24h",
            description="AI agents or tools attempted to access secrets. All were blocked.",
            severity="critical" if total_secret >= 5 else "high",
            affected_agents=list({e.agent_id[:8] for e in secret_access_events}),
            suggested_fix="Review which tools are triggering secret access flags.",
        ))
        suggestions.append(HardeningSuggestion(
            action="review_secret_access",
            description="Review secret access events and add targeted allowlist rules if needed.",
        ))

    # 3. Check auth configuration
    total_checks += 1
    from cloud.auth.config import AUTH_ENABLED, ADMIN_PASSWORD
    if not AUTH_ENABLED:
        risks.append(ScanRisk(
            id="auth-disabled",
            title="Authentication is disabled",
            description="The Cloud API has no authentication. Anyone with network access can read and modify data.",
            severity="critical",
            suggested_fix="Set ANGELCLAW_AUTH_ENABLED=true and configure admin credentials.",
        ))
        suggestions.append(HardeningSuggestion(
            action="enable_auth",
            description="Enable authentication: set ANGELCLAW_AUTH_ENABLED=true in your environment.",
        ))
    elif not ADMIN_PASSWORD:
        risks.append(ScanRisk(
            id="no-admin-password",
            title="No admin password configured",
            description="Auth is enabled but ANGELCLAW_ADMIN_PASSWORD is empty.",
            severity="critical",
            suggested_fix="Set ANGELCLAW_ADMIN_PASSWORD to a strong password.",
        ))

    # 4. Check binding configuration (public exposure without auth)
    total_checks += 1
    bind_host = os.environ.get("ANGELCLAW_BIND_HOST", "127.0.0.1")
    if bind_host == "0.0.0.0" and not AUTH_ENABLED:
        risks.append(ScanRisk(
            id="public-no-auth",
            title="Public exposure without authentication",
            description="The API is bound to 0.0.0.0 (all interfaces) with auth disabled.",
            severity="critical",
            suggested_fix="Either bind to 127.0.0.1 or enable authentication.",
        ))

    # 5. Check for high-severity event spikes
    total_checks += 1
    hour_cutoff = now - timedelta(hours=1)
    recent_critical = (
        db.query(EventRow)
        .filter(
            EventRow.timestamp >= hour_cutoff,
            EventRow.severity.in_(["critical", "high"]),
        )
        .count()
    )
    if recent_critical >= 10:
        risks.append(ScanRisk(
            id="severity-spike",
            title=f"{recent_critical} high/critical events in the last hour",
            description="Unusually high number of severe events detected.",
            severity="high",
            suggested_fix="Review recent events and consider tightening policy rules.",
        ))
        suggestions.append(HardeningSuggestion(
            action="tighten_policy_rule",
            scope="all_agents",
            description="Use 'propose policy improvements' to get targeted rule suggestions.",
        ))

    # 6. Check for no agents registered
    total_checks += 1
    if not agents:
        risks.append(ScanRisk(
            id="no-agents",
            title="No agents registered",
            description="No ANGELNODEs are connected. The system has nothing to protect.",
            severity="medium",
            suggested_fix="Deploy an ANGELNODE agent and configure ANGELCLAW_CLOUD_URL.",
        ))

    # 7. Check webhook not configured
    total_checks += 1
    webhook_url = os.environ.get("ANGELCLAW_WEBHOOK_URL", "")
    if not webhook_url:
        risks.append(ScanRisk(
            id="no-webhook",
            title="No webhook/SIEM integration configured",
            description="Critical alerts are only visible in the dashboard. Configure a webhook for external alerting.",
            severity="low",
            suggested_fix="Set ANGELCLAW_WEBHOOK_URL to receive alerts via webhook.",
        ))

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    risks.sort(key=lambda r: sev_order.get(r.severity, 4))

    critical_count = sum(1 for r in risks if r.severity == "critical")
    high_count = sum(1 for r in risks if r.severity == "high")

    summary = (
        f"Scanned {total_checks} checks. "
        f"Found {len(risks)} risk(s): {critical_count} critical, {high_count} high."
    )

    return GuardianScanResult(
        top_risks=risks[:10],
        hardening_suggestions=suggestions,
        scanned_at=now,
        total_checks=total_checks,
        summary=summary,
    )
