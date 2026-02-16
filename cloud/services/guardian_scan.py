"""AngelClaw AGI Guardian – Guardian Scan Service.

Aggregates system exposures and returns structured risk assessments
with hardening suggestions. Includes ClawSec-inspired threat categories:
  - Prompt injection risk
  - Data leakage risk
  - Tool & supply-chain risk
  - Session & memory risk
  - Lethal Trifecta assessment
  - Evil AGI / CLAW BOT detection
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

    # ---- ClawSec-inspired threat checks ----

    # 8. Prompt injection risk (check recent events for injection patterns)
    total_checks += 1
    try:
        from cloud.angelclaw.shield import shield, ThreatCategory
        injection_events = [
            e for e in all_recent
            if (e.details or {}).get("prompt_injection")
            or "injection" in str(e.details or {}).lower()
        ]
        if injection_events:
            risks.append(ScanRisk(
                id="prompt-injection-risk",
                title=f"{len(injection_events)} prompt injection indicator(s)",
                description="Events flagged as potential prompt injection attempts in the last 24h.",
                severity="high" if len(injection_events) >= 3 else "medium",
                affected_agents=list({e.agent_id[:8] for e in injection_events}),
                suggested_fix="Review flagged events. AngelClaw shield blocks injections automatically.",
            ))
    except Exception:
        pass

    # 9. Data leakage risk (outbound data transfer events)
    total_checks += 1
    leakage_events = [
        e for e in all_recent
        if e.category == "network"
        and e.severity in ("critical", "high")
        and any(k in str(e.details or {}).lower() for k in ["exfil", "upload", "post", "transfer"])
    ]
    if leakage_events:
        risks.append(ScanRisk(
            id="data-leakage-risk",
            title=f"{len(leakage_events)} potential data leakage event(s)",
            description="High-severity network events with data transfer indicators detected.",
            severity="critical" if len(leakage_events) >= 3 else "high",
            affected_agents=list({e.agent_id[:8] for e in leakage_events}),
            suggested_fix="Review outbound network events. Consider restricting agent network access.",
        ))

    # 10. Tool/supply-chain risk
    total_checks += 1
    try:
        from cloud.angelclaw.shield import shield as _shield
        skills_status = _shield.get_status()
        if skills_status.get("skills_registered", 0) > 0:
            from cloud.angelclaw.shield import verify_all_skills
            integrity = verify_all_skills()
            if integrity.get("drifted", 0) > 0:
                risks.append(ScanRisk(
                    id="supply-chain-drift",
                    title=f"{integrity['drifted']} module(s) modified since registration",
                    description="AngelClaw core modules have been modified. Verify changes are authorized.",
                    severity="high",
                    suggested_fix="Re-register skills after legitimate updates with 'shield verify'.",
                ))
    except Exception:
        pass

    # 11. Session/memory risk (context flooding, large payloads)
    total_checks += 1
    memory_risk_events = [
        e for e in all_recent
        if (e.details or {}).get("payload_size_bytes", 0) > 500000
        or "context" in str(e.details or {}).lower() and "overflow" in str(e.details or {}).lower()
    ]
    if memory_risk_events:
        risks.append(ScanRisk(
            id="session-memory-risk",
            title=f"{len(memory_risk_events)} session/memory risk event(s)",
            description="Large payloads or context manipulation patterns detected.",
            severity="medium",
            affected_agents=list({e.agent_id[:8] for e in memory_risk_events}),
            suggested_fix="Review agent context window sizes. Limit payload sizes in policy.",
        ))

    # 12. Lethal Trifecta assessment
    total_checks += 1
    try:
        from cloud.angelclaw.shield import assess_lethal_trifecta
        event_dicts = [
            {
                "category": e.category, "type": e.type,
                "details": e.details or {}, "severity": e.severity,
            }
            for e in all_recent[:200]
        ]
        trifecta = assess_lethal_trifecta(event_dicts)
        if trifecta.active:
            risks.append(ScanRisk(
                id="lethal-trifecta",
                title="Lethal Trifecta ACTIVE",
                description=(
                    "All 3 pillars present: private data access + untrusted content + "
                    "external communication. Maximum attack surface for data exfiltration."
                ),
                severity="critical",
                suggested_fix="Restrict external comms for agents with private data access.",
            ))
        elif trifecta.score > 0.3:
            risks.append(ScanRisk(
                id="lethal-trifecta-partial",
                title=f"Partial Lethal Trifecta ({int(trifecta.score * 100)}%)",
                description="Multiple trifecta pillars detected. Monitoring for escalation.",
                severity="medium",
                suggested_fix="Review agent permissions to minimize trifecta exposure.",
            ))
    except Exception:
        pass

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
        top_risks=risks[:15],
        hardening_suggestions=suggestions,
        scanned_at=now,
        total_checks=total_checks,
        summary=summary,
    )
