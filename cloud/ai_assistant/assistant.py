"""AngelClaw AI – Security Assistant core logic.

Provides structured analysis functions that query the Cloud database and
return deterministic, auditable results.  No external LLM is used; all
logic is rule-based against stored events and incidents.

SECURITY NOTE: This module is strictly read-only against the database.
It queries data and returns analysis objects.  It MUST NOT modify any
database state — no inserts, updates, or deletes.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from cloud.db.models import AgentNodeRow, EventRow, IncidentRow

from .models import (
    AffectedAgent,
    ClassificationCount,
    IncidentSummary,
    ProposedPolicyChanges,
    ProposedRule,
    SeverityCount,
)

logger = logging.getLogger("angelgrid.ai_assistant")

# How far back to look for "recent" data
DEFAULT_LOOKBACK_HOURS = 24


def summarize_recent_incidents(
    db: Session,
    tenant_id: str,
    lookback_hours: int = DEFAULT_LOOKBACK_HOURS,
) -> IncidentSummary:
    """Summarize recent incidents for a tenant.

    Queries the incident and agent tables, aggregates by classification
    and severity, identifies the most-affected agents, and generates
    deterministic recommendations based on patterns.

    This function is strictly read-only.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

    # Fetch recent incidents
    incidents = db.query(IncidentRow).filter(IncidentRow.created_at >= cutoff).all()

    if not incidents:
        return IncidentSummary(
            tenant_id=tenant_id,
            period_start=cutoff,
            period_end=datetime.now(timezone.utc),
            total_incidents=0,
            recommended_focus=["No incidents in the lookback period — review is up to date."],
        )

    # Aggregate by classification
    classification_counter: Counter[str] = Counter()
    severity_counter: Counter[str] = Counter()
    agent_counter: Counter[str] = Counter()

    for inc in incidents:
        classification_counter[inc.classification] += 1
        severity_counter[inc.severity] += 1
        # Count affected agents via event IDs (stored as JSON list)
        for eid in inc.event_ids or []:
            event_row = db.query(EventRow).filter_by(id=eid).first()
            if event_row:
                agent_counter[event_row.agent_id] += 1

    # Build top affected agents with hostname lookup
    top_agents: list[AffectedAgent] = []
    for agent_id, count in agent_counter.most_common(5):
        agent_row = db.query(AgentNodeRow).filter_by(id=agent_id).first()
        top_agents.append(
            AffectedAgent(
                agent_id=agent_id,
                hostname=agent_row.hostname if agent_row else "unknown",
                incident_count=count,
            )
        )

    # Generate recommendations based on patterns
    recommendations = _generate_recommendations(classification_counter, severity_counter)

    return IncidentSummary(
        tenant_id=tenant_id,
        period_start=cutoff,
        period_end=datetime.now(timezone.utc),
        total_incidents=len(incidents),
        by_classification=[
            ClassificationCount(classification=c, count=n)
            for c, n in classification_counter.most_common()
        ],
        by_severity=[SeverityCount(severity=s, count=n) for s, n in severity_counter.most_common()],
        top_affected_agents=top_agents,
        recommended_focus=recommendations,
    )


def propose_policy_tightening(
    db: Session,
    agent_group_id: str,
    lookback_hours: int = DEFAULT_LOOKBACK_HOURS,
) -> ProposedPolicyChanges:
    """Analyze recent events for an agent group and propose policy tightening.

    Looks at block/alert events, identifies recurring patterns that lack
    explicit rules, and proposes new rules to close gaps.

    SECURITY NOTE: This function returns proposals only.  It does NOT
    modify the PolicySet or any database state.  Proposals must go
    through explicit human approval before being applied.

    This function is strictly read-only.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

    # Fetch recent high-severity events for agents in this group
    # For the MVP, agent_group_id maps to a tag on AgentNodeRow
    agents = db.query(AgentNodeRow).filter(AgentNodeRow.tags.contains(agent_group_id)).all()
    agent_ids = {a.id for a in agents}

    if not agent_ids:
        return ProposedPolicyChanges(
            agent_group_id=agent_group_id,
            analysis_summary=f"No agents found with group tag '{agent_group_id}'.",
        )

    events = (
        db.query(EventRow)
        .filter(
            EventRow.agent_id.in_(agent_ids),
            EventRow.timestamp >= cutoff,
            EventRow.severity.in_(["warn", "high", "critical"]),
        )
        .all()
    )

    if not events:
        return ProposedPolicyChanges(
            agent_group_id=agent_group_id,
            analysis_summary=(
                "No high-severity events in the lookback period."
                " Current policy appears adequate."
            ),
        )

    # Analyze patterns: group by category + type
    pattern_counter: Counter[tuple[str, str]] = Counter()
    for ev in events:
        pattern_counter[(ev.category, ev.type)] += 1

    proposed_rules: list[ProposedRule] = []
    for (category, ev_type), count in pattern_counter.most_common(10):
        # Only propose rules for patterns that recur
        if count < 2:
            continue
        proposed_rules.append(
            ProposedRule(
                description=f"Tighten policy for {category}/{ev_type} events (seen {count}x)",
                match_summary=f"category={category}, type={ev_type}",
                action="block" if count >= 5 else "alert",
                risk_level="high" if count >= 5 else "medium",
                rationale=(
                    f"Observed {count} high-severity events of"
                    f" type '{ev_type}' in category"
                    f" '{category}' within the last"
                    f" {lookback_hours}h. "
                    + (
                        "Recommend blocking — pattern is persistent."
                        if count >= 5
                        else "Recommend alerting for further"
                        " investigation."
                    )
                ),
            )
        )

    return ProposedPolicyChanges(
        agent_group_id=agent_group_id,
        proposed_rules=proposed_rules,
        analysis_summary=(
            f"Analyzed {len(events)} high-severity events across {len(agent_ids)} agents. "
            f"Identified {len(proposed_rules)} recurring patterns"
            f" that could benefit from explicit rules."
        ),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def explain_event_with_context(
    db: Session,
    event_id: str,
) -> dict:
    """Return event explanation with surrounding context window.

    Helper used by the Guardian Chat and event_context endpoint.
    This function is strictly read-only.
    """
    from datetime import timedelta

    from shared.security.secret_scanner import redact_dict, redact_secrets

    event_row = db.query(EventRow).filter_by(id=event_id).first()
    if not event_row:
        return {"error": f"Event '{event_id}' not found"}

    # Build explanation via policy engine
    explanation = f"Event {event_row.category}/{event_row.type} with severity {event_row.severity}"
    try:
        from pathlib import Path

        from angelnode.core.engine import PolicyEngine
        from shared.models.event import Event, EventCategory, Severity

        event = Event(
            id=event_row.id,
            agent_id=event_row.agent_id,
            timestamp=event_row.timestamp,
            category=EventCategory(event_row.category),
            type=event_row.type,
            severity=Severity(event_row.severity),
            details=event_row.details or {},
            source=event_row.source,
        )
        policy_path = (
            Path(__file__).resolve().parent.parent.parent
            / "angelnode"
            / "config"
            / "default_policy.json"
        )
        if policy_path.exists():
            engine = PolicyEngine.from_file(policy_path)
            decision = engine.evaluate(event)
            explanation = (
                f"Action: {decision.action.value.upper()}. "
                f"Reason: {decision.reason}. "
                f"Risk level: {decision.risk_level.value}."
            )
    except Exception:
        pass

    # Context window
    window_start = event_row.timestamp - timedelta(minutes=5)
    window_end = event_row.timestamp + timedelta(minutes=5)
    history = (
        db.query(EventRow)
        .filter(
            EventRow.agent_id == event_row.agent_id,
            EventRow.timestamp >= window_start,
            EventRow.timestamp <= window_end,
            EventRow.id != event_row.id,
        )
        .order_by(EventRow.timestamp.asc())
        .limit(20)
        .all()
    )

    return {
        "event_id": event_row.id,
        "category": event_row.category,
        "type": event_row.type,
        "severity": event_row.severity,
        "explanation": redact_secrets(explanation),
        "details": redact_dict(event_row.details) if event_row.details else {},
        "context_window": [
            {
                "id": h.id,
                "category": h.category,
                "type": h.type,
                "severity": h.severity,
                "timestamp": h.timestamp.isoformat(),
            }
            for h in history
        ],
    }


def _generate_recommendations(
    classifications: Counter[str],
    severities: Counter[str],
) -> list[str]:
    """Generate human-readable, solution-oriented recommendations.

    AngelClaw philosophy: guardian angel, not gatekeeper.  Recommendations
    should help users stay safe while continuing to use AI freely.  Focus
    on targeted fixes, not broad restrictions.
    """
    recommendations: list[str] = []

    critical_count = severities.get("critical", 0)
    high_count = severities.get("high", 0)

    if critical_count > 0:
        recommendations.append(
            f"{critical_count} CRITICAL incident(s) detected — worth a quick look to make sure "
            "nothing slipped through. AngelClaw blocked the dangerous actions automatically."
        )

    if classifications.get("prompt_injection", 0) > 0:
        recommendations.append(
            "Prompt injection attempts were caught and blocked. Your AI agents are safe to keep "
            "using — consider adding input-validation rules for the specific patterns detected."
        )

    if classifications.get("data_exfiltration", 0) > 0:
        recommendations.append(
            "Potential data exfiltration was flagged. If your AI agents need to call"
            " external APIs, add those domains to the network egress allowlist so"
            " legitimate traffic flows freely."
        )

    if classifications.get("malicious_tool_use", 0) > 0:
        recommendations.append(
            "Some tool calls were flagged as risky. Review the specific tools"
            " involved — if they're safe for your workflow, add them to the AI"
            " tool allowlist so your agents aren't slowed down."
        )

    if high_count > 3:
        recommendations.append(
            f"{high_count} HIGH severity events were caught. You can use the /propose endpoint "
            "to get targeted rule suggestions that close the gaps without blocking legitimate work."
        )

    if not recommendations:
        recommendations.append(
            "Everything looks good — your AI agents are running freely and AngelClaw is quietly "
            "watching in the background. No action needed."
        )

    return recommendations
