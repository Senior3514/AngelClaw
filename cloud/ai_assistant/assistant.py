"""ANGELGRID AI – Security Assistant core logic.

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
    incidents = (
        db.query(IncidentRow)
        .filter(IncidentRow.created_at >= cutoff)
        .all()
    )

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
        for eid in (inc.event_ids or []):
            event_row = db.query(EventRow).filter_by(id=eid).first()
            if event_row:
                agent_counter[event_row.agent_id] += 1

    # Build top affected agents with hostname lookup
    top_agents: list[AffectedAgent] = []
    for agent_id, count in agent_counter.most_common(5):
        agent_row = db.query(AgentNodeRow).filter_by(id=agent_id).first()
        top_agents.append(AffectedAgent(
            agent_id=agent_id,
            hostname=agent_row.hostname if agent_row else "unknown",
            incident_count=count,
        ))

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
        by_severity=[
            SeverityCount(severity=s, count=n)
            for s, n in severity_counter.most_common()
        ],
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
    agents = db.query(AgentNodeRow).filter(
        AgentNodeRow.tags.contains(agent_group_id)
    ).all()
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
            analysis_summary="No high-severity events in the lookback period. Current policy appears adequate.",
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
        proposed_rules.append(ProposedRule(
            description=f"Tighten policy for {category}/{ev_type} events (seen {count}x)",
            match_summary=f"category={category}, type={ev_type}",
            action="block" if count >= 5 else "alert",
            risk_level="high" if count >= 5 else "medium",
            rationale=(
                f"Observed {count} high-severity events of type '{ev_type}' in category "
                f"'{category}' within the last {lookback_hours}h. "
                f"{'Recommend blocking — pattern is persistent.' if count >= 5 else 'Recommend alerting for further investigation.'}"
            ),
        ))

    return ProposedPolicyChanges(
        agent_group_id=agent_group_id,
        proposed_rules=proposed_rules,
        analysis_summary=(
            f"Analyzed {len(events)} high-severity events across {len(agent_ids)} agents. "
            f"Identified {len(proposed_rules)} recurring patterns that could benefit from explicit rules."
        ),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _generate_recommendations(
    classifications: Counter[str],
    severities: Counter[str],
) -> list[str]:
    """Generate human-readable recommendations from incident patterns."""
    recommendations: list[str] = []

    critical_count = severities.get("critical", 0)
    high_count = severities.get("high", 0)

    if critical_count > 0:
        recommendations.append(
            f"{critical_count} CRITICAL incident(s) detected — immediate investigation required."
        )

    if classifications.get("prompt_injection", 0) > 0:
        recommendations.append(
            "Prompt injection attempts detected — review AI agent input validation and tool restrictions."
        )

    if classifications.get("data_exfiltration", 0) > 0:
        recommendations.append(
            "Potential data exfiltration — audit outbound network rules and restrict external API access."
        )

    if classifications.get("malicious_tool_use", 0) > 0:
        recommendations.append(
            "Malicious tool use incidents — consider tightening AI tool allowlists."
        )

    if high_count > 3:
        recommendations.append(
            f"{high_count} HIGH severity incidents — consider running propose_policy_tightening() for affected agent groups."
        )

    if not recommendations:
        recommendations.append(
            "Incident volume is within normal range. Continue monitoring."
        )

    return recommendations
