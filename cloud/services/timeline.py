"""AngelClaw Cloud – Agent Timeline Builder.

Queries events, policy versions, sessions, and AI tool calls for one agent
and returns a sorted chronological timeline with redacted details.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from cloud.api.guardian_models import AgentTimeline, TimelineEntry
from cloud.db.models import EventRow, PolicySetRow
from shared.security.secret_scanner import redact_dict

logger = logging.getLogger("angelgrid.cloud.timeline")


def build_agent_timeline(
    db: Session,
    agent_id: str,
    hours: int = 24,
) -> AgentTimeline:
    """Build a chronological timeline for an agent."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    entries: list[TimelineEntry] = []

    # Events
    events = (
        db.query(EventRow)
        .filter(EventRow.agent_id == agent_id, EventRow.timestamp >= cutoff)
        .order_by(EventRow.timestamp.asc())
        .all()
    )

    for ev in events:
        entry_type = "ai_tool_call" if ev.category == "ai_tool" else "event"
        safe_details = redact_dict(ev.details) if ev.details else {}
        entries.append(
            TimelineEntry(
                timestamp=ev.timestamp,
                entry_type=entry_type,
                summary=f"{ev.category}/{ev.type} — {ev.severity}",
                severity=ev.severity,
                details={
                    "event_id": ev.id,
                    "category": ev.category,
                    "type": ev.type,
                    "source": ev.source,
                    **safe_details,
                },
            )
        )

    # Policy changes (global, not per-agent, but relevant context)
    policies = (
        db.query(PolicySetRow)
        .filter(PolicySetRow.created_at >= cutoff)
        .order_by(PolicySetRow.created_at.asc())
        .all()
    )
    for ps in policies:
        entries.append(
            TimelineEntry(
                timestamp=ps.created_at,
                entry_type="policy_change",
                summary=f"Policy updated: {ps.name} (v{ps.version_hash[:8]})",
                details={
                    "policy_id": ps.id,
                    "version_hash": ps.version_hash,
                    "rule_count": len(ps.rules_json) if ps.rules_json else 0,
                },
            )
        )

    # Detect session boundaries (5-min gap)
    if events:
        prev_ts = events[0].timestamp
        entries.append(
            TimelineEntry(
                timestamp=events[0].timestamp,
                entry_type="session_start",
                summary="Session started",
            )
        )
        for ev in events[1:]:
            gap = (ev.timestamp - prev_ts).total_seconds()
            if gap > 300:
                entries.append(
                    TimelineEntry(
                        timestamp=ev.timestamp,
                        entry_type="session_start",
                        summary=f"New session started (gap: {int(gap)}s)",
                    )
                )
            prev_ts = ev.timestamp

    # Sort all entries chronologically
    entries.sort(key=lambda e: e.timestamp)

    return AgentTimeline(
        agent_id=agent_id,
        hours=hours,
        entries=entries,
        total_events=len(events),
    )
