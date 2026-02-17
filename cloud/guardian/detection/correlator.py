"""AngelClaw – Cross-event / cross-agent correlation engine.

Links related events into chains that may represent multi-step attacks
(kill chains).  Tags chains with MITRE ATT&CK tactics.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from cloud.db.models import EventRow
from cloud.guardian.models import CorrelationChain, MitreTactic, ThreatIndicator

logger = logging.getLogger("angelgrid.cloud.guardian.detection.correlator")

# Map event characteristics to MITRE tactics
_TACTIC_HINTS: dict[str, str] = {
    "auth": MitreTactic.INITIAL_ACCESS.value,
    "login": MitreTactic.INITIAL_ACCESS.value,
    "scan": MitreTactic.RECONNAISSANCE.value,
    "recon": MitreTactic.RECONNAISSANCE.value,
    "shell": MitreTactic.EXECUTION.value,
    "exec": MitreTactic.EXECUTION.value,
    "command": MitreTactic.EXECUTION.value,
    "file": MitreTactic.PERSISTENCE.value,
    "write": MitreTactic.PERSISTENCE.value,
    "chmod": MitreTactic.PRIVILEGE_ESCALATION.value,
    "sudo": MitreTactic.PRIVILEGE_ESCALATION.value,
    "passwd": MitreTactic.PRIVILEGE_ESCALATION.value,
    "secret": MitreTactic.CREDENTIAL_ACCESS.value,
    "credential": MitreTactic.CREDENTIAL_ACCESS.value,
    "token": MitreTactic.CREDENTIAL_ACCESS.value,
    "network": MitreTactic.EXFILTRATION.value,
    "upload": MitreTactic.EXFILTRATION.value,
    "post": MitreTactic.EXFILTRATION.value,
    "delete": MitreTactic.IMPACT.value,
    "destroy": MitreTactic.IMPACT.value,
    "drop": MitreTactic.IMPACT.value,
}


def _infer_tactic(event: EventRow) -> str | None:
    """Infer a MITRE tactic from event type and details."""
    event_type = (event.type or "").lower()
    for hint, tactic in _TACTIC_HINTS.items():
        if hint in event_type:
            return tactic
    return None


class CorrelationEngine:
    """Correlates events across agents and time windows into attack chains."""

    def __init__(self, max_chain_gap_seconds: int = 300) -> None:
        self.max_chain_gap = max_chain_gap_seconds

    def correlate(
        self,
        events: list[EventRow],
    ) -> list[CorrelationChain]:
        """Find correlation chains in a set of events.

        Groups events by agent, then links sequential high-severity events
        into chains where each step maps to a different MITRE tactic.
        """
        if len(events) < 2:
            return []

        # Group by agent
        per_agent: dict[str, list[EventRow]] = defaultdict(list)
        for e in events:
            per_agent[e.agent_id].append(e)

        chains: list[CorrelationChain] = []

        for agent_id, agent_events in per_agent.items():
            agent_chains = self._build_agent_chains(agent_id, agent_events)
            chains.extend(agent_chains)

        # Also check cross-agent chains (same source/tool)
        cross_chains = self._build_cross_agent_chains(events)
        chains.extend(cross_chains)

        # Filter: only keep chains with >=2 distinct tactics
        significant = [c for c in chains if len(set(c.tactics)) >= 2]

        for c in significant:
            logger.info(
                "[CORRELATION] chain=%s agents=%s tactics=%s events=%d",
                c.chain_id[:8],
                c.agent_ids[:3],
                c.tactics,
                len(c.event_ids),
            )

        return significant

    def _build_agent_chains(
        self,
        agent_id: str,
        events: list[EventRow],
    ) -> list[CorrelationChain]:
        """Build chains from a single agent's events."""
        # Only consider medium+ severity
        relevant = [e for e in events if e.severity in ("medium", "high", "critical")]
        if len(relevant) < 2:
            return []

        sorted_events = sorted(relevant, key=lambda e: e.timestamp)
        chains: list[CorrelationChain] = []
        current_chain_events: list[EventRow] = [sorted_events[0]]
        current_tactics: list[str] = []

        tactic = _infer_tactic(sorted_events[0])
        if tactic:
            current_tactics.append(tactic)

        for i in range(1, len(sorted_events)):
            prev = sorted_events[i - 1]
            curr = sorted_events[i]
            gap = (curr.timestamp - prev.timestamp).total_seconds()

            tactic = _infer_tactic(curr)

            if gap <= self.max_chain_gap:
                current_chain_events.append(curr)
                if tactic and (not current_tactics or current_tactics[-1] != tactic):
                    current_tactics.append(tactic)
            else:
                # Gap too large — close current chain
                if len(current_chain_events) >= 2 and len(set(current_tactics)) >= 2:
                    chains.append(
                        self._make_chain(
                            current_chain_events,
                            [agent_id],
                            current_tactics,
                        )
                    )
                current_chain_events = [curr]
                current_tactics = [tactic] if tactic else []

        # Close last chain
        if len(current_chain_events) >= 2 and len(set(current_tactics)) >= 2:
            chains.append(
                self._make_chain(
                    current_chain_events,
                    [agent_id],
                    current_tactics,
                )
            )

        return chains

    def _build_cross_agent_chains(
        self,
        events: list[EventRow],
    ) -> list[CorrelationChain]:
        """Detect coordinated activity across multiple agents.

        Looks for the same tool or source appearing across agents
        within the time window.
        """
        # Group by tool_name or source
        by_tool: dict[str, list[EventRow]] = defaultdict(list)
        for e in events:
            tool = (e.details or {}).get("tool_name", "")
            if tool:
                by_tool[tool].append(e)

        chains: list[CorrelationChain] = []
        for tool, tool_events in by_tool.items():
            agents = {e.agent_id for e in tool_events}
            if len(agents) < 2:
                continue

            sorted_events = sorted(tool_events, key=lambda e: e.timestamp)
            span = (sorted_events[-1].timestamp - sorted_events[0].timestamp).total_seconds()
            if span > self.max_chain_gap:
                continue

            tactics = []
            for e in sorted_events:
                t = _infer_tactic(e)
                if t and (not tactics or tactics[-1] != t):
                    tactics.append(t)

            if len(agents) >= 2:
                chains.append(
                    self._make_chain(
                        sorted_events,
                        list(agents),
                        tactics,
                    )
                )

        return chains

    @staticmethod
    def _make_chain(
        events: list[EventRow],
        agent_ids: list[str],
        tactics: list[str],
    ) -> CorrelationChain:
        """Create a CorrelationChain from events."""
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        span = (sorted_events[-1].timestamp - sorted_events[0].timestamp).total_seconds()

        # Severity = max severity in chain
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        max_sev = min(
            (e.severity for e in events if e.severity),
            key=lambda s: sev_order.get(s, 4),
            default="medium",
        )

        # Confidence based on number of distinct tactics
        confidence = min(1.0, 0.3 + len(set(tactics)) * 0.15)

        tactic_str = " → ".join(tactics[:6])
        return CorrelationChain(
            event_ids=[e.id for e in sorted_events],
            agent_ids=agent_ids,
            tactics=tactics,
            severity=max_sev,
            confidence=round(confidence, 2),
            description=f"Kill chain: {tactic_str} ({len(events)} events, {span:.0f}s)",
            time_span_seconds=span,
        )

    # ------------------------------------------------------------------
    # Convert chains to threat indicators
    # ------------------------------------------------------------------

    def chains_to_indicators(
        self,
        chains: list[CorrelationChain],
    ) -> list[ThreatIndicator]:
        """Convert significant chains into ThreatIndicators."""
        indicators = []
        for chain in chains:
            indicators.append(
                ThreatIndicator(
                    indicator_type="correlation",
                    pattern_name="kill_chain",
                    severity=chain.severity,
                    confidence=chain.confidence,
                    description=chain.description,
                    related_event_ids=chain.event_ids[:20],
                    related_agent_ids=chain.agent_ids[:10],
                    suggested_playbook="escalate_to_human",
                    mitre_tactic=chain.tactics[-1] if chain.tactics else None,
                    metadata={
                        "chain_id": chain.chain_id,
                        "tactics": chain.tactics,
                        "time_span_seconds": chain.time_span_seconds,
                    },
                )
            )
        return indicators


# Module-level singleton
correlation_engine = CorrelationEngine()
