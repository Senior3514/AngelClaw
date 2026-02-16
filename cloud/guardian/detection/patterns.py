"""AngelClaw – Pattern-based threat detection.

Matches incoming events against a library of known-dangerous patterns.
Each pattern returns a ThreatIndicator when triggered.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from cloud.db.models import EventRow
from cloud.guardian.models import MitreTactic, ThreatIndicator

logger = logging.getLogger("angelgrid.cloud.guardian.detection.patterns")


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

class PatternDetector:
    """Stateless pattern matcher run against event batches or windows."""

    def detect(
        self,
        events: list[EventRow],
        window_seconds: int = 300,
    ) -> list[ThreatIndicator]:
        """Run all pattern checks and return indicators found."""
        indicators: list[ThreatIndicator] = []
        if not events:
            return indicators

        indicators.extend(self._check_repeated_secret_exfil(events))
        indicators.extend(self._check_high_severity_burst(events))
        indicators.extend(self._check_credential_stuffing(events, window_seconds))
        indicators.extend(self._check_data_staging(events, window_seconds))
        indicators.extend(self._check_privilege_chain(events, window_seconds))
        indicators.extend(self._check_lateral_movement(events, window_seconds))
        indicators.extend(self._check_policy_tampering(events))

        for ind in indicators:
            logger.info(
                "[PATTERN] %s | severity=%s confidence=%.2f | %s",
                ind.pattern_name, ind.severity, ind.confidence, ind.description,
            )
        return indicators

    # ---------------------------------------------------------------
    # Individual patterns
    # ---------------------------------------------------------------

    def _check_repeated_secret_exfil(
        self, events: list[EventRow],
    ) -> list[ThreatIndicator]:
        """>=2 secret-access events in a batch → critical."""
        secret_events = [
            e for e in events
            if (e.details or {}).get("accesses_secrets") is True
        ]
        if len(secret_events) < 2:
            return []
        agents = list({e.agent_id for e in secret_events})
        return [ThreatIndicator(
            indicator_type="pattern_match",
            pattern_name="repeated_secret_exfil",
            severity="critical",
            confidence=0.95,
            description=(
                f"Repeated secret access: {len(secret_events)} events "
                f"from {len(agents)} agent(s)"
            ),
            related_event_ids=[e.id for e in secret_events],
            related_agent_ids=agents,
            suggested_playbook="quarantine_agent",
            mitre_tactic=MitreTactic.CREDENTIAL_ACCESS.value,
        )]

    def _check_high_severity_burst(
        self, events: list[EventRow],
    ) -> list[ThreatIndicator]:
        """>=5 high/critical events from one agent → high."""
        agent_counts: Counter[str] = Counter()
        agent_events: dict[str, list[EventRow]] = defaultdict(list)
        for e in events:
            if e.severity in ("high", "critical"):
                agent_counts[e.agent_id] += 1
                agent_events[e.agent_id].append(e)

        indicators = []
        for agent_id, count in agent_counts.items():
            if count >= 5:
                evts = agent_events[agent_id]
                indicators.append(ThreatIndicator(
                    indicator_type="pattern_match",
                    pattern_name="high_severity_burst",
                    severity="high",
                    confidence=0.85,
                    description=(
                        f"Severity burst: {count} high/critical events "
                        f"from agent {agent_id[:8]}"
                    ),
                    related_event_ids=[e.id for e in evts],
                    related_agent_ids=[agent_id],
                    suggested_playbook="throttle_agent",
                    mitre_tactic=MitreTactic.IMPACT.value,
                ))
        return indicators

    def _check_credential_stuffing(
        self, events: list[EventRow], window_seconds: int,
    ) -> list[ThreatIndicator]:
        """>5 failed auth attempts from same source in window → high."""
        auth_failures: dict[str, list[EventRow]] = defaultdict(list)
        for e in events:
            if e.type and "auth" in e.type.lower() and e.severity in ("high", "critical"):
                source = (e.details or {}).get("source", e.agent_id)
                auth_failures[source].append(e)

        indicators = []
        for source, evts in auth_failures.items():
            if len(evts) >= 5:
                indicators.append(ThreatIndicator(
                    indicator_type="pattern_match",
                    pattern_name="credential_stuffing",
                    severity="high",
                    confidence=0.80,
                    description=(
                        f"Credential stuffing: {len(evts)} auth failures "
                        f"from source {source[:16]}"
                    ),
                    related_event_ids=[e.id for e in evts],
                    related_agent_ids=list({e.agent_id for e in evts}),
                    suggested_playbook="block_source",
                    mitre_tactic=MitreTactic.CREDENTIAL_ACCESS.value,
                ))
        return indicators

    def _check_data_staging(
        self, events: list[EventRow], window_seconds: int,
    ) -> list[ThreatIndicator]:
        """Large file write followed by network upload within window → critical."""
        per_agent: dict[str, list[EventRow]] = defaultdict(list)
        for e in events:
            per_agent[e.agent_id].append(e)

        indicators = []
        for agent_id, agent_events in per_agent.items():
            sorted_events = sorted(agent_events, key=lambda e: e.timestamp)
            file_writes = [
                e for e in sorted_events
                if e.type and "file" in e.type.lower()
                and e.severity in ("high", "critical")
            ]
            net_uploads = [
                e for e in sorted_events
                if e.type and "network" in e.type.lower()
                and (e.details or {}).get("payload_size_bytes", 0) > 500_000
            ]
            for fw in file_writes:
                for nu in net_uploads:
                    delta = (nu.timestamp - fw.timestamp).total_seconds()
                    if 0 < delta <= window_seconds:
                        indicators.append(ThreatIndicator(
                            indicator_type="pattern_match",
                            pattern_name="data_staging",
                            severity="critical",
                            confidence=0.75,
                            description=(
                                f"Data staging: file write then network upload "
                                f"within {int(delta)}s from agent {agent_id[:8]}"
                            ),
                            related_event_ids=[fw.id, nu.id],
                            related_agent_ids=[agent_id],
                            suggested_playbook="quarantine_agent",
                            mitre_tactic=MitreTactic.EXFILTRATION.value,
                        ))
                        break  # one indicator per agent
                else:
                    continue
                break
        return indicators

    def _check_privilege_chain(
        self, events: list[EventRow], window_seconds: int,
    ) -> list[ThreatIndicator]:
        """auth → file → shell from same agent in sequence → high."""
        per_agent: dict[str, list[EventRow]] = defaultdict(list)
        for e in events:
            if e.type and any(k in (e.type or "").lower() for k in ("auth", "file", "shell")):
                per_agent[e.agent_id].append(e)

        indicators = []
        for agent_id, agent_events in per_agent.items():
            sorted_events = sorted(agent_events, key=lambda e: e.timestamp)
            categories_seen: list[str] = []
            for e in sorted_events:
                cat = "auth" if "auth" in (e.type or "").lower() else \
                      "file" if "file" in (e.type or "").lower() else "shell"
                if not categories_seen or categories_seen[-1] != cat:
                    categories_seen.append(cat)

            if len(categories_seen) >= 3:
                chain_str = " → ".join(categories_seen[:5])
                indicators.append(ThreatIndicator(
                    indicator_type="pattern_match",
                    pattern_name="privilege_chain",
                    severity="high",
                    confidence=0.70,
                    description=(
                        f"Privilege chain: {chain_str} from agent {agent_id[:8]}"
                    ),
                    related_event_ids=[e.id for e in sorted_events[:10]],
                    related_agent_ids=[agent_id],
                    suggested_playbook="escalate_to_human",
                    mitre_tactic=MitreTactic.PRIVILEGE_ESCALATION.value,
                ))
        return indicators

    def _check_lateral_movement(
        self, events: list[EventRow], window_seconds: int,
    ) -> list[ThreatIndicator]:
        """AI tool calls targeting multiple agents rapidly → high."""
        ai_events = [
            e for e in events
            if e.type and "ai" in (e.type or "").lower()
        ]
        if len(ai_events) < 3:
            return []

        # Group by source agent, check targets
        source_targets: dict[str, set[str]] = defaultdict(set)
        source_events: dict[str, list[str]] = defaultdict(list)
        for e in ai_events:
            source = (e.details or {}).get("source_agent", e.agent_id)
            target = (e.details or {}).get("target_agent", "")
            if target and target != source:
                source_targets[source].add(target)
                source_events[source].append(e.id)

        indicators = []
        for source, targets in source_targets.items():
            if len(targets) >= 3:
                indicators.append(ThreatIndicator(
                    indicator_type="pattern_match",
                    pattern_name="lateral_movement",
                    severity="high",
                    confidence=0.70,
                    description=(
                        f"Lateral movement: agent {source[:8]} targeted "
                        f"{len(targets)} other agents via AI tool calls"
                    ),
                    related_event_ids=source_events[source][:10],
                    related_agent_ids=[source] + list(targets)[:5],
                    suggested_playbook="quarantine_agent",
                    mitre_tactic=MitreTactic.LATERAL_MOVEMENT.value,
                ))
        return indicators

    def _check_policy_tampering(
        self, events: list[EventRow],
    ) -> list[ThreatIndicator]:
        """Attempts to modify policy files or disable rules → critical."""
        tampering = [
            e for e in events
            if e.type and any(k in (e.type or "").lower() for k in ("policy", "config"))
            and e.severity in ("high", "critical")
        ]
        if not tampering:
            return []

        return [ThreatIndicator(
            indicator_type="pattern_match",
            pattern_name="policy_tampering",
            severity="critical",
            confidence=0.90,
            description=(
                f"Policy tampering: {len(tampering)} suspicious policy/config "
                f"modification attempt(s)"
            ),
            related_event_ids=[e.id for e in tampering],
            related_agent_ids=list({e.agent_id for e in tampering}),
            suggested_playbook="escalate_to_human",
            mitre_tactic=MitreTactic.PERSISTENCE.value,
        )]


# Module-level singleton
pattern_detector = PatternDetector()
