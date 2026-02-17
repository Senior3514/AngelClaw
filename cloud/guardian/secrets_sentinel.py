"""AngelClaw – Vault Keeper (Secrets Sentinel).

Monitors secret-access events, credential rotation status, and secret
sprawl.  Reuses the shared secret_scanner for pattern detection.
Part of the Angel Legion.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from cloud.guardian.base_agent import SubAgent
from cloud.guardian.models import (
    AgentResult,
    AgentTask,
    AgentType,
    Permission,
    ThreatIndicator,
)

logger = logging.getLogger("angelgrid.cloud.guardian.secrets_sentinel")

# Event types this sentinel cares about
_SECRET_TYPES = frozenset(
    {
        "secret.access",
        "secret.rotation",
        "secret.creation",
        "secret.exposure",
        "secret.exfiltration",
        "auth.token_issued",
        "auth.token_revoked",
        "auth.login_failed",
    }
)

# Thresholds
_ACCESS_BURST_THRESHOLD = 5  # N secret accesses from one agent in one batch = suspicious
_FAILED_AUTH_THRESHOLD = 3   # N failed logins from one agent


class SecretsSentinel(SubAgent):
    """Vault Keeper — watches for secret exposure and credential abuse."""

    def __init__(self) -> None:
        super().__init__(
            agent_type=AgentType.SECRETS,
            permissions={Permission.READ_EVENTS, Permission.READ_SECRETS},
        )

    async def handle_task(self, task: AgentTask) -> AgentResult:
        """Analyze secret-related events.

        Expected payload:
            events: list[dict] — serialized events
            window_seconds: int
        """
        self.require_permission(Permission.READ_SECRETS)

        events_data = task.payload.get("events", [])
        if not events_data:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type.value,
                result_data={"indicators": []},
            )

        # Filter to secret-relevant events
        secret_events = [
            e for e in events_data if e.get("type", "") in _SECRET_TYPES
            or "secret" in e.get("type", "").lower()
            or "credential" in e.get("type", "").lower()
        ]

        indicators: list[ThreatIndicator] = []

        # 1. Detect secret access bursts per agent
        indicators.extend(_detect_access_burst(secret_events))

        # 2. Detect secret exposure in event details
        indicators.extend(_detect_secret_in_payload(events_data))

        # 3. Detect brute-force auth patterns
        indicators.extend(_detect_auth_brute_force(secret_events))

        # 4. Check for exfiltration-typed events
        for event in secret_events:
            if event.get("type") == "secret.exfiltration":
                agent_id = event.get("agent_id", "")
                indicators.append(
                    ThreatIndicator(
                        indicator_type="secret_exposure",
                        pattern_name="secret_exfiltration",
                        severity="critical",
                        confidence=0.95,
                        description=(
                            f"Secret exfiltration detected from agent {agent_id[:8]}"
                        ),
                        related_event_ids=[event.get("id", "")],
                        related_agent_ids=[agent_id] if agent_id else [],
                        suggested_playbook="quarantine_agent",
                        mitre_tactic="exfiltration",
                    )
                )

        logger.info(
            "[VAULT KEEPER] Analyzed %d secret events → %d indicators",
            len(secret_events),
            len(indicators),
        )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            agent_type=self.agent_type.value,
            result_data={
                "indicators": [ind.model_dump(mode="json") for ind in indicators],
                "stats": {
                    "secret_events": len(secret_events),
                    "total_events": len(events_data),
                    "indicators_found": len(indicators),
                },
            },
        )


def _detect_access_burst(events: list[dict]) -> list[ThreatIndicator]:
    """Detect agents accessing many secrets in a short burst."""
    per_agent: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if "access" in e.get("type", "").lower():
            per_agent[e.get("agent_id", "")].append(e)

    indicators: list[ThreatIndicator] = []
    for agent_id, agent_events in per_agent.items():
        if not agent_id or len(agent_events) < _ACCESS_BURST_THRESHOLD:
            continue
        indicators.append(
            ThreatIndicator(
                indicator_type="secret_exposure",
                pattern_name="secret_access_burst",
                severity="high",
                confidence=0.8,
                description=(
                    f"Agent {agent_id[:8]} accessed {len(agent_events)} secrets "
                    f"in rapid succession"
                ),
                related_event_ids=[e.get("id", "") for e in agent_events[:20]],
                related_agent_ids=[agent_id],
                suggested_playbook="throttle_agent",
                mitre_tactic="credential_access",
            )
        )
    return indicators


def _detect_secret_in_payload(events: list[dict]) -> list[ThreatIndicator]:
    """Scan event payloads for raw secrets using the shared scanner."""
    try:
        from shared.security.secret_scanner import scan_text
    except ImportError:
        return []

    indicators: list[ThreatIndicator] = []
    for event in events:
        details = event.get("details", {})
        text = str(details)
        findings = scan_text(text)
        if findings:
            agent_id = event.get("agent_id", "")
            indicators.append(
                ThreatIndicator(
                    indicator_type="secret_exposure",
                    pattern_name="secret_in_payload",
                    severity="critical",
                    confidence=0.9,
                    description=(
                        f"Raw secret detected in event payload from agent "
                        f"{agent_id[:8]}: {len(findings)} pattern(s)"
                    ),
                    related_event_ids=[event.get("id", "")],
                    related_agent_ids=[agent_id] if agent_id else [],
                    suggested_playbook="quarantine_agent",
                    mitre_tactic="credential_access",
                    metadata={"pattern_types": [f["type"] for f in findings[:5]]},
                )
            )
    return indicators


def _detect_auth_brute_force(events: list[dict]) -> list[ThreatIndicator]:
    """Detect brute-force login attempts."""
    per_agent: dict[str, int] = defaultdict(int)
    per_agent_ids: dict[str, list[str]] = defaultdict(list)

    for e in events:
        if e.get("type") == "auth.login_failed":
            agent_id = e.get("agent_id", "")
            per_agent[agent_id] += 1
            per_agent_ids[agent_id].append(e.get("id", ""))

    indicators: list[ThreatIndicator] = []
    for agent_id, count in per_agent.items():
        if not agent_id or count < _FAILED_AUTH_THRESHOLD:
            continue
        indicators.append(
            ThreatIndicator(
                indicator_type="secret_exposure",
                pattern_name="auth_brute_force",
                severity="high",
                confidence=0.85,
                description=(
                    f"Brute-force detected: {count} failed login attempts "
                    f"from agent {agent_id[:8]}"
                ),
                related_event_ids=per_agent_ids[agent_id][:20],
                related_agent_ids=[agent_id],
                suggested_playbook="throttle_agent",
                mitre_tactic="credential_access",
            )
        )
    return indicators
