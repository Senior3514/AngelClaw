"""AngelClaw – Net Warden (Network Sentinel).

Monitors network-related events for exposure, suspicious connections,
DNS anomalies, and topology changes.  Part of the Angel Legion.
"""

from __future__ import annotations

import logging
import re

from cloud.guardian.base_agent import SubAgent
from cloud.guardian.models import (
    AgentResult,
    AgentTask,
    AgentType,
    Permission,
    ThreatIndicator,
)

logger = logging.getLogger("angelgrid.cloud.guardian.network_sentinel")

# Suspicious outbound destinations (private ranges are OK)
_SUSPICIOUS_PORTS = {4444, 5555, 6666, 1337, 31337, 9001, 9050, 9150}

_PRIVATE_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|fd[0-9a-f]{2}:)"
)

# Event types relevant to this sentinel
_NETWORK_TYPES = frozenset(
    {
        "network.connection",
        "network.listen",
        "network.dns",
        "network.outbound",
        "network.inbound",
        "network.port_open",
        "network.topology_change",
    }
)


class NetworkSentinel(SubAgent):
    """Net Warden — watches for network exposure and suspicious connections."""

    def __init__(self) -> None:
        super().__init__(
            agent_type=AgentType.NETWORK,
            permissions={Permission.READ_EVENTS, Permission.READ_AGENTS, Permission.READ_NETWORK},
        )

    async def handle_task(self, task: AgentTask) -> AgentResult:
        """Analyze network events for threats.

        Expected payload:
            events: list[dict] — serialized events
            window_seconds: int
        """
        self.require_permission(Permission.READ_NETWORK)

        events_data = task.payload.get("events", [])
        if not events_data:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type.value,
                result_data={"indicators": []},
            )

        # Filter to network-relevant events
        network_events = [
            e for e in events_data if e.get("type", "") in _NETWORK_TYPES
            or "network" in e.get("type", "").lower()
        ]

        indicators: list[ThreatIndicator] = []

        for event in network_events:
            details = event.get("details", {})
            event_type = event.get("type", "")
            agent_id = event.get("agent_id", "")

            # Check for suspicious outbound ports
            dst_port = details.get("dst_port") or details.get("port")
            if dst_port and int(dst_port) in _SUSPICIOUS_PORTS:
                indicators.append(
                    ThreatIndicator(
                        indicator_type="network_exposure",
                        pattern_name="suspicious_outbound_port",
                        severity="high",
                        confidence=0.8,
                        description=(
                            f"Outbound connection to suspicious port {dst_port} "
                            f"from agent {agent_id[:8]}"
                        ),
                        related_event_ids=[event.get("id", "")],
                        related_agent_ids=[agent_id] if agent_id else [],
                        suggested_playbook="block_source",
                        mitre_tactic="exfiltration",
                    )
                )

            # Check for unexpected public exposure
            if event_type in ("network.listen", "network.port_open"):
                bind_addr = details.get("bind_address", "")
                if bind_addr and not _PRIVATE_RE.match(bind_addr) and bind_addr != "0.0.0.0":
                    indicators.append(
                        ThreatIndicator(
                            indicator_type="network_exposure",
                            pattern_name="public_port_exposure",
                            severity="high",
                            confidence=0.85,
                            description=(
                                f"Service bound to public address {bind_addr} "
                                f"on agent {agent_id[:8]}"
                            ),
                            related_event_ids=[event.get("id", "")],
                            related_agent_ids=[agent_id] if agent_id else [],
                            suggested_playbook="throttle_agent",
                        )
                    )

            # Check for DNS to known-bad patterns
            dns_query = details.get("dns_query", "") or details.get("domain", "")
            if dns_query and _is_suspicious_domain(dns_query):
                indicators.append(
                    ThreatIndicator(
                        indicator_type="network_exposure",
                        pattern_name="suspicious_dns",
                        severity="high",
                        confidence=0.75,
                        description=f"DNS query to suspicious domain: {dns_query}",
                        related_event_ids=[event.get("id", "")],
                        related_agent_ids=[agent_id] if agent_id else [],
                        suggested_playbook="block_source",
                        mitre_tactic="exfiltration",
                    )
                )

        # Check for port scan patterns (many ports from same agent in short time)
        port_scan_indicators = _detect_port_scan(network_events)
        indicators.extend(port_scan_indicators)

        logger.info(
            "[NET WARDEN] Analyzed %d network events → %d indicators",
            len(network_events),
            len(indicators),
        )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            agent_type=self.agent_type.value,
            result_data={
                "indicators": [ind.model_dump(mode="json") for ind in indicators],
                "stats": {
                    "network_events": len(network_events),
                    "total_events": len(events_data),
                    "indicators_found": len(indicators),
                },
            },
        )


def _is_suspicious_domain(domain: str) -> bool:
    """Check if a domain matches suspicious patterns."""
    suspicious_tlds = {".onion", ".bit", ".bazar", ".coin"}
    suspicious_patterns = {"c2.", "beacon.", "exfil.", "callback.", "payload."}
    domain_lower = domain.lower()
    for tld in suspicious_tlds:
        if domain_lower.endswith(tld):
            return True
    for pat in suspicious_patterns:
        if pat in domain_lower:
            return True
    # Very long subdomains often indicate DNS tunneling
    labels = domain_lower.split(".")
    if any(len(label) > 50 for label in labels):
        return True
    return False


def _detect_port_scan(events: list[dict]) -> list[ThreatIndicator]:
    """Detect port scan patterns — many distinct ports from same agent."""
    from collections import defaultdict

    agent_ports: dict[str, set[int]] = defaultdict(set)
    agent_event_ids: dict[str, list[str]] = defaultdict(list)

    for e in events:
        agent_id = e.get("agent_id", "")
        details = e.get("details", {})
        port = details.get("dst_port") or details.get("port")
        if agent_id and port:
            try:
                agent_ports[agent_id].add(int(port))
                agent_event_ids[agent_id].append(e.get("id", ""))
            except (ValueError, TypeError):
                pass

    indicators: list[ThreatIndicator] = []
    for agent_id, ports in agent_ports.items():
        if len(ports) >= 10:
            indicators.append(
                ThreatIndicator(
                    indicator_type="network_exposure",
                    pattern_name="port_scan_detected",
                    severity="critical",
                    confidence=0.9,
                    description=(
                        f"Port scan detected: {len(ports)} distinct ports "
                        f"from agent {agent_id[:8]}"
                    ),
                    related_event_ids=agent_event_ids[agent_id][:20],
                    related_agent_ids=[agent_id],
                    suggested_playbook="quarantine_agent",
                    mitre_tactic="reconnaissance",
                )
            )
    return indicators
