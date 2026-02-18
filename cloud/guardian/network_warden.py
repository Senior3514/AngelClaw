"""AngelClaw – Net Warden (Network Warden).

Monitors network-related events for exposure, suspicious connections,
DNS anomalies, and topology changes.  Part of the Angel Legion.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict

from cloud.guardian.base_agent import SubAgent
from cloud.guardian.models import (
    AgentResult,
    AgentTask,
    AgentType,
    Permission,
    ThreatIndicator,
)

logger = logging.getLogger("angelgrid.cloud.guardian.network_warden")

# Suspicious outbound destinations (private ranges are OK)
_SUSPICIOUS_PORTS = {4444, 5555, 6666, 1337, 31337, 9001, 9050, 9150}

_PRIVATE_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|fd[0-9a-f]{2}:)"
)

# Event types relevant to this warden
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


class NetworkWarden(SubAgent):
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

        # V2.1 — expanded network detection
        indicators.extend(_detect_dns_tunneling(network_events))
        indicators.extend(_detect_beaconing(network_events))
        indicators.extend(_detect_tor_connections(network_events))

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


def _detect_dns_tunneling(events: list[dict]) -> list[ThreatIndicator]:
    """V2.1 — Detect DNS tunneling via long labels or high subdomain volume."""
    per_agent_dns: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        details = e.get("details", {})
        dns_query = details.get("dns_query", "") or details.get("domain", "")
        if dns_query:
            per_agent_dns[e.get("agent_id", "")].append(e)

    indicators: list[ThreatIndicator] = []
    for agent_id, dns_events in per_agent_dns.items():
        if not agent_id:
            continue
        long_labels = 0
        unique_subdomains: set[str] = set()
        for e in dns_events:
            details = e.get("details", {})
            domain = details.get("dns_query", "") or details.get("domain", "")
            labels = domain.split(".")
            for label in labels:
                if len(label) > 30:
                    long_labels += 1
            if len(labels) >= 3:
                unique_subdomains.add(labels[0])

        if long_labels >= 3 or len(unique_subdomains) >= 20:
            indicators.append(
                ThreatIndicator(
                    indicator_type="network_exposure",
                    pattern_name="dns_tunneling",
                    severity="critical",
                    confidence=0.85,
                    description=(
                        f"DNS tunneling suspected: agent {agent_id[:8]} — "
                        f"{long_labels} long labels, {len(unique_subdomains)} unique subdomains"
                    ),
                    related_event_ids=[e.get("id", "") for e in dns_events[:20]],
                    related_agent_ids=[agent_id],
                    suggested_playbook="quarantine_agent",
                    mitre_tactic="exfiltration",
                )
            )
    return indicators


def _detect_beaconing(events: list[dict]) -> list[ThreatIndicator]:
    """V2.1 — Detect C2 beaconing via regular-interval connections."""
    from datetime import datetime

    per_agent_dest: dict[str, dict[str, list[datetime]]] = defaultdict(lambda: defaultdict(list))
    for e in events:
        details = e.get("details", {})
        dst = details.get("dst_ip", "") or details.get("destination", "")
        agent_id = e.get("agent_id", "")
        if not dst or not agent_id:
            continue
        ts = e.get("timestamp")
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts)
            except (ValueError, TypeError):
                continue
        elif not isinstance(ts, datetime):
            continue
        per_agent_dest[agent_id][dst].append(ts)

    indicators: list[ThreatIndicator] = []
    for agent_id, dests in per_agent_dest.items():
        for dst, timestamps in dests.items():
            if len(timestamps) < 4:
                continue
            timestamps.sort()
            intervals = [
                (timestamps[i+1] - timestamps[i]).total_seconds()
                for i in range(len(timestamps) - 1)
            ]
            if not intervals:
                continue
            avg_interval = sum(intervals) / len(intervals)
            if avg_interval <= 0:
                continue
            # Check regularity: std dev < 20% of mean
            variance = sum((iv - avg_interval) ** 2 for iv in intervals) / len(intervals)
            std_dev = variance ** 0.5
            if avg_interval > 5 and std_dev / avg_interval < 0.2:
                indicators.append(
                    ThreatIndicator(
                        indicator_type="network_exposure",
                        pattern_name="c2_beaconing",
                        severity="critical",
                        confidence=0.85,
                        description=(
                            f"C2 beaconing: agent {agent_id[:8]} → {dst} "
                            f"every ~{avg_interval:.0f}s ({len(timestamps)} connections)"
                        ),
                        related_agent_ids=[agent_id],
                        suggested_playbook="quarantine_agent",
                        mitre_tactic="exfiltration",
                    )
                )
    return indicators


def _detect_tor_connections(events: list[dict]) -> list[ThreatIndicator]:
    """V2.1 — Detect Tor/anonymization network usage."""
    tor_ports = {9050, 9150, 9051}
    indicators: list[ThreatIndicator] = []
    for e in events:
        details = e.get("details", {})
        dst_port = details.get("dst_port") or details.get("port")
        agent_id = e.get("agent_id", "")
        if dst_port:
            try:
                if int(dst_port) in tor_ports:
                    indicators.append(
                        ThreatIndicator(
                            indicator_type="network_exposure",
                            pattern_name="tor_connection",
                            severity="high",
                            confidence=0.80,
                            description=(
                                f"Tor/anonymization connection detected: port {dst_port} "
                                f"from agent {agent_id[:8]}"
                            ),
                            related_event_ids=[e.get("id", "")],
                            related_agent_ids=[agent_id] if agent_id else [],
                            suggested_playbook="quarantine_agent",
                            mitre_tactic="exfiltration",
                        )
                    )
            except (ValueError, TypeError):
                pass
    return indicators
