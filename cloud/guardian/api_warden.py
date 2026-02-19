"""AngelClaw – API Warden (Gate Keeper).

Monitors API-related events for abuse patterns: endpoint enumeration,
auth failure spikes, oversized payloads, unusual HTTP methods, and
rate limit evasion. Part of the Angel Legion.
"""

from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict

from cloud.guardian.base_agent import SubAgent
from cloud.guardian.models import (
    AgentResult,
    AgentTask,
    AgentType,
    Permission,
    ThreatIndicator,
)

logger = logging.getLogger("angelgrid.cloud.guardian.api_warden")

_UNUSUAL_METHODS = frozenset({"TRACE", "CONNECT", "OPTIONS", "PATCH", "PROPFIND", "MKCOL"})
_SENSITIVE_PATHS_RE = re.compile(
    r"(?i)(/admin|/api/v\d+/auth|\.env|/debug|/internal|/actuator|/swagger|/graphql)"
)
_ENUMERATION_RE = re.compile(
    r"(?i)(404|not.found|endpoint.not|invalid.path|unknown.route)"
)

_API_TYPES = frozenset({
    "api_security.auth_failure",
    "api_security.rate_exceeded",
    "api_security.payload_oversize",
    "api_security.enumeration",
    "api_security.method_abuse",
    "api_security.injection_attempt",
})


class ApiWarden(SubAgent):
    """Gate Keeper — watches for API abuse and authentication anomalies."""

    def __init__(self) -> None:
        super().__init__(
            agent_type=AgentType.API_SECURITY,
            permissions={
                Permission.READ_EVENTS,
                Permission.READ_AGENTS,
                Permission.READ_API_SECURITY,
            },
        )

    async def handle_task(self, task: AgentTask) -> AgentResult:
        """Analyze events for API abuse patterns.

        Expected payload:
            events: list[dict] — serialized events
            window_seconds: int
        """
        events = task.payload.get("events", [])
        indicators: list[ThreatIndicator] = []

        api_events = [
            e for e in events
            if e.get("category") == "api_security" or e.get("type", "") in _API_TYPES
        ]

        # Pattern 1: Endpoint enumeration (many 404s from same source)
        source_404s: dict[str, list] = defaultdict(list)
        for e in events:
            details = e.get("details") or {}
            status = str(details.get("status_code", ""))
            response = str(details.get("response", ""))
            etype = e.get("type", "") or ""
            if status == "404" or _ENUMERATION_RE.search(f"{response} {etype}"):
                source = details.get("source_ip", "") or details.get("client_ip", "") or "unknown"
                source_404s[source].append(e)

        for source, evts in source_404s.items():
            if len(evts) >= 5:
                indicators.append(ThreatIndicator(
                    indicator_type="api_abuse",
                    pattern_name="endpoint_enumeration",
                    severity="high" if len(evts) >= 10 else "medium",
                    confidence=0.85,
                    description=(
                        f"Source {source} triggered {len(evts)} 404/not-found responses. "
                        "This pattern indicates automated endpoint"
                        " scanning or directory enumeration."
                    ),
                    related_event_ids=[e.get("id", "") for e in evts[:5]],
                    metadata={
                        "title": "Endpoint Enumeration Detected",
                        "category": "api_security",
                        "mitigations": [
                            "Rate limit or block the source IP",
                            "Enable WAF rules for path traversal",
                            "Review API endpoint exposure",
                        ],
                    },
                ))

        # Pattern 2: Auth failure spikes
        auth_failures = [
            e for e in events
            if e.get("type", "").startswith("api_security.auth_fail")
            or (e.get("details") or {}).get("status_code") in (401, 403)
        ]
        if len(auth_failures) >= 5:
            source_counts = Counter(
                (e.get("details") or {}).get("source_ip", "unknown") for e in auth_failures
            )
            top_source = source_counts.most_common(1)[0] if source_counts else ("unknown", 0)
            indicators.append(ThreatIndicator(
                indicator_type="api_abuse",
                pattern_name="auth_failure_spike",
                severity="high" if len(auth_failures) >= 10 else "medium",
                confidence=0.80,
                description=(
                    f"Detected {len(auth_failures)} authentication failures. "
                    f"Top source: {top_source[0]} ({top_source[1]} failures). "
                    "May indicate brute-force or credential stuffing attack."
                ),
                related_event_ids=[e.get("id", "") for e in auth_failures[:5]],
                metadata={
                    "title": "API Authentication Failure Spike",
                    "category": "api_security",
                    "mitigations": [
                        "Implement account lockout after N failures",
                        "Enable CAPTCHA for repeated failures",
                        "Block offending source IPs",
                    ],
                },
            ))

        # Pattern 3: Oversized payloads
        oversize = [
            e for e in events
            if e.get("type", "") == "api_security.payload_oversize"
            or (e.get("details") or {}).get("payload_size", 0) > 1_000_000
        ]
        if oversize:
            indicators.append(ThreatIndicator(
                indicator_type="api_abuse",
                pattern_name="oversized_payload",
                severity="medium",
                confidence=0.75,
                description=(
                    f"Detected {len(oversize)} oversized payload(s). "
                    "Large payloads may indicate DoS attempts, data exfiltration, "
                    "or exploitation of deserialization vulnerabilities."
                ),
                related_event_ids=[e.get("id", "") for e in oversize[:5]],
                metadata={
                    "title": "Oversized API Payloads Detected",
                    "category": "api_security",
                    "mitigations": [
                        "Enforce request body size limits",
                        "Validate Content-Length headers",
                        "Monitor for payload-based attacks",
                    ],
                },
            ))

        # Pattern 4: Unusual HTTP methods
        unusual_method_events = []
        for e in events:
            method = ((e.get("details") or {}).get("method", "") or "").upper()
            if method in _UNUSUAL_METHODS:
                unusual_method_events.append(e)

        if len(unusual_method_events) >= 3:
            indicators.append(ThreatIndicator(
                indicator_type="api_abuse",
                pattern_name="unusual_http_methods",
                severity="medium",
                confidence=0.70,
                description=(
                    f"Detected {len(unusual_method_events)} requests using unusual HTTP methods "
                    "(TRACE, CONNECT, PROPFIND, etc.). This may indicate web server probing "
                    "or cross-site tracing attacks."
                ),
                related_event_ids=[e.get("id", "") for e in unusual_method_events[:5]],
                metadata={
                    "title": "Unusual HTTP Methods Detected",
                    "category": "api_security",
                    "mitigations": [
                        "Disable unnecessary HTTP methods",
                        "Return 405 Method Not Allowed",
                        "Enable WAF rules for method filtering",
                    ],
                },
            ))

        # Pattern 5: Rate limit evasion (rotating IPs hitting same endpoint)
        endpoint_sources: dict[str, set] = defaultdict(set)
        for e in events:
            details = e.get("details") or {}
            endpoint = details.get("path", "") or details.get("endpoint", "")
            source = details.get("source_ip", "")
            if endpoint and source:
                endpoint_sources[endpoint].add(source)

        for endpoint, sources in endpoint_sources.items():
            if len(sources) >= 5 and _SENSITIVE_PATHS_RE.search(endpoint):
                indicators.append(ThreatIndicator(
                    indicator_type="api_abuse",
                    pattern_name="rate_limit_evasion",
                    severity="high",
                    confidence=0.80,
                    description=(
                        f"Sensitive endpoint '{endpoint}' accessed from {len(sources)} "
                        "distinct IPs. Distributed access to sensitive endpoints suggests "
                        "coordinated rate limit evasion."
                    ),
                    related_event_ids=[],
                    metadata={
                        "title": "Rate Limit Evasion Pattern",
                        "category": "api_security",
                        "mitigations": [
                            "Implement per-endpoint rate limits",
                            "Enable behavioral analysis",
                            "Monitor for distributed attack patterns",
                        ],
                    },
                ))

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            agent_type=self.agent_type.value,
            result_data={
                "indicators": [ind.model_dump(mode="json") for ind in indicators],
                "summary": (
                    f"API security scan: {len(indicators)} issue(s)"
                    f" found across {len(events)} events"
                ),
                "stats": {
                    "api_events": len(api_events),
                    "auth_failures": len(auth_failures),
                    "enumeration_sources": len(source_404s),
                    "oversize_payloads": len(oversize),
                    "unusual_methods": len(unusual_method_events),
                },
            },
        )
