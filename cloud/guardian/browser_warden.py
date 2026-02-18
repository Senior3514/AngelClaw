"""AngelClaw – Glass Eye (Browser Warden).

Processes events from browser extensions.  Detects suspicious URLs,
extension conflicts, page content injection, and browser-specific threats.
Part of the Angel Legion.
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

logger = logging.getLogger("angelgrid.cloud.guardian.browser_warden")

# Event types this warden cares about
_BROWSER_TYPES = frozenset(
    {
        "browser.navigation",
        "browser.download",
        "browser.extension_install",
        "browser.extension_conflict",
        "browser.page_injection",
        "browser.form_submit",
        "browser.cookie_access",
        "browser.storage_access",
    }
)

# Suspicious URL patterns
_SUSPICIOUS_URL_PATTERNS = [
    re.compile(r"(?i)https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[:/]"),  # raw IP
    re.compile(r"(?i)data:text/html"),                                       # data URI
    re.compile(r"(?i)javascript:"),                                          # JS URI
    re.compile(r"(?i)https?://.*\.(onion|bit|bazar)(\/|$)"),                # dark web
    re.compile(r"(?i)https?://[^/]*\.ru/.*\.(exe|bat|cmd|ps1|sh)"),         # risky downloads
]

# Injection signatures in page content
_INJECTION_PATTERNS = [
    re.compile(r"(?i)<\s*iframe\s+.*src\s*="),
    re.compile(r"(?i)<\s*script\s+.*src\s*=\s*[\"']https?://"),
    re.compile(r"(?i)document\.cookie"),
    re.compile(r"(?i)eval\s*\("),
    re.compile(r"(?i)window\.location\s*="),
]


class BrowserWarden(SubAgent):
    """Glass Eye — browser extension event analysis and protection."""

    def __init__(self) -> None:
        super().__init__(
            agent_type=AgentType.BROWSER,
            permissions={Permission.READ_EVENTS, Permission.READ_BROWSER},
        )

    async def handle_task(self, task: AgentTask) -> AgentResult:
        """Analyze browser events for threats.

        Expected payload:
            events: list[dict] — serialized events
            window_seconds: int
        """
        self.require_permission(Permission.READ_BROWSER)

        events_data = task.payload.get("events", [])
        if not events_data:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type.value,
                result_data={"indicators": []},
            )

        # Filter to browser-relevant events
        browser_events = [
            e for e in events_data if e.get("type", "") in _BROWSER_TYPES
            or "browser" in e.get("type", "").lower()
        ]

        indicators: list[ThreatIndicator] = []

        # 1. Suspicious URL detection
        indicators.extend(_detect_suspicious_urls(browser_events))

        # 2. Page injection detection
        indicators.extend(_detect_page_injection(browser_events))

        # 3. Extension conflict / unauthorized extension
        indicators.extend(_detect_extension_threats(browser_events))

        # 4. Excessive cookie/storage access
        indicators.extend(_detect_data_access_abuse(browser_events))

        logger.info(
            "[GLASS EYE] Analyzed %d browser events → %d indicators",
            len(browser_events),
            len(indicators),
        )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            agent_type=self.agent_type.value,
            result_data={
                "indicators": [ind.model_dump(mode="json") for ind in indicators],
                "stats": {
                    "browser_events": len(browser_events),
                    "total_events": len(events_data),
                    "indicators_found": len(indicators),
                },
            },
        )


def _detect_suspicious_urls(events: list[dict]) -> list[ThreatIndicator]:
    """Flag navigation or download events with suspicious URLs."""
    indicators: list[ThreatIndicator] = []
    for e in events:
        details = e.get("details", {})
        url = details.get("url", "") or details.get("target_url", "")
        if not url:
            continue

        for pattern in _SUSPICIOUS_URL_PATTERNS:
            if pattern.search(url):
                agent_id = e.get("agent_id", "")
                indicators.append(
                    ThreatIndicator(
                        indicator_type="browser_threat",
                        pattern_name="suspicious_url",
                        severity="high",
                        confidence=0.8,
                        description=f"Suspicious URL detected: {url[:100]}",
                        related_event_ids=[e.get("id", "")],
                        related_agent_ids=[agent_id] if agent_id else [],
                        suggested_playbook="block_source",
                        mitre_tactic="initial_access",
                    )
                )
                break  # one indicator per event
    return indicators


def _detect_page_injection(events: list[dict]) -> list[ThreatIndicator]:
    """Detect content injection patterns in page-related events."""
    indicators: list[ThreatIndicator] = []
    for e in events:
        if e.get("type") != "browser.page_injection":
            details = e.get("details", {})
            content = details.get("content", "") or details.get("page_content", "")
        else:
            content = str(e.get("details", {}))

        if not content:
            continue

        for pattern in _INJECTION_PATTERNS:
            if pattern.search(content):
                agent_id = e.get("agent_id", "")
                indicators.append(
                    ThreatIndicator(
                        indicator_type="browser_threat",
                        pattern_name="page_content_injection",
                        severity="critical",
                        confidence=0.85,
                        description=(
                            f"Content injection detected in browser event "
                            f"from agent {agent_id[:8]}"
                        ),
                        related_event_ids=[e.get("id", "")],
                        related_agent_ids=[agent_id] if agent_id else [],
                        suggested_playbook="block_source",
                        mitre_tactic="execution",
                    )
                )
                break
    return indicators


def _detect_extension_threats(events: list[dict]) -> list[ThreatIndicator]:
    """Detect extension installation or conflict events."""
    indicators: list[ThreatIndicator] = []
    for e in events:
        event_type = e.get("type", "")
        details = e.get("details", {})
        agent_id = e.get("agent_id", "")

        if event_type == "browser.extension_conflict":
            indicators.append(
                ThreatIndicator(
                    indicator_type="browser_threat",
                    pattern_name="extension_conflict",
                    severity="medium",
                    confidence=0.7,
                    description=(
                        f"Extension conflict: "
                        f"{details.get('extension_name', 'unknown')}"
                    ),
                    related_event_ids=[e.get("id", "")],
                    related_agent_ids=[agent_id] if agent_id else [],
                    suggested_playbook="escalate_to_human",
                )
            )

        if event_type == "browser.extension_install":
            ext_name = details.get("extension_name", "")
            ext_id = details.get("extension_id", "")
            indicators.append(
                ThreatIndicator(
                    indicator_type="browser_threat",
                    pattern_name="extension_install",
                    severity="medium",
                    confidence=0.6,
                    description=(
                        f"New extension installed: {ext_name or ext_id}"
                    ),
                    related_event_ids=[e.get("id", "")],
                    related_agent_ids=[agent_id] if agent_id else [],
                    suggested_playbook="escalate_to_human",
                )
            )
    return indicators


def _detect_data_access_abuse(events: list[dict]) -> list[ThreatIndicator]:
    """Detect excessive cookie or storage access."""
    per_agent: dict[str, int] = defaultdict(int)
    per_agent_ids: dict[str, list[str]] = defaultdict(list)

    for e in events:
        if e.get("type") in ("browser.cookie_access", "browser.storage_access"):
            agent_id = e.get("agent_id", "")
            per_agent[agent_id] += 1
            per_agent_ids[agent_id].append(e.get("id", ""))

    indicators: list[ThreatIndicator] = []
    for agent_id, count in per_agent.items():
        if not agent_id or count < 10:
            continue
        indicators.append(
            ThreatIndicator(
                indicator_type="browser_threat",
                pattern_name="excessive_data_access",
                severity="high",
                confidence=0.75,
                description=(
                    f"Excessive cookie/storage access: {count} events "
                    f"from agent {agent_id[:8]}"
                ),
                related_event_ids=per_agent_ids[agent_id][:20],
                related_agent_ids=[agent_id],
                suggested_playbook="throttle_agent",
                mitre_tactic="credential_access",
            )
        )
    return indicators
