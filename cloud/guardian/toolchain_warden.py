"""AngelClaw – Tool Smith (Toolchain Warden).

Monitors AI tool usage, supply chain integrity, and tool invocation
patterns.  Detects unauthorized tools, version drift, excessive usage,
and output injection.  Part of the Angel Legion.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict

from cloud.guardian.base_agent import SubAgent
from cloud.guardian.models import (
    AgentResult,
    AgentTask,
    AgentType,
    Permission,
    ThreatIndicator,
)

logger = logging.getLogger("angelgrid.cloud.guardian.toolchain_warden")

# Event types this warden cares about
_TOOL_TYPES = frozenset(
    {
        "ai_tool.invoke",
        "ai_tool.result",
        "ai_tool.blocked",
        "ai_tool.error",
        "ai_tool.version_change",
        "ai_tool.install",
        "ai_tool.uninstall",
    }
)

# Thresholds
_TOOL_BURST_THRESHOLD = 20   # tool invocations per agent per batch
_VERSION_CHANGE_SEVERITY = "high"


class ToolchainWarden(SubAgent):
    """Tool Smith — watches for tool abuse and supply chain tampering."""

    def __init__(self) -> None:
        super().__init__(
            agent_type=AgentType.TOOLCHAIN,
            permissions={Permission.READ_EVENTS, Permission.READ_TOOLS},
        )

    async def handle_task(self, task: AgentTask) -> AgentResult:
        """Analyze tool-related events.

        Expected payload:
            events: list[dict] — serialized events
            window_seconds: int
        """
        self.require_permission(Permission.READ_TOOLS)

        events_data = task.payload.get("events", [])
        if not events_data:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type.value,
                result_data={"indicators": []},
            )

        # Filter to tool-relevant events
        tool_events = [
            e for e in events_data if e.get("type", "") in _TOOL_TYPES
            or "ai_tool" in e.get("type", "").lower()
            or "tool" in e.get("type", "").lower()
        ]

        indicators: list[ThreatIndicator] = []

        # 1. Detect tool invocation bursts
        indicators.extend(_detect_tool_burst(tool_events))

        # 2. Detect version changes (supply chain)
        indicators.extend(_detect_version_changes(tool_events))

        # 3. Detect blocked-but-retried tools
        indicators.extend(_detect_blocked_retries(tool_events))

        # 4. Detect tool output injection patterns
        indicators.extend(_detect_output_injection(tool_events))

        # V2.1 — expanded toolchain detection
        indicators.extend(_detect_dependency_confusion(tool_events))
        indicators.extend(_detect_unauthorized_tools(tool_events))

        logger.info(
            "[TOOL SMITH] Analyzed %d tool events → %d indicators",
            len(tool_events),
            len(indicators),
        )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            agent_type=self.agent_type.value,
            result_data={
                "indicators": [ind.model_dump(mode="json") for ind in indicators],
                "stats": {
                    "tool_events": len(tool_events),
                    "total_events": len(events_data),
                    "indicators_found": len(indicators),
                },
            },
        )


def _detect_tool_burst(events: list[dict]) -> list[ThreatIndicator]:
    """Detect agents making excessive tool invocations."""
    per_agent: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if "invoke" in e.get("type", ""):
            per_agent[e.get("agent_id", "")].append(e)

    indicators: list[ThreatIndicator] = []
    for agent_id, agent_events in per_agent.items():
        if not agent_id or len(agent_events) < _TOOL_BURST_THRESHOLD:
            continue
        tools = Counter(
            e.get("details", {}).get("tool_name", "unknown") for e in agent_events
        )
        indicators.append(
            ThreatIndicator(
                indicator_type="toolchain_abuse",
                pattern_name="tool_invocation_burst",
                severity="high",
                confidence=0.8,
                description=(
                    f"Agent {agent_id[:8]} invoked {len(agent_events)} tools rapidly. "
                    f"Top: {tools.most_common(3)}"
                ),
                related_event_ids=[e.get("id", "") for e in agent_events[:20]],
                related_agent_ids=[agent_id],
                suggested_playbook="throttle_agent",
            )
        )
    return indicators


def _detect_version_changes(events: list[dict]) -> list[ThreatIndicator]:
    """Detect tool version changes that might indicate supply chain attacks."""
    indicators: list[ThreatIndicator] = []
    for e in events:
        if e.get("type") != "ai_tool.version_change":
            continue
        details = e.get("details", {})
        tool_name = details.get("tool_name", "unknown")
        old_ver = details.get("old_version", "?")
        new_ver = details.get("new_version", "?")
        agent_id = e.get("agent_id", "")

        indicators.append(
            ThreatIndicator(
                indicator_type="toolchain_abuse",
                pattern_name="tool_version_drift",
                severity=_VERSION_CHANGE_SEVERITY,
                confidence=0.7,
                description=(
                    f"Tool '{tool_name}' version changed: {old_ver} → {new_ver} "
                    f"on agent {agent_id[:8]}"
                ),
                related_event_ids=[e.get("id", "")],
                related_agent_ids=[agent_id] if agent_id else [],
                suggested_playbook="escalate_to_human",
            )
        )
    return indicators


def _detect_blocked_retries(events: list[dict]) -> list[ThreatIndicator]:
    """Detect an agent retrying a blocked tool — suggests evasion."""
    blocked: dict[str, set[str]] = defaultdict(set)  # agent_id -> tool_names blocked
    invoked: dict[str, set[str]] = defaultdict(set)  # agent_id -> tool_names invoked

    for e in events:
        agent_id = e.get("agent_id", "")
        tool_name = e.get("details", {}).get("tool_name", "")
        if not agent_id or not tool_name:
            continue
        if e.get("type") == "ai_tool.blocked":
            blocked[agent_id].add(tool_name)
        elif e.get("type") == "ai_tool.invoke":
            invoked[agent_id].add(tool_name)

    indicators: list[ThreatIndicator] = []
    for agent_id, blocked_tools in blocked.items():
        retried = blocked_tools & invoked[agent_id]
        if retried:
            indicators.append(
                ThreatIndicator(
                    indicator_type="toolchain_abuse",
                    pattern_name="blocked_tool_retry",
                    severity="critical",
                    confidence=0.9,
                    description=(
                        f"Agent {agent_id[:8]} retried blocked tools: "
                        f"{', '.join(sorted(retried)[:5])}"
                    ),
                    related_agent_ids=[agent_id],
                    suggested_playbook="quarantine_agent",
                    mitre_tactic="execution",
                )
            )
    return indicators


def _detect_output_injection(events: list[dict]) -> list[ThreatIndicator]:
    """Detect injection patterns in tool output/result events."""
    import re

    injection_patterns = [
        re.compile(r"(?i)ignore\s+(previous|all)\s+instructions"),
        re.compile(r"(?i)you\s+are\s+now\s+in\s+"),
        re.compile(r"(?i)system\s*prompt\s*:"),
        re.compile(r"(?i)<\s*/?\s*script\s*>"),
    ]

    indicators: list[ThreatIndicator] = []
    for e in events:
        if e.get("type") != "ai_tool.result":
            continue
        output = str(e.get("details", {}).get("output", ""))
        for pattern in injection_patterns:
            if pattern.search(output):
                agent_id = e.get("agent_id", "")
                indicators.append(
                    ThreatIndicator(
                        indicator_type="toolchain_abuse",
                        pattern_name="tool_output_injection",
                        severity="critical",
                        confidence=0.85,
                        description=(
                            f"Prompt injection in tool output on agent {agent_id[:8]}"
                        ),
                        related_event_ids=[e.get("id", "")],
                        related_agent_ids=[agent_id] if agent_id else [],
                        suggested_playbook="quarantine_agent",
                        mitre_tactic="execution",
                    )
                )
                break  # one indicator per event
    return indicators


def _detect_dependency_confusion(events: list[dict]) -> list[ThreatIndicator]:
    """V2.1 — Detect dependency confusion / supply chain attacks."""
    suspicious_patterns = [
        "install --index-url",
        "install --extra-index-url",
        "npm install --registry",
        "pip install -i ",
        "gem install --source",
    ]
    indicators: list[ThreatIndicator] = []
    for e in events:
        details = e.get("details", {})
        cmd = str(details.get("command", "") or details.get("args", "")).lower()
        for pattern in suspicious_patterns:
            if pattern in cmd:
                agent_id = e.get("agent_id", "")
                indicators.append(
                    ThreatIndicator(
                        indicator_type="toolchain_abuse",
                        pattern_name="dependency_confusion",
                        severity="critical",
                        confidence=0.85,
                        description=(
                            f"Dependency confusion: custom package registry usage "
                            f"on agent {agent_id[:8]}"
                        ),
                        related_event_ids=[e.get("id", "")],
                        related_agent_ids=[agent_id] if agent_id else [],
                        suggested_playbook="quarantine_agent",
                        mitre_tactic="persistence",
                    )
                )
                break
    return indicators


def _detect_unauthorized_tools(events: list[dict]) -> list[ThreatIndicator]:
    """V2.1 — Detect usage of unauthorized/unknown tools."""
    # Known safe tool families
    _KNOWN_TOOL_PREFIXES = {
        "file_", "read_", "write_", "list_", "search_", "query_",
        "analyze_", "report_", "scan_", "monitor_", "check_",
    }
    per_agent_unknown: dict[str, list[str]] = defaultdict(list)
    per_agent_events: dict[str, list[str]] = defaultdict(list)

    for e in events:
        if "invoke" not in e.get("type", ""):
            continue
        details = e.get("details", {})
        tool_name = details.get("tool_name", "")
        agent_id = e.get("agent_id", "")
        if not tool_name or not agent_id:
            continue
        is_known = any(tool_name.lower().startswith(p) for p in _KNOWN_TOOL_PREFIXES)
        if not is_known:
            per_agent_unknown[agent_id].append(tool_name)
            per_agent_events[agent_id].append(e.get("id", ""))

    indicators: list[ThreatIndicator] = []
    for agent_id, tools in per_agent_unknown.items():
        if len(tools) >= 3:
            unique_tools = sorted(set(tools))
            indicators.append(
                ThreatIndicator(
                    indicator_type="toolchain_abuse",
                    pattern_name="unauthorized_tools",
                    severity="high",
                    confidence=0.70,
                    description=(
                        f"Unauthorized tools on agent {agent_id[:8]}: "
                        f"{', '.join(unique_tools[:5])}"
                    ),
                    related_event_ids=per_agent_events[agent_id][:20],
                    related_agent_ids=[agent_id],
                    suggested_playbook="escalate_to_human",
                    mitre_tactic="execution",
                )
            )
    return indicators
