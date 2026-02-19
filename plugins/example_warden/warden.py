"""AngelClaw V2.5 — Example Warden Plugin.

A minimal warden that counts incoming events and raises a summary
indicator when the event count exceeds a configurable threshold.
Intended as a starting point for writing custom plugins.
"""

from __future__ import annotations

import logging
from typing import Any

from cloud.guardian.base_agent import SubAgent
from cloud.guardian.models import AgentResult, AgentTask, AgentType, Permission

logger = logging.getLogger("angelgrid.plugins.example_warden")

_EVENT_THRESHOLD = 10


class ExampleWarden(SubAgent):
    """Demonstration warden that counts events and flags high volume."""

    def __init__(
        self,
        agent_type: AgentType = AgentType.PLUGIN,
        permissions: set[Permission] | None = None,
    ) -> None:
        super().__init__(
            agent_type=agent_type,
            permissions=permissions or {Permission.READ_EVENTS},
        )
        self._event_count: int = 0

    async def handle_task(self, task: AgentTask) -> AgentResult:
        """Process an incoming detection task.

        Increments the internal event counter for each event in the
        payload.  When the cumulative count exceeds ``_EVENT_THRESHOLD``,
        the result includes a summary indicator flagging elevated
        activity.
        """
        events: list[dict[str, Any]] = task.payload.get("events", [])
        self._event_count += len(events)

        indicator: dict[str, Any] | None = None
        if self._event_count > _EVENT_THRESHOLD:
            indicator = {
                "indicator_type": "threshold_breach",
                "pattern_name": "example_high_volume",
                "severity": "medium",
                "confidence": 0.7,
                "description": (
                    f"ExampleWarden detected elevated activity: "
                    f"{self._event_count} cumulative events "
                    f"(threshold={_EVENT_THRESHOLD})"
                ),
                "event_count": self._event_count,
            }
            logger.info(
                "[%s] Threshold breached — %d events observed",
                self.agent_id,
                self._event_count,
            )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            agent_type=self.agent_type.value,
            success=True,
            result_data={
                "events_processed": len(events),
                "cumulative_count": self._event_count,
                "indicator": indicator,
            },
        )

    @property
    def event_count(self) -> int:
        """Return the cumulative number of events observed."""
        return self._event_count

    def reset_count(self) -> None:
        """Reset the event counter to zero."""
        self._event_count = 0
        logger.info("[%s] Event counter reset", self.agent_id)
