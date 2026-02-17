"""AngelClaw – Sub-Agent base class.

Every guardian sub-agent (Sentinel, Response, Forensic, Audit) extends
this ABC.  The Orchestrator dispatches tasks and enforces permissions.
"""

from __future__ import annotations

import logging
import time
import uuid
from abc import ABC, abstractmethod

from cloud.guardian.models import (
    AgentResult,
    AgentStatus,
    AgentTask,
    AgentType,
    Permission,
)

logger = logging.getLogger("angelgrid.cloud.guardian.agent")


class SubAgent(ABC):
    """Abstract base for all ANGEL guardian sub-agents."""

    def __init__(
        self,
        agent_type: AgentType,
        permissions: set[Permission],
    ) -> None:
        self.agent_id: str = f"{agent_type.value}-{uuid.uuid4().hex[:8]}"
        self.agent_type: AgentType = agent_type
        self.permissions: set[Permission] = permissions
        self.status: AgentStatus = AgentStatus.IDLE
        self._tasks_completed: int = 0
        self._tasks_failed: int = 0

    # ------------------------------------------------------------------
    # Permission enforcement
    # ------------------------------------------------------------------

    def check_permission(self, required: Permission) -> bool:
        """Return True if this agent holds the required permission."""
        return required in self.permissions

    def require_permission(self, required: Permission) -> None:
        """Raise if this agent lacks the required permission."""
        if not self.check_permission(required):
            raise PermissionError(
                f"Agent {self.agent_id} ({self.agent_type.value}) "
                f"lacks permission: {required.value}"
            )

    # ------------------------------------------------------------------
    # Task handling
    # ------------------------------------------------------------------

    async def execute(self, task: AgentTask) -> AgentResult:
        """Run a task with status tracking, timing, and error handling.

        Subclasses implement ``handle_task`` — this wrapper manages
        lifecycle concerns.
        """
        self.status = AgentStatus.BUSY
        start = time.monotonic()

        try:
            result = await self.handle_task(task)
            self._tasks_completed += 1
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type.value,
                success=result.success,
                result_data=result.result_data,
                error=result.error,
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except PermissionError as exc:
            self._tasks_failed += 1
            logger.error(
                "[%s] Permission denied: %s",
                self.agent_id,
                exc,
            )
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type.value,
                success=False,
                error=f"Permission denied: {exc}",
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as exc:
            self._tasks_failed += 1
            logger.exception(
                "[%s] Task %s failed: %s",
                self.agent_id,
                task.task_id,
                exc,
            )
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type.value,
                success=False,
                error=str(exc),
                duration_ms=(time.monotonic() - start) * 1000,
            )
        finally:
            self.status = AgentStatus.IDLE

    @abstractmethod
    async def handle_task(self, task: AgentTask) -> AgentResult:
        """Process a single task. Implemented by each sub-agent."""
        ...

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def health_check(self) -> bool:
        """Return True if the agent is operational."""
        return self.status != AgentStatus.ERROR

    async def shutdown(self) -> None:
        """Graceful shutdown hook."""
        self.status = AgentStatus.STOPPED
        logger.info(
            "[%s] Shut down (completed=%d, failed=%d)",
            self.agent_id,
            self._tasks_completed,
            self._tasks_failed,
        )

    # ------------------------------------------------------------------
    # Info
    # ------------------------------------------------------------------

    def info(self) -> dict:
        """Return agent metadata for the Orchestrator registry."""
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type.value,
            "status": self.status.value,
            "permissions": sorted(p.value for p in self.permissions),
            "tasks_completed": self._tasks_completed,
            "tasks_failed": self._tasks_failed,
        }
