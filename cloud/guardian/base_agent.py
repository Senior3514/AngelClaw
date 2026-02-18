"""AngelClaw – Sub-Agent base class (Angel Legion).

Every guardian sub-agent extends this ABC.  The Seraph (orchestrator)
dispatches tasks and enforces permissions.

V2 upgrades:
  - Timeout enforcement on all task execution
  - Status tracking and lifecycle management

V2.2 upgrades:
  - Health metrics & performance tracking (uptime, latency, error rate)
  - Consecutive failure tracking with auto-degradation
  - Last-error introspection for diagnostics
  - Success rate computation for adaptive orchestration
"""

from __future__ import annotations

import asyncio
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

# V2.2 — Auto-degrade agent after this many consecutive failures
_AUTO_DEGRADE_THRESHOLD = 5


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
        # V2.2 — Health metrics & performance tracking
        self._last_error: str = ""
        self._last_error_at: float = 0.0
        self._consecutive_failures: int = 0
        self._total_duration_ms: float = 0.0
        self._last_task_duration_ms: float = 0.0
        self._started_at: float = time.monotonic()

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
            timeout = task.timeout_seconds
            if timeout and timeout > 0:
                result = await asyncio.wait_for(self.handle_task(task), timeout=timeout)
            else:
                result = await self.handle_task(task)
            self._tasks_completed += 1
            duration_ms = (time.monotonic() - start) * 1000
            self._total_duration_ms += duration_ms
            self._last_task_duration_ms = duration_ms
            # V2.2 — Reset consecutive failures on success
            self._consecutive_failures = 0
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type.value,
                success=result.success,
                result_data=result.result_data,
                error=result.error,
                duration_ms=duration_ms,
            )
        except asyncio.TimeoutError:
            return self._handle_failure(
                task, start, f"Task timed out after {task.timeout_seconds}s"
            )
        except PermissionError as exc:
            return self._handle_failure(task, start, f"Permission denied: {exc}")
        except Exception as exc:
            logger.exception(
                "[%s] Task %s failed: %s",
                self.agent_id,
                task.task_id,
                exc,
            )
            return self._handle_failure(task, start, str(exc))
        finally:
            if self.status != AgentStatus.ERROR:
                self.status = AgentStatus.IDLE

    def _handle_failure(self, task: AgentTask, start: float, error: str) -> AgentResult:
        """Common failure handling with V2.2 health tracking."""
        self._tasks_failed += 1
        duration_ms = (time.monotonic() - start) * 1000
        self._total_duration_ms += duration_ms
        self._last_task_duration_ms = duration_ms
        self._last_error = error
        self._last_error_at = time.monotonic()
        self._consecutive_failures += 1

        # V2.2 — Auto-degrade on repeated failures
        if self._consecutive_failures >= _AUTO_DEGRADE_THRESHOLD:
            self.status = AgentStatus.ERROR
            logger.warning(
                "[%s] Auto-degraded after %d consecutive failures",
                self.agent_id,
                self._consecutive_failures,
            )

        logger.error("[%s] Task %s: %s", self.agent_id, task.task_id, error)
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            agent_type=self.agent_type.value,
            success=False,
            error=error,
            duration_ms=duration_ms,
        )

    @abstractmethod
    async def handle_task(self, task: AgentTask) -> AgentResult:
        """Process a single task. Implemented by each sub-agent."""
        ...

    # ------------------------------------------------------------------
    # V2.2 — Health & metrics
    # ------------------------------------------------------------------

    @property
    def success_rate(self) -> float:
        """Return the task success rate (0.0-1.0)."""
        total = self._tasks_completed + self._tasks_failed
        if total == 0:
            return 1.0
        return self._tasks_completed / total

    @property
    def avg_duration_ms(self) -> float:
        """Return average task duration in milliseconds."""
        total = self._tasks_completed + self._tasks_failed
        if total == 0:
            return 0.0
        return self._total_duration_ms / total

    @property
    def uptime_seconds(self) -> float:
        """Return seconds since agent was created."""
        return time.monotonic() - self._started_at

    @property
    def is_healthy(self) -> bool:
        """Return True if agent is operational and not degraded."""
        return self.status not in (AgentStatus.ERROR, AgentStatus.STOPPED)

    def reset_health(self) -> None:
        """Reset error state — used by orchestrator to recover degraded agents."""
        if self.status == AgentStatus.ERROR:
            self.status = AgentStatus.IDLE
            self._consecutive_failures = 0
            self._last_error = ""
            logger.info("[%s] Health reset — agent recovered", self.agent_id)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def health_check(self) -> bool:
        """Return True if the agent is operational."""
        return self.status not in (AgentStatus.ERROR, AgentStatus.STOPPED)

    async def shutdown(self) -> None:
        """Graceful shutdown hook."""
        self.status = AgentStatus.STOPPED
        logger.info(
            "[%s] Shut down (completed=%d, failed=%d, rate=%.0f%%)",
            self.agent_id,
            self._tasks_completed,
            self._tasks_failed,
            self.success_rate * 100,
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
            # V2.2 — Extended metrics
            "success_rate": round(self.success_rate, 3),
            "avg_duration_ms": round(self.avg_duration_ms, 1),
            "consecutive_failures": self._consecutive_failures,
            "last_error": self._last_error[:200] if self._last_error else "",
            "uptime_seconds": round(self.uptime_seconds, 0),
        }
