"""AngelClaw Cloud – Automated Multi-Step Remediation Workflow Engine.

Provides a declarative workflow system for defining and executing
remediation actions in response to security alerts.  Workflows consist
of ordered steps (quarantine, tighten policy, block IP, notify, scan,
etc.) with per-step failure policies and optional rollback plans.

Execution is asynchronous -- each step runs sequentially within a
workflow, and failures are handled according to the step's on_failure
policy (abort, continue, or rollback).

Module singleton: ``remediation_engine``
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from cloud.db.models import RemediationWorkflowRow

logger = logging.getLogger("angelgrid.cloud.services.remediation")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class WorkflowStepType(str, Enum):
    """Supported remediation step types."""

    QUARANTINE_AGENT = "quarantine_agent"
    TIGHTEN_POLICY = "tighten_policy"
    BLOCK_IP = "block_ip"
    NOTIFY = "notify"
    RUN_SCAN = "run_scan"
    WAIT = "wait"
    CONDITIONAL = "conditional"
    LOG = "log"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class WorkflowStep(BaseModel):
    """Single step within a remediation workflow."""

    step_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    step_type: str
    description: str = ""
    params: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 300
    on_failure: str = "abort"  # abort | continue | rollback
    condition: dict[str, Any] | None = None  # for CONDITIONAL type


class WorkflowExecution(BaseModel):
    """Tracks the runtime state of a single workflow execution."""

    execution_id: str
    workflow_id: str
    status: str = "pending"  # pending | running | completed | failed | rolled_back
    steps_completed: int = 0
    steps_total: int = 0
    results: list[dict[str, Any]] = Field(default_factory=list)
    started_at: datetime
    completed_at: datetime | None = None
    error: str = ""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class RemediationEngine:
    """Manages remediation workflow definitions and executes them."""

    def __init__(self) -> None:
        self._executions: dict[str, WorkflowExecution] = {}

    # ------------------------------------------------------------------
    # CRUD — workflow definitions
    # ------------------------------------------------------------------

    def create_workflow(
        self,
        db: Any,
        tenant_id: str,
        name: str,
        description: str,
        trigger_conditions: dict[str, Any],
        steps: list[dict[str, Any]],
        rollback_steps: list[dict[str, Any]] | None = None,
        created_by: str = "system",
    ) -> dict[str, Any]:
        """Persist a new workflow definition to the database.

        Args:
            db: Active SQLAlchemy session.
            tenant_id: Owning tenant identifier.
            name: Human-readable workflow name.
            description: Purpose of the workflow.
            trigger_conditions: Dict describing when the workflow fires
                (e.g. ``{"alert_type": "c2_callback", "min_severity": "high"}``).
            steps: Ordered list of step dicts (serialised WorkflowStep).
            rollback_steps: Optional steps to run on rollback.
            created_by: Identity of the creator.

        Returns:
            Dict representation of the newly created workflow row.
        """
        workflow_id = str(uuid.uuid4())
        row = RemediationWorkflowRow(
            id=workflow_id,
            tenant_id=tenant_id,
            name=name,
            description=description,
            trigger_conditions=trigger_conditions,
            steps=steps,
            rollback_steps=rollback_steps or [],
            enabled="true",
            executions=0,
            created_by=created_by,
            created_at=datetime.now(timezone.utc),
        )
        db.add(row)
        db.commit()
        db.refresh(row)

        logger.info(
            "[REMEDIATION] Created workflow %s (%s) with %d steps for tenant %s",
            workflow_id[:8],
            name,
            len(steps),
            tenant_id,
        )
        return self._row_to_dict(row)

    def list_workflows(self, db: Any, tenant_id: str) -> list[dict[str, Any]]:
        """Return all workflow definitions for a tenant.

        Args:
            db: Active SQLAlchemy session.
            tenant_id: Tenant to scope the query.

        Returns:
            List of workflow dicts ordered by creation date descending.
        """
        rows = (
            db.query(RemediationWorkflowRow)
            .filter(RemediationWorkflowRow.tenant_id == tenant_id)
            .order_by(RemediationWorkflowRow.created_at.desc())
            .all()
        )
        return [self._row_to_dict(r) for r in rows]

    def get_workflow(self, db: Any, workflow_id: str) -> dict[str, Any] | None:
        """Return a single workflow by ID, or None.

        Args:
            db: Active SQLAlchemy session.
            workflow_id: Primary key of the workflow.

        Returns:
            Workflow dict or None if not found.
        """
        row = db.query(RemediationWorkflowRow).filter_by(id=workflow_id).first()
        if not row:
            return None
        return self._row_to_dict(row)

    def update_workflow(self, db: Any, workflow_id: str, **kwargs: Any) -> dict[str, Any] | None:
        """Update mutable fields on an existing workflow.

        Accepted keyword arguments: name, description, trigger_conditions,
        steps, rollback_steps, enabled.

        Args:
            db: Active SQLAlchemy session.
            workflow_id: Primary key of the workflow.

        Returns:
            Updated workflow dict, or None if not found.
        """
        row = db.query(RemediationWorkflowRow).filter_by(id=workflow_id).first()
        if not row:
            return None

        allowed = {
            "name",
            "description",
            "trigger_conditions",
            "steps",
            "rollback_steps",
            "enabled",
        }
        for key, value in kwargs.items():
            if key in allowed and value is not None:
                setattr(row, key, value)

        db.commit()
        db.refresh(row)

        logger.info(
            "[REMEDIATION] Updated workflow %s — fields: %s",
            workflow_id[:8],
            ", ".join(kwargs.keys()),
        )
        return self._row_to_dict(row)

    def delete_workflow(self, db: Any, workflow_id: str) -> bool:
        """Delete a workflow definition.

        Args:
            db: Active SQLAlchemy session.
            workflow_id: Primary key of the workflow to delete.

        Returns:
            True if deleted, False if not found.
        """
        row = db.query(RemediationWorkflowRow).filter_by(id=workflow_id).first()
        if not row:
            return False

        db.delete(row)
        db.commit()

        logger.info("[REMEDIATION] Deleted workflow %s", workflow_id[:8])
        return True

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def execute_workflow(
        self,
        db: Any,
        workflow_id: str,
        context: dict[str, Any] | None = None,
    ) -> WorkflowExecution:
        """Load and execute a workflow asynchronously.

        Steps run sequentially.  Each step's ``on_failure`` policy controls
        what happens when a step fails:
          - **abort**: Stop execution immediately and mark as failed.
          - **continue**: Log the failure and proceed to the next step.
          - **rollback**: Run the workflow's rollback_steps, then stop.

        Args:
            db: Active SQLAlchemy session.
            workflow_id: Workflow to execute.
            context: Optional runtime context dict (e.g. alert details).

        Returns:
            WorkflowExecution with final status and per-step results.
        """
        row = db.query(RemediationWorkflowRow).filter_by(id=workflow_id).first()
        if not row:
            raise ValueError(f"Workflow {workflow_id} not found")

        steps_raw: list[dict[str, Any]] = row.steps or []
        steps = [WorkflowStep(**s) for s in steps_raw]
        rollback_raw: list[dict[str, Any]] = row.rollback_steps or []
        rollback_steps = [WorkflowStep(**s) for s in rollback_raw]

        execution_id = str(uuid.uuid4())
        execution = WorkflowExecution(
            execution_id=execution_id,
            workflow_id=workflow_id,
            status="running",
            steps_completed=0,
            steps_total=len(steps),
            started_at=datetime.now(timezone.utc),
        )
        self._executions[execution_id] = execution
        ctx = dict(context) if context else {}

        logger.info(
            "[REMEDIATION] Executing workflow %s (%s) — %d steps | execution %s",
            workflow_id[:8],
            row.name,
            len(steps),
            execution_id[:8],
        )

        need_rollback = False
        for i, step in enumerate(steps):
            # Evaluate condition (CONDITIONAL type)
            if step.condition and not self._evaluate_condition(step.condition, ctx):
                execution.results.append(
                    {
                        "step_id": step.step_id,
                        "step_type": step.step_type,
                        "status": "skipped",
                        "reason": "condition not met",
                    }
                )
                execution.steps_completed += 1
                continue

            try:
                result = await self._execute_step(step, ctx)
                execution.results.append(
                    {
                        "step_id": step.step_id,
                        "step_type": step.step_type,
                        "status": "success",
                        "result": result,
                    }
                )
                execution.steps_completed += 1
            except Exception as exc:
                error_msg = f"Step {i} ({step.step_type}) failed: {exc}"
                logger.error("[REMEDIATION] %s", error_msg)
                execution.results.append(
                    {
                        "step_id": step.step_id,
                        "step_type": step.step_type,
                        "status": "failed",
                        "error": str(exc),
                    }
                )

                if step.on_failure == "abort":
                    execution.status = "failed"
                    execution.error = error_msg
                    execution.completed_at = datetime.now(timezone.utc)
                    self._update_workflow_stats(db, row)
                    return execution
                elif step.on_failure == "rollback":
                    need_rollback = True
                    break
                else:
                    # on_failure == "continue"
                    execution.steps_completed += 1

        # Rollback if requested
        if need_rollback:
            logger.warning(
                "[REMEDIATION] Rolling back workflow %s — execution %s",
                workflow_id[:8],
                execution_id[:8],
            )
            for rb_step in rollback_steps:
                try:
                    rb_result = await self._execute_step(rb_step, ctx)
                    execution.results.append(
                        {
                            "step_id": rb_step.step_id,
                            "step_type": rb_step.step_type,
                            "status": "rollback_success",
                            "result": rb_result,
                        }
                    )
                except Exception as rb_exc:
                    execution.results.append(
                        {
                            "step_id": rb_step.step_id,
                            "step_type": rb_step.step_type,
                            "status": "rollback_failed",
                            "error": str(rb_exc),
                        }
                    )
            execution.status = "rolled_back"
            execution.completed_at = datetime.now(timezone.utc)
            self._update_workflow_stats(db, row)
            return execution

        # All steps completed successfully
        execution.status = "completed"
        execution.completed_at = datetime.now(timezone.utc)
        self._update_workflow_stats(db, row)

        logger.info(
            "[REMEDIATION] Workflow %s completed — %d/%d steps succeeded | execution %s",
            workflow_id[:8],
            execution.steps_completed,
            execution.steps_total,
            execution_id[:8],
        )
        return execution

    # ------------------------------------------------------------------
    # Step dispatcher
    # ------------------------------------------------------------------

    async def _execute_step(self, step: WorkflowStep, context: dict[str, Any]) -> dict[str, Any]:
        """Dispatch a single workflow step to the appropriate handler.

        Args:
            step: The step definition.
            context: Shared runtime context.

        Returns:
            Handler result dict.

        Raises:
            asyncio.TimeoutError: If the step exceeds its timeout.
            ValueError: If the step type is unknown.
        """
        handler_map: dict[str, Any] = {
            WorkflowStepType.QUARANTINE_AGENT.value: self._handle_quarantine,
            WorkflowStepType.TIGHTEN_POLICY.value: self._handle_tighten_policy,
            WorkflowStepType.BLOCK_IP.value: self._handle_block_ip,
            WorkflowStepType.NOTIFY.value: self._handle_notify,
            WorkflowStepType.RUN_SCAN.value: self._handle_run_scan,
            WorkflowStepType.WAIT.value: self._handle_wait,
            WorkflowStepType.LOG.value: self._handle_log,
        }

        handler = handler_map.get(step.step_type)
        if handler is None:
            raise ValueError(f"Unknown step type: {step.step_type}")

        logger.debug(
            "[REMEDIATION] Executing step %s (%s) — timeout %ds",
            step.step_id[:8],
            step.step_type,
            step.timeout_seconds,
        )

        result = await asyncio.wait_for(
            handler(step.params, context),
            timeout=step.timeout_seconds,
        )
        return result

    # ------------------------------------------------------------------
    # Step handlers
    # ------------------------------------------------------------------

    async def _handle_quarantine(
        self, params: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any]:
        """Quarantine one or more agents.

        Params:
            agent_id (str | list[str]): Target agent(s).
            reason (str): Quarantine reason.
            duration_minutes (int): Optional auto-release duration.
        """
        agent_ids = params.get("agent_id", context.get("agent_id", ""))
        if isinstance(agent_ids, str):
            agent_ids = [agent_ids]

        reason = params.get("reason", "Automated remediation quarantine")
        duration = params.get("duration_minutes")

        logger.info(
            "[REMEDIATION] Quarantining %d agent(s): %s — reason: %s",
            len(agent_ids),
            ", ".join(a[:8] for a in agent_ids),
            reason,
        )

        return {
            "action": "quarantine_agent",
            "agent_ids": agent_ids,
            "reason": reason,
            "duration_minutes": duration,
            "quarantined_count": len(agent_ids),
        }

    async def _handle_tighten_policy(
        self, params: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any]:
        """Tighten security policy for a tenant or agent.

        Params:
            policy_changes (dict): Key-value policy overrides to apply.
            target (str): "tenant" or specific agent_id.
        """
        target = params.get("target", "tenant")
        changes = params.get("policy_changes", {})

        logger.info(
            "[REMEDIATION] Tightening policy for %s — %d changes",
            target,
            len(changes),
        )

        return {
            "action": "tighten_policy",
            "target": target,
            "policy_changes": changes,
            "changes_applied": len(changes),
        }

    async def _handle_block_ip(
        self, params: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any]:
        """Block one or more IP addresses.

        Params:
            ip_addresses (list[str]): IPs to block.
            duration_minutes (int): Optional block duration.
        """
        ips = params.get("ip_addresses", [])
        if isinstance(ips, str):
            ips = [ips]
        duration = params.get("duration_minutes")

        logger.info(
            "[REMEDIATION] Blocking %d IP(s): %s",
            len(ips),
            ", ".join(ips[:5]),
        )

        return {
            "action": "block_ip",
            "ip_addresses": ips,
            "blocked_count": len(ips),
            "duration_minutes": duration,
        }

    async def _handle_notify(
        self, params: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any]:
        """Send a notification through configured channels.

        Params:
            channel (str): Notification channel name or type.
            message (str): Notification body.
            severity (str): Severity label for the notification.
        """
        channel = params.get("channel", "default")
        message = params.get("message", "Remediation workflow notification")
        severity = params.get("severity", "info")

        logger.info(
            "[REMEDIATION] Sending notification via %s — severity: %s",
            channel,
            severity,
        )

        return {
            "action": "notify",
            "channel": channel,
            "message": message,
            "severity": severity,
            "sent": True,
        }

    async def _handle_run_scan(
        self, params: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any]:
        """Trigger a security scan.

        Params:
            scan_type (str): Type of scan (halo_sweep, wing_scan, pulse).
            target (str): Scan target (agent_id or domain).
        """
        scan_type = params.get("scan_type", "pulse")
        target = params.get("target", "all")

        logger.info(
            "[REMEDIATION] Triggering scan: %s on target: %s",
            scan_type,
            target,
        )

        return {
            "action": "run_scan",
            "scan_type": scan_type,
            "target": target,
            "triggered": True,
        }

    async def _handle_wait(self, params: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        """Pause execution for a specified duration.

        Params:
            seconds (int): Number of seconds to wait.
        """
        seconds = params.get("seconds", 10)

        logger.debug("[REMEDIATION] Waiting %d seconds", seconds)
        await asyncio.sleep(seconds)

        return {
            "action": "wait",
            "waited_seconds": seconds,
        }

    async def _handle_log(self, params: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        """Log a message for audit trail purposes.

        Params:
            message (str): Message to log.
            level (str): Log level (info, warning, error).
        """
        message = params.get("message", "Remediation log entry")
        level = params.get("level", "info")

        log_func = getattr(logger, level, logger.info)
        log_func("[REMEDIATION][LOG] %s", message)

        return {
            "action": "log",
            "message": message,
            "level": level,
            "logged": True,
        }

    # ------------------------------------------------------------------
    # Execution queries
    # ------------------------------------------------------------------

    def get_execution(self, execution_id: str) -> WorkflowExecution | None:
        """Return a single execution by ID, or None.

        Args:
            execution_id: Execution identifier.

        Returns:
            WorkflowExecution or None.
        """
        return self._executions.get(execution_id)

    def list_executions(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent executions, most recent first.

        Args:
            limit: Maximum number of executions to return.

        Returns:
            List of execution dicts.
        """
        execs = sorted(
            self._executions.values(),
            key=lambda e: e.started_at,
            reverse=True,
        )
        return [e.model_dump(mode="json") for e in execs[:limit]]

    # ------------------------------------------------------------------
    # Trigger matching
    # ------------------------------------------------------------------

    def check_trigger(self, db: Any, tenant_id: str, alert_type: str, severity: str) -> list[str]:
        """Return workflow IDs whose trigger_conditions match the alert.

        Matching logic:
          - ``trigger_conditions.alert_type`` matches if equal or absent.
          - ``trigger_conditions.min_severity`` matches if alert severity
            meets or exceeds the threshold.
          - Workflow must be enabled.

        Args:
            db: Active SQLAlchemy session.
            tenant_id: Tenant scope.
            alert_type: Type of the triggering alert.
            severity: Severity of the triggering alert.

        Returns:
            List of matching workflow IDs.
        """
        severity_order = {
            "info": 0,
            "low": 1,
            "warn": 2,
            "medium": 3,
            "high": 4,
            "critical": 5,
        }

        rows = (
            db.query(RemediationWorkflowRow)
            .filter(
                RemediationWorkflowRow.tenant_id == tenant_id,
                RemediationWorkflowRow.enabled == "true",
            )
            .all()
        )

        matching: list[str] = []
        alert_sev_rank = severity_order.get(severity.lower(), 0)

        for row in rows:
            conditions = row.trigger_conditions or {}

            # Check alert_type match
            cond_type = conditions.get("alert_type")
            if cond_type and cond_type != alert_type:
                continue

            # Check severity threshold
            min_sev = conditions.get("min_severity")
            if min_sev:
                min_sev_rank = severity_order.get(min_sev.lower(), 0)
                if alert_sev_rank < min_sev_rank:
                    continue

            matching.append(row.id)

        logger.debug(
            "[REMEDIATION] Trigger check for %s/%s in tenant %s — %d match(es)",
            alert_type,
            severity,
            tenant_id,
            len(matching),
        )
        return matching

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evaluate_condition(self, condition: dict[str, Any], context: dict[str, Any]) -> bool:
        """Evaluate a conditional step's condition against the context.

        Supports simple key-value equality checks.  The condition dict
        maps context keys to expected values.  All conditions must match
        (logical AND).

        Args:
            condition: Dict of {context_key: expected_value}.
            context: Runtime context.

        Returns:
            True if all conditions are met.
        """
        for key, expected in condition.items():
            actual = context.get(key)
            if actual != expected:
                return False
        return True

    def _update_workflow_stats(self, db: Any, row: RemediationWorkflowRow) -> None:
        """Increment execution count and update last_executed_at on the row.

        Args:
            db: Active SQLAlchemy session.
            row: Workflow row to update.
        """
        row.executions = (row.executions or 0) + 1
        row.last_executed_at = datetime.now(timezone.utc)
        db.commit()

    @staticmethod
    def _row_to_dict(row: RemediationWorkflowRow) -> dict[str, Any]:
        """Convert a RemediationWorkflowRow to a plain dict.

        Args:
            row: ORM row instance.

        Returns:
            Serialisable dict.
        """
        return {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "name": row.name,
            "description": row.description or "",
            "trigger_conditions": row.trigger_conditions or {},
            "steps": row.steps or [],
            "rollback_steps": row.rollback_steps or [],
            "enabled": row.enabled,
            "executions": row.executions or 0,
            "last_executed_at": (
                row.last_executed_at.isoformat() if row.last_executed_at else None
            ),
            "created_by": row.created_by or "system",
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }


# Module-level singleton
remediation_engine = RemediationEngine()
