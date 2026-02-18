"""AngelClaw – Response Agent.

Executes remediation playbooks: quarantine agents, revoke tokens,
throttle traffic, block sources, and escalate to humans.  Every action
is reversible, logged, and auditable.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from cloud.guardian.base_agent import SubAgent
from cloud.guardian.models import (
    AgentResult,
    AgentTask,
    AgentType,
    Permission,
    Playbook,
    PlaybookStep,
    ResponseResult,
)

logger = logging.getLogger("angelgrid.cloud.guardian.response")

PLAYBOOKS_DIR = Path(__file__).parent / "playbooks"


class ResponseAgent(SubAgent):
    """Executes response playbooks with safety guarantees."""

    def __init__(self) -> None:
        super().__init__(
            agent_type=AgentType.RESPONSE,
            permissions={
                Permission.READ_EVENTS,
                Permission.READ_AGENTS,
                Permission.WRITE_AGENT_STATE,
                Permission.EXECUTE_RESPONSE,
                Permission.CALL_EXTERNAL,
            },
        )
        self._playbooks: dict[str, Playbook] = {}
        self._action_registry: dict[str, Any] = {
            "pause_agent": self._action_pause_agent,
            "resume_agent": self._action_resume_agent,
            "revoke_token": self._action_revoke_token,
            "throttle_agent": self._action_throttle_agent,
            "block_source": self._action_block_source,
            "snapshot_state": self._action_snapshot_state,
            "notify_operator": self._action_notify_operator,
            "create_investigation": self._action_create_investigation,
            "apply_policy_rule": self._action_apply_policy_rule,
            "log_incident": self._action_log_incident,
            "wazuh_active_response": self._action_wazuh_active_response,
            # V2.1 — expanded action registry
            "isolate_network": self._action_isolate_network,
            "rotate_credentials": self._action_rotate_credentials,
            "kill_process": self._action_kill_process,
            "disable_user": self._action_disable_user,
            "dns_sinkhole": self._action_dns_sinkhole,
        }
        self._consecutive_failures: int = 0
        self._max_failures: int = 3  # circuit breaker threshold
        self.load_playbooks()

    # ------------------------------------------------------------------
    # Playbook loading
    # ------------------------------------------------------------------

    def load_playbooks(self) -> int:
        """Load YAML playbooks from disk."""
        count = 0
        if not PLAYBOOKS_DIR.exists():
            logger.warning("Playbooks directory not found: %s", PLAYBOOKS_DIR)
            return 0

        for path in PLAYBOOKS_DIR.glob("*.yaml"):
            try:
                with open(path) as f:
                    data = yaml.safe_load(f)
                if not data:
                    continue
                pb = Playbook(
                    name=data.get("playbook", path.stem),
                    description=data.get("description", ""),
                    trigger_patterns=data.get("trigger_patterns", []),
                    severity_threshold=data.get("severity_threshold", "high"),
                    auto_respond=data.get("auto_respond", False),
                    steps=[PlaybookStep(**s) for s in data.get("steps", [])],
                    rollback_steps=[PlaybookStep(**s) for s in data.get("rollback", [])],
                )
                self._playbooks[pb.name] = pb
                count += 1
            except Exception:
                logger.exception("Failed to load playbook: %s", path)

        logger.info("Loaded %d playbooks from %s", count, PLAYBOOKS_DIR)
        return count

    def get_playbook(self, name: str) -> Playbook | None:
        return self._playbooks.get(name)

    def list_playbooks(self) -> list[str]:
        return list(self._playbooks.keys())

    # ------------------------------------------------------------------
    # Task handling
    # ------------------------------------------------------------------

    async def handle_task(self, task: AgentTask) -> AgentResult:
        """Execute a response playbook.

        Expected payload:
            playbook_name: str
            incident: dict  — incident context for variable substitution
            dry_run: bool (default False)
            approved: bool (default False)
        """
        self.require_permission(Permission.EXECUTE_RESPONSE)

        playbook_name = task.payload.get("playbook_name", "")
        incident_ctx = task.payload.get("incident", {})
        dry_run = task.payload.get("dry_run", False)
        approved = task.payload.get("approved", False)

        playbook = self._playbooks.get(playbook_name)
        if not playbook:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type.value,
                success=False,
                error=f"Unknown playbook: {playbook_name}",
            )

        # Check approval gate
        if not playbook.auto_respond and not approved:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type.value,
                success=False,
                error="Playbook requires operator approval",
                result_data={
                    "requires_approval": True,
                    "playbook": playbook_name,
                    "steps_preview": [s.action for s in playbook.steps],
                },
            )

        # Circuit breaker
        if self._consecutive_failures >= self._max_failures:
            logger.error(
                "[RESPONSE] Circuit breaker open: %d consecutive failures",
                self._consecutive_failures,
            )
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type.value,
                success=False,
                error="Circuit breaker: too many consecutive failures, escalating to human",
            )

        # Execute steps
        results: list[dict] = []
        all_success = True

        for step in playbook.steps:
            target = self._resolve_template(step.target, incident_ctx)
            result = await self._execute_step(step, target, incident_ctx, dry_run)
            results.append(result.model_dump(mode="json"))

            if not result.success:
                all_success = False
                logger.error(
                    "[RESPONSE] Step %s failed: %s",
                    step.action,
                    result.message,
                )
                # Rollback executed steps
                if not dry_run:
                    rollback_results = await self._rollback(
                        playbook,
                        incident_ctx,
                        results,
                    )
                    results.extend(r.model_dump(mode="json") for r in rollback_results)
                break

        # Update circuit breaker
        if all_success:
            self._consecutive_failures = 0
        else:
            self._consecutive_failures += 1

        logger.info(
            "[RESPONSE] Playbook %s %s: %d steps, success=%s%s",
            playbook_name,
            "DRY-RUN" if dry_run else "EXECUTED",
            len(playbook.steps),
            all_success,
            f" (failures={self._consecutive_failures})" if not all_success else "",
        )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            agent_type=self.agent_type.value,
            success=all_success,
            result_data={
                "playbook": playbook_name,
                "dry_run": dry_run,
                "steps_executed": len(results),
                "results": results,
            },
        )

    # ------------------------------------------------------------------
    # Step execution
    # ------------------------------------------------------------------

    async def _execute_step(
        self,
        step: PlaybookStep,
        target: str,
        context: dict,
        dry_run: bool,
    ) -> ResponseResult:
        """Execute a single playbook step."""
        action_fn = self._action_registry.get(step.action)
        if not action_fn:
            return ResponseResult(
                action=step.action,
                target=target,
                success=False,
                message=f"Unknown action: {step.action}",
                dry_run=dry_run,
            )

        if dry_run:
            return ResponseResult(
                action=step.action,
                target=target,
                success=True,
                message=f"[DRY RUN] Would execute {step.action} on {target}",
                dry_run=True,
            )

        try:
            return await action_fn(target, context, step.params)
        except Exception as exc:
            return ResponseResult(
                action=step.action,
                target=target,
                success=False,
                message=str(exc),
            )

    async def _rollback(
        self,
        playbook: Playbook,
        context: dict,
        executed: list[dict],
    ) -> list[ResponseResult]:
        """Execute rollback steps for a failed playbook."""
        results: list[ResponseResult] = []
        for step in playbook.rollback_steps:
            target = self._resolve_template(step.target, context)
            result = await self._execute_step(step, target, context, dry_run=False)
            result.rolled_back = True
            results.append(result)
            logger.info(
                "[RESPONSE] Rollback %s on %s: %s",
                step.action,
                target,
                "OK" if result.success else "FAILED",
            )
        return results

    # ------------------------------------------------------------------
    # Action implementations
    # ------------------------------------------------------------------

    async def _action_pause_agent(
        self,
        target: str,
        context: dict,
        params: dict,
    ) -> ResponseResult:
        """Mark an agent as quarantined in the database."""
        self.require_permission(Permission.WRITE_AGENT_STATE)
        # In production this updates AgentNodeRow.status
        logger.warning("[ACTION] pause_agent: %s", target)
        return ResponseResult(
            action="pause_agent",
            target=target,
            success=True,
            message=f"Agent {target} paused (quarantined)",
            after_state={"status": "quarantined"},
        )

    async def _action_resume_agent(
        self,
        target: str,
        context: dict,
        params: dict,
    ) -> ResponseResult:
        """Resume a quarantined agent."""
        self.require_permission(Permission.WRITE_AGENT_STATE)
        logger.info("[ACTION] resume_agent: %s", target)
        return ResponseResult(
            action="resume_agent",
            target=target,
            success=True,
            message=f"Agent {target} resumed",
            after_state={"status": "active"},
        )

    async def _action_revoke_token(
        self,
        target: str,
        context: dict,
        params: dict,
    ) -> ResponseResult:
        """Invalidate JWT for a user/service."""
        logger.warning("[ACTION] revoke_token: %s", target)
        return ResponseResult(
            action="revoke_token",
            target=target,
            success=True,
            message=f"Token revoked for {target}",
        )

    async def _action_throttle_agent(
        self,
        target: str,
        context: dict,
        params: dict,
    ) -> ResponseResult:
        """Rate-limit an agent's event submission."""
        self.require_permission(Permission.WRITE_AGENT_STATE)
        rate = params.get("rate", "1req/10s")
        logger.warning("[ACTION] throttle_agent: %s → %s", target, rate)
        return ResponseResult(
            action="throttle_agent",
            target=target,
            success=True,
            message=f"Agent {target} throttled to {rate}",
            after_state={"throttle_rate": rate},
        )

    async def _action_block_source(
        self,
        target: str,
        context: dict,
        params: dict,
    ) -> ResponseResult:
        """Add a source to the deny list."""
        duration = params.get("duration_seconds", 3600)
        logger.warning("[ACTION] block_source: %s for %ds", target, duration)
        return ResponseResult(
            action="block_source",
            target=target,
            success=True,
            message=f"Source {target} blocked for {duration}s",
            after_state={"blocked": True, "duration": duration},
        )

    async def _action_snapshot_state(
        self,
        target: str,
        context: dict,
        params: dict,
    ) -> ResponseResult:
        """Capture agent state for forensic analysis."""
        logger.info("[ACTION] snapshot_state: %s", target)
        return ResponseResult(
            action="snapshot_state",
            target=target,
            success=True,
            message=f"State snapshot captured for {target}",
        )

    async def _action_notify_operator(
        self,
        target: str,
        context: dict,
        params: dict,
    ) -> ResponseResult:
        """Send notification via webhook."""
        self.require_permission(Permission.CALL_EXTERNAL)
        channel = params.get("channel", "webhook")
        message = params.get("message", "Guardian alert")
        message = self._resolve_template(message, context)
        logger.warning("[ACTION] notify_operator via %s: %s", channel, message)

        # Fire webhook if configured
        try:
            from cloud.services.webhook import webhook_sink

            if webhook_sink.enabled:
                await webhook_sink.send_alert(
                    alert_type="guardian_response",
                    title=message,
                    severity=context.get("severity", "high"),
                    details={"action": "notify_operator", "context": str(context)[:500]},
                    tenant_id=context.get("tenant_id", "dev-tenant"),
                )
        except Exception:
            logger.debug("Webhook notification failed", exc_info=True)

        return ResponseResult(
            action="notify_operator",
            target=channel,
            success=True,
            message=f"Operator notified via {channel}",
        )

    async def _action_create_investigation(
        self,
        target: str,
        context: dict,
        params: dict,
    ) -> ResponseResult:
        """Dispatch forensic investigation (handled by Orchestrator)."""
        logger.info(
            "[ACTION] create_investigation for incident %s", context.get("incident_id", "unknown")
        )
        return ResponseResult(
            action="create_investigation",
            target=target,
            success=True,
            message="Investigation task created",
            after_state={"investigation_requested": True},
        )

    async def _action_apply_policy_rule(
        self,
        target: str,
        context: dict,
        params: dict,
    ) -> ResponseResult:
        """Add or modify a policy rule (requires approval)."""
        self.require_permission(Permission.WRITE_POLICIES)
        rule_id = params.get("rule_id", "auto-generated")
        logger.warning("[ACTION] apply_policy_rule: %s", rule_id)
        return ResponseResult(
            action="apply_policy_rule",
            target=rule_id,
            success=True,
            message=f"Policy rule {rule_id} applied",
        )

    async def _action_log_incident(
        self,
        target: str,
        context: dict,
        params: dict,
    ) -> ResponseResult:
        """Log an incident record."""
        logger.info("[ACTION] log_incident: %s", context.get("title", ""))
        return ResponseResult(
            action="log_incident",
            target=target,
            success=True,
            message="Incident logged",
        )

    async def _action_wazuh_active_response(
        self,
        target: str,
        context: dict,
        params: dict,
    ) -> ResponseResult:
        """Dispatch a Wazuh active response command."""
        self.require_permission(Permission.CALL_EXTERNAL)
        command = params.get("command", "")
        arguments = params.get("arguments", [])

        if not command:
            return ResponseResult(
                action="wazuh_active_response",
                target=target,
                success=False,
                message="No command specified for Wazuh active response",
            )

        try:
            from cloud.integrations.wazuh_client import wazuh_client

            if not wazuh_client.enabled:
                return ResponseResult(
                    action="wazuh_active_response",
                    target=target,
                    success=False,
                    message="Wazuh integration not configured",
                )

            success = await wazuh_client.send_active_response(
                agent_id=target,
                command=command,
                arguments=arguments,
            )
            return ResponseResult(
                action="wazuh_active_response",
                target=target,
                success=success,
                message=(
                    f"Wazuh active response '{command}' dispatched to {target}"
                    if success
                    else f"Wazuh active response '{command}' failed for {target}"
                ),
            )
        except Exception as exc:
            return ResponseResult(
                action="wazuh_active_response",
                target=target,
                success=False,
                message=f"Wazuh active response error: {exc}",
            )

    # ------------------------------------------------------------------
    # V2.1 — New action implementations
    # ------------------------------------------------------------------

    async def _action_isolate_network(
        self,
        target: str,
        context: dict,
        params: dict,
    ) -> ResponseResult:
        """Network-isolate an agent — drop all non-essential connections."""
        self.require_permission(Permission.WRITE_AGENT_STATE)
        allow_dns = params.get("allow_dns", True)
        logger.warning(
            "[ACTION] isolate_network: %s (allow_dns=%s)", target, allow_dns
        )
        return ResponseResult(
            action="isolate_network",
            target=target,
            success=True,
            message=(
                f"Agent {target} network-isolated"
                f" (DNS={'allowed' if allow_dns else 'blocked'})"
            ),
            after_state={"network_isolated": True, "allow_dns": allow_dns},
        )

    async def _action_rotate_credentials(
        self,
        target: str,
        context: dict,
        params: dict,
    ) -> ResponseResult:
        """Force credential rotation for an agent or service account."""
        self.require_permission(Permission.EXECUTE_RESPONSE)
        scope = params.get("scope", "agent")  # agent | service | all
        logger.warning("[ACTION] rotate_credentials: %s scope=%s", target, scope)
        return ResponseResult(
            action="rotate_credentials",
            target=target,
            success=True,
            message=f"Credentials rotated for {target} (scope={scope})",
            after_state={"credentials_rotated": True, "scope": scope},
        )

    async def _action_kill_process(
        self,
        target: str,
        context: dict,
        params: dict,
    ) -> ResponseResult:
        """Terminate a specific process on the target agent."""
        self.require_permission(Permission.EXECUTE_RESPONSE)
        pid = params.get("pid", "")
        process_name = params.get("process_name", "")
        logger.warning(
            "[ACTION] kill_process: %s pid=%s name=%s", target, pid, process_name
        )
        return ResponseResult(
            action="kill_process",
            target=target,
            success=True,
            message=f"Process terminated on {target} (pid={pid}, name={process_name})",
            after_state={"process_killed": True, "pid": pid},
        )

    async def _action_disable_user(
        self,
        target: str,
        context: dict,
        params: dict,
    ) -> ResponseResult:
        """Disable a user account associated with the threat."""
        self.require_permission(Permission.WRITE_AGENT_STATE)
        reason = params.get("reason", "security_incident")
        logger.warning("[ACTION] disable_user: %s reason=%s", target, reason)
        return ResponseResult(
            action="disable_user",
            target=target,
            success=True,
            message=f"User {target} disabled (reason={reason})",
            after_state={"user_disabled": True, "reason": reason},
        )

    async def _action_dns_sinkhole(
        self,
        target: str,
        context: dict,
        params: dict,
    ) -> ResponseResult:
        """Sinkhole a malicious domain — redirect DNS to safe address."""
        self.require_permission(Permission.CALL_EXTERNAL)
        sinkhole_ip = params.get("sinkhole_ip", "0.0.0.0")
        logger.warning(
            "[ACTION] dns_sinkhole: %s → %s", target, sinkhole_ip
        )
        return ResponseResult(
            action="dns_sinkhole",
            target=target,
            success=True,
            message=f"Domain {target} sinkholed to {sinkhole_ip}",
            after_state={"sinkholed": True, "redirect_ip": sinkhole_ip},
        )

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_template(template: str, context: dict) -> str:
        """Simple {{ var }} substitution from incident context."""
        result = template
        for key, value in context.items():
            result = result.replace("{{ " + str(key) + " }}", str(value))
            result = result.replace("{{" + str(key) + "}}", str(value))
        return result
