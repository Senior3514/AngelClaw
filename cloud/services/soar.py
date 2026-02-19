"""AngelClaw V4.0 — Omniscience: SOAR Engine.

Security Orchestration, Automation and Response engine with trigger-based
playbook execution, priority queuing, and rate limiting.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.soar")


class SOARPlaybook(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    name: str
    description: str = ""
    trigger_type: str  # alert, event_pattern, schedule, manual, ioc_match
    trigger_config: dict[str, Any] = {}
    actions: list[dict[str, Any]] = []
    enabled: bool = True
    priority: int = 5
    max_executions_per_hour: int = 10
    executions_total: int = 0
    last_executed_at: datetime | None = None
    created_by: str = "system"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SOARExecution(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    playbook_id: str
    tenant_id: str = "dev-tenant"
    status: str = "running"  # running, completed, failed, aborted
    trigger_context: dict[str, Any] = {}
    action_results: list[dict[str, Any]] = []
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    error: str | None = None


class SOAREngine:
    """SOAR engine with playbook management and execution."""

    def __init__(self) -> None:
        self._playbooks: dict[str, SOARPlaybook] = {}
        self._executions: dict[str, SOARExecution] = {}
        self._tenant_playbooks: dict[str, list[str]] = defaultdict(list)
        self._hourly_counts: dict[str, int] = defaultdict(int)  # playbook_id -> executions this hour

    def create_playbook(
        self,
        tenant_id: str,
        name: str,
        trigger_type: str,
        trigger_config: dict | None = None,
        actions: list[dict] | None = None,
        description: str = "",
        priority: int = 5,
        max_executions_per_hour: int = 10,
        created_by: str = "system",
    ) -> dict:
        pb = SOARPlaybook(
            tenant_id=tenant_id,
            name=name,
            trigger_type=trigger_type,
            trigger_config=trigger_config or {},
            actions=actions or [],
            description=description,
            priority=priority,
            max_executions_per_hour=max_executions_per_hour,
            created_by=created_by,
        )
        self._playbooks[pb.id] = pb
        self._tenant_playbooks[tenant_id].append(pb.id)
        logger.info("[SOAR] Created playbook '%s' trigger=%s for %s", name, trigger_type, tenant_id)
        return pb.model_dump(mode="json")

    def get_playbook(self, playbook_id: str) -> dict | None:
        pb = self._playbooks.get(playbook_id)
        return pb.model_dump(mode="json") if pb else None

    def list_playbooks(self, tenant_id: str, trigger_type: str | None = None) -> list[dict]:
        results = []
        for pid in self._tenant_playbooks.get(tenant_id, []):
            pb = self._playbooks.get(pid)
            if not pb:
                continue
            if trigger_type and pb.trigger_type != trigger_type:
                continue
            results.append(pb.model_dump(mode="json"))
        results.sort(key=lambda p: p.get("priority", 5))
        return results

    def toggle_playbook(self, playbook_id: str, enabled: bool) -> dict | None:
        pb = self._playbooks.get(playbook_id)
        if not pb:
            return None
        pb.enabled = enabled
        return pb.model_dump(mode="json")

    def delete_playbook(self, playbook_id: str) -> bool:
        pb = self._playbooks.pop(playbook_id, None)
        if not pb:
            return False
        self._tenant_playbooks[pb.tenant_id] = [
            p for p in self._tenant_playbooks[pb.tenant_id] if p != playbook_id
        ]
        return True

    def execute_playbook(
        self,
        playbook_id: str,
        trigger_context: dict | None = None,
    ) -> dict:
        pb = self._playbooks.get(playbook_id)
        if not pb:
            return {"error": "Playbook not found"}
        if not pb.enabled:
            return {"error": "Playbook is disabled"}

        # Rate limiting
        if self._hourly_counts[playbook_id] >= pb.max_executions_per_hour:
            return {"error": "Rate limit exceeded for this playbook"}

        execution = SOARExecution(
            playbook_id=playbook_id,
            tenant_id=pb.tenant_id,
            trigger_context=trigger_context or {},
        )

        # Execute each action step
        for i, action in enumerate(pb.actions):
            action_type = action.get("type", "log")
            try:
                result = self._execute_action(action_type, action, trigger_context or {})
                execution.action_results.append({
                    "step": i + 1,
                    "type": action_type,
                    "status": "completed",
                    "result": result,
                })
            except Exception as exc:
                execution.action_results.append({
                    "step": i + 1,
                    "type": action_type,
                    "status": "failed",
                    "error": str(exc),
                })
                if action.get("on_failure", "abort") == "abort":
                    execution.status = "failed"
                    execution.error = f"Step {i + 1} failed: {exc}"
                    break

        if execution.status != "failed":
            execution.status = "completed"
        execution.completed_at = datetime.now(timezone.utc)

        self._executions[execution.id] = execution
        pb.executions_total += 1
        pb.last_executed_at = datetime.now(timezone.utc)
        self._hourly_counts[playbook_id] += 1

        logger.info("[SOAR] Executed playbook '%s': %s", pb.name, execution.status)
        return execution.model_dump(mode="json")

    def check_triggers(self, tenant_id: str, event_context: dict) -> list[str]:
        """Check which playbooks should be triggered by an event."""
        triggered = []
        for pid in self._tenant_playbooks.get(tenant_id, []):
            pb = self._playbooks.get(pid)
            if not pb or not pb.enabled:
                continue
            if self._matches_trigger(pb, event_context):
                triggered.append(pb.id)
        return triggered

    def get_execution(self, execution_id: str) -> dict | None:
        ex = self._executions.get(execution_id)
        return ex.model_dump(mode="json") if ex else None

    def list_executions(self, tenant_id: str, limit: int = 50) -> list[dict]:
        results = [
            ex.model_dump(mode="json")
            for ex in self._executions.values()
            if ex.tenant_id == tenant_id
        ]
        results.sort(key=lambda e: e.get("started_at", ""), reverse=True)
        return results[:limit]

    def get_stats(self, tenant_id: str) -> dict:
        playbooks = [
            self._playbooks[p] for p in self._tenant_playbooks.get(tenant_id, [])
            if p in self._playbooks
        ]
        execs = [e for e in self._executions.values() if e.tenant_id == tenant_id]
        return {
            "total_playbooks": len(playbooks),
            "enabled_playbooks": sum(1 for p in playbooks if p.enabled),
            "total_executions": len(execs),
            "successful": sum(1 for e in execs if e.status == "completed"),
            "failed": sum(1 for e in execs if e.status == "failed"),
        }

    def _matches_trigger(self, playbook: SOARPlaybook, context: dict) -> bool:
        tc = playbook.trigger_config
        if playbook.trigger_type == "alert":
            if tc.get("alert_type") and context.get("alert_type") != tc["alert_type"]:
                return False
            if tc.get("min_severity"):
                sev_order = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
                if sev_order.get(context.get("severity", "info"), 1) < sev_order.get(tc["min_severity"], 1):
                    return False
            return True
        elif playbook.trigger_type == "ioc_match":
            return context.get("event_type") == "ioc_match"
        elif playbook.trigger_type == "event_pattern":
            req_category = tc.get("category")
            if req_category and context.get("category") != req_category:
                return False
            return True
        return False

    def _execute_action(self, action_type: str, action: dict, context: dict) -> dict:
        """Execute a single SOAR action step."""
        if action_type == "log":
            return {"message": action.get("message", "SOAR action logged")}
        elif action_type == "quarantine":
            return {"agent_id": action.get("agent_id", context.get("agent_id")), "quarantined": True}
        elif action_type == "notify":
            return {"channel": action.get("channel", "default"), "notified": True}
        elif action_type == "block_ip":
            return {"ip": action.get("ip", context.get("source_ip")), "blocked": True}
        elif action_type == "enrich":
            return {"enriched": True, "source": action.get("source", "threat_intel")}
        elif action_type == "run_scan":
            return {"scan_triggered": True}
        elif action_type == "create_incident":
            return {"incident_created": True}
        else:
            return {"action": action_type, "status": "executed"}


# Module-level singleton
soar_engine = SOAREngine()
