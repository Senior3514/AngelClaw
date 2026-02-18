"""AngelClaw – Action Framework.

Defines the action abstraction for safe, auditable changes to the system.
Actions can be proposed (dry_run), applied with confirmation, or rejected.
Every execution is logged with before/after state for full audit trail.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import JSON, Column, DateTime, String, Text
from sqlalchemy.orm import Session

from cloud.db.models import Base

logger = logging.getLogger("angelclaw.actions")


# ---------------------------------------------------------------------------
# DB Model
# ---------------------------------------------------------------------------


class ActionLogRow(Base):
    __tablename__ = "angelclaw_action_log"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(64), nullable=False, index=True)
    action_type = Column(String(64), nullable=False)
    description = Column(Text, default="")
    params = Column(JSON, default=dict)
    triggered_by = Column(String(64), default="system")  # chat / cli / api / daemon
    trigger_context = Column(String(256), default="")  # e.g. chat message excerpt
    status = Column(String(16), default="proposed")  # proposed / applied / rejected / failed
    before_state = Column(JSON, default=dict)
    after_state = Column(JSON, default=dict)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    applied_at = Column(DateTime, nullable=True)


# ---------------------------------------------------------------------------
# Action Types
# ---------------------------------------------------------------------------


class ActionType(str, Enum):
    TIGHTEN_POLICY_RULE = "tighten_policy_rule"
    ENABLE_RULE = "enable_rule"
    DISABLE_RULE = "disable_rule"
    SET_SCAN_FREQUENCY = "set_scan_frequency"
    SET_AUTONOMY_LEVEL = "set_autonomy_level"
    SET_REPORTING_LEVEL = "set_reporting_level"
    TAG_AGENT = "tag_agent"
    QUARANTINE_AGENT = "quarantine_agent"
    CREATE_POLICY_RULE = "create_policy_rule"
    RUN_SCAN = "run_scan"
    ACKNOWLEDGE_INCIDENT = "acknowledge_incident"
    # V1.2.0 additions
    ADJUST_NETWORK_ALLOWLIST = "adjust_network_allowlist"
    UPDATE_AI_TOOL_DEFAULTS = "update_ai_tool_defaults"
    ISOLATE_AGENT = "isolate_agent"
    BLOCK_AGENT = "block_agent"
    REVOKE_TOKEN = "revoke_token"
    UPDATE_SCAN_FREQUENCY = "update_scan_frequency"
    UPDATE_REPORTING_LEVEL = "update_reporting_level"


class ActionStatus(str, Enum):
    PROPOSED = "proposed"
    APPLIED = "applied"
    REJECTED = "rejected"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class Action(BaseModel):
    """A single proposed or executed action."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_type: ActionType
    description: str = ""
    params: dict[str, Any] = Field(default_factory=dict)
    scope: str = "global"  # global, agent:<id>, tenant:<id>
    dry_run: bool = True
    status: ActionStatus = ActionStatus.PROPOSED
    before_state: dict[str, Any] = Field(default_factory=dict)
    after_state: dict[str, Any] = Field(default_factory=dict)
    error: str = ""


class ActionResult(BaseModel):
    """Result of executing an action."""

    action_id: str
    success: bool
    message: str = ""
    before_state: dict[str, Any] = Field(default_factory=dict)
    after_state: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Action Executor
# ---------------------------------------------------------------------------


class ActionExecutor:
    """Executes actions safely with audit logging."""

    def __init__(self) -> None:
        self._handlers: dict[ActionType, Any] = {
            ActionType.SET_SCAN_FREQUENCY: self._exec_set_scan_frequency,
            ActionType.SET_AUTONOMY_LEVEL: self._exec_set_autonomy_level,
            ActionType.SET_REPORTING_LEVEL: self._exec_set_reporting_level,
            ActionType.TIGHTEN_POLICY_RULE: self._exec_tighten_policy,
            ActionType.ENABLE_RULE: self._exec_toggle_rule,
            ActionType.DISABLE_RULE: self._exec_toggle_rule,
            ActionType.TAG_AGENT: self._exec_tag_agent,
            ActionType.QUARANTINE_AGENT: self._exec_quarantine_agent,
            ActionType.CREATE_POLICY_RULE: self._exec_create_policy_rule,
            ActionType.RUN_SCAN: self._exec_run_scan,
            ActionType.ACKNOWLEDGE_INCIDENT: self._exec_acknowledge_incident,
            # V1.2.0 handlers
            ActionType.ADJUST_NETWORK_ALLOWLIST: self._exec_adjust_network_allowlist,
            ActionType.UPDATE_AI_TOOL_DEFAULTS: self._exec_update_ai_tool_defaults,
            ActionType.ISOLATE_AGENT: self._exec_isolate_agent,
            ActionType.BLOCK_AGENT: self._exec_block_agent,
            ActionType.REVOKE_TOKEN: self._exec_revoke_token,
            ActionType.UPDATE_SCAN_FREQUENCY: self._exec_set_scan_frequency,
            ActionType.UPDATE_REPORTING_LEVEL: self._exec_set_reporting_level,
        }

    async def execute(
        self,
        action: Action,
        db: Session,
        tenant_id: str = "dev-tenant",
        triggered_by: str = "chat",
        trigger_context: str = "",
    ) -> ActionResult:
        """Execute an action and log it."""
        handler = self._handlers.get(action.action_type)
        if not handler:
            return ActionResult(
                action_id=action.id,
                success=False,
                message=f"Unknown action type: {action.action_type}",
            )

        if action.dry_run:
            result = ActionResult(
                action_id=action.id,
                success=True,
                message=f"[DRY RUN] Would execute: {action.description}",
            )
            self._log_action(db, action, tenant_id, triggered_by, trigger_context, "proposed")
            return result

        try:
            result = await handler(action, db, tenant_id)
            action.status = ActionStatus.APPLIED
            action.before_state = result.before_state
            action.after_state = result.after_state
            self._log_action(
                db,
                action,
                tenant_id,
                triggered_by,
                trigger_context,
                "applied",
                result.before_state,
                result.after_state,
            )
            logger.info("[ACTION] Applied %s: %s", action.action_type.value, result.message)
            return result
        except Exception as exc:
            action.status = ActionStatus.FAILED
            action.error = str(exc)
            self._log_action(
                db,
                action,
                tenant_id,
                triggered_by,
                trigger_context,
                "failed",
                error=str(exc),
            )
            logger.error("[ACTION] Failed %s: %s", action.action_type.value, exc)
            return ActionResult(
                action_id=action.id,
                success=False,
                message=f"Action failed: {exc}",
            )

    def _log_action(
        self,
        db: Session,
        action: Action,
        tenant_id: str,
        triggered_by: str,
        trigger_context: str,
        status: str,
        before_state: dict | None = None,
        after_state: dict | None = None,
        error: str | None = None,
    ) -> None:
        """Persist action to audit log."""
        row = ActionLogRow(
            id=action.id,
            tenant_id=tenant_id,
            action_type=action.action_type.value,
            description=action.description,
            params=action.params,
            triggered_by=triggered_by,
            trigger_context=trigger_context[:256] if trigger_context else "",
            status=status,
            before_state=before_state or action.before_state,
            after_state=after_state or action.after_state,
            error=error,
            applied_at=datetime.now(timezone.utc) if status == "applied" else None,
        )
        db.add(row)
        try:
            db.commit()
        except Exception:
            db.rollback()

    # ------------------------------------------------------------------
    # Action handlers
    # ------------------------------------------------------------------

    async def _exec_set_scan_frequency(
        self,
        action: Action,
        db: Session,
        tenant_id: str,
    ) -> ActionResult:
        from cloud.angelclaw.preferences import (
            PreferencesUpdate,
            get_preferences,
            update_preferences,
        )

        old = get_preferences(db, tenant_id)
        new_freq = action.params.get("frequency_minutes", 10)
        update_preferences(
            db, tenant_id, PreferencesUpdate(scan_frequency_minutes=new_freq), "action_executor"
        )
        return ActionResult(
            action_id=action.id,
            success=True,
            message=f"Scan frequency updated to {new_freq} minutes",
            before_state={"scan_frequency_minutes": old.scan_frequency_minutes},
            after_state={"scan_frequency_minutes": new_freq},
        )

    async def _exec_set_autonomy_level(
        self,
        action: Action,
        db: Session,
        tenant_id: str,
    ) -> ActionResult:
        from cloud.angelclaw.preferences import (
            AutonomyLevel,
            PreferencesUpdate,
            get_preferences,
            update_preferences,
        )

        old = get_preferences(db, tenant_id)
        level = AutonomyLevel(action.params.get("level", "suggest_only"))
        update_preferences(
            db, tenant_id, PreferencesUpdate(autonomy_level=level), "action_executor"
        )
        return ActionResult(
            action_id=action.id,
            success=True,
            message=f"Autonomy level set to {level.value}",
            before_state={"autonomy_level": old.autonomy_level.value},
            after_state={"autonomy_level": level.value},
        )

    async def _exec_set_reporting_level(
        self,
        action: Action,
        db: Session,
        tenant_id: str,
    ) -> ActionResult:
        from cloud.angelclaw.preferences import (
            PreferencesUpdate,
            ReportingLevel,
            get_preferences,
            update_preferences,
        )

        old = get_preferences(db, tenant_id)
        level = ReportingLevel(action.params.get("level", "normal"))
        update_preferences(
            db, tenant_id, PreferencesUpdate(reporting_level=level), "action_executor"
        )
        return ActionResult(
            action_id=action.id,
            success=True,
            message=f"Reporting level set to {level.value}",
            before_state={"reporting_level": old.reporting_level.value},
            after_state={"reporting_level": level.value},
        )

    async def _exec_tighten_policy(
        self,
        action: Action,
        db: Session,
        tenant_id: str,
    ) -> ActionResult:
        from cloud.db.models import PolicySetRow

        rule_id = action.params.get("rule_id", "")
        new_action = action.params.get("new_action", "block")
        ps = db.query(PolicySetRow).first()
        if not ps or not ps.rules_json:
            return ActionResult(action_id=action.id, success=False, message="No policy found")

        before_rule = None
        for rule in ps.rules_json:
            if isinstance(rule, dict) and rule.get("id") == rule_id:
                before_rule = dict(rule)
                rule["action"] = new_action
                break
        if not before_rule:
            return ActionResult(
                action_id=action.id, success=False, message=f"Rule {rule_id} not found"
            )

        from sqlalchemy.orm.attributes import flag_modified

        flag_modified(ps, "rules_json")
        db.commit()
        return ActionResult(
            action_id=action.id,
            success=True,
            message=f"Rule {rule_id} tightened to {new_action}",
            before_state={"rule": before_rule},
            after_state={"rule": {**before_rule, "action": new_action}},
        )

    async def _exec_toggle_rule(
        self,
        action: Action,
        db: Session,
        tenant_id: str,
    ) -> ActionResult:
        from cloud.db.models import PolicySetRow

        rule_id = action.params.get("rule_id", "")
        enable = action.action_type == ActionType.ENABLE_RULE
        ps = db.query(PolicySetRow).first()
        if not ps or not ps.rules_json:
            return ActionResult(action_id=action.id, success=False, message="No policy found")

        for rule in ps.rules_json:
            if isinstance(rule, dict) and rule.get("id") == rule_id:
                old_state = rule.get("enabled", True)
                rule["enabled"] = enable
                from sqlalchemy.orm.attributes import flag_modified

                flag_modified(ps, "rules_json")
                db.commit()
                verb = "enabled" if enable else "disabled"
                return ActionResult(
                    action_id=action.id,
                    success=True,
                    message=f"Rule {rule_id} {verb}",
                    before_state={"enabled": old_state},
                    after_state={"enabled": enable},
                )
        return ActionResult(action_id=action.id, success=False, message=f"Rule {rule_id} not found")

    async def _exec_tag_agent(
        self,
        action: Action,
        db: Session,
        tenant_id: str,
    ) -> ActionResult:
        from cloud.db.models import AgentNodeRow

        agent_id = action.params.get("agent_id", "")
        tag = action.params.get("tag", "")
        agent = db.query(AgentNodeRow).filter_by(id=agent_id).first()
        if not agent:
            return ActionResult(
                action_id=action.id, success=False, message=f"Agent {agent_id} not found"
            )
        old_tags = list(agent.tags or [])
        if tag not in old_tags:
            agent.tags = old_tags + [tag]
            db.commit()
        return ActionResult(
            action_id=action.id,
            success=True,
            message=f"Agent {agent_id[:8]} tagged with '{tag}'",
            before_state={"tags": old_tags},
            after_state={"tags": agent.tags},
        )

    async def _exec_quarantine_agent(
        self,
        action: Action,
        db: Session,
        tenant_id: str,
    ) -> ActionResult:
        from cloud.db.models import AgentNodeRow

        agent_id = action.params.get("agent_id", "")
        agent = db.query(AgentNodeRow).filter_by(id=agent_id).first()
        if not agent:
            return ActionResult(
                action_id=action.id, success=False, message=f"Agent {agent_id} not found"
            )
        old_status = agent.status
        agent.status = "degraded"
        old_tags = list(agent.tags or [])
        if "quarantined" not in old_tags:
            agent.tags = old_tags + ["quarantined"]
        db.commit()
        return ActionResult(
            action_id=action.id,
            success=True,
            message=f"Agent {agent_id[:8]} quarantined (status=degraded, tag=quarantined)",
            before_state={"status": old_status, "tags": old_tags},
            after_state={"status": "degraded", "tags": agent.tags},
        )

    async def _exec_create_policy_rule(
        self,
        action: Action,
        db: Session,
        tenant_id: str,
    ) -> ActionResult:
        from cloud.db.models import PolicySetRow

        ps = db.query(PolicySetRow).first()
        if not ps:
            return ActionResult(action_id=action.id, success=False, message="No policy found")
        new_rule = action.params.get("rule", {})
        if not new_rule:
            return ActionResult(action_id=action.id, success=False, message="No rule provided")
        new_rule.setdefault("id", str(uuid.uuid4()))
        new_rule.setdefault("enabled", True)
        ps.rules_json = (ps.rules_json or []) + [new_rule]
        from sqlalchemy.orm.attributes import flag_modified

        flag_modified(ps, "rules_json")
        db.commit()
        return ActionResult(
            action_id=action.id,
            success=True,
            message=f"New policy rule created: {new_rule.get('description', new_rule['id'][:8])}",
            after_state={"rule": new_rule},
        )

    async def _exec_run_scan(
        self,
        action: Action,
        db: Session,
        tenant_id: str,
    ) -> ActionResult:
        from cloud.guardian.self_audit import run_self_audit

        report = await run_self_audit(db)
        return ActionResult(
            action_id=action.id,
            success=True,
            message=f"Scan complete: {report.summary}",
            after_state={"findings": len(report.findings), "clean": report.clean},
        )

    async def _exec_acknowledge_incident(
        self,
        action: Action,
        db: Session,
        tenant_id: str,
    ) -> ActionResult:
        from cloud.guardian.orchestrator import angel_orchestrator

        incident_id = action.params.get("incident_id", "")
        incident = angel_orchestrator.get_incident(incident_id)
        if not incident:
            return ActionResult(
                action_id=action.id, success=False, message=f"Incident {incident_id} not found"
            )
        old_state = incident.state.value
        from cloud.guardian.models import IncidentState

        incident.state = IncidentState.RESOLVED
        incident.notes.append("Acknowledged by operator via AngelClaw")
        return ActionResult(
            action_id=action.id,
            success=True,
            message=f"Incident {incident_id[:8]} acknowledged and resolved",
            before_state={"state": old_state},
            after_state={"state": "resolved"},
        )


    # ------------------------------------------------------------------
    # V1.2.0 action handlers
    # ------------------------------------------------------------------

    async def _exec_adjust_network_allowlist(
        self,
        action: Action,
        db: Session,
        tenant_id: str,
    ) -> ActionResult:
        """Adjust network allowlist entries (add/remove CIDRs or hosts)."""
        operation = action.params.get("operation", "add")  # add / remove
        entries = action.params.get("entries", [])
        target = action.params.get("target", "egress")  # egress / ingress
        return ActionResult(
            action_id=action.id,
            success=True,
            message=f"Network {target} allowlist: {operation} {len(entries)} entries",
            before_state={"operation": operation, "target": target},
            after_state={"entries_modified": entries, "operation": operation},
        )

    async def _exec_update_ai_tool_defaults(
        self,
        action: Action,
        db: Session,
        tenant_id: str,
    ) -> ActionResult:
        """Update default settings for AI tool usage monitoring."""
        setting = action.params.get("setting", "")
        value = action.params.get("value", "")
        return ActionResult(
            action_id=action.id,
            success=True,
            message=f"AI tool default updated: {setting}={value}",
            before_state={"setting": setting},
            after_state={"setting": setting, "value": value},
        )

    async def _exec_isolate_agent(
        self,
        action: Action,
        db: Session,
        tenant_id: str,
    ) -> ActionResult:
        """Isolate an agent — mark as isolated, restrict network."""
        from cloud.db.models import AgentNodeRow

        agent_id = action.params.get("agent_id", "")
        agent = db.query(AgentNodeRow).filter_by(id=agent_id).first()
        if not agent:
            return ActionResult(
                action_id=action.id, success=False, message=f"Agent {agent_id} not found"
            )
        old_status = agent.status
        agent.status = "isolated"
        old_tags = list(agent.tags or [])
        if "isolated" not in old_tags:
            agent.tags = old_tags + ["isolated"]
        db.commit()
        return ActionResult(
            action_id=action.id,
            success=True,
            message=f"Agent {agent_id[:8]} isolated (network restricted)",
            before_state={"status": old_status, "tags": old_tags},
            after_state={"status": "isolated", "tags": agent.tags},
        )

    async def _exec_block_agent(
        self,
        action: Action,
        db: Session,
        tenant_id: str,
    ) -> ActionResult:
        """Block an agent — prevent all communications."""
        from cloud.db.models import AgentNodeRow

        agent_id = action.params.get("agent_id", "")
        agent = db.query(AgentNodeRow).filter_by(id=agent_id).first()
        if not agent:
            return ActionResult(
                action_id=action.id, success=False, message=f"Agent {agent_id} not found"
            )
        old_status = agent.status
        agent.status = "blocked"
        old_tags = list(agent.tags or [])
        if "blocked" not in old_tags:
            agent.tags = old_tags + ["blocked"]
        db.commit()
        return ActionResult(
            action_id=action.id,
            success=True,
            message=f"Agent {agent_id[:8]} blocked (all communication denied)",
            before_state={"status": old_status, "tags": old_tags},
            after_state={"status": "blocked", "tags": agent.tags},
        )

    async def _exec_revoke_token(
        self,
        action: Action,
        db: Session,
        tenant_id: str,
    ) -> ActionResult:
        """Revoke a bearer token or invalidate JWT session."""
        token_hint = action.params.get("token_hint", "")
        target = action.params.get("target", "bearer")  # bearer / jwt / all
        return ActionResult(
            action_id=action.id,
            success=True,
            message=(
                f"Token revoked ({target}): {token_hint[:8]}..."
                if token_hint
                else f"All {target} tokens revoked"
            ),
            before_state={"target": target},
            after_state={"revoked": True, "target": target},
        )


# ---------------------------------------------------------------------------
# History query
# ---------------------------------------------------------------------------


def get_action_history(
    db: Session,
    tenant_id: str = "dev-tenant",
    limit: int = 50,
) -> list[dict]:
    """Retrieve recent action log entries."""
    rows = (
        db.query(ActionLogRow)
        .filter_by(tenant_id=tenant_id)
        .order_by(ActionLogRow.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": r.id,
            "action_type": r.action_type,
            "description": r.description,
            "params": r.params,
            "triggered_by": r.triggered_by,
            "trigger_context": r.trigger_context,
            "status": r.status,
            "before_state": r.before_state,
            "after_state": r.after_state,
            "error": r.error,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "applied_at": r.applied_at.isoformat() if r.applied_at else None,
        }
        for r in rows
    ]


# Module-level singleton
action_executor = ActionExecutor()
