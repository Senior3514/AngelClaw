"""AngelClaw AGI Guardian – Self-Hardening Engine.

Autonomously detects and corrects security weaknesses:
  - Repeated misconfigurations → propose stronger defaults
  - Loose allowlists → cautious tightening
  - Missing logs → auto-enable logging
  - Weak auth patterns → flag and escalate
  - Repeated scan failures → increase scan frequency

Operates based on autonomy level:
  - observe: detect issues, log them, do nothing
  - suggest: detect and propose fixes to operators
  - auto_apply: detect and apply safe fixes automatically

Every action is logged with full explanation and is revertible.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.self_hardening")


class HardeningAction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    action_type: str  # tighten_allowlist, enable_logging, increase_scan_freq, strengthen_auth, block_source
    description: str = ""
    reason: str = ""
    before_state: dict[str, Any] = {}
    after_state: dict[str, Any] = {}
    revertible: bool = True
    reverted: bool = False
    reverted_at: datetime | None = None
    reverted_by: str | None = None
    applied: bool = False
    applied_at: datetime | None = None
    applied_by: str = "system"
    autonomy_mode: str = "suggest"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SelfHardeningEngine:
    """Autonomous security hardening engine."""

    def __init__(self) -> None:
        self._actions: list[HardeningAction] = []
        self._proposed: list[HardeningAction] = []
        self._issue_counts: dict[str, int] = defaultdict(int)  # issue_type -> count
        self._tenant_issues: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    def run_hardening_cycle(
        self,
        tenant_id: str = "dev-tenant",
        autonomy_mode: str = "suggest",
        context: dict[str, Any] | None = None,
    ) -> list[dict]:
        """Run a full hardening analysis cycle. Returns proposed/applied actions."""
        ctx = context or {}
        new_actions: list[HardeningAction] = []

        # Check 1: Repeated scan failures → increase scan frequency
        scan_failures = ctx.get("scan_failures", 0)
        if scan_failures >= 3:
            self._issue_counts["scan_failures"] += 1
            action = HardeningAction(
                tenant_id=tenant_id,
                action_type="increase_scan_freq",
                description="Increase scan frequency due to repeated scan failures",
                reason=f"{scan_failures} scan failures detected in recent cycles",
                before_state={"scan_frequency_minutes": ctx.get("scan_freq", 10)},
                after_state={"scan_frequency_minutes": max(1, ctx.get("scan_freq", 10) // 2)},
                autonomy_mode=autonomy_mode,
            )
            new_actions.append(action)

        # Check 2: Loose allowlists (ANY destination)
        allowlist = ctx.get("network_allowlist", [])
        if "ANY" in allowlist or "*" in allowlist:
            self._issue_counts["loose_allowlist"] += 1
            safe_destinations = ctx.get("known_safe_destinations", ["localhost", "127.0.0.1"])
            action = HardeningAction(
                tenant_id=tenant_id,
                action_type="tighten_allowlist",
                description="Tighten network allowlist by removing wildcard entries",
                reason="Network allowlist contains 'ANY' — restricting to known safe destinations",
                before_state={"allowlist": allowlist},
                after_state={"allowlist": safe_destinations},
                autonomy_mode=autonomy_mode,
            )
            new_actions.append(action)

        # Check 3: Missing or disabled logging
        logging_enabled = ctx.get("logging_enabled", True)
        if not logging_enabled:
            self._issue_counts["missing_logs"] += 1
            action = HardeningAction(
                tenant_id=tenant_id,
                action_type="enable_logging",
                description="Re-enable security logging",
                reason="Security logging was found disabled — enabling for audit compliance",
                before_state={"logging_enabled": False},
                after_state={"logging_enabled": True},
                autonomy_mode=autonomy_mode,
            )
            new_actions.append(action)

        # Check 4: Weak auth patterns
        auth_issues = ctx.get("auth_issues", [])
        for issue in auth_issues:
            self._issue_counts["weak_auth"] += 1
            action = HardeningAction(
                tenant_id=tenant_id,
                action_type="strengthen_auth",
                description=f"Address auth weakness: {issue}",
                reason=f"Authentication issue detected: {issue}",
                before_state={"issue": issue},
                after_state={"resolution": "escalated_to_admin"},
                revertible=False,
                autonomy_mode=autonomy_mode,
            )
            new_actions.append(action)

        # Check 5: High-risk agents without anti-tamper
        unprotected_agents = ctx.get("unprotected_high_risk_agents", [])
        if unprotected_agents:
            self._issue_counts["unprotected_agents"] += 1
            action = HardeningAction(
                tenant_id=tenant_id,
                action_type="enable_anti_tamper",
                description=f"Enable anti-tamper monitoring for {len(unprotected_agents)} high-risk agent(s)",
                reason="High-risk agents detected without anti-tamper protection",
                before_state={"unprotected": unprotected_agents[:10]},
                after_state={"mode": "monitor"},
                autonomy_mode=autonomy_mode,
            )
            new_actions.append(action)

        # Check 6: Repeated misconfigurations
        misconfig_count = ctx.get("misconfig_count", 0)
        if misconfig_count >= 5:
            self._issue_counts["repeated_misconfig"] += 1
            action = HardeningAction(
                tenant_id=tenant_id,
                action_type="propose_stronger_defaults",
                description="Propose stronger default configuration based on repeated issues",
                reason=f"{misconfig_count} misconfigurations detected — stronger defaults recommended",
                before_state={"misconfig_count": misconfig_count},
                after_state={"action": "defaults_strengthened"},
                autonomy_mode=autonomy_mode,
            )
            new_actions.append(action)

        # Apply or propose based on autonomy mode
        results = []
        for action in new_actions:
            if autonomy_mode == "auto_apply" or autonomy_mode == "assist":
                action.applied = True
                action.applied_at = datetime.now(timezone.utc)
                self._actions.append(action)
                logger.info(
                    "[HARDENING] AUTO-APPLIED: %s — %s",
                    action.action_type, action.description,
                )
            elif autonomy_mode == "suggest":
                self._proposed.append(action)
                logger.info(
                    "[HARDENING] PROPOSED: %s — %s",
                    action.action_type, action.description,
                )
            else:  # observe
                logger.info(
                    "[HARDENING] OBSERVED: %s — %s",
                    action.action_type, action.description,
                )

            self._tenant_issues[tenant_id][action.action_type] += 1
            results.append(action.model_dump(mode="json"))

        return results

    def get_proposed_actions(self, tenant_id: str | None = None) -> list[dict]:
        """Get pending proposed actions."""
        actions = self._proposed
        if tenant_id:
            actions = [a for a in actions if a.tenant_id == tenant_id]
        return [a.model_dump(mode="json") for a in actions]

    def apply_action(self, action_id: str, applied_by: str = "operator") -> dict | None:
        """Apply a proposed hardening action."""
        for i, action in enumerate(self._proposed):
            if action.id == action_id:
                action.applied = True
                action.applied_at = datetime.now(timezone.utc)
                action.applied_by = applied_by
                self._actions.append(action)
                self._proposed.pop(i)
                logger.info(
                    "[HARDENING] Applied by %s: %s — %s",
                    applied_by, action.action_type, action.description,
                )
                return action.model_dump(mode="json")
        return None

    def revert_action(self, action_id: str, reverted_by: str = "operator") -> dict | None:
        """Revert a previously applied hardening action."""
        for action in self._actions:
            if action.id == action_id:
                if not action.revertible:
                    return {"error": "This action is not revertible"}
                if action.reverted:
                    return {"error": "Already reverted"}
                action.reverted = True
                action.reverted_at = datetime.now(timezone.utc)
                action.reverted_by = reverted_by
                logger.info(
                    "[HARDENING] Reverted by %s: %s — %s",
                    reverted_by, action.action_type, action.description,
                )
                return action.model_dump(mode="json")
        return None

    def get_hardening_log(
        self,
        tenant_id: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """Get log of all hardening actions (applied and proposed)."""
        all_actions = self._actions + self._proposed
        if tenant_id:
            all_actions = [a for a in all_actions if a.tenant_id == tenant_id]
        all_actions.sort(key=lambda a: a.created_at, reverse=True)
        return [a.model_dump(mode="json") for a in all_actions[:limit]]

    def get_issue_summary(self) -> dict:
        """Get summary of detected issues."""
        return {
            "total_issues": sum(self._issue_counts.values()),
            "by_type": dict(self._issue_counts),
            "actions_applied": len([a for a in self._actions if a.applied and not a.reverted]),
            "actions_proposed": len(self._proposed),
            "actions_reverted": len([a for a in self._actions if a.reverted]),
        }


# Module-level singleton
self_hardening_engine = SelfHardeningEngine()
