"""AngelClaw V4.5 \u2014 Sovereign: Identity-Based Zero-Trust Access Policies.

Manages identity-based access policies that evaluate identity_type and
identity_pattern against resource_pattern with rich conditions including
time-of-day, geolocation, device trust minimums, and risk ceilings.
Returns granular decisions: allow, deny, mfa_required, or step_up.
"""

from __future__ import annotations

import fnmatch
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("angelclaw.identity_policy")

# Decision priority (higher number = stronger enforcement)
_DECISION_PRIORITY = {
    "allow": 0,
    "mfa_required": 1,
    "step_up": 2,
    "deny": 3,
}


class IdentityPolicy:
    def __init__(
        self,
        tenant_id: str,
        name: str,
        identity_type: str,
        identity_pattern: str,
        resource_pattern: str,
        decision: str = "allow",
        conditions: dict[str, Any] | None = None,
        priority: int = 100,
        enabled: bool = True,
        description: str = "",
    ) -> None:
        self.id = str(uuid.uuid4())
        self.tenant_id = tenant_id
        self.name = name
        self.identity_type = identity_type       # user, service, group, role
        self.identity_pattern = identity_pattern  # e.g. "admin-*", "svc-payment"
        self.resource_pattern = resource_pattern  # e.g. "/api/billing/*", "db:production"
        self.decision = decision                  # allow | deny | mfa_required | step_up
        self.conditions = conditions or {}        # time_of_day, geo, device_trust_min, risk_max
        self.priority = priority                  # Lower = evaluated first
        self.enabled = enabled
        self.description = description
        self.match_count = 0
        self.last_matched_at: datetime | None = None
        self.created_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "identity_type": self.identity_type,
            "identity_pattern": self.identity_pattern,
            "resource_pattern": self.resource_pattern,
            "decision": self.decision,
            "conditions": self.conditions,
            "priority": self.priority,
            "enabled": self.enabled,
            "description": self.description,
            "match_count": self.match_count,
            "last_matched_at": self.last_matched_at.isoformat() if self.last_matched_at else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class IdentityPolicyService:
    """Identity-based zero-trust policy evaluation engine."""

    def __init__(self) -> None:
        self._policies: dict[str, IdentityPolicy] = {}
        self._tenant_policies: dict[str, list[str]] = defaultdict(list)
        self._evaluation_count: int = 0

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create_policy(
        self,
        tenant_id: str,
        name: str,
        identity_type: str,
        identity_pattern: str,
        resource_pattern: str,
        decision: str = "allow",
        conditions: dict[str, Any] | None = None,
        priority: int = 100,
        enabled: bool = True,
        description: str = "",
    ) -> dict:
        """Create a new identity-based access policy."""
        if decision not in _DECISION_PRIORITY:
            raise ValueError(f"Invalid decision '{decision}'; must be one of {list(_DECISION_PRIORITY)}")
        policy = IdentityPolicy(
            tenant_id=tenant_id,
            name=name,
            identity_type=identity_type,
            identity_pattern=identity_pattern,
            resource_pattern=resource_pattern,
            decision=decision,
            conditions=conditions,
            priority=priority,
            enabled=enabled,
            description=description,
        )
        self._policies[policy.id] = policy
        self._tenant_policies[tenant_id].append(policy.id)
        logger.info(
            "[IDENTITY_POLICY] Created policy %s (%s) for tenant %s \u2014 %s %s on %s",
            policy.id[:8], name, tenant_id, decision, identity_pattern, resource_pattern,
        )
        return policy.to_dict()

    def list_policies(
        self,
        tenant_id: str,
        identity_type: str | None = None,
        enabled_only: bool = False,
    ) -> list[dict]:
        """List identity policies for a tenant, sorted by priority."""
        results = []
        for pid in self._tenant_policies.get(tenant_id, []):
            policy = self._policies.get(pid)
            if not policy:
                continue
            if enabled_only and not policy.enabled:
                continue
            if identity_type and policy.identity_type != identity_type:
                continue
            results.append(policy.to_dict())
        results.sort(key=lambda p: p["priority"])
        return results

    def update_policy(self, policy_id: str, **kwargs: Any) -> dict | None:
        """Update fields on an existing policy."""
        policy = self._policies.get(policy_id)
        if not policy:
            return None
        allowed_fields = {
            "name", "identity_type", "identity_pattern",
            "resource_pattern", "decision", "conditions",
            "priority", "enabled", "description",
        }
        for key, value in kwargs.items():
            if key in allowed_fields:
                if key == "decision" and value not in _DECISION_PRIORITY:
                    continue
                setattr(policy, key, value)
        policy.updated_at = datetime.now(timezone.utc)
        logger.info("[IDENTITY_POLICY] Updated policy %s", policy_id[:8])
        return policy.to_dict()

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate_access(
        self,
        tenant_id: str,
        identity_type: str,
        identity_name: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> dict:
        """Evaluate access for an identity against a resource.

        Checks all matching policies in priority order.  The strongest
        applicable decision wins (deny > step_up > mfa_required > allow).

        Args:
            tenant_id: Owning tenant.
            identity_type: Type of identity (user, service, group, role).
            identity_name: Actual identity name to match against patterns.
            resource: Resource being accessed.
            context: Runtime context (time_of_day, geo, device_trust, risk_score).

        Returns:
            Evaluation result with decision, matching policies, conditions.
        """
        self._evaluation_count += 1
        ctx = context or {}
        policies = self._get_sorted_policies(tenant_id)

        matched_policies: list[dict] = []
        strongest_decision = "allow"

        for policy in policies:
            if not policy.enabled:
                continue
            if policy.identity_type != identity_type:
                continue
            if not fnmatch.fnmatch(identity_name, policy.identity_pattern):
                continue
            if not fnmatch.fnmatch(resource, policy.resource_pattern):
                continue

            # Check conditions
            condition_result = self._evaluate_conditions(policy.conditions, ctx)
            if not condition_result["conditions_met"]:
                continue

            # Record match
            policy.match_count += 1
            policy.last_matched_at = datetime.now(timezone.utc)

            effective_decision = condition_result.get("elevated_decision", policy.decision)
            matched_policies.append({
                "policy_id": policy.id,
                "policy_name": policy.name,
                "decision": effective_decision,
                "priority": policy.priority,
                "conditions_evaluated": condition_result,
            })

            # Keep strongest decision
            if _DECISION_PRIORITY.get(effective_decision, 0) > _DECISION_PRIORITY.get(strongest_decision, 0):
                strongest_decision = effective_decision

        if not matched_policies:
            # Default deny \u2014 zero trust
            strongest_decision = "deny"
            reason = "no_matching_policy"
        else:
            reason = "policy_match"

        logger.info(
            "[IDENTITY_POLICY] %s access for %s:%s -> %s \u2014 %d policies matched",
            strongest_decision.upper(), identity_type, identity_name, resource, len(matched_policies),
        )
        return {
            "decision": strongest_decision,
            "identity_type": identity_type,
            "identity_name": identity_name,
            "resource": resource,
            "matched_policies": matched_policies,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return statistics for identity policies in a tenant."""
        policies = [
            self._policies[pid]
            for pid in self._tenant_policies.get(tenant_id, [])
            if pid in self._policies
        ]
        by_decision: dict[str, int] = defaultdict(int)
        by_identity_type: dict[str, int] = defaultdict(int)
        total_matches = 0
        for p in policies:
            by_decision[p.decision] += 1
            by_identity_type[p.identity_type] += 1
            total_matches += p.match_count
        return {
            "total_policies": len(policies),
            "enabled": sum(1 for p in policies if p.enabled),
            "disabled": sum(1 for p in policies if not p.enabled),
            "by_decision": dict(by_decision),
            "by_identity_type": dict(by_identity_type),
            "total_matches": total_matches,
            "total_evaluations": self._evaluation_count,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_sorted_policies(self, tenant_id: str) -> list[IdentityPolicy]:
        """Get policies sorted by priority (ascending)."""
        policies = [
            self._policies[pid]
            for pid in self._tenant_policies.get(tenant_id, [])
            if pid in self._policies
        ]
        policies.sort(key=lambda p: p.priority)
        return policies

    @staticmethod
    def _evaluate_conditions(
        conditions: dict[str, Any],
        context: dict[str, Any],
    ) -> dict:
        """Evaluate policy conditions against runtime context.

        Supported conditions:
        - time_of_day: {"start": 9, "end": 17} \u2014 hours (24h)
        - geo: list of allowed country codes
        - device_trust_min: minimum device trust score (0-100)
        - risk_max: maximum acceptable risk score (0-100)
        """
        if not conditions:
            return {"conditions_met": True}

        result: dict[str, Any] = {"conditions_met": True, "details": {}}
        elevated_decision: str | None = None

        # Time of day
        time_cond = conditions.get("time_of_day")
        if time_cond:
            current_hour = context.get("time_of_day", datetime.now(timezone.utc).hour)
            start = time_cond.get("start", 0)
            end = time_cond.get("end", 24)
            in_window = start <= current_hour < end
            result["details"]["time_of_day"] = {
                "current_hour": current_hour,
                "allowed_window": f"{start:02d}:00-{end:02d}:00",
                "in_window": in_window,
            }
            if not in_window:
                elevated_decision = "step_up"

        # Geolocation
        geo_cond = conditions.get("geo")
        if geo_cond:
            current_geo = context.get("geo", "unknown")
            geo_allowed = current_geo in geo_cond
            result["details"]["geo"] = {
                "current": current_geo,
                "allowed": geo_cond,
                "match": geo_allowed,
            }
            if not geo_allowed:
                elevated_decision = "deny"

        # Device trust minimum
        trust_min = conditions.get("device_trust_min")
        if trust_min is not None:
            current_trust = context.get("device_trust", 0)
            trust_ok = current_trust >= trust_min
            result["details"]["device_trust"] = {
                "current": current_trust,
                "minimum": trust_min,
                "met": trust_ok,
            }
            if not trust_ok:
                new_decision = "mfa_required" if current_trust >= trust_min * 0.5 else "deny"
                if _DECISION_PRIORITY.get(new_decision, 0) > _DECISION_PRIORITY.get(elevated_decision or "allow", 0):
                    elevated_decision = new_decision

        # Risk maximum
        risk_max = conditions.get("risk_max")
        if risk_max is not None:
            current_risk = context.get("risk_score", 0)
            risk_ok = current_risk <= risk_max
            result["details"]["risk"] = {
                "current": current_risk,
                "maximum": risk_max,
                "met": risk_ok,
            }
            if not risk_ok:
                new_decision = "step_up" if current_risk <= risk_max * 1.5 else "deny"
                if _DECISION_PRIORITY.get(new_decision, 0) > _DECISION_PRIORITY.get(elevated_decision or "allow", 0):
                    elevated_decision = new_decision

        if elevated_decision:
            result["elevated_decision"] = elevated_decision

        return result


# Module-level singleton
identity_policy_service = IdentityPolicyService()
