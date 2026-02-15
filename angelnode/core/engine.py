"""ANGELGRID – Local Policy Evaluation Engine.

The engine loads a PolicySet and evaluates incoming Events against it.
Matching is performed in rule-list order; the first matching rule wins.
If no rule matches, the default action is ALLOW (open policy — configurable).

SECURITY NOTE: This is the critical decision path. Every action mediated by
ANGELNODE passes through engine.evaluate().  Changes here must be reviewed
with extra care.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from shared.models.decision import Decision
from shared.models.event import Event
from shared.models.policy import PolicyAction, PolicyMatch, PolicyRule, PolicySet, RiskLevel

logger = logging.getLogger("angelnode.engine")


class PolicyEngine:
    """Loads a PolicySet and evaluates Events against its rules."""

    def __init__(self, policy_set: PolicySet | None = None) -> None:
        self._policy_set = policy_set or PolicySet()
        logger.info(
            "PolicyEngine initialized — %d rules, version=%s",
            len(self._policy_set.rules),
            self._policy_set.version,
        )

    # ------------------------------------------------------------------
    # Policy loading
    # ------------------------------------------------------------------

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyEngine":
        """Load a PolicySet from a JSON file on disk."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        policy_set = PolicySet.model_validate(data)
        return cls(policy_set)

    def reload(self, policy_set: PolicySet) -> None:
        """Hot-reload the active PolicySet (e.g. after a Cloud sync)."""
        self._policy_set = policy_set
        logger.info(
            "PolicySet reloaded — %d rules, version=%s",
            len(self._policy_set.rules),
            self._policy_set.version,
        )

    @property
    def policy_version(self) -> str:
        return self._policy_set.version

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, event: Event) -> Decision:
        """Evaluate an Event against the loaded PolicySet.

        Rules are checked in list order. The first enabled rule whose match
        conditions are satisfied determines the decision.  If nothing matches,
        the default is ALLOW.

        SECURITY NOTE: default-allow is suitable for the MVP/bootstrap phase.
        Production deployments should switch to default-deny via configuration.
        """
        for rule in self._policy_set.rules:
            if not rule.enabled:
                continue
            if self._matches(rule.match, event):
                logger.debug("Rule %s matched event %s", rule.id, event.id)
                return Decision(
                    action=rule.action,
                    reason=rule.description or f"Matched rule {rule.id}",
                    matched_rule_id=rule.id,
                    risk_level=rule.risk_level,
                )

        # No rule matched — default allow
        return Decision(
            action=PolicyAction.ALLOW,
            reason="No policy rule matched; default allow",
            risk_level=RiskLevel.NONE,
        )

    # ------------------------------------------------------------------
    # Match logic
    # ------------------------------------------------------------------

    @staticmethod
    def _matches(match: PolicyMatch, event: Event) -> bool:
        """Return True if all specified match conditions are satisfied."""
        # Category filter
        if match.categories is not None:
            if event.category.value not in match.categories:
                return False

        # Type filter
        if match.types is not None:
            if event.type not in match.types:
                return False

        # Source pattern (regex)
        if match.source_pattern is not None:
            if event.source is None:
                return False
            if not re.search(match.source_pattern, event.source):
                return False

        # Detail conditions (exact key-value match)
        if match.detail_conditions is not None:
            for key, expected in match.detail_conditions.items():
                if event.details.get(key) != expected:
                    return False

        return True
