"""ANGELGRID – Local Policy Evaluation Engine.

The engine loads a PolicySet and evaluates incoming Events against it.
Matching is performed in rule-list order; the first matching rule wins.

If no rule matches, the engine falls back to a **per-category default action**
loaded from category_defaults.json.  High-risk categories (AI_TOOL, SHELL,
FILE, NETWORK, DB, AUTH) default to BLOCK.  Low-risk categories (LOGGING,
METRIC) default to ALLOW.  This implements the zero-trust principle:
deny-by-default for anything that can affect system state.

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

# Hardcoded fallback when category_defaults.json is missing or a category
# is not listed.  SECURITY: this MUST be BLOCK — fail-closed.
_ULTIMATE_FALLBACK = Decision(
    action=PolicyAction.BLOCK,
    reason="No rule matched and no category default configured; fail-closed",
    risk_level=RiskLevel.HIGH,
)


def _load_category_defaults(path: str | Path) -> dict[str, Decision]:
    """Parse category_defaults.json into a {category_value: Decision} map."""
    path = Path(path)
    if not path.exists():
        logger.warning(
            "Category defaults file not found at %s — all unmatched events will be BLOCKED",
            path,
        )
        return {}

    raw = json.loads(path.read_text(encoding="utf-8"))
    defaults: dict[str, Decision] = {}
    for category, cfg in raw.get("defaults", {}).items():
        try:
            defaults[category] = Decision(
                action=PolicyAction(cfg["action"]),
                reason=cfg.get("reason", f"Category default for {category}"),
                risk_level=RiskLevel(cfg.get("risk_level", "high")),
            )
        except (KeyError, ValueError) as exc:
            logger.error("Invalid category default for '%s': %s", category, exc)
    logger.info("Loaded category defaults for %d categories", len(defaults))
    return defaults


class PolicyEngine:
    """Loads a PolicySet and evaluates Events against its rules."""

    def __init__(
        self,
        policy_set: PolicySet | None = None,
        category_defaults: dict[str, Decision] | None = None,
    ) -> None:
        self._policy_set = policy_set or PolicySet()
        self._category_defaults = category_defaults or {}
        logger.info(
            "PolicyEngine initialized — %d rules, version=%s, %d category defaults",
            len(self._policy_set.rules),
            self._policy_set.version,
            len(self._category_defaults),
        )

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_file(
        cls,
        policy_path: str | Path,
        category_defaults_path: str | Path | None = None,
    ) -> "PolicyEngine":
        """Load a PolicySet and category defaults from JSON files on disk."""
        policy_path = Path(policy_path)
        if not policy_path.exists():
            raise FileNotFoundError(f"Policy file not found: {policy_path}")
        data = json.loads(policy_path.read_text(encoding="utf-8"))
        policy_set = PolicySet.model_validate(data)

        # Default: look for category_defaults.json next to the policy file
        if category_defaults_path is None:
            category_defaults_path = policy_path.parent / "category_defaults.json"

        cat_defaults = _load_category_defaults(category_defaults_path)
        return cls(policy_set, cat_defaults)

    # ------------------------------------------------------------------
    # Hot-reload
    # ------------------------------------------------------------------

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

    @property
    def category_defaults(self) -> dict[str, Decision]:
        """Expose loaded category defaults (read-only snapshot)."""
        return dict(self._category_defaults)

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, event: Event) -> Decision:
        """Evaluate an Event against the loaded PolicySet.

        Rules are checked in list order. The first enabled rule whose match
        conditions are satisfied determines the decision.

        If no rule matches, the per-category default action is used.
        If the category has no configured default, the ultimate fallback
        is BLOCK (fail-closed).

        SECURITY NOTE: This is default-deny for high-risk categories.
        Only categories explicitly configured as 'allow' in
        category_defaults.json will pass through without a matching rule.
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

        # No rule matched — use per-category default
        category_key = event.category.value
        default = self._category_defaults.get(category_key)
        if default is not None:
            logger.debug(
                "No rule matched event %s; category default '%s' → %s",
                event.id, category_key, default.action.value,
            )
            return default

        # Category not in defaults — BLOCK (fail-closed)
        logger.warning(
            "No rule matched event %s and no category default for '%s'; BLOCKING (fail-closed)",
            event.id, category_key,
        )
        return _ULTIMATE_FALLBACK

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
