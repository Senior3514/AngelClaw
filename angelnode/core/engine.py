"""ANGELGRID – Local Policy Evaluation Engine.

The engine loads a PolicySet and evaluates incoming Events against it.
Matching is performed in rule-list order; the first matching rule wins.

If no rule matches, the engine falls back to a **per-category default action**
loaded from category_defaults.json.  High-risk categories (AI_TOOL, SHELL,
FILE, NETWORK, DB, AUTH) default to BLOCK.  Low-risk categories (LOGGING,
METRIC) default to ALLOW.  This implements the zero-trust principle:
deny-by-default for anything that can affect system state.

Match conditions in detail_conditions support:
  - Exact match:    "key": value
  - Regex match:    "key_pattern": "regex"     (matched via re.search)
  - List membership: "key_in": [v1, v2, ...]   (event value must be in list)
  - Numeric GT:     "key_gt": number           (event value must be > number)
  - Burst detection: "burst_window_seconds" + "burst_threshold"

SECURITY NOTE: This is the critical decision path. Every action mediated by
ANGELNODE passes through engine.evaluate().  Changes here must be reviewed
with extra care.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from collections import deque
from pathlib import Path

from shared.models.decision import Decision
from shared.models.event import Event
from shared.models.policy import PolicyAction, PolicyMatch, PolicySet, RiskLevel

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


class BurstTracker:
    """Thread-safe sliding-window counter for burst/rate detection.

    Tracks event timestamps per (category, type) key and returns True
    when the count in the last `window_seconds` exceeds `threshold`.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # key → deque of timestamps (monotonic seconds)
        self._windows: dict[str, deque[float]] = {}

    def record_and_check(
        self,
        category: str,
        event_type: str,
        window_seconds: int,
        threshold: int,
    ) -> bool:
        """Record an event and return True if the burst threshold is exceeded."""
        key = f"{category}:{event_type}"
        now = time.monotonic()
        cutoff = now - window_seconds

        with self._lock:
            if key not in self._windows:
                self._windows[key] = deque()
            q = self._windows[key]
            # Evict expired entries
            while q and q[0] < cutoff:
                q.popleft()
            q.append(now)
            return len(q) > threshold


class PolicyEngine:
    """Loads a PolicySet and evaluates Events against its rules."""

    def __init__(
        self,
        policy_set: PolicySet | None = None,
        category_defaults: dict[str, Decision] | None = None,
    ) -> None:
        self._policy_set = policy_set or PolicySet()
        self._category_defaults = category_defaults or {}
        self._burst_tracker = BurstTracker()
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
                event.id,
                category_key,
                default.action.value,
            )
            return default

        # Category not in defaults — BLOCK (fail-closed)
        logger.warning(
            "No rule matched event %s and no category default for '%s'; BLOCKING (fail-closed)",
            event.id,
            category_key,
        )
        return _ULTIMATE_FALLBACK

    # ------------------------------------------------------------------
    # Match logic
    # ------------------------------------------------------------------

    def _matches(self, match: PolicyMatch, event: Event) -> bool:
        """Return True if all specified match conditions are satisfied.

        Supports extended detail_conditions:
          - "key": value           → exact match against event.details[key]
          - "key_pattern": "re"    → regex match against
            event.details[key] (key without _pattern suffix)
          - "key_in": [...]        → event.details[key] must be in the list
          - "key_gt": number       → event.details[key] must be > number
          - "burst_window_seconds" + "burst_threshold" → sliding-window burst detection
        """
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

        # Detail conditions (extended matching)
        if match.detail_conditions is not None:
            if not self._match_details(match.detail_conditions, event):
                return False

        return True

    def _match_details(self, conditions: dict, event: Event) -> bool:
        """Evaluate extended detail_conditions against event.details.

        Processes conditions in a single pass, recognizing suffixed keys
        (_pattern, _in, _gt) as special operators.
        """
        details = event.details

        # Extract burst params if present (handled separately)
        burst_window = conditions.get("burst_window_seconds")
        burst_threshold = conditions.get("burst_threshold")

        for key, expected in conditions.items():
            # Skip burst meta-keys (handled below)
            if key in ("burst_window_seconds", "burst_threshold"):
                continue

            # Regex pattern match: "foo_pattern": "regex" matches details["foo"]
            if key.endswith("_pattern"):
                base_key = key[: -len("_pattern")]
                actual = details.get(base_key)
                if actual is None:
                    return False
                if not re.search(str(expected), str(actual)):
                    return False
                continue

            # List membership: "foo_in": [...] matches if details["foo"] in list
            if key.endswith("_in"):
                base_key = key[: -len("_in")]
                actual = details.get(base_key)
                if actual is None:
                    return False
                if actual not in expected:
                    return False
                continue

            # Numeric greater-than: "foo_gt": N matches if details["foo"] > N
            if key.endswith("_gt"):
                base_key = key[: -len("_gt")]
                actual = details.get(base_key)
                if actual is None:
                    return False
                try:
                    if float(actual) <= float(expected):
                        return False
                except (TypeError, ValueError):
                    return False
                continue

            # Default: exact match
            if details.get(key) != expected:
                return False

        # Burst detection (if both burst keys are present)
        if burst_window is not None and burst_threshold is not None:
            if not self._burst_tracker.record_and_check(
                event.category.value,
                event.type,
                int(burst_window),
                int(burst_threshold),
            ):
                return False

        return True
