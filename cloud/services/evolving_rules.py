"""AngelClaw V5.0 — Transcendence: Self-Evolving Detection Rules.

AI-managed detection rules that improve over time based on true/false positive
feedback. Tracks rule lineage across generations and automatically tunes
thresholds and conditions.

Features:
  - Create and manage detection rules with conditions
  - Record true/false positive outcomes for learning
  - Evolve rules into improved generations with auto-tuned thresholds
  - Full lineage tracking across rule generations
"""

from __future__ import annotations

import logging
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.evolving_rules")


class DetectionRule(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    name: str
    description: str = ""
    category: str = "generic"  # network, endpoint, identity, cloud, application
    severity: str = "medium"
    conditions: dict[str, Any] = {}  # field -> {operator, value}
    threshold: float = 0.5
    enabled: bool = True
    generation: int = 1
    parent_id: str | None = None
    lineage: list[str] = []  # ordered list of ancestor rule IDs
    true_positives: int = 0
    false_positives: int = 0
    total_evaluations: int = 0
    precision: float = 0.0
    fitness_score: float = 0.5
    tags: list[str] = []
    created_by: str = "system"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evolved_at: datetime | None = None


class RuleOutcome(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str
    tenant_id: str = "dev-tenant"
    outcome: str  # true_positive, false_positive, true_negative, false_negative
    context: dict[str, Any] = {}
    recorded_by: str = "system"
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EvolvingRulesService:
    """Self-evolving detection rules with feedback-driven improvement."""

    def __init__(self) -> None:
        self._rules: dict[str, DetectionRule] = {}
        self._tenant_rules: dict[str, list[str]] = defaultdict(list)
        self._outcomes: dict[str, list[RuleOutcome]] = defaultdict(list)

    # -- Rule CRUD --

    def create_rule(
        self,
        tenant_id: str,
        name: str,
        category: str = "generic",
        severity: str = "medium",
        conditions: dict | None = None,
        threshold: float = 0.5,
        description: str = "",
        tags: list[str] | None = None,
        parent_id: str | None = None,
        created_by: str = "system",
    ) -> dict:
        # Build lineage from parent
        lineage: list[str] = []
        generation = 1
        if parent_id:
            parent = self._rules.get(parent_id)
            if parent:
                lineage = list(parent.lineage) + [parent.id]
                generation = parent.generation + 1

        rule = DetectionRule(
            tenant_id=tenant_id,
            name=name,
            description=description,
            category=category,
            severity=severity,
            conditions=conditions or {},
            threshold=threshold,
            generation=generation,
            parent_id=parent_id,
            lineage=lineage,
            tags=tags or [],
            created_by=created_by,
        )
        self._rules[rule.id] = rule
        self._tenant_rules[tenant_id].append(rule.id)
        logger.info(
            "[EVOLVING] Created rule '%s' gen=%d category=%s for %s",
            name, generation, category, tenant_id,
        )
        return rule.model_dump(mode="json")

    def get_rule(self, rule_id: str) -> dict | None:
        rule = self._rules.get(rule_id)
        return rule.model_dump(mode="json") if rule else None

    def list_rules(
        self,
        tenant_id: str,
        category: str | None = None,
        enabled_only: bool = False,
    ) -> list[dict]:
        results = []
        for rid in self._tenant_rules.get(tenant_id, []):
            rule = self._rules.get(rid)
            if not rule:
                continue
            if category and rule.category != category:
                continue
            if enabled_only and not rule.enabled:
                continue
            results.append(rule.model_dump(mode="json"))
        results.sort(key=lambda r: r.get("fitness_score", 0), reverse=True)
        return results

    def toggle_rule(self, rule_id: str, enabled: bool) -> dict | None:
        rule = self._rules.get(rule_id)
        if not rule:
            return None
        rule.enabled = enabled
        return rule.model_dump(mode="json")

    # -- Evaluation --

    def evaluate_rule(
        self,
        rule_id: str,
        event: dict,
    ) -> dict:
        """Evaluate a rule against an event and return match result."""
        rule = self._rules.get(rule_id)
        if not rule:
            return {"error": "Rule not found"}
        if not rule.enabled:
            return {"match": False, "reason": "Rule is disabled"}

        match, score, details = self._evaluate_conditions(rule, event)
        rule.total_evaluations += 1

        return {
            "rule_id": rule.id,
            "rule_name": rule.name,
            "match": match,
            "score": round(score, 3),
            "threshold": rule.threshold,
            "details": details,
            "generation": rule.generation,
        }

    # -- Outcome Recording --

    def record_outcome(
        self,
        rule_id: str,
        outcome: str,
        context: dict | None = None,
        recorded_by: str = "system",
    ) -> dict | None:
        valid_outcomes = {"true_positive", "false_positive", "true_negative", "false_negative"}
        if outcome not in valid_outcomes:
            return None

        rule = self._rules.get(rule_id)
        if not rule:
            return None

        record = RuleOutcome(
            rule_id=rule_id,
            tenant_id=rule.tenant_id,
            outcome=outcome,
            context=context or {},
            recorded_by=recorded_by,
        )
        self._outcomes[rule_id].append(record)

        # Cap outcome history per rule
        if len(self._outcomes[rule_id]) > 1000:
            self._outcomes[rule_id] = self._outcomes[rule_id][-1000:]

        # Update rule metrics
        if outcome == "true_positive":
            rule.true_positives += 1
        elif outcome == "false_positive":
            rule.false_positives += 1

        # Recalculate precision and fitness
        total_pos = rule.true_positives + rule.false_positives
        rule.precision = round(rule.true_positives / max(total_pos, 1), 3)
        rule.fitness_score = self._compute_fitness(rule)

        logger.info(
            "[EVOLVING] Outcome for rule '%s': %s (precision=%.3f, fitness=%.3f)",
            rule.name, outcome, rule.precision, rule.fitness_score,
        )
        return record.model_dump(mode="json")

    # -- Evolution --

    def evolve_rules(
        self,
        tenant_id: str,
        min_evaluations: int = 10,
        max_false_positive_rate: float = 0.3,
    ) -> list[dict]:
        """Create improved next-generation rules from underperforming ones."""
        evolved = []
        for rid in list(self._tenant_rules.get(tenant_id, [])):
            rule = self._rules.get(rid)
            if not rule or not rule.enabled:
                continue
            total_pos = rule.true_positives + rule.false_positives
            if total_pos < min_evaluations:
                continue

            fp_rate = rule.false_positives / max(total_pos, 1)
            if fp_rate <= max_false_positive_rate:
                continue

            # Create evolved child rule with tighter threshold
            new_threshold = min(0.95, rule.threshold + 0.1 * (1.0 + fp_rate))
            new_conditions = self._tighten_conditions(rule.conditions, fp_rate)

            child = self.create_rule(
                tenant_id=tenant_id,
                name=f"{rule.name} (gen {rule.generation + 1})",
                category=rule.category,
                severity=rule.severity,
                conditions=new_conditions,
                threshold=round(new_threshold, 3),
                description=(
                    f"Evolved from '{rule.name}' to reduce FP rate "
                    f"({fp_rate:.1%} -> target <{max_false_positive_rate:.0%})"
                ),
                tags=rule.tags + ["evolved"],
                parent_id=rule.id,
                created_by="evolution_engine",
            )

            # Disable parent
            rule.enabled = False
            rule.evolved_at = datetime.now(timezone.utc)

            evolved.append(child)
            logger.info(
                "[EVOLVING] Evolved rule '%s' gen=%d -> gen=%d (FP rate %.1f%%)",
                rule.name, rule.generation, rule.generation + 1, fp_rate * 100,
            )

        return evolved

    # -- Lineage --

    def get_lineage(self, rule_id: str) -> list[dict]:
        """Get the full evolution history/lineage of a rule."""
        rule = self._rules.get(rule_id)
        if not rule:
            return []

        lineage_rules = []
        for ancestor_id in rule.lineage:
            ancestor = self._rules.get(ancestor_id)
            if ancestor:
                lineage_rules.append({
                    "id": ancestor.id,
                    "name": ancestor.name,
                    "generation": ancestor.generation,
                    "threshold": ancestor.threshold,
                    "precision": ancestor.precision,
                    "fitness_score": ancestor.fitness_score,
                    "true_positives": ancestor.true_positives,
                    "false_positives": ancestor.false_positives,
                    "enabled": ancestor.enabled,
                    "created_at": ancestor.created_at.isoformat(),
                    "evolved_at": ancestor.evolved_at.isoformat() if ancestor.evolved_at else None,
                })

        # Add current rule
        lineage_rules.append({
            "id": rule.id,
            "name": rule.name,
            "generation": rule.generation,
            "threshold": rule.threshold,
            "precision": rule.precision,
            "fitness_score": rule.fitness_score,
            "true_positives": rule.true_positives,
            "false_positives": rule.false_positives,
            "enabled": rule.enabled,
            "created_at": rule.created_at.isoformat(),
            "evolved_at": rule.evolved_at.isoformat() if rule.evolved_at else None,
        })

        return lineage_rules

    # -- Stats --

    def get_stats(self, tenant_id: str) -> dict:
        rules = [
            self._rules[r]
            for r in self._tenant_rules.get(tenant_id, [])
            if r in self._rules
        ]
        by_category: dict[str, int] = defaultdict(int)
        by_generation: dict[int, int] = defaultdict(int)
        total_tp = 0
        total_fp = 0
        for rule in rules:
            by_category[rule.category] += 1
            by_generation[rule.generation] += 1
            total_tp += rule.true_positives
            total_fp += rule.false_positives

        active_rules = [r for r in rules if r.enabled]
        avg_fitness = (
            round(sum(r.fitness_score for r in active_rules) / len(active_rules), 3)
            if active_rules else 0.0
        )
        avg_precision = (
            round(sum(r.precision for r in active_rules) / len(active_rules), 3)
            if active_rules else 0.0
        )

        return {
            "total_rules": len(rules),
            "active_rules": len(active_rules),
            "by_category": dict(by_category),
            "by_generation": {str(k): v for k, v in sorted(by_generation.items())},
            "total_true_positives": total_tp,
            "total_false_positives": total_fp,
            "avg_fitness": avg_fitness,
            "avg_precision": avg_precision,
            "total_outcomes": sum(len(v) for v in self._outcomes.values()),
        }

    # -- Internal --

    def _evaluate_conditions(
        self,
        rule: DetectionRule,
        event: dict,
    ) -> tuple[bool, float, list[str]]:
        """Evaluate rule conditions against an event.

        Returns (match, score, details).
        """
        if not rule.conditions:
            return (False, 0.0, ["No conditions defined"])

        matches = 0
        total = 0
        details = []

        for field, condition in rule.conditions.items():
            total += 1
            event_val = event.get(field)

            if isinstance(condition, dict):
                operator = condition.get("operator", "eq")
                expected = condition.get("value")
            else:
                operator = "eq"
                expected = condition

            if event_val is None:
                details.append(f"{field}: missing from event")
                continue

            matched = False
            if operator == "eq":
                matched = str(event_val) == str(expected)
            elif operator == "neq":
                matched = str(event_val) != str(expected)
            elif operator == "gt":
                try:
                    matched = float(event_val) > float(expected)
                except (ValueError, TypeError):
                    pass
            elif operator == "lt":
                try:
                    matched = float(event_val) < float(expected)
                except (ValueError, TypeError):
                    pass
            elif operator == "gte":
                try:
                    matched = float(event_val) >= float(expected)
                except (ValueError, TypeError):
                    pass
            elif operator == "lte":
                try:
                    matched = float(event_val) <= float(expected)
                except (ValueError, TypeError):
                    pass
            elif operator == "contains":
                matched = str(expected).lower() in str(event_val).lower()
            elif operator == "regex":
                try:
                    matched = bool(re.search(str(expected), str(event_val)))
                except re.error:
                    pass
            elif operator == "in":
                if isinstance(expected, list):
                    matched = event_val in expected
                else:
                    matched = str(event_val) in str(expected)

            if matched:
                matches += 1
                details.append(f"{field}: matched ({operator} {expected})")
            else:
                details.append(f"{field}: no match ({event_val} {operator} {expected})")

        score = matches / max(total, 1)
        is_match = score >= rule.threshold

        return (is_match, score, details)

    def _compute_fitness(self, rule: DetectionRule) -> float:
        """Compute fitness score based on precision and evaluation volume."""
        total_pos = rule.true_positives + rule.false_positives
        if total_pos == 0:
            return 0.5  # neutral starting fitness

        precision = rule.true_positives / total_pos
        # Confidence factor: more evaluations = more reliable score
        confidence = min(1.0, total_pos / 50.0)
        # Fitness = weighted precision with confidence
        fitness = 0.5 * (1 - confidence) + precision * confidence
        return round(fitness, 3)

    def _tighten_conditions(
        self,
        conditions: dict[str, Any],
        fp_rate: float,
    ) -> dict[str, Any]:
        """Create tighter conditions based on false positive rate."""
        new_conditions = {}
        for field, condition in conditions.items():
            if isinstance(condition, dict):
                new_cond = dict(condition)
                operator = new_cond.get("operator", "eq")
                value = new_cond.get("value")

                # For numeric thresholds, tighten based on FP rate
                if operator in ("gt", "gte") and value is not None:
                    try:
                        num_val = float(value)
                        adjustment = num_val * 0.1 * (1 + fp_rate)
                        new_cond["value"] = round(num_val + adjustment, 3)
                    except (ValueError, TypeError):
                        pass
                elif operator in ("lt", "lte") and value is not None:
                    try:
                        num_val = float(value)
                        adjustment = num_val * 0.1 * (1 + fp_rate)
                        new_cond["value"] = round(num_val - adjustment, 3)
                    except (ValueError, TypeError):
                        pass

                new_conditions[field] = new_cond
            else:
                new_conditions[field] = condition

        return new_conditions


# Module-level singleton
evolving_rules_service = EvolvingRulesService()
