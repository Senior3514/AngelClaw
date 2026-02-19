"""AngelClaw V5.0 — Transcendence: Natural Language Policy Engine.

Allows operators to define security policies in plain English.  The engine
parses natural-language statements into structured rule sets using keyword
extraction, assigns a confidence score, and routes them through an
approval workflow before enforcement.

Features:
  - Natural-language policy creation with automatic rule extraction
  - Keyword-based parsing (block, allow, deny, require, if, when, from, to)
  - Confidence scoring based on rule extraction quality
  - Approval / rejection workflow with audit trail
"""

from __future__ import annotations

import logging
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("angelclaw.nl_policy")

# Keywords used for rule extraction
_ACTION_KEYWORDS = {"block", "allow", "deny", "require"}
_CONDITION_KEYWORDS = {"if", "when"}
_DIRECTION_KEYWORDS = {"from", "to"}


class NLPolicy:
    def __init__(
        self,
        tenant_id: str,
        natural_language: str,
        parsed_rules: list[dict[str, Any]] | None = None,
        confidence_score: float = 0.0,
        created_by: str = "system",
    ) -> None:
        self.id = str(uuid.uuid4())
        self.tenant_id = tenant_id
        self.natural_language = natural_language
        self.parsed_rules: list[dict[str, Any]] = parsed_rules or []
        self.status = "draft"                # draft, pending_review, approved, rejected
        self.confidence_score = confidence_score
        self.created_by = created_by
        self.approved_by: str | None = None
        self.created_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "natural_language": self.natural_language,
            "parsed_rules": self.parsed_rules,
            "status": self.status,
            "confidence_score": self.confidence_score,
            "created_by": self.created_by,
            "approved_by": self.approved_by,
            "created_at": self.created_at.isoformat(),
        }


class NLPolicyService:
    """Natural-language policy engine with keyword-based rule extraction."""

    def __init__(self) -> None:
        self._policies: dict[str, NLPolicy] = {}
        self._tenant_policies: dict[str, list[str]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def create_nl_policy(
        self,
        tenant_id: str,
        natural_language: str,
        created_by: str = "system",
    ) -> dict:
        """Parse a natural-language statement into structured rules.

        The parser scans for action keywords (block, allow, deny, require),
        condition keywords (if, when), and direction keywords (from, to) to
        build a list of rule dicts.  A confidence score is computed based on
        how many meaningful tokens were extracted.
        """
        parsed_rules = self._parse_nl(natural_language)
        confidence = self._compute_confidence(natural_language, parsed_rules)

        policy = NLPolicy(
            tenant_id=tenant_id,
            natural_language=natural_language,
            parsed_rules=parsed_rules,
            confidence_score=confidence,
            created_by=created_by,
        )
        policy.status = "pending_review"

        self._policies[policy.id] = policy
        self._tenant_policies[tenant_id].append(policy.id)
        logger.info(
            "[NL_POLICY] Created policy %s for %s — confidence=%.2f, %d rules extracted",
            policy.id[:8], tenant_id, confidence, len(parsed_rules),
        )
        return policy.to_dict()

    def list_policies(self, tenant_id: str) -> list[dict]:
        """List all NL policies for a tenant."""
        results = []
        for pid in self._tenant_policies.get(tenant_id, []):
            policy = self._policies.get(pid)
            if policy:
                results.append(policy.to_dict())
        return results

    def approve_policy(self, policy_id: str, approved_by: str) -> dict | None:
        """Approve a pending NL policy for enforcement."""
        policy = self._policies.get(policy_id)
        if not policy:
            return None
        policy.status = "approved"
        policy.approved_by = approved_by
        logger.info("[NL_POLICY] Policy %s approved by %s", policy_id[:8], approved_by)
        return policy.to_dict()

    def reject_policy(self, policy_id: str) -> dict | None:
        """Reject a pending NL policy."""
        policy = self._policies.get(policy_id)
        if not policy:
            return None
        policy.status = "rejected"
        logger.info("[NL_POLICY] Policy %s rejected", policy_id[:8])
        return policy.to_dict()

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return NL policy statistics for a tenant."""
        policies = [
            self._policies[pid]
            for pid in self._tenant_policies.get(tenant_id, [])
            if pid in self._policies
        ]
        by_status: dict[str, int] = defaultdict(int)
        for p in policies:
            by_status[p.status] += 1
        scores = [p.confidence_score for p in policies]
        return {
            "total": len(policies),
            "by_status": dict(by_status),
            "avg_confidence": round(sum(scores) / max(len(scores), 1), 4),
        }

    # ------------------------------------------------------------------
    # Internal helpers — NL parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_nl(text: str) -> list[dict[str, Any]]:
        """Extract structured rules from a natural-language policy statement.

        Scans for action/condition/direction keywords and captures the
        tokens that follow each keyword as its value.  Each sentence is
        treated as a potential rule.
        """
        rules: list[dict[str, Any]] = []
        sentences = re.split(r"[.;!\n]+", text)
        for sentence in sentences:
            sentence = sentence.strip()
            if not sentence:
                continue
            tokens = sentence.lower().split()
            rule: dict[str, Any] = {"raw": sentence}

            # Extract action
            for kw in _ACTION_KEYWORDS:
                if kw in tokens:
                    idx = tokens.index(kw)
                    rule["action"] = kw
                    # Capture the next few tokens as target
                    target_tokens = tokens[idx + 1: idx + 4]
                    if target_tokens:
                        rule["target"] = " ".join(target_tokens)
                    break

            # Extract conditions (if / when)
            for kw in _CONDITION_KEYWORDS:
                if kw in tokens:
                    idx = tokens.index(kw)
                    condition_tokens = tokens[idx + 1: idx + 6]
                    if condition_tokens:
                        rule["condition"] = " ".join(condition_tokens)
                    break

            # Extract direction (from / to)
            for kw in _DIRECTION_KEYWORDS:
                if kw in tokens:
                    idx = tokens.index(kw)
                    direction_tokens = tokens[idx + 1: idx + 4]
                    if direction_tokens:
                        rule[kw] = " ".join(direction_tokens)

            # Only keep rules that have at least an action
            if "action" in rule:
                rules.append(rule)

        return rules

    @staticmethod
    def _compute_confidence(text: str, parsed_rules: list[dict[str, Any]]) -> float:
        """Compute a confidence score (0.0-1.0) for the parsed result.

        Higher score when more keywords were matched and more rules were
        extracted relative to the number of sentences.
        """
        if not text.strip():
            return 0.0

        sentences = [s.strip() for s in re.split(r"[.;!\n]+", text) if s.strip()]
        if not sentences:
            return 0.0

        # Base: ratio of sentences that produced rules
        rule_ratio = len(parsed_rules) / len(sentences) if sentences else 0.0

        # Bonus: average number of extracted fields per rule
        if parsed_rules:
            fields_per_rule = [
                sum(1 for k in r if k != "raw") for r in parsed_rules
            ]
            avg_fields = sum(fields_per_rule) / len(fields_per_rule)
            field_bonus = min(avg_fields / 4.0, 0.3)  # cap bonus at 0.3
        else:
            field_bonus = 0.0

        confidence = min(rule_ratio * 0.7 + field_bonus, 1.0)
        return round(confidence, 4)


# Module-level singleton
nl_policy_service = NLPolicyService()
