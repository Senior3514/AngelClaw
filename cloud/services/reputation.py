"""AngelClaw V3.5 — Sentinel: Reputation Scoring Service.

Maintains reputation scores for IPs, domains, hashes, and emails.
Scores range from 0 (malicious) to 100 (clean).
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("angelclaw.reputation")

# Known-bad indicators (built-in baseline)
_KNOWN_MALICIOUS_PATTERNS = [
    "tor-exit", "proxy", "vpn-exit", "botnet", "c2",
    "malware", "phishing", "spam", "brute-force",
]


class ReputationEntry:
    def __init__(
        self,
        tenant_id: str,
        entity_type: str,
        entity_value: str,
        score: int = 50,
        category: str | None = None,
        sources: list[str] | None = None,
    ) -> None:
        self.id = str(uuid.uuid4())
        self.tenant_id = tenant_id
        self.entity_type = entity_type
        self.entity_value = entity_value
        self.score = max(0, min(100, score))
        self.category = category
        self.sources = sources or []
        self.last_checked = datetime.now(timezone.utc)
        self.created_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "entity_type": self.entity_type,
            "entity_value": self.entity_value,
            "score": self.score,
            "category": self.category,
            "sources": self.sources,
            "risk_level": self._risk_level(),
            "last_checked": self.last_checked.isoformat(),
            "created_at": self.created_at.isoformat(),
        }

    def _risk_level(self) -> str:
        if self.score <= 20:
            return "critical"
        elif self.score <= 40:
            return "high"
        elif self.score <= 60:
            return "medium"
        elif self.score <= 80:
            return "low"
        return "clean"


class ReputationService:
    """Reputation scoring engine for IPs, domains, hashes, emails."""

    def __init__(self) -> None:
        self._entries: dict[str, ReputationEntry] = {}
        self._index: dict[str, str] = {}  # "tenant:type:value" -> entry_id
        self._query_count: int = 0

    def lookup(self, tenant_id: str, entity_type: str, entity_value: str) -> dict:
        """Look up or compute reputation for an entity."""
        self._query_count += 1
        key = f"{tenant_id}:{entity_type}:{entity_value}"
        entry_id = self._index.get(key)

        if entry_id and entry_id in self._entries:
            entry = self._entries[entry_id]
            entry.last_checked = datetime.now(timezone.utc)
            return entry.to_dict()

        # Compute initial reputation
        score, category = self._compute_reputation(entity_type, entity_value)
        entry = ReputationEntry(
            tenant_id=tenant_id,
            entity_type=entity_type,
            entity_value=entity_value,
            score=score,
            category=category,
            sources=["angelclaw_builtin"],
        )
        self._entries[entry.id] = entry
        self._index[key] = entry.id
        return entry.to_dict()

    def update_score(
        self,
        tenant_id: str,
        entity_type: str,
        entity_value: str,
        score_delta: int,
        source: str = "manual",
        category: str | None = None,
    ) -> dict | None:
        """Adjust reputation score for an entity."""
        key = f"{tenant_id}:{entity_type}:{entity_value}"
        entry_id = self._index.get(key)
        if not entry_id or entry_id not in self._entries:
            # Create new entry
            entry = ReputationEntry(
                tenant_id=tenant_id,
                entity_type=entity_type,
                entity_value=entity_value,
                score=max(0, min(100, 50 + score_delta)),
                category=category,
                sources=[source],
            )
            self._entries[entry.id] = entry
            self._index[key] = entry.id
            return entry.to_dict()

        entry = self._entries[entry_id]
        entry.score = max(0, min(100, entry.score + score_delta))
        if category:
            entry.category = category
        if source not in entry.sources:
            entry.sources.append(source)
        entry.last_checked = datetime.now(timezone.utc)
        return entry.to_dict()

    def bulk_lookup(self, tenant_id: str, entities: list[dict]) -> list[dict]:
        """Look up reputation for multiple entities at once."""
        results = []
        for entity in entities:
            result = self.lookup(
                tenant_id,
                entity.get("entity_type", "ip"),
                entity.get("entity_value", ""),
            )
            results.append(result)
        return results

    def get_worst(self, tenant_id: str, limit: int = 20) -> list[dict]:
        """Get entities with worst reputation scores."""
        tenant_entries = [
            e for e in self._entries.values() if e.tenant_id == tenant_id
        ]
        tenant_entries.sort(key=lambda e: e.score)
        return [e.to_dict() for e in tenant_entries[:limit]]

    def get_stats(self, tenant_id: str) -> dict:
        tenant_entries = [e for e in self._entries.values() if e.tenant_id == tenant_id]
        by_type: dict[str, int] = defaultdict(int)
        by_risk: dict[str, int] = defaultdict(int)
        for e in tenant_entries:
            by_type[e.entity_type] += 1
            by_risk[e._risk_level()] += 1
        return {
            "total_entries": len(tenant_entries),
            "by_type": dict(by_type),
            "by_risk_level": dict(by_risk),
            "total_queries": self._query_count,
        }

    def _compute_reputation(self, entity_type: str, value: str) -> tuple[int, str | None]:
        """Compute baseline reputation score using built-in heuristics."""
        lower_val = value.lower()

        # Private/loopback IPs are clean
        if entity_type == "ip":
            if lower_val.startswith(("127.", "10.", "192.168.", "172.16.", "::1", "fe80:")):
                return 90, "private"

        # Check known-bad patterns
        for pattern in _KNOWN_MALICIOUS_PATTERNS:
            if pattern in lower_val:
                return 15, pattern

        # Default neutral score
        return 50, None


# Module-level singleton
reputation_service = ReputationService()
