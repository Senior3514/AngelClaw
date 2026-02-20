"""AngelClaw V7.0 — Empyrion: Threat Federation Service.

Cross-organisation threat intelligence federation with trust-based
sharing, anonymous indicator exchange, collective defense scoring,
and aggregated threat landscape visibility.

Features:
  - Organisation trust network with tiered trust levels
  - Anonymous indicator sharing with privacy controls
  - Collective defense scoring across federation members
  - Threat landscape aggregation from federated data
  - Per-tenant isolation with federation analytics
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.threat_federation")

_TRUST_LEVELS = {"public": 1, "basic": 2, "verified": 3, "trusted": 4, "alliance": 5}


class FederationMember(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    org_name: str
    trust_level: str = "basic"  # public, basic, verified, trusted, alliance
    trust_score: int = 2  # numeric trust level (1-5)
    indicators_shared: int = 0
    indicators_consumed: int = 0
    active: bool = True
    joined_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_activity_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SharedIndicator(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_tenant_id: str = "dev-tenant"
    indicator_type: str  # ip, domain, hash, url, email, cve
    indicator_value: str
    anonymized_value: str = ""
    anonymized: bool = False
    confidence: float = 50.0
    min_trust_required: int = 1
    context: dict[str, Any] = {}
    shared_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None


class ThreatFederationService:
    """Cross-organisation threat intelligence federation."""

    def __init__(self) -> None:
        self._members: dict[str, FederationMember] = {}
        self._tenant_members: dict[str, str] = {}  # tenant_id -> member_id
        self._indicators: dict[str, SharedIndicator] = {}
        self._consumption_log: dict[str, list[str]] = defaultdict(list)  # tenant -> indicator_ids

    # ------------------------------------------------------------------
    # Federation Membership
    # ------------------------------------------------------------------

    def join_federation(
        self,
        tenant_id: str,
        org_name: str,
        trust_level: str = "basic",
    ) -> dict:
        """Join the threat intelligence federation."""
        # Check if already a member
        existing_mid = self._tenant_members.get(tenant_id)
        if existing_mid and existing_mid in self._members:
            return {"error": "Tenant is already a federation member"}

        tlevel = trust_level if trust_level in _TRUST_LEVELS else "basic"

        member = FederationMember(
            tenant_id=tenant_id,
            org_name=org_name,
            trust_level=tlevel,
            trust_score=_TRUST_LEVELS.get(tlevel, 2),
        )
        self._members[member.id] = member
        self._tenant_members[tenant_id] = member.id

        logger.info(
            "[THREAT_FED] '%s' joined federation with trust_level=%s for %s",
            org_name,
            tlevel,
            tenant_id,
        )
        return member.model_dump(mode="json")

    def get_member(self, tenant_id: str) -> dict | None:
        """Get federation membership details for a tenant."""
        mid = self._tenant_members.get(tenant_id)
        if not mid:
            return None
        member = self._members.get(mid)
        return member.model_dump(mode="json") if member else None

    def update_trust_level(
        self,
        tenant_id: str,
        trust_level: str,
    ) -> dict | None:
        """Update trust level for a federation member."""
        mid = self._tenant_members.get(tenant_id)
        if not mid:
            return None
        member = self._members.get(mid)
        if not member:
            return None

        tlevel = trust_level if trust_level in _TRUST_LEVELS else member.trust_level
        member.trust_level = tlevel
        member.trust_score = _TRUST_LEVELS.get(tlevel, 2)

        logger.info("[THREAT_FED] Updated trust level for %s to %s", tenant_id, tlevel)
        return member.model_dump(mode="json")

    # ------------------------------------------------------------------
    # Intelligence Sharing
    # ------------------------------------------------------------------

    def share_intelligence(
        self,
        tenant_id: str,
        indicator_type: str,
        indicator_value: str,
        anonymize: bool = False,
        confidence: float = 50.0,
        context: dict | None = None,
    ) -> dict:
        """Share a threat indicator with the federation."""
        mid = self._tenant_members.get(tenant_id)
        if not mid:
            return {"error": "Tenant is not a federation member"}

        member = self._members.get(mid)
        if not member or not member.active:
            return {"error": "Federation membership is inactive"}

        anon_value = ""
        if anonymize:
            anon_value = hashlib.sha256(indicator_value.encode()).hexdigest()[:16]

        indicator = SharedIndicator(
            source_tenant_id=tenant_id,
            indicator_type=indicator_type,
            indicator_value=indicator_value if not anonymize else "",
            anonymized_value=anon_value if anonymize else "",
            anonymized=anonymize,
            confidence=max(0.0, min(100.0, confidence)),
            min_trust_required=member.trust_score,
            context=context or {},
        )

        self._indicators[indicator.id] = indicator
        member.indicators_shared += 1
        member.last_activity_at = datetime.now(timezone.utc)

        logger.info(
            "[THREAT_FED] Shared %s indicator (anonymized=%s) from %s",
            indicator_type,
            anonymize,
            tenant_id,
        )
        return indicator.model_dump(mode="json")

    # ------------------------------------------------------------------
    # Intelligence Consumption
    # ------------------------------------------------------------------

    def consume_intelligence(
        self,
        tenant_id: str,
        min_trust: int = 1,
        indicator_type: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Consume shared threat intelligence from the federation."""
        mid = self._tenant_members.get(tenant_id)
        if not mid:
            return []

        member = self._members.get(mid)
        if not member or not member.active:
            return []

        results = []
        for indicator in self._indicators.values():
            # Skip own indicators
            if indicator.source_tenant_id == tenant_id:
                continue
            # Check trust level
            if indicator.min_trust_required > member.trust_score:
                continue
            if min_trust and indicator.min_trust_required < min_trust:
                continue
            if indicator_type and indicator.indicator_type != indicator_type:
                continue

            # Prepare consumable data (respect anonymization)
            data = {
                "id": indicator.id,
                "indicator_type": indicator.indicator_type,
                "confidence": indicator.confidence,
                "shared_at": indicator.shared_at.isoformat(),
                "context": indicator.context,
            }
            if indicator.anonymized:
                data["anonymized_value"] = indicator.anonymized_value
            else:
                data["indicator_value"] = indicator.indicator_value

            results.append(data)
            if len(results) >= limit:
                break

        # Track consumption
        member.indicators_consumed += len(results)
        member.last_activity_at = datetime.now(timezone.utc)
        self._consumption_log[tenant_id].extend([r["id"] for r in results])

        logger.info(
            "[THREAT_FED] %s consumed %d indicators (min_trust=%d)",
            tenant_id,
            len(results),
            min_trust,
        )
        return results

    # ------------------------------------------------------------------
    # Federation Status & Scoring
    # ------------------------------------------------------------------

    def get_federation_status(self, tenant_id: str) -> dict:
        """Return federation status overview."""
        mid = self._tenant_members.get(tenant_id)
        member = self._members.get(mid) if mid else None

        total_members = sum(1 for m in self._members.values() if m.active)
        total_indicators = len(self._indicators)

        by_trust: dict[str, int] = defaultdict(int)
        for m in self._members.values():
            if m.active:
                by_trust[m.trust_level] += 1

        return {
            "tenant_id": tenant_id,
            "is_member": member is not None,
            "trust_level": member.trust_level if member else None,
            "indicators_shared": member.indicators_shared if member else 0,
            "indicators_consumed": member.indicators_consumed if member else 0,
            "total_federation_members": total_members,
            "total_shared_indicators": total_indicators,
            "by_trust_level": dict(by_trust),
        }

    def get_collective_score(self, tenant_id: str) -> dict:
        """Compute collective defense score from federation data."""
        active_members = [m for m in self._members.values() if m.active]
        if not active_members:
            return {"tenant_id": tenant_id, "collective_score": 0.0, "members": 0}

        total_shared = sum(m.indicators_shared for m in active_members)
        total_consumed = sum(m.indicators_consumed for m in active_members)
        avg_trust = sum(m.trust_score for m in active_members) / len(active_members)

        # Collective score formula: participation + trust + volume
        participation = min(len(active_members) * 5, 30)
        trust_component = avg_trust * 10
        volume_component = min(total_shared * 0.5, 30)
        engagement = min(total_consumed * 0.1, 20)

        score = min(participation + trust_component + volume_component + engagement, 100.0)

        return {
            "tenant_id": tenant_id,
            "collective_score": round(score, 1),
            "members": len(active_members),
            "total_indicators_shared": total_shared,
            "total_indicators_consumed": total_consumed,
            "avg_trust_level": round(avg_trust, 1),
            "components": {
                "participation": round(participation, 1),
                "trust": round(trust_component, 1),
                "volume": round(volume_component, 1),
                "engagement": round(engagement, 1),
            },
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return threat federation statistics for a tenant."""
        mid = self._tenant_members.get(tenant_id)
        member = self._members.get(mid) if mid else None

        all_indicators = list(self._indicators.values())
        by_type: dict[str, int] = defaultdict(int)
        for ind in all_indicators:
            by_type[ind.indicator_type] += 1

        return {
            "is_member": member is not None,
            "trust_level": member.trust_level if member else None,
            "indicators_shared": member.indicators_shared if member else 0,
            "indicators_consumed": member.indicators_consumed if member else 0,
            "total_federation_members": sum(1 for m in self._members.values() if m.active),
            "total_indicators_in_federation": len(all_indicators),
            "indicators_by_type": dict(by_type),
        }


# Module-level singleton
threat_federation_service = ThreatFederationService()
