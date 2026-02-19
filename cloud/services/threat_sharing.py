"""AngelClaw V5.0 — Transcendence: Cross-Tenant Threat Intelligence Sharing.

Enables tenants to share threat indicators (IPs, domains, hashes, URLs,
emails) with one another through a trust-scored feed.  Consumers can
subscribe to the shared feed, filtering by minimum trust score, and mark
indicators as consumed for attribution tracking.

Features:
  - Indicator sharing with automatic trust scoring
  - Cross-tenant feed with trust-based filtering
  - Consumption tracking (who consumed what)
  - Per-tenant analytics (shared count, consumed count, by type, avg trust)
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("angelclaw.threat_sharing")

# Default trust score assigned to newly shared indicators
_DEFAULT_TRUST_SCORE = 0.8


class SharedIndicator:
    def __init__(
        self,
        source_tenant: str,
        indicator_type: str,
        indicator_value: str,
        severity: str = "medium",
        context: dict[str, Any] | None = None,
        trust_score: float = _DEFAULT_TRUST_SCORE,
    ) -> None:
        self.id = str(uuid.uuid4())
        self.source_tenant = source_tenant
        self.indicator_type = indicator_type  # ip, domain, hash, url, email
        self.indicator_value = indicator_value
        self.severity = severity
        self.context: dict[str, Any] = context or {}
        self.shared_at = datetime.now(timezone.utc)
        self.consumed_by: list[str] = []
        self.trust_score = trust_score

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_tenant": self.source_tenant,
            "indicator_type": self.indicator_type,
            "indicator_value": self.indicator_value,
            "severity": self.severity,
            "context": self.context,
            "shared_at": self.shared_at.isoformat(),
            "consumed_by": self.consumed_by,
            "trust_score": self.trust_score,
        }


class ThreatSharingService:
    """Cross-tenant threat intelligence sharing with trust scoring."""

    def __init__(self) -> None:
        self._indicators: dict[str, SharedIndicator] = {}
        self._tenant_shared: dict[str, list[str]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def share_indicator(
        self,
        tenant_id: str,
        indicator_type: str,
        indicator_value: str,
        severity: str = "medium",
        context: dict[str, Any] | None = None,
    ) -> dict:
        """Share a threat indicator from a tenant into the common feed."""
        indicator = SharedIndicator(
            source_tenant=tenant_id,
            indicator_type=indicator_type,
            indicator_value=indicator_value,
            severity=severity,
            context=context,
            trust_score=_DEFAULT_TRUST_SCORE,
        )
        self._indicators[indicator.id] = indicator
        self._tenant_shared[tenant_id].append(indicator.id)
        logger.info(
            "[THREAT_SHARE] Tenant %s shared %s indicator '%s' (trust=%.2f)",
            tenant_id, indicator_type, indicator_value, indicator.trust_score,
        )
        return indicator.to_dict()

    def list_shared(self, tenant_id: str) -> list[dict]:
        """List all indicators shared by a specific tenant."""
        results = []
        for iid in self._tenant_shared.get(tenant_id, []):
            indicator = self._indicators.get(iid)
            if indicator:
                results.append(indicator.to_dict())
        return results

    def consume_indicator(
        self,
        indicator_id: str,
        consumer_tenant_id: str,
    ) -> dict | None:
        """Mark an indicator as consumed by a tenant."""
        indicator = self._indicators.get(indicator_id)
        if not indicator:
            return None
        if consumer_tenant_id not in indicator.consumed_by:
            indicator.consumed_by.append(consumer_tenant_id)
        logger.info(
            "[THREAT_SHARE] Tenant %s consumed indicator %s",
            consumer_tenant_id, indicator_id[:8],
        )
        return indicator.to_dict()

    def get_feed(
        self,
        tenant_id: str,
        min_trust: float = 0.5,
    ) -> list[dict]:
        """Return shared indicators from *other* tenants above a trust threshold."""
        results = []
        for indicator in self._indicators.values():
            if indicator.source_tenant == tenant_id:
                continue
            if indicator.trust_score < min_trust:
                continue
            results.append(indicator.to_dict())
        results.sort(key=lambda i: i["trust_score"], reverse=True)
        return results

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return threat-sharing statistics for a tenant."""
        shared = [
            self._indicators[iid]
            for iid in self._tenant_shared.get(tenant_id, [])
            if iid in self._indicators
        ]
        by_type: dict[str, int] = defaultdict(int)
        total_consumed = 0
        trust_scores: list[float] = []
        for ind in shared:
            by_type[ind.indicator_type] += 1
            total_consumed += len(ind.consumed_by)
            trust_scores.append(ind.trust_score)
        return {
            "total_shared": len(shared),
            "total_consumed": total_consumed,
            "by_type": dict(by_type),
            "avg_trust": round(
                sum(trust_scores) / max(len(trust_scores), 1), 4,
            ),
        }


# Module-level singleton
threat_sharing_service = ThreatSharingService()
