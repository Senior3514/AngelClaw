"""AngelClaw V3.5 — Sentinel: IOC Matching Engine.

Real-time matching of Indicators of Compromise against live event streams.
Records matches and generates alerts when IOCs are triggered.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("angelclaw.ioc_engine")


class IOCMatch:
    """Represents a match between an IOC and a live event."""

    def __init__(
        self,
        tenant_id: str,
        ioc_id: str,
        event_id: str,
        agent_id: str | None,
        match_field: str,
        matched_value: str,
        severity: str = "high",
    ) -> None:
        self.id = str(uuid.uuid4())
        self.tenant_id = tenant_id
        self.ioc_id = ioc_id
        self.event_id = event_id
        self.agent_id = agent_id
        self.match_field = match_field
        self.matched_value = matched_value
        self.severity = severity
        self.acknowledged = False
        self.created_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "ioc_id": self.ioc_id,
            "event_id": self.event_id,
            "agent_id": self.agent_id,
            "match_field": self.match_field,
            "matched_value": self.matched_value,
            "severity": self.severity,
            "acknowledged": self.acknowledged,
            "created_at": self.created_at.isoformat(),
        }


class IOCMatchingEngine:
    """Real-time IOC matching against event streams."""

    def __init__(self) -> None:
        self._matches: list[IOCMatch] = []
        self._match_counts: dict[str, int] = defaultdict(int)  # ioc_id -> count

    def scan_events(
        self,
        tenant_id: str,
        events: list[dict],
        ioc_lookup: dict[str, list[dict]] | None = None,
    ) -> list[dict]:
        """Scan a batch of events against known IOCs.

        Args:
            tenant_id: Tenant scope
            events: List of event dicts with details
            ioc_lookup: Optional pre-built lookup {value: [ioc_dicts]}

        Returns:
            List of match dicts
        """
        if not ioc_lookup:
            return []

        new_matches = []
        for event in events:
            details = event.get("details", {}) if isinstance(event, dict) else {}
            event_id = event.get("id", str(uuid.uuid4()))
            agent_id = event.get("agent_id")

            # Check common fields
            check_fields = {
                "source_ip": details.get("source_ip") or details.get("src_ip"),
                "dest_ip": details.get("dest_ip") or details.get("dst_ip"),
                "ip": details.get("ip"),
                "domain": details.get("domain") or details.get("hostname"),
                "url": details.get("url"),
                "hash": details.get("hash") or details.get("sha256") or details.get("md5"),
                "email": details.get("email"),
            }

            for field_name, value in check_fields.items():
                if not value:
                    continue
                matched_iocs = ioc_lookup.get(str(value), [])
                for ioc in matched_iocs:
                    match = IOCMatch(
                        tenant_id=tenant_id,
                        ioc_id=ioc.get("id", ""),
                        event_id=event_id,
                        agent_id=agent_id,
                        match_field=field_name,
                        matched_value=str(value),
                        severity=ioc.get("severity", "high"),
                    )
                    self._matches.append(match)
                    self._match_counts[ioc.get("id", "")] += 1
                    new_matches.append(match.to_dict())

        if new_matches:
            logger.info(
                "[IOC_ENGINE] %d IOC match(es) found in %d events for tenant %s",
                len(new_matches),
                len(events),
                tenant_id,
            )
        return new_matches

    def get_matches(
        self,
        tenant_id: str,
        limit: int = 100,
        acknowledged: bool | None = None,
        severity: str | None = None,
    ) -> list[dict]:
        results = []
        for m in reversed(self._matches):
            if m.tenant_id != tenant_id:
                continue
            if acknowledged is not None and m.acknowledged != acknowledged:
                continue
            if severity and m.severity != severity:
                continue
            results.append(m.to_dict())
            if len(results) >= limit:
                break
        return results

    def acknowledge_match(self, match_id: str) -> bool:
        for m in self._matches:
            if m.id == match_id:
                m.acknowledged = True
                return True
        return False

    def get_stats(self, tenant_id: str) -> dict:
        tenant_matches = [m for m in self._matches if m.tenant_id == tenant_id]
        unack = sum(1 for m in tenant_matches if not m.acknowledged)
        by_severity: dict[str, int] = defaultdict(int)
        for m in tenant_matches:
            by_severity[m.severity] += 1
        return {
            "total_matches": len(tenant_matches),
            "unacknowledged": unack,
            "by_severity": dict(by_severity),
            "top_iocs": sorted(self._match_counts.items(), key=lambda x: x[1], reverse=True)[:10],
        }


# Module-level singleton
ioc_engine = IOCMatchingEngine()
