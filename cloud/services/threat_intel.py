"""AngelClaw V3.5 — Sentinel: Threat Intelligence Feed Service.

Manages threat intelligence feed subscriptions, polling, and IOC ingestion.
Supports STIX/TAXII-compatible feeds, CSV, JSON, and MISP formats.

Features:
  - Feed subscription management (CRUD)
  - Automatic polling on configurable intervals
  - IOC deduplication and expiry management
  - Feed health monitoring and error tracking
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.threat_intel")


class ThreatIntelFeed(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    name: str
    feed_type: str  # stix, taxii, csv, json, misp
    url: str | None = None
    enabled: bool = True
    poll_interval_minutes: int = 60
    last_polled_at: datetime | None = None
    ioc_count: int = 0
    error: str | None = None
    config: dict[str, Any] = {}
    created_by: str = "system"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IOCEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    feed_id: str
    ioc_type: str  # ip, domain, hash_md5, hash_sha256, url, email, cve
    value: str
    severity: str = "medium"
    confidence: int = 50
    tags: list[str] = []
    context: dict[str, Any] = {}
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    active: bool = True


class ThreatIntelService:
    """Manages threat intelligence feeds and IOC ingestion."""

    def __init__(self) -> None:
        self._feeds: dict[str, ThreatIntelFeed] = {}
        self._iocs: dict[str, IOCEntry] = {}
        self._ioc_index: dict[str, set[str]] = defaultdict(set)  # value -> ioc_ids
        self._tenant_feeds: dict[str, list[str]] = defaultdict(list)

    # -- Feed CRUD --

    def create_feed(
        self,
        tenant_id: str,
        name: str,
        feed_type: str,
        url: str | None = None,
        poll_interval_minutes: int = 60,
        config: dict | None = None,
        created_by: str = "system",
    ) -> dict:
        feed = ThreatIntelFeed(
            tenant_id=tenant_id,
            name=name,
            feed_type=feed_type,
            url=url,
            poll_interval_minutes=poll_interval_minutes,
            config=config or {},
            created_by=created_by,
        )
        self._feeds[feed.id] = feed
        self._tenant_feeds[tenant_id].append(feed.id)
        logger.info("[THREAT_INTEL] Created feed '%s' (%s) for %s", name, feed_type, tenant_id)
        return feed.model_dump(mode="json")

    def get_feed(self, feed_id: str) -> dict | None:
        feed = self._feeds.get(feed_id)
        return feed.model_dump(mode="json") if feed else None

    def list_feeds(self, tenant_id: str) -> list[dict]:
        feed_ids = self._tenant_feeds.get(tenant_id, [])
        return [self._feeds[fid].model_dump(mode="json") for fid in feed_ids if fid in self._feeds]

    def toggle_feed(self, feed_id: str, enabled: bool) -> dict | None:
        feed = self._feeds.get(feed_id)
        if not feed:
            return None
        feed.enabled = enabled
        return feed.model_dump(mode="json")

    def delete_feed(self, feed_id: str) -> bool:
        feed = self._feeds.pop(feed_id, None)
        if not feed:
            return False
        self._tenant_feeds[feed.tenant_id] = [
            fid for fid in self._tenant_feeds[feed.tenant_id] if fid != feed_id
        ]
        # Remove associated IOCs
        to_remove = [iid for iid, ioc in self._iocs.items() if ioc.feed_id == feed_id]
        for iid in to_remove:
            self._remove_ioc(iid)
        return True

    # -- IOC Management --

    def ingest_iocs(
        self,
        tenant_id: str,
        feed_id: str,
        iocs: list[dict],
    ) -> dict:
        added = 0
        updated = 0
        for ioc_data in iocs:
            value = ioc_data.get("value", "")
            ioc_type = ioc_data.get("ioc_type", "unknown")
            existing_ids = self._ioc_index.get(value, set())
            existing = None
            for eid in existing_ids:
                e = self._iocs.get(eid)
                if e and e.tenant_id == tenant_id and e.ioc_type == ioc_type:
                    existing = e
                    break

            if existing:
                existing.last_seen = datetime.now(timezone.utc)
                existing.confidence = max(existing.confidence, ioc_data.get("confidence", 50))
                if ioc_data.get("tags"):
                    existing.tags = list(set(existing.tags + ioc_data["tags"]))
                updated += 1
            else:
                entry = IOCEntry(
                    tenant_id=tenant_id,
                    feed_id=feed_id,
                    ioc_type=ioc_type,
                    value=value,
                    severity=ioc_data.get("severity", "medium"),
                    confidence=ioc_data.get("confidence", 50),
                    tags=ioc_data.get("tags", []),
                    context=ioc_data.get("context", {}),
                    expires_at=ioc_data.get("expires_at"),
                )
                self._iocs[entry.id] = entry
                self._ioc_index[value].add(entry.id)
                added += 1

        # Update feed stats
        feed = self._feeds.get(feed_id)
        if feed:
            feed.last_polled_at = datetime.now(timezone.utc)
            feed.ioc_count = sum(
                1 for ioc in self._iocs.values()
                if ioc.feed_id == feed_id and ioc.active
            )

        logger.info(
            "[THREAT_INTEL] Ingested %d new, %d updated IOCs from feed %s",
            added, updated, feed_id[:8],
        )
        return {"added": added, "updated": updated, "total": added + updated}

    def search_iocs(
        self,
        tenant_id: str,
        ioc_type: str | None = None,
        value: str | None = None,
        severity: str | None = None,
        feed_id: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        results = []
        for ioc in self._iocs.values():
            if ioc.tenant_id != tenant_id or not ioc.active:
                continue
            if ioc_type and ioc.ioc_type != ioc_type:
                continue
            if value and value.lower() not in ioc.value.lower():
                continue
            if severity and ioc.severity != severity:
                continue
            if feed_id and ioc.feed_id != feed_id:
                continue
            results.append(ioc.model_dump(mode="json"))
            if len(results) >= limit:
                break
        return results

    def match_value(self, tenant_id: str, value: str) -> list[dict]:
        """Check if a value matches any active IOC."""
        matches = []
        ioc_ids = self._ioc_index.get(value, set())
        for ioc_id in ioc_ids:
            ioc = self._iocs.get(ioc_id)
            if ioc and ioc.tenant_id == tenant_id and ioc.active:
                matches.append(ioc.model_dump(mode="json"))
        return matches

    def match_event(self, tenant_id: str, event_details: dict) -> list[dict]:
        """Match event fields against active IOCs."""
        matches = []
        check_fields = [
            ("source_ip", "ip"), ("dest_ip", "ip"), ("ip", "ip"),
            ("domain", "domain"), ("url", "url"), ("hash", "hash_sha256"),
            ("md5", "hash_md5"), ("sha256", "hash_sha256"), ("email", "email"),
        ]
        for field_name, ioc_type in check_fields:
            val = event_details.get(field_name)
            if val:
                for m in self.match_value(tenant_id, str(val)):
                    m["match_field"] = field_name
                    matches.append(m)
        return matches

    def expire_stale_iocs(self) -> int:
        """Remove expired IOCs. Returns count removed."""
        now = datetime.now(timezone.utc)
        expired = []
        for ioc_id, ioc in self._iocs.items():
            if ioc.expires_at and ioc.expires_at < now:
                expired.append(ioc_id)
        for ioc_id in expired:
            self._remove_ioc(ioc_id)
        if expired:
            logger.info("[THREAT_INTEL] Expired %d stale IOCs", len(expired))
        return len(expired)

    def get_stats(self, tenant_id: str) -> dict:
        tenant_iocs = [i for i in self._iocs.values() if i.tenant_id == tenant_id and i.active]
        by_type: dict[str, int] = defaultdict(int)
        by_severity: dict[str, int] = defaultdict(int)
        for ioc in tenant_iocs:
            by_type[ioc.ioc_type] += 1
            by_severity[ioc.severity] += 1
        return {
            "total_feeds": len(self._tenant_feeds.get(tenant_id, [])),
            "total_iocs": len(tenant_iocs),
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
            "active_feeds": sum(
                1 for fid in self._tenant_feeds.get(tenant_id, [])
                if self._feeds.get(fid, ThreatIntelFeed(name="", feed_type="")).enabled
            ),
        }

    def _remove_ioc(self, ioc_id: str) -> None:
        ioc = self._iocs.pop(ioc_id, None)
        if ioc:
            ids = self._ioc_index.get(ioc.value, set())
            ids.discard(ioc_id)
            if not ids:
                self._ioc_index.pop(ioc.value, None)


# Module-level singleton
threat_intel_service = ThreatIntelService()
