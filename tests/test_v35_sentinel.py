"""Tests for V3.5 Sentinel: Threat Intel, IOC Engine, Reputation.

Covers feed CRUD, IOC ingestion/search/expiry, real-time IOC matching,
reputation lookup/scoring, bulk operations, stats, and edge cases.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cloud.services.ioc_engine import IOCMatchingEngine
from cloud.services.reputation import ReputationService
from cloud.services.threat_intel import ThreatIntelService

# ---------------------------------------------------------------------------
# ThreatIntelService
# ---------------------------------------------------------------------------


class TestThreatIntelFeedBasic:
    """Basic feed CRUD operations."""

    def test_create_feed(self):
        svc = ThreatIntelService()
        feed = svc.create_feed("t1", "AlienVault OTX", "stix", url="https://otx.example.com")
        assert feed["name"] == "AlienVault OTX"
        assert feed["feed_type"] == "stix"
        assert feed["tenant_id"] == "t1"
        assert feed["enabled"] is True
        assert "id" in feed

    def test_list_feeds_empty(self):
        svc = ThreatIntelService()
        assert svc.list_feeds("t1") == []

    def test_list_feeds_returns_created(self):
        svc = ThreatIntelService()
        svc.create_feed("t1", "Feed A", "csv")
        svc.create_feed("t1", "Feed B", "json")
        feeds = svc.list_feeds("t1")
        assert len(feeds) == 2
        names = {f["name"] for f in feeds}
        assert names == {"Feed A", "Feed B"}

    def test_list_feeds_tenant_isolation(self):
        svc = ThreatIntelService()
        svc.create_feed("t1", "Feed A", "csv")
        svc.create_feed("t2", "Feed B", "json")
        assert len(svc.list_feeds("t1")) == 1
        assert len(svc.list_feeds("t2")) == 1

    def test_get_feed(self):
        svc = ThreatIntelService()
        created = svc.create_feed("t1", "My Feed", "misp")
        fetched = svc.get_feed(created["id"])
        assert fetched is not None
        assert fetched["name"] == "My Feed"

    def test_get_feed_nonexistent(self):
        svc = ThreatIntelService()
        assert svc.get_feed("nonexistent-id") is None

    def test_delete_feed(self):
        svc = ThreatIntelService()
        feed = svc.create_feed("t1", "Temp Feed", "csv")
        assert svc.delete_feed(feed["id"]) is True
        assert svc.get_feed(feed["id"]) is None
        assert svc.list_feeds("t1") == []

    def test_delete_feed_nonexistent(self):
        svc = ThreatIntelService()
        assert svc.delete_feed("nonexistent-id") is False

    def test_toggle_feed(self):
        svc = ThreatIntelService()
        feed = svc.create_feed("t1", "Toggle Feed", "stix")
        result = svc.toggle_feed(feed["id"], False)
        assert result is not None
        assert result["enabled"] is False
        result = svc.toggle_feed(feed["id"], True)
        assert result["enabled"] is True

    def test_toggle_feed_nonexistent(self):
        svc = ThreatIntelService()
        assert svc.toggle_feed("nonexistent-id", True) is None


class TestThreatIntelIOCIngestion:
    """IOC ingestion, deduplication, and search."""

    def test_ingest_iocs_adds_new(self):
        svc = ThreatIntelService()
        feed = svc.create_feed("t1", "Feed A", "csv")
        result = svc.ingest_iocs(
            "t1",
            feed["id"],
            [
                {"ioc_type": "ip", "value": "10.0.0.1", "severity": "high"},
                {"ioc_type": "domain", "value": "evil.com", "severity": "critical"},
            ],
        )
        assert result["added"] == 2
        assert result["updated"] == 0
        assert result["total"] == 2

    def test_ingest_iocs_deduplicates(self):
        svc = ThreatIntelService()
        feed = svc.create_feed("t1", "Feed A", "csv")
        svc.ingest_iocs(
            "t1",
            feed["id"],
            [
                {"ioc_type": "ip", "value": "10.0.0.1", "confidence": 50},
            ],
        )
        result = svc.ingest_iocs(
            "t1",
            feed["id"],
            [
                {"ioc_type": "ip", "value": "10.0.0.1", "confidence": 90},
            ],
        )
        assert result["added"] == 0
        assert result["updated"] == 1

    def test_ingest_updates_feed_ioc_count(self):
        svc = ThreatIntelService()
        feed = svc.create_feed("t1", "Feed A", "csv")
        svc.ingest_iocs(
            "t1",
            feed["id"],
            [
                {"ioc_type": "ip", "value": "1.1.1.1"},
                {"ioc_type": "ip", "value": "2.2.2.2"},
            ],
        )
        updated_feed = svc.get_feed(feed["id"])
        assert updated_feed["ioc_count"] == 2

    def test_search_iocs_by_type(self):
        svc = ThreatIntelService()
        feed = svc.create_feed("t1", "Feed A", "csv")
        svc.ingest_iocs(
            "t1",
            feed["id"],
            [
                {"ioc_type": "ip", "value": "10.0.0.1"},
                {"ioc_type": "domain", "value": "evil.com"},
                {"ioc_type": "ip", "value": "10.0.0.2"},
            ],
        )
        results = svc.search_iocs("t1", ioc_type="ip")
        assert len(results) == 2
        assert all(r["ioc_type"] == "ip" for r in results)

    def test_search_iocs_by_value(self):
        svc = ThreatIntelService()
        feed = svc.create_feed("t1", "Feed A", "csv")
        svc.ingest_iocs(
            "t1",
            feed["id"],
            [
                {"ioc_type": "domain", "value": "evil.com"},
                {"ioc_type": "domain", "value": "good.org"},
            ],
        )
        results = svc.search_iocs("t1", value="evil")
        assert len(results) == 1
        assert results[0]["value"] == "evil.com"

    def test_search_iocs_by_severity(self):
        svc = ThreatIntelService()
        feed = svc.create_feed("t1", "Feed A", "csv")
        svc.ingest_iocs(
            "t1",
            feed["id"],
            [
                {"ioc_type": "ip", "value": "1.1.1.1", "severity": "high"},
                {"ioc_type": "ip", "value": "2.2.2.2", "severity": "low"},
            ],
        )
        results = svc.search_iocs("t1", severity="high")
        assert len(results) == 1
        assert results[0]["severity"] == "high"

    def test_search_iocs_empty(self):
        svc = ThreatIntelService()
        results = svc.search_iocs("t1", ioc_type="ip")
        assert results == []

    def test_search_iocs_tenant_isolation(self):
        svc = ThreatIntelService()
        feed1 = svc.create_feed("t1", "Feed A", "csv")
        feed2 = svc.create_feed("t2", "Feed B", "csv")
        svc.ingest_iocs("t1", feed1["id"], [{"ioc_type": "ip", "value": "1.1.1.1"}])
        svc.ingest_iocs("t2", feed2["id"], [{"ioc_type": "ip", "value": "2.2.2.2"}])
        assert len(svc.search_iocs("t1")) == 1
        assert len(svc.search_iocs("t2")) == 1
        assert svc.search_iocs("t1")[0]["value"] == "1.1.1.1"


class TestThreatIntelIOCExpiry:
    """IOC expiration management."""

    def test_expire_stale_iocs_removes_expired(self):
        svc = ThreatIntelService()
        feed = svc.create_feed("t1", "Feed A", "csv")
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        svc.ingest_iocs(
            "t1",
            feed["id"],
            [
                {"ioc_type": "ip", "value": "1.1.1.1", "expires_at": past},
                {"ioc_type": "ip", "value": "2.2.2.2"},
            ],
        )
        removed = svc.expire_stale_iocs()
        assert removed == 1
        # Only the non-expired IOC remains
        results = svc.search_iocs("t1")
        assert len(results) == 1
        assert results[0]["value"] == "2.2.2.2"

    def test_expire_stale_iocs_none_expired(self):
        svc = ThreatIntelService()
        feed = svc.create_feed("t1", "Feed A", "csv")
        future = datetime.now(timezone.utc) + timedelta(hours=24)
        svc.ingest_iocs(
            "t1",
            feed["id"],
            [
                {"ioc_type": "ip", "value": "1.1.1.1", "expires_at": future},
            ],
        )
        removed = svc.expire_stale_iocs()
        assert removed == 0

    def test_expire_stale_iocs_empty(self):
        svc = ThreatIntelService()
        assert svc.expire_stale_iocs() == 0


class TestThreatIntelStats:
    """Statistics and aggregation."""

    def test_get_stats_empty(self):
        svc = ThreatIntelService()
        stats = svc.get_stats("t1")
        assert stats["total_feeds"] == 0
        assert stats["total_iocs"] == 0
        assert stats["by_type"] == {}
        assert stats["by_severity"] == {}

    def test_get_stats_counts(self):
        svc = ThreatIntelService()
        feed = svc.create_feed("t1", "Feed A", "csv")
        svc.ingest_iocs(
            "t1",
            feed["id"],
            [
                {"ioc_type": "ip", "value": "1.1.1.1", "severity": "high"},
                {"ioc_type": "ip", "value": "2.2.2.2", "severity": "high"},
                {"ioc_type": "domain", "value": "evil.com", "severity": "critical"},
            ],
        )
        stats = svc.get_stats("t1")
        assert stats["total_feeds"] == 1
        assert stats["total_iocs"] == 3
        assert stats["by_type"]["ip"] == 2
        assert stats["by_type"]["domain"] == 1
        assert stats["by_severity"]["high"] == 2
        assert stats["by_severity"]["critical"] == 1
        assert stats["active_feeds"] == 1

    def test_get_stats_disabled_feed(self):
        svc = ThreatIntelService()
        feed = svc.create_feed("t1", "Feed A", "csv")
        svc.toggle_feed(feed["id"], False)
        stats = svc.get_stats("t1")
        assert stats["total_feeds"] == 1
        assert stats["active_feeds"] == 0


class TestThreatIntelEdgeCases:
    """Edge cases and advanced scenarios."""

    def test_delete_feed_removes_associated_iocs(self):
        svc = ThreatIntelService()
        feed = svc.create_feed("t1", "Feed A", "csv")
        svc.ingest_iocs(
            "t1",
            feed["id"],
            [
                {"ioc_type": "ip", "value": "1.1.1.1"},
                {"ioc_type": "ip", "value": "2.2.2.2"},
            ],
        )
        assert len(svc.search_iocs("t1")) == 2
        svc.delete_feed(feed["id"])
        assert len(svc.search_iocs("t1")) == 0

    def test_match_value_exact(self):
        svc = ThreatIntelService()
        feed = svc.create_feed("t1", "Feed A", "csv")
        svc.ingest_iocs(
            "t1",
            feed["id"],
            [
                {"ioc_type": "ip", "value": "10.0.0.99"},
            ],
        )
        matches = svc.match_value("t1", "10.0.0.99")
        assert len(matches) == 1
        assert matches[0]["value"] == "10.0.0.99"

    def test_match_value_no_match(self):
        svc = ThreatIntelService()
        matches = svc.match_value("t1", "1.2.3.4")
        assert matches == []

    def test_match_event_multiple_fields(self):
        svc = ThreatIntelService()
        feed = svc.create_feed("t1", "Feed A", "csv")
        svc.ingest_iocs(
            "t1",
            feed["id"],
            [
                {"ioc_type": "ip", "value": "10.0.0.1"},
                {"ioc_type": "domain", "value": "evil.com"},
            ],
        )
        matches = svc.match_event("t1", {"source_ip": "10.0.0.1", "domain": "evil.com"})
        assert len(matches) == 2

    def test_ingest_iocs_merges_tags_on_update(self):
        svc = ThreatIntelService()
        feed = svc.create_feed("t1", "Feed A", "csv")
        svc.ingest_iocs(
            "t1",
            feed["id"],
            [
                {"ioc_type": "ip", "value": "10.0.0.1", "tags": ["apt"]},
            ],
        )
        svc.ingest_iocs(
            "t1",
            feed["id"],
            [
                {"ioc_type": "ip", "value": "10.0.0.1", "tags": ["c2"]},
            ],
        )
        results = svc.search_iocs("t1", value="10.0.0.1")
        assert len(results) == 1
        assert "apt" in results[0]["tags"]
        assert "c2" in results[0]["tags"]


# ---------------------------------------------------------------------------
# IOCMatchingEngine
# ---------------------------------------------------------------------------


class TestIOCMatchingBasic:
    """Basic IOC scanning and matching."""

    def test_scan_events_with_matches(self):
        engine = IOCMatchingEngine()
        ioc_lookup = {
            "10.0.0.99": [{"id": "ioc-1", "severity": "critical"}],
        }
        events = [
            {"id": "evt-1", "agent_id": "agent-a", "details": {"source_ip": "10.0.0.99"}},
        ]
        matches = engine.scan_events("t1", events, ioc_lookup)
        assert len(matches) == 1
        assert matches[0]["ioc_id"] == "ioc-1"
        assert matches[0]["matched_value"] == "10.0.0.99"
        assert matches[0]["match_field"] == "source_ip"
        assert matches[0]["severity"] == "critical"

    def test_scan_events_no_matches(self):
        engine = IOCMatchingEngine()
        ioc_lookup = {
            "10.0.0.99": [{"id": "ioc-1", "severity": "high"}],
        }
        events = [
            {"id": "evt-1", "details": {"source_ip": "192.168.1.1"}},
        ]
        matches = engine.scan_events("t1", events, ioc_lookup)
        assert matches == []

    def test_scan_events_no_lookup_returns_empty(self):
        engine = IOCMatchingEngine()
        events = [{"id": "evt-1", "details": {"source_ip": "10.0.0.1"}}]
        matches = engine.scan_events("t1", events)
        assert matches == []

    def test_scan_events_empty_events(self):
        engine = IOCMatchingEngine()
        matches = engine.scan_events("t1", [], {"10.0.0.1": [{"id": "ioc-1"}]})
        assert matches == []

    def test_scan_events_multiple_fields(self):
        engine = IOCMatchingEngine()
        ioc_lookup = {
            "10.0.0.1": [{"id": "ioc-ip", "severity": "high"}],
            "evil.com": [{"id": "ioc-domain", "severity": "critical"}],
        }
        events = [
            {"id": "evt-1", "details": {"source_ip": "10.0.0.1", "domain": "evil.com"}},
        ]
        matches = engine.scan_events("t1", events, ioc_lookup)
        assert len(matches) == 2
        ioc_ids = {m["ioc_id"] for m in matches}
        assert ioc_ids == {"ioc-ip", "ioc-domain"}

    def test_scan_events_multiple_events(self):
        engine = IOCMatchingEngine()
        ioc_lookup = {
            "bad.ip": [{"id": "ioc-1", "severity": "high"}],
        }
        events = [
            {"id": "evt-1", "details": {"ip": "bad.ip"}},
            {"id": "evt-2", "details": {"ip": "good.ip"}},
            {"id": "evt-3", "details": {"ip": "bad.ip"}},
        ]
        matches = engine.scan_events("t1", events, ioc_lookup)
        assert len(matches) == 2


class TestIOCMatchingAcknowledge:
    """Match acknowledgement."""

    def test_acknowledge_match(self):
        engine = IOCMatchingEngine()
        ioc_lookup = {"10.0.0.1": [{"id": "ioc-1", "severity": "high"}]}
        events = [{"id": "evt-1", "details": {"ip": "10.0.0.1"}}]
        matches = engine.scan_events("t1", events, ioc_lookup)
        match_id = matches[0]["id"]

        assert engine.acknowledge_match(match_id) is True

        # Verify it is acknowledged via get_matches
        all_matches = engine.get_matches("t1")
        acked = [m for m in all_matches if m["id"] == match_id]
        assert len(acked) == 1
        assert acked[0]["acknowledged"] is True

    def test_acknowledge_nonexistent_match(self):
        engine = IOCMatchingEngine()
        assert engine.acknowledge_match("nonexistent-id") is False

    def test_get_matches_filter_acknowledged(self):
        engine = IOCMatchingEngine()
        ioc_lookup = {"10.0.0.1": [{"id": "ioc-1", "severity": "high"}]}
        events = [
            {"id": "evt-1", "details": {"ip": "10.0.0.1"}},
            {"id": "evt-2", "details": {"ip": "10.0.0.1"}},
        ]
        matches = engine.scan_events("t1", events, ioc_lookup)
        engine.acknowledge_match(matches[0]["id"])

        unacked = engine.get_matches("t1", acknowledged=False)
        assert len(unacked) == 1
        acked = engine.get_matches("t1", acknowledged=True)
        assert len(acked) == 1

    def test_get_matches_filter_severity(self):
        engine = IOCMatchingEngine()
        ioc_lookup = {
            "10.0.0.1": [{"id": "ioc-1", "severity": "high"}],
            "evil.com": [{"id": "ioc-2", "severity": "critical"}],
        }
        events = [
            {"id": "evt-1", "details": {"ip": "10.0.0.1", "domain": "evil.com"}},
        ]
        engine.scan_events("t1", events, ioc_lookup)
        high_only = engine.get_matches("t1", severity="high")
        assert len(high_only) == 1
        assert high_only[0]["severity"] == "high"


class TestIOCMatchingStats:
    """IOC engine statistics."""

    def test_get_stats_empty(self):
        engine = IOCMatchingEngine()
        stats = engine.get_stats("t1")
        assert stats["total_matches"] == 0
        assert stats["unacknowledged"] == 0
        assert stats["by_severity"] == {}
        assert stats["top_iocs"] == []

    def test_get_stats_counts(self):
        engine = IOCMatchingEngine()
        ioc_lookup = {
            "10.0.0.1": [{"id": "ioc-1", "severity": "high"}],
            "evil.com": [{"id": "ioc-2", "severity": "critical"}],
        }
        events = [
            {"id": "evt-1", "details": {"ip": "10.0.0.1", "domain": "evil.com"}},
        ]
        engine.scan_events("t1", events, ioc_lookup)
        stats = engine.get_stats("t1")
        assert stats["total_matches"] == 2
        assert stats["unacknowledged"] == 2
        assert stats["by_severity"]["high"] == 1
        assert stats["by_severity"]["critical"] == 1
        assert len(stats["top_iocs"]) == 2

    def test_get_stats_after_acknowledge(self):
        engine = IOCMatchingEngine()
        ioc_lookup = {"10.0.0.1": [{"id": "ioc-1", "severity": "high"}]}
        matches = engine.scan_events(
            "t1", [{"id": "e1", "details": {"ip": "10.0.0.1"}}], ioc_lookup
        )
        engine.acknowledge_match(matches[0]["id"])
        stats = engine.get_stats("t1")
        assert stats["total_matches"] == 1
        assert stats["unacknowledged"] == 0

    def test_get_stats_tenant_isolation(self):
        engine = IOCMatchingEngine()
        ioc_lookup = {"10.0.0.1": [{"id": "ioc-1", "severity": "high"}]}
        engine.scan_events("t1", [{"id": "e1", "details": {"ip": "10.0.0.1"}}], ioc_lookup)
        engine.scan_events("t2", [{"id": "e2", "details": {"ip": "10.0.0.1"}}], ioc_lookup)
        assert engine.get_stats("t1")["total_matches"] == 1
        assert engine.get_stats("t2")["total_matches"] == 1


class TestIOCMatchingEdgeCases:
    """Edge cases for the IOC matching engine."""

    def test_scan_events_with_missing_details(self):
        engine = IOCMatchingEngine()
        ioc_lookup = {"10.0.0.1": [{"id": "ioc-1"}]}
        events = [{"id": "evt-1"}]  # no details key
        matches = engine.scan_events("t1", events, ioc_lookup)
        assert matches == []

    def test_scan_events_generates_event_id_if_missing(self):
        engine = IOCMatchingEngine()
        ioc_lookup = {"10.0.0.1": [{"id": "ioc-1", "severity": "high"}]}
        events = [{"details": {"ip": "10.0.0.1"}}]  # no id key
        matches = engine.scan_events("t1", events, ioc_lookup)
        assert len(matches) == 1
        assert matches[0]["event_id"]  # auto-generated, non-empty

    def test_get_matches_limit(self):
        engine = IOCMatchingEngine()
        ioc_lookup = {"10.0.0.1": [{"id": "ioc-1", "severity": "high"}]}
        for i in range(10):
            engine.scan_events("t1", [{"id": f"e-{i}", "details": {"ip": "10.0.0.1"}}], ioc_lookup)
        limited = engine.get_matches("t1", limit=3)
        assert len(limited) == 3


# ---------------------------------------------------------------------------
# ReputationService
# ---------------------------------------------------------------------------


class TestReputationBasic:
    """Basic reputation lookup and scoring."""

    def test_lookup_new_entity_default_score(self):
        svc = ReputationService()
        result = svc.lookup("t1", "ip", "8.8.8.8")
        assert result["entity_type"] == "ip"
        assert result["entity_value"] == "8.8.8.8"
        assert result["score"] == 50  # default neutral score
        assert result["risk_level"] == "medium"
        assert "angelclaw_builtin" in result["sources"]

    def test_lookup_private_ip_high_score(self):
        svc = ReputationService()
        result = svc.lookup("t1", "ip", "192.168.1.1")
        assert result["score"] == 90
        assert result["category"] == "private"
        assert result["risk_level"] == "clean"

    def test_lookup_loopback_ip(self):
        svc = ReputationService()
        result = svc.lookup("t1", "ip", "127.0.0.1")
        assert result["score"] == 90
        assert result["category"] == "private"

    def test_lookup_known_malicious_pattern(self):
        svc = ReputationService()
        result = svc.lookup("t1", "domain", "tor-exit-node.example.com")
        assert result["score"] == 15
        assert result["category"] == "tor-exit"
        assert result["risk_level"] == "critical"

    def test_lookup_caches_result(self):
        svc = ReputationService()
        first = svc.lookup("t1", "ip", "8.8.8.8")
        second = svc.lookup("t1", "ip", "8.8.8.8")
        assert first["id"] == second["id"]


class TestReputationUpdateScore:
    """Score adjustment operations."""

    def test_update_score_existing_entity(self):
        svc = ReputationService()
        svc.lookup("t1", "ip", "8.8.8.8")  # create entry with score=50
        updated = svc.update_score("t1", "ip", "8.8.8.8", -30, source="threat_intel")
        assert updated is not None
        assert updated["score"] == 20
        assert "threat_intel" in updated["sources"]

    def test_update_score_new_entity(self):
        svc = ReputationService()
        result = svc.update_score("t1", "domain", "new-domain.com", -20, source="feed")
        assert result is not None
        assert result["score"] == 30  # 50 + (-20)

    def test_update_score_clamps_to_zero(self):
        svc = ReputationService()
        svc.lookup("t1", "ip", "8.8.8.8")  # score=50
        result = svc.update_score("t1", "ip", "8.8.8.8", -100)
        assert result["score"] == 0

    def test_update_score_clamps_to_hundred(self):
        svc = ReputationService()
        svc.lookup("t1", "ip", "8.8.8.8")  # score=50
        result = svc.update_score("t1", "ip", "8.8.8.8", 100)
        assert result["score"] == 100

    def test_update_score_with_category(self):
        svc = ReputationService()
        svc.lookup("t1", "ip", "8.8.8.8")
        result = svc.update_score("t1", "ip", "8.8.8.8", -40, category="botnet")
        assert result["category"] == "botnet"

    def test_update_score_appends_source(self):
        svc = ReputationService()
        svc.lookup("t1", "ip", "8.8.8.8")  # source: angelclaw_builtin
        svc.update_score("t1", "ip", "8.8.8.8", -10, source="feed_a")
        svc.update_score("t1", "ip", "8.8.8.8", -5, source="feed_b")
        result = svc.lookup("t1", "ip", "8.8.8.8")
        assert "angelclaw_builtin" in result["sources"]
        assert "feed_a" in result["sources"]
        assert "feed_b" in result["sources"]

    def test_update_score_does_not_duplicate_source(self):
        svc = ReputationService()
        svc.lookup("t1", "ip", "8.8.8.8")
        svc.update_score("t1", "ip", "8.8.8.8", -5, source="manual")
        svc.update_score("t1", "ip", "8.8.8.8", -5, source="manual")
        result = svc.lookup("t1", "ip", "8.8.8.8")
        assert result["sources"].count("manual") == 1


class TestReputationBulkLookup:
    """Bulk reputation lookup."""

    def test_bulk_lookup_multiple_entities(self):
        svc = ReputationService()
        entities = [
            {"entity_type": "ip", "entity_value": "8.8.8.8"},
            {"entity_type": "domain", "entity_value": "example.com"},
            {"entity_type": "ip", "entity_value": "192.168.1.1"},
        ]
        results = svc.bulk_lookup("t1", entities)
        assert len(results) == 3
        assert results[0]["entity_value"] == "8.8.8.8"
        assert results[2]["score"] == 90  # private IP

    def test_bulk_lookup_empty(self):
        svc = ReputationService()
        results = svc.bulk_lookup("t1", [])
        assert results == []

    def test_bulk_lookup_increments_query_count(self):
        svc = ReputationService()
        entities = [
            {"entity_type": "ip", "entity_value": "1.1.1.1"},
            {"entity_type": "ip", "entity_value": "2.2.2.2"},
        ]
        svc.bulk_lookup("t1", entities)
        stats = svc.get_stats("t1")
        assert stats["total_queries"] == 2


class TestReputationWorstEntities:
    """Get entities with worst reputation."""

    def test_get_worst_entities(self):
        svc = ReputationService()
        svc.update_score("t1", "ip", "bad-ip-1", -40)  # score=10
        svc.update_score("t1", "ip", "bad-ip-2", -20)  # score=30
        svc.update_score("t1", "ip", "good-ip", 30)  # score=80
        worst = svc.get_worst("t1", limit=2)
        assert len(worst) == 2
        assert worst[0]["score"] <= worst[1]["score"]
        assert worst[0]["entity_value"] == "bad-ip-1"

    def test_get_worst_entities_empty(self):
        svc = ReputationService()
        assert svc.get_worst("t1") == []

    def test_get_worst_entities_limit(self):
        svc = ReputationService()
        for i in range(10):
            svc.update_score("t1", "ip", f"ip-{i}", -(i * 5))
        worst = svc.get_worst("t1", limit=3)
        assert len(worst) == 3


class TestReputationStats:
    """Reputation service statistics."""

    def test_get_stats_empty(self):
        svc = ReputationService()
        stats = svc.get_stats("t1")
        assert stats["total_entries"] == 0
        assert stats["by_type"] == {}
        assert stats["by_risk_level"] == {}
        assert stats["total_queries"] == 0

    def test_get_stats_counts(self):
        svc = ReputationService()
        svc.lookup("t1", "ip", "8.8.8.8")  # medium
        svc.lookup("t1", "domain", "example.com")  # medium
        svc.lookup("t1", "ip", "192.168.1.1")  # clean (90)
        stats = svc.get_stats("t1")
        assert stats["total_entries"] == 3
        assert stats["by_type"]["ip"] == 2
        assert stats["by_type"]["domain"] == 1
        assert stats["total_queries"] == 3
        assert "clean" in stats["by_risk_level"] or "medium" in stats["by_risk_level"]

    def test_get_stats_tenant_isolation(self):
        svc = ReputationService()
        svc.lookup("t1", "ip", "1.1.1.1")
        svc.lookup("t2", "ip", "2.2.2.2")
        assert svc.get_stats("t1")["total_entries"] == 1
        assert svc.get_stats("t2")["total_entries"] == 1


class TestReputationEdgeCases:
    """Edge cases for reputation scoring."""

    def test_risk_level_boundaries(self):
        svc = ReputationService()
        # score=0 -> critical
        svc.update_score("t1", "ip", "a", -50)  # 50 + (-50) = 0
        result = svc.lookup("t1", "ip", "a")
        assert result["risk_level"] == "critical"

    def test_risk_level_high(self):
        svc = ReputationService()
        svc.update_score("t1", "ip", "b", -20)  # score=30
        result = svc.lookup("t1", "ip", "b")
        assert result["risk_level"] == "high"

    def test_risk_level_low(self):
        svc = ReputationService()
        svc.update_score("t1", "ip", "c", 20)  # score=70
        result = svc.lookup("t1", "ip", "c")
        assert result["risk_level"] == "low"

    def test_risk_level_clean(self):
        svc = ReputationService()
        svc.update_score("t1", "ip", "d", 40)  # score=90
        result = svc.lookup("t1", "ip", "d")
        assert result["risk_level"] == "clean"

    def test_multiple_malicious_patterns(self):
        svc = ReputationService()
        r1 = svc.lookup("t1", "domain", "botnet-c2.example.com")
        assert r1["score"] == 15
        r2 = svc.lookup("t1", "domain", "phishing-site.example.com")
        assert r2["score"] == 15
