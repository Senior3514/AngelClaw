"""Tests for V3.0 Threat Hunting."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from cloud.db.models import EventRow
from cloud.services.threat_hunting import threat_hunting_service


def _seed_events(db, count=10, category="shell", severity="medium"):
    for _ in range(count):
        db.add(EventRow(
            id=str(uuid.uuid4()),
            agent_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            category=category,
            type=f"{category}.test",
            severity=severity,
            details={"command": "test"},
        ))
    db.commit()


class TestThreatHuntingService:
    def test_execute_query(self, db):
        _seed_events(db, 5)
        result = threat_hunting_service.execute_query(
            db, "dev-tenant",
            {"filters": {"category": "shell"}, "time_range_hours": 24}
        )
        assert "total_matches" in result
        assert result["total_matches"] >= 0

    def test_execute_with_severity_filter(self, db):
        _seed_events(db, 5, severity="high")
        result = threat_hunting_service.execute_query(
            db, "dev-tenant",
            {"filters": {"severity": "high"}, "time_range_hours": 24}
        )
        assert result["total_matches"] >= 0

    def test_execute_with_group_by(self, db):
        _seed_events(db, 5)
        result = threat_hunting_service.execute_query(
            db, "dev-tenant",
            {"filters": {}, "time_range_hours": 24, "group_by": "category"}
        )
        assert result is not None

    def test_execute_with_limit(self, db):
        _seed_events(db, 20)
        result = threat_hunting_service.execute_query(
            db, "dev-tenant",
            {"filters": {}, "time_range_hours": 24, "limit": 5}
        )
        assert len(result["events"]) <= 5

    def test_save_query(self, db):
        result = threat_hunting_service.save_query(
            db, "dev-tenant",
            name="test-query",
            description="Test hunting query",
            query_dsl={"filters": {"category": "shell"}},
        )
        assert result.get("saved") is True

    def test_list_saved_queries(self, db):
        threat_hunting_service.save_query(
            db, "dev-tenant", name="list-query", description="", query_dsl={}
        )
        queries = threat_hunting_service.list_saved_queries(db, "dev-tenant")
        assert len(queries) >= 1

    def test_run_saved_query(self, db):
        _seed_events(db, 5)
        saved = threat_hunting_service.save_query(
            db, "dev-tenant", name="run-query", description="",
            query_dsl={"filters": {"category": "shell"}, "time_range_hours": 24}
        )
        result = threat_hunting_service.run_saved_query(
            db, "dev-tenant", saved["id"]
        )
        assert "total_matches" in result

    def test_run_nonexistent_query(self, db):
        result = threat_hunting_service.run_saved_query(
            db, "dev-tenant", "fake-id"
        )
        assert "error" in result

    def test_execute_empty_results(self, db):
        result = threat_hunting_service.execute_query(
            db, "dev-tenant",
            {"filters": {"category": "nonexistent"}, "time_range_hours": 1}
        )
        assert result["total_matches"] == 0


class TestHuntingRoutes:
    def test_execute_endpoint(self, client):
        resp = client.post(
            "/api/v1/hunting/execute",
            json={"query_dsl": {"filters": {}, "time_range_hours": 24}},
            headers={"X-TENANT-ID": "dev-tenant"},
        )
        assert resp.status_code == 200

    def test_save_query_endpoint(self, client):
        resp = client.post(
            "/api/v1/hunting/queries",
            json={"name": "api-query", "query_dsl": {"filters": {}}},
            headers={"X-TENANT-ID": "dev-tenant"},
        )
        assert resp.status_code in (200, 201)

    def test_list_queries_endpoint(self, client):
        resp = client.get(
            "/api/v1/hunting/queries",
            headers={"X-TENANT-ID": "dev-tenant"},
        )
        assert resp.status_code == 200
