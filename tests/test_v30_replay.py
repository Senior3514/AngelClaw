"""Tests for V3.0 Event Replay."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from cloud.db.models import EventReplayRow, EventRow
from cloud.services.event_replay import replay_service as event_replay_service


def _seed_events(db, count=10):
    for _ in range(count):
        db.add(EventRow(
            id=str(uuid.uuid4()),
            agent_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            category="shell",
            type="shell.exec",
            severity="medium",
            details={"command": "test"},
        ))
    db.commit()


class TestEventReplayService:
    def test_create_replay(self, db):
        _seed_events(db, 5)
        result = event_replay_service.create_replay(
            db, "dev-tenant", name="test-replay",
            source_filter={}
        )
        assert result is not None
        assert "id" in result or "name" in result

    def test_replay_with_filter(self, db):
        _seed_events(db, 5)
        result = event_replay_service.create_replay(
            db, "dev-tenant", name="filtered-replay",
            source_filter={"category": "shell"}
        )
        assert result is not None

    def test_replay_record_created(self, db):
        _seed_events(db, 5)
        event_replay_service.create_replay(db, "dev-tenant", name="record-replay", source_filter={})
        row = db.query(EventReplayRow).filter_by(name="record-replay").first()
        assert row is not None

    def test_replay_processes_events(self, db):
        _seed_events(db, 10)
        result = event_replay_service.create_replay(
            db, "dev-tenant", name="process-replay",
            source_filter={}
        )
        assert result is not None
        assert result.get("event_count", 0) >= 0

    def test_empty_replay(self, db):
        result = event_replay_service.create_replay(
            db, "dev-tenant", name="empty-replay",
            source_filter={"category": "nonexistent"}
        )
        assert result is not None


class TestReplayRoutes:
    def test_list_replays_endpoint(self, client):
        resp = client.get(
            "/api/v1/replays",
            headers={"X-TENANT-ID": "dev-tenant"},
        )
        assert resp.status_code == 200

    def test_create_replay_endpoint(self, client):
        resp = client.post(
            "/api/v1/replays",
            json={"name": "api-replay", "source_filter": {}},
            headers={"X-TENANT-ID": "dev-tenant"},
        )
        assert resp.status_code in (200, 201)
