"""Tests for V2.4 Quarantine Manager."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from cloud.db.models import QuarantineRecordRow
from cloud.services.quarantine import QuarantineManager


@pytest.fixture
def qm():
    return QuarantineManager()


@pytest.fixture
def agent_id():
    return str(uuid.uuid4())


class TestQuarantineManager:
    def test_quarantine_agent(self, db, qm, agent_id):
        result = qm.quarantine_agent(
            db,
            "dev-tenant",
            agent_id,
            reason="Suspicious activity",
            quarantined_by="test-user",
        )
        assert result.id is not None
        assert result.status == "active"

    def test_list_quarantined(self, db, qm, agent_id):
        qm.quarantine_agent(
            db,
            "dev-tenant",
            agent_id,
            reason="Test",
            quarantined_by="test-user",
        )
        records = qm.list_quarantined(db, "dev-tenant")
        assert len(records) >= 1

    def test_release_agent(self, db, qm, agent_id):
        qm.quarantine_agent(
            db,
            "dev-tenant",
            agent_id,
            reason="Test",
            quarantined_by="test-user",
        )
        result = qm.release_agent(db, "dev-tenant", agent_id, released_by="test-user")
        assert result is not None
        assert result.status == "released"

    def test_timed_release(self, db, qm, agent_id):
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        result = qm.quarantine_agent(
            db,
            "dev-tenant",
            agent_id,
            reason="Timed quarantine",
            quarantined_by="test-user",
            release_at=future,
        )
        assert result.id is not None
        record = db.query(QuarantineRecordRow).filter_by(agent_id=agent_id).first()
        if record:
            assert record.release_at is not None

    def test_quarantine_record_created(self, db, qm, agent_id):
        qm.quarantine_agent(
            db,
            "dev-tenant",
            agent_id,
            reason="Record test",
            quarantined_by="test-user",
        )
        record = db.query(QuarantineRecordRow).filter_by(agent_id=agent_id).first()
        assert record is not None
        assert record.reason == "Record test"

    def test_quarantine_status_active(self, db, qm, agent_id):
        qm.quarantine_agent(
            db,
            "dev-tenant",
            agent_id,
            reason="Status test",
            quarantined_by="test-user",
        )
        record = db.query(QuarantineRecordRow).filter_by(agent_id=agent_id).first()
        assert record is not None
        assert record.status == "active"

    def test_double_quarantine(self, db, qm, agent_id):
        qm.quarantine_agent(
            db,
            "dev-tenant",
            agent_id,
            reason="First",
            quarantined_by="test-user",
        )
        result = qm.quarantine_agent(
            db,
            "dev-tenant",
            agent_id,
            reason="Second",
            quarantined_by="test-user",
        )
        # Should handle gracefully — returns existing record
        assert result is not None

    def test_release_non_quarantined(self, db, qm):
        result = qm.release_agent(
            db,
            "dev-tenant",
            str(uuid.uuid4()),
            released_by="test-user",
        )
        # Returns None when no active quarantine exists
        assert result is None

    def test_quarantine_with_custom_by(self, db, qm, agent_id):
        result = qm.quarantine_agent(
            db,
            "dev-tenant",
            agent_id,
            reason="Admin action",
            quarantined_by="admin@example.com",
        )
        assert result is not None
        assert result.quarantined_by == "admin@example.com"
