"""Tests for V2.5 Audit Export."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from cloud.db.models import EventRow, GuardianChangeRow
from cloud.services.export import export_service


def _seed_events(db, count=5):
    for _ in range(count):
        db.add(EventRow(
            id=str(uuid.uuid4()),
            agent_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            category="shell",
            type="shell.exec",
            severity="medium",
            details={"command": "ls"},
        ))
    db.commit()


class TestExportService:
    def test_export_events_json(self, db):
        _seed_events(db, 3)
        content, content_type = export_service.export_events(db, tenant_id="dev-tenant", format="json")
        assert isinstance(content, str)
        assert content_type == "application/json"

    def test_export_events_csv(self, db):
        _seed_events(db, 3)
        content, content_type = export_service.export_events(db, tenant_id="dev-tenant", format="csv")
        assert content is not None
        assert content_type == "text/csv"

    def test_export_events_with_filter(self, db):
        _seed_events(db, 3)
        content, content_type = export_service.export_events(
            db, tenant_id="dev-tenant", format="json", category="shell"
        )
        assert isinstance(content, str)
        assert content_type == "application/json"

    def test_export_audit_trail(self, db):
        db.add(GuardianChangeRow(
            id=str(uuid.uuid4()),
            tenant_id="dev-tenant",
            change_type="policy_update",
            description="Test change",
        ))
        db.commit()
        content, content_type = export_service.export_audit_trail(db, tenant_id="dev-tenant")
        assert isinstance(content, str)

    def test_export_alerts(self, db):
        content, content_type = export_service.export_alerts(db, tenant_id="dev-tenant")
        assert isinstance(content, str)

    def test_export_policies(self, db):
        content, content_type = export_service.export_policies(db)
        assert isinstance(content, str)

    def test_export_empty_events(self, db):
        content, content_type = export_service.export_events(db, tenant_id="dev-tenant", format="json")
        assert isinstance(content, str)

    def test_export_events_severity_filter(self, db):
        _seed_events(db, 3)
        content, content_type = export_service.export_events(
            db, tenant_id="dev-tenant", format="json", severity="medium"
        )
        assert isinstance(content, str)
        assert content_type == "application/json"
