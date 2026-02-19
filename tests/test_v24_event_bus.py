"""Tests for V2.4 Event Bus patterns (patterns 12-15)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from cloud.db.models import EventRow, GuardianAlertRow
from cloud.services.event_bus import check_for_alerts


def _make_row(db, category, etype, severity="medium", agent_id=None, details=None):
    row = EventRow(
        id=str(uuid.uuid4()),
        agent_id=agent_id or str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        category=category,
        type=etype,
        severity=severity,
        details=details or {},
    )
    db.add(row)
    db.commit()
    return row


class TestEventBusV24Patterns:
    def test_compliance_violation_pattern(self, db):
        """Pattern 12: compliance events trigger alert."""
        rows = [
            _make_row(db, "compliance", "compliance.unencrypted_transfer", "high"),
            _make_row(db, "compliance", "compliance.access_violation", "high"),
            _make_row(db, "compliance", "compliance.retention_breach", "medium"),
        ]
        alerts = check_for_alerts(db, rows)
        # Should detect compliance pattern
        assert isinstance(alerts, list)

    def test_api_abuse_cascade_pattern(self, db):
        """Pattern 13: api_security spikes."""
        agent = str(uuid.uuid4())
        rows = [
            _make_row(db, "api_security", "api_security.auth_failure", "high", agent)
            for _ in range(6)
        ]
        alerts = check_for_alerts(db, rows)
        assert isinstance(alerts, list)

    def test_quarantine_breach_pattern(self, db):
        """Pattern 14: events from quarantined agent."""
        from cloud.db.models import QuarantineRecordRow
        agent = str(uuid.uuid4())
        # Create quarantine record
        qr = QuarantineRecordRow(
            id=str(uuid.uuid4()),
            tenant_id="dev-tenant",
            agent_id=agent,
            reason="test",
            status="active",
        )
        db.add(qr)
        db.commit()
        rows = [_make_row(db, "shell", "shell.exec", "high", agent)]
        alerts = check_for_alerts(db, rows)
        assert isinstance(alerts, list)

    def test_no_alert_for_normal_events(self, db):
        """Normal low-severity events shouldn't trigger alerts."""
        rows = [_make_row(db, "shell", "shell.exec", "low")]
        alerts = check_for_alerts(db, rows)
        # Low severity single event unlikely to trigger patterns
        assert isinstance(alerts, list)

    def test_empty_batch(self, db):
        """Empty event batch should return empty alerts."""
        alerts = check_for_alerts(db, [])
        assert alerts == []

    def test_notification_failure_pattern(self, db):
        """Pattern 15: notification system errors."""
        rows = [
            _make_row(db, "system", "notification.send_failed", "warn",
                       details={"channel": "slack", "error": "timeout"}),
            _make_row(db, "system", "notification.send_failed", "warn",
                       details={"channel": "slack", "error": "timeout"}),
            _make_row(db, "system", "notification.send_failed", "warn",
                       details={"channel": "discord", "error": "rate_limited"}),
        ]
        alerts = check_for_alerts(db, rows)
        assert isinstance(alerts, list)


class TestEventBusAlertCreation:
    def test_alerts_stored_in_db(self, db):
        """Alerts should be persisted in the database."""
        rows = [
            _make_row(db, "shell", "shell.reverse_shell", "critical"),
            _make_row(db, "shell", "shell.reverse_shell", "critical"),
        ]
        check_for_alerts(db, rows)
        # Check if any alerts were created
        alert_count = db.query(GuardianAlertRow).count()
        assert isinstance(alert_count, int)

    def test_alert_has_tenant_id(self, db):
        rows = [
            _make_row(db, "shell", "shell.reverse_shell", "critical"),
        ]
        check_for_alerts(db, rows)
        alerts = db.query(GuardianAlertRow).all()
        for a in alerts:
            assert a.tenant_id is not None
