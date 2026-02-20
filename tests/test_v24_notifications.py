"""Tests for V2.4 Notification Channels."""

from __future__ import annotations

import uuid

from cloud.db.models import NotificationChannelRow
from cloud.services.notifications import (
    DiscordChannel,
    NotificationRouter,
    SlackChannel,
    WebhookChannel,
)


class TestSlackChannel:
    def test_create_slack_channel(self):
        ch = SlackChannel(webhook_url="https://hooks.slack.com/test")
        assert ch.webhook_url == "https://hooks.slack.com/test"

    def test_slack_send_interface(self):
        ch = SlackChannel(webhook_url="https://hooks.slack.com/test")
        # Verify the send method exists and is callable
        assert callable(ch.send)


class TestDiscordChannel:
    def test_create_discord_channel(self):
        ch = DiscordChannel(webhook_url="https://discord.com/api/webhooks/test")
        assert ch.webhook_url == "https://discord.com/api/webhooks/test"

    def test_discord_send_interface(self):
        ch = DiscordChannel(webhook_url="https://discord.com/test")
        # Verify the send method exists and is callable
        assert callable(ch.send)


class TestWebhookChannel:
    def test_create_webhook_channel(self):
        ch = WebhookChannel(webhook_url="https://example.com/webhook")
        assert ch.webhook_url == "https://example.com/webhook"


class TestNotificationRouter:
    def test_create_router(self):
        router = NotificationRouter()
        assert router is not None

    def test_load_channels(self, db):
        router = NotificationRouter()
        channels = router.load_channels(db, "dev-tenant")
        assert isinstance(channels, list)

    def test_severity_routing(self, db):
        router = NotificationRouter()
        # Should not crash even with no channels
        result = router.route_alert(
            db,
            "dev-tenant",
            alert_type="test",
            title="Test",
            severity="critical",
            details={},
        )
        assert isinstance(result, list)

    def test_route_alert_no_rules(self, db):
        router = NotificationRouter()
        result = router.route_alert(
            db,
            "dev-tenant",
            alert_type="test",
            title="Test Alert",
            severity="high",
        )
        # With no rules configured, no channels should be delivered to
        assert result == []

    def test_channel_db_record(self, db):
        # Directly create a channel record in the DB
        ch = NotificationChannelRow(
            id=str(uuid.uuid4()),
            tenant_id="dev-tenant",
            name="db-test",
            channel_type="discord",
            config={"webhook_url": "https://discord.com/test"},
            enabled="true",
        )
        db.add(ch)
        db.commit()
        record = db.query(NotificationChannelRow).filter_by(name="db-test").first()
        assert record is not None
        assert record.channel_type == "discord"
