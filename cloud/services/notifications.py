"""AngelClaw Cloud -- Notification Channel & Routing Service.

Multi-channel notification system that routes Guardian alerts to external
services (Slack, Discord, generic webhooks).  Supports per-tenant channel
configuration, severity-based routing rules, HMAC-signed webhook payloads,
and test-notification delivery.

Channel types:
  - slack   -- posts to a Slack incoming-webhook URL
  - discord -- posts to a Discord webhook URL using embeds
  - webhook -- posts JSON to a generic URL with HMAC-SHA256 signature

Routing rules map (min_severity, alert_types) to one or more channels.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy.orm import Session

from cloud.db.models import NotificationChannelRow, NotificationRuleRow

logger = logging.getLogger("angelgrid.cloud.notifications")

# Severity ordering used for min_severity comparisons
_SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "warn": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


def _severity_gte(severity: str, minimum: str) -> bool:
    """Return True if *severity* is >= *minimum* in the severity ladder."""
    return _SEVERITY_ORDER.get(severity, 0) >= _SEVERITY_ORDER.get(minimum, 0)


def _color_for_severity(severity: str) -> str:
    """Return a hex colour string appropriate for the severity level."""
    return {
        "critical": "#FF0000",
        "high": "#FF6600",
        "warn": "#FFCC00",
        "medium": "#FFCC00",
        "low": "#00CCFF",
        "info": "#36A64F",
    }.get(severity, "#808080")


def _discord_color_int(severity: str) -> int:
    """Return a Discord-compatible integer colour for the severity level."""
    mapping = {
        "critical": 0xFF0000,
        "high": 0xFF6600,
        "warn": 0xFFCC00,
        "medium": 0xFFCC00,
        "low": 0x00CCFF,
        "info": 0x36A64F,
    }
    return mapping.get(severity, 0x808080)


# ---------------------------------------------------------------------------
# Abstract base channel
# ---------------------------------------------------------------------------


class NotificationChannel(ABC):
    """Abstract base class for notification delivery channels."""

    @abstractmethod
    def send(
        self,
        title: str,
        message: str,
        severity: str,
        details: dict[str, Any] | None = None,
    ) -> bool:
        """Deliver a notification.

        Args:
            title: Short alert title.
            message: Longer descriptive message.
            severity: Alert severity (info/low/warn/medium/high/critical).
            details: Optional structured payload.

        Returns:
            True on successful delivery, False otherwise.
        """
        ...


# ---------------------------------------------------------------------------
# Slack channel
# ---------------------------------------------------------------------------


class SlackChannel(NotificationChannel):
    """Send notifications to a Slack incoming-webhook URL."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(
        self,
        title: str,
        message: str,
        severity: str,
        details: dict[str, Any] | None = None,
    ) -> bool:
        """Post a Slack message with colour-coded attachment."""
        color = _color_for_severity(severity)
        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": title,
                    "text": message,
                    "fields": [
                        {"title": "Severity", "value": severity.upper(), "short": True},
                        {
                            "title": "Time",
                            "value": datetime.now(timezone.utc).isoformat(),
                            "short": True,
                        },
                    ],
                    "footer": "AngelClaw Guardian",
                }
            ]
        }
        if details:
            payload["attachments"][0]["fields"].append(
                {
                    "title": "Details",
                    "value": json.dumps(details, default=str)[:1024],
                    "short": False,
                }
            )

        try:
            with httpx.Client(timeout=10) as client:
                resp = client.post(self.webhook_url, json=payload)
            if resp.status_code < 300:
                logger.info("[SLACK] Notification sent: %s (%s)", title, severity)
                return True
            logger.warning(
                "[SLACK] Delivery failed: %d %s", resp.status_code, resp.text[:200]
            )
            return False
        except Exception:
            logger.exception("[SLACK] Failed to send notification: %s", title)
            return False


# ---------------------------------------------------------------------------
# Discord channel
# ---------------------------------------------------------------------------


class DiscordChannel(NotificationChannel):
    """Send notifications to a Discord webhook URL using embeds."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(
        self,
        title: str,
        message: str,
        severity: str,
        details: dict[str, Any] | None = None,
    ) -> bool:
        """Post a Discord embed with colour-coded severity."""
        color = _discord_color_int(severity)
        embed: dict[str, Any] = {
            "title": title,
            "description": message,
            "color": color,
            "fields": [
                {"name": "Severity", "value": severity.upper(), "inline": True},
                {
                    "name": "Time",
                    "value": datetime.now(timezone.utc).isoformat(),
                    "inline": True,
                },
            ],
            "footer": {"text": "AngelClaw Guardian"},
        }
        if details:
            embed["fields"].append(
                {
                    "name": "Details",
                    "value": f"```json\n{json.dumps(details, default=str)[:1000]}\n```",
                    "inline": False,
                }
            )

        payload = {"embeds": [embed]}

        try:
            with httpx.Client(timeout=10) as client:
                resp = client.post(self.webhook_url, json=payload)
            if resp.status_code < 300:
                logger.info("[DISCORD] Notification sent: %s (%s)", title, severity)
                return True
            logger.warning(
                "[DISCORD] Delivery failed: %d %s", resp.status_code, resp.text[:200]
            )
            return False
        except Exception:
            logger.exception("[DISCORD] Failed to send notification: %s", title)
            return False


# ---------------------------------------------------------------------------
# Generic webhook channel
# ---------------------------------------------------------------------------


class WebhookChannel(NotificationChannel):
    """Send notifications to a generic webhook URL with HMAC-SHA256 signing."""

    def __init__(self, webhook_url: str, secret: str = ""):
        self.webhook_url = webhook_url
        self.secret = secret

    def send(
        self,
        title: str,
        message: str,
        severity: str,
        details: dict[str, Any] | None = None,
    ) -> bool:
        """POST a JSON payload with optional HMAC-SHA256 signature header."""
        payload = {
            "source": "angelclaw",
            "title": title,
            "message": message,
            "severity": severity,
            "details": details or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        body = json.dumps(payload, default=str)
        headers: dict[str, str] = {"Content-Type": "application/json"}

        if self.secret:
            signature = hmac.new(
                self.secret.encode(),
                body.encode(),
                hashlib.sha256,
            ).hexdigest()
            headers["X-AngelClaw-Signature"] = f"sha256={signature}"

        try:
            with httpx.Client(timeout=10) as client:
                resp = client.post(self.webhook_url, content=body, headers=headers)
            if resp.status_code < 300:
                logger.info("[WEBHOOK] Notification sent: %s (%s)", title, severity)
                return True
            logger.warning(
                "[WEBHOOK] Delivery failed: %d %s", resp.status_code, resp.text[:200]
            )
            return False
        except Exception:
            logger.exception("[WEBHOOK] Failed to send notification: %s", title)
            return False


# ---------------------------------------------------------------------------
# Channel factory
# ---------------------------------------------------------------------------


def _build_channel(channel_type: str, config: dict[str, Any]) -> NotificationChannel:
    """Instantiate the correct NotificationChannel subclass from DB config."""
    url = config.get("webhook_url", "")
    if channel_type == "slack":
        return SlackChannel(webhook_url=url)
    if channel_type == "discord":
        return DiscordChannel(webhook_url=url)
    # Default: generic webhook
    return WebhookChannel(webhook_url=url, secret=config.get("secret", ""))


# ---------------------------------------------------------------------------
# Notification router
# ---------------------------------------------------------------------------


class NotificationRouter:
    """Route Guardian alerts to matching notification channels.

    Loads channel and rule configuration from the database on each call
    so that hot-reloading is supported without service restart.
    """

    # ------------------------------------------------------------------
    # Load channels and rules
    # ------------------------------------------------------------------

    def load_channels(
        self, db: Session, tenant_id: str
    ) -> list[NotificationChannelRow]:
        """Load all enabled notification channels for a tenant.

        Args:
            db: Active database session.
            tenant_id: Owning tenant identifier.

        Returns:
            List of enabled NotificationChannelRow entries.
        """
        return (
            db.query(NotificationChannelRow)
            .filter(
                NotificationChannelRow.tenant_id == tenant_id,
                NotificationChannelRow.enabled == "true",
            )
            .all()
        )

    # ------------------------------------------------------------------
    # Route an alert
    # ------------------------------------------------------------------

    def route_alert(
        self,
        db: Session,
        tenant_id: str,
        alert_type: str,
        title: str,
        severity: str,
        details: dict[str, Any] | None = None,
    ) -> list[str]:
        """Match routing rules and send the alert to every matching channel.

        Args:
            db: Active database session.
            tenant_id: Owning tenant.
            alert_type: Type tag of the alert (e.g. ``repeated_secret_exfil``).
            title: Human-readable alert title.
            severity: Alert severity string.
            details: Optional structured payload forwarded to channels.

        Returns:
            List of channel IDs that successfully delivered the notification.
        """
        # Load all enabled rules for the tenant
        rules = (
            db.query(NotificationRuleRow)
            .filter(
                NotificationRuleRow.tenant_id == tenant_id,
                NotificationRuleRow.enabled == "true",
            )
            .all()
        )

        if not rules:
            logger.debug(
                "[NOTIFY] No notification rules for tenant %s", tenant_id
            )
            return []

        # Build a lookup of channels by ID
        channels = self.load_channels(db, tenant_id)
        channel_map: dict[str, NotificationChannelRow] = {
            ch.id: ch for ch in channels
        }

        delivered: list[str] = []
        message = f"[{severity.upper()}] {title}"

        for rule in rules:
            # Check severity threshold
            if not _severity_gte(severity, rule.min_severity or "high"):
                continue

            # Check alert-type filter (empty list means match all types)
            rule_types = rule.alert_types or []
            if rule_types and alert_type not in rule_types:
                continue

            # Find the target channel
            ch_row = channel_map.get(rule.channel_id)
            if not ch_row:
                logger.warning(
                    "[NOTIFY] Rule %s references missing channel %s",
                    rule.id[:8],
                    rule.channel_id[:8],
                )
                continue

            # Build the concrete channel and send
            try:
                channel = _build_channel(ch_row.channel_type, ch_row.config or {})
                success = channel.send(
                    title=title,
                    message=message,
                    severity=severity,
                    details=details,
                )
                if success:
                    delivered.append(ch_row.id)
            except Exception:
                logger.exception(
                    "[NOTIFY] Failed to deliver via channel %s (%s)",
                    ch_row.name,
                    ch_row.channel_type,
                )

        if delivered:
            logger.info(
                "[NOTIFY] Alert '%s' (%s) delivered to %d channel(s)",
                title[:60],
                severity,
                len(delivered),
            )
        return delivered

    # ------------------------------------------------------------------
    # Send test notification
    # ------------------------------------------------------------------

    def send_test(self, db: Session, channel_id: str) -> bool:
        """Send a test notification through a specific channel.

        Args:
            db: Active database session.
            channel_id: ID of the channel to test.

        Returns:
            True if the test notification was delivered successfully.

        Raises:
            ValueError: If the channel is not found.
        """
        ch_row = (
            db.query(NotificationChannelRow)
            .filter(NotificationChannelRow.id == channel_id)
            .first()
        )
        if not ch_row:
            raise ValueError(f"Channel {channel_id} not found")

        channel = _build_channel(ch_row.channel_type, ch_row.config or {})
        success = channel.send(
            title="AngelClaw Test Notification",
            message=(
                "This is a test notification from AngelClaw Guardian. "
                "If you received this message, the channel is configured correctly."
            ),
            severity="info",
            details={
                "channel_name": ch_row.name,
                "channel_type": ch_row.channel_type,
                "test": True,
            },
        )
        if success:
            logger.info("[NOTIFY] Test notification sent via channel %s", ch_row.name)
        else:
            logger.warning("[NOTIFY] Test notification FAILED for channel %s", ch_row.name)
        return success


# Module-level singleton
notification_router = NotificationRouter()
