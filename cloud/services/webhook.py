"""AngelClaw Cloud – Webhook Integration Service.

Sends critical Guardian Alerts to a configured webhook URL with optional
HMAC-SHA256 signing. Used for SIEM integration (Splunk, Elastic, Wazuh, etc.).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("angelgrid.cloud.webhook")


class WebhookSink:
    """Send critical Guardian Alerts to configured webhook URL."""

    def __init__(self):
        self.url: str = os.environ.get("ANGELCLAW_WEBHOOK_URL", "")
        self.secret: str = os.environ.get("ANGELCLAW_WEBHOOK_SECRET", "")
        self._client: httpx.AsyncClient | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    async def send_alert(
        self,
        alert_type: str,
        title: str,
        severity: str,
        details: dict | None = None,
        tenant_id: str = "dev-tenant",
        related_event_ids: list[str] | None = None,
    ) -> bool:
        """POST JSON payload to webhook URL with optional HMAC signature.

        Returns True if the webhook was sent successfully, False otherwise.
        """
        if not self.enabled:
            return False

        payload = {
            "source": "angelclaw",
            "alert_type": alert_type,
            "title": title,
            "severity": severity,
            "details": details or {},
            "tenant_id": tenant_id,
            "related_event_ids": related_event_ids or [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        body = json.dumps(payload, default=str)
        headers = {"Content-Type": "application/json"}

        # Sign with HMAC-SHA256 if secret is configured
        if self.secret:
            signature = hmac.new(
                self.secret.encode(),
                body.encode(),
                hashlib.sha256,
            ).hexdigest()
            headers["X-AngelClaw-Signature"] = f"sha256={signature}"

        try:
            if self._client is None:
                self._client = httpx.AsyncClient(timeout=10)

            resp = await self._client.post(self.url, content=body, headers=headers)

            if resp.status_code < 300:
                logger.info(
                    "[WEBHOOK] Alert sent: %s (%s) → %d",
                    alert_type, severity, resp.status_code,
                )
                return True
            else:
                logger.warning(
                    "[WEBHOOK] Alert delivery failed: %s → %d %s",
                    alert_type, resp.status_code, resp.text[:200],
                )
                return False
        except Exception:
            logger.exception("[WEBHOOK] Failed to send alert: %s", alert_type)
            return False

    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None


# Module-level singleton
webhook_sink = WebhookSink()
