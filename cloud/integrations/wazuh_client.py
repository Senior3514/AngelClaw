"""AngelClaw Cloud – Wazuh XDR API Client.

Async client for the Wazuh Manager REST API.  Provides:
  - Alert retrieval (GET /alerts)
  - Agent status checks (GET /agents)
  - Active response dispatch (PUT /active-response)
  - File integrity (syscheck) events (GET /syscheck)

Graceful degradation: if ANGELCLAW_WAZUH_URL is not set, all methods
return empty results without raising exceptions.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

import httpx

logger = logging.getLogger("angelgrid.cloud.integrations.wazuh")


class WazuhClient:
    """Async client for the Wazuh Manager API."""

    def __init__(self) -> None:
        self.base_url = os.environ.get("ANGELCLAW_WAZUH_URL", "").rstrip("/")
        self.username = os.environ.get("ANGELCLAW_WAZUH_USER", "")
        self.password = os.environ.get("ANGELCLAW_WAZUH_PASSWORD", "")
        self.verify_ssl: bool = os.environ.get(
            "ANGELCLAW_WAZUH_VERIFY_SSL",
            "true",
        ).lower() not in ("0", "false", "no")
        self._token: str | None = None
        self._token_expires: datetime | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.base_url and self.username)

    # ------------------------------------------------------------------
    # Auth — JWT token management
    # ------------------------------------------------------------------

    async def _ensure_token(self) -> str | None:
        """Authenticate and cache the JWT token."""
        if not self.enabled:
            return None

        now = datetime.now(timezone.utc)
        if self._token and self._token_expires and now < self._token_expires:
            return self._token

        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=10) as client:
                resp = await client.post(
                    f"{self.base_url}/security/user/authenticate",
                    auth=(self.username, self.password),
                )
                resp.raise_for_status()
                data = resp.json()
                self._token = data.get("data", {}).get("token", "")
                # Wazuh tokens last ~15 min; refresh at 12 min
                from datetime import timedelta

                self._token_expires = now + timedelta(minutes=12)
                logger.info("[WAZUH] Authenticated successfully")
                return self._token
        except Exception:
            logger.warning("[WAZUH] Authentication failed", exc_info=True)
            self._token = None
            return None

    async def _request(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        json_body: dict | None = None,
    ) -> dict[str, Any]:
        """Make an authenticated request to Wazuh API."""
        token = await self._ensure_token()
        if not token:
            return {}

        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=15) as client:
                resp = await client.request(
                    method,
                    f"{self.base_url}{path}",
                    headers={"Authorization": f"Bearer {token}"},
                    params=params,
                    json=json_body,
                )
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                self._token = None  # Force re-auth
            logger.warning("[WAZUH] API error %s %s: %s", method, path, exc)
            return {}
        except Exception:
            logger.warning("[WAZUH] Request failed %s %s", method, path, exc_info=True)
            return {}

    # ------------------------------------------------------------------
    # Alert retrieval
    # ------------------------------------------------------------------

    async def get_alerts(
        self,
        limit: int = 50,
        severity: int | None = None,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Fetch recent Wazuh alerts.

        Args:
            limit: Max alerts to return (1-500).
            severity: Minimum rule level (1-15). None = all.
            offset: Pagination offset.
        """
        if not self.enabled:
            return []

        params: dict[str, Any] = {
            "limit": min(limit, 500),
            "offset": offset,
            "sort": "-timestamp",
        }
        if severity is not None:
            params["level"] = severity

        data = await self._request("GET", "/alerts", params=params)
        items = data.get("data", {}).get("affected_items", [])
        logger.debug("[WAZUH] Retrieved %d alerts", len(items))
        return items

    # ------------------------------------------------------------------
    # Agent status
    # ------------------------------------------------------------------

    async def get_agent_status(self, agent_id: str) -> dict[str, Any]:
        """Check Wazuh agent health by agent ID."""
        if not self.enabled:
            return {}

        data = await self._request("GET", f"/agents/{agent_id}")
        items = data.get("data", {}).get("affected_items", [])
        return items[0] if items else {}

    async def get_all_agents(self, limit: int = 100) -> list[dict[str, Any]]:
        """List all Wazuh agents."""
        if not self.enabled:
            return []

        data = await self._request("GET", "/agents", params={"limit": limit})
        return data.get("data", {}).get("affected_items", [])

    # ------------------------------------------------------------------
    # Active response
    # ------------------------------------------------------------------

    async def send_active_response(
        self,
        agent_id: str,
        command: str,
        arguments: list[str] | None = None,
    ) -> bool:
        """Trigger a Wazuh active response on a specific agent.

        Args:
            agent_id: Wazuh agent ID.
            command: Active response command name.
            arguments: Optional command arguments.

        Returns:
            True if the command was dispatched successfully.
        """
        if not self.enabled:
            return False

        body: dict[str, Any] = {
            "command": command,
            "arguments": arguments or [],
        }

        data = await self._request(
            "PUT",
            f"/active-response/{agent_id}",
            json_body=body,
        )

        success = data.get("data", {}).get("total_affected_items", 0) > 0
        if success:
            logger.warning(
                "[WAZUH] Active response dispatched: agent=%s cmd=%s",
                agent_id,
                command,
            )
        else:
            logger.warning(
                "[WAZUH] Active response failed: agent=%s cmd=%s",
                agent_id,
                command,
            )
        return success

    # ------------------------------------------------------------------
    # Syscheck (file integrity monitoring)
    # ------------------------------------------------------------------

    async def get_syscheck_events(
        self,
        agent_id: str,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Get file integrity monitoring events for an agent."""
        if not self.enabled:
            return []

        data = await self._request(
            "GET",
            f"/syscheck/{agent_id}",
            params={"limit": limit, "sort": "-date"},
        )
        return data.get("data", {}).get("affected_items", [])

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    async def health_check(self) -> dict[str, Any]:
        """Check Wazuh Manager API connectivity."""
        if not self.enabled:
            return {"status": "disabled", "reason": "ANGELCLAW_WAZUH_URL not configured"}

        data = await self._request("GET", "/manager/status")
        if data:
            return {"status": "ok", "manager": data.get("data", {})}
        return {"status": "unreachable", "url": self.base_url}


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
wazuh_client = WazuhClient()
