"""ANGELGRID – Cloud Sync Client for ANGELNODE.

Handles startup registration with ANGELGRID Cloud and periodic policy
polling.  Runs as a background asyncio task within the ANGELNODE server
process.

Lifecycle:
  1. On startup, POST /api/v1/agents/register to the Cloud.
  2. Store the returned agent_id and apply the initial PolicySet.
  3. Every SYNC_INTERVAL seconds, GET /api/v1/policies/current.
  4. If the policy version has changed, hot-reload the engine.
  5. Log every sync attempt (success or failure) to the JSONL log.

SECURITY NOTE: If the Cloud is unreachable the agent continues with its
last-known policy.  Registration and sync failures are logged but never
cause the agent to stop enforcing policy (fail-closed principle).
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import socket
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import httpx

from shared.models.policy import PolicyRule, PolicySet

logger = logging.getLogger("angelnode.cloud_sync")

# ---------------------------------------------------------------------------
# Configuration via environment variables
# ---------------------------------------------------------------------------
CLOUD_URL: Optional[str] = os.environ.get("ANGELGRID_CLOUD_URL")
TENANT_ID: str = os.environ.get("ANGELGRID_TENANT_ID", "default")
SYNC_INTERVAL: int = int(os.environ.get("ANGELGRID_SYNC_INTERVAL", "60"))
AGENT_TYPE: str = os.environ.get("ANGELNODE_AGENT_TYPE", "server")
AGENT_VERSION: str = os.environ.get("ANGELNODE_VERSION", "0.2.0")
AGENT_TAGS: list[str] = [
    t.strip()
    for t in os.environ.get("ANGELNODE_TAGS", "").split(",")
    if t.strip()
]


class CloudSyncClient:
    """Manages registration and periodic policy sync with ANGELGRID Cloud."""

    def __init__(
        self,
        cloud_url: str,
        tenant_id: str,
        on_policy_update: Callable[[PolicySet], None],
        on_sync_log: Callable[[dict[str, Any]], None],
        on_agent_id_update: Callable[[str], None],
        on_sync_timestamp: Callable[[datetime], None],
    ) -> None:
        self._cloud_url = cloud_url.rstrip("/")
        self._tenant_id = tenant_id
        self._on_policy_update = on_policy_update
        self._on_sync_log = on_sync_log
        self._on_agent_id_update = on_agent_id_update
        self._on_sync_timestamp = on_sync_timestamp

        self._agent_id: Optional[str] = None
        self._current_version: Optional[str] = None
        self._task: Optional[asyncio.Task] = None
        self._running = False

    @property
    def agent_id(self) -> Optional[str]:
        return self._agent_id

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    async def register(self) -> bool:
        """Register this ANGELNODE with the Cloud and apply initial policy.

        Returns True on success, False on failure.  Failure is non-fatal:
        the agent continues with its local policy file.
        """
        hostname = socket.gethostname()
        payload = {
            "type": AGENT_TYPE,
            "os": platform.system().lower(),
            "hostname": hostname,
            "tags": AGENT_TAGS + [f"tenant:{self._tenant_id}"],
            "version": AGENT_VERSION,
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    f"{self._cloud_url}/api/v1/agents/register",
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPError as exc:
            logger.error("Registration failed: %s", exc)
            self._log_sync_event("register", success=False, error=str(exc))
            return False

        self._agent_id = data["agent_id"]
        self._on_agent_id_update(self._agent_id)
        logger.info("Registered with Cloud — agent_id=%s", self._agent_id)

        # Apply initial PolicySet if returned
        policy_data = data.get("policy_set")
        if policy_data and policy_data.get("rules") is not None:
            self._apply_policy(policy_data)

        self._on_sync_timestamp(datetime.now(timezone.utc))
        self._log_sync_event(
            "register",
            success=True,
            policy_version=self._current_version,
        )
        return True

    # ------------------------------------------------------------------
    # Polling loop
    # ------------------------------------------------------------------

    async def start_polling(self) -> None:
        """Start the background policy-polling loop."""
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
        logger.info(
            "Policy sync polling started — interval=%ds, cloud=%s",
            SYNC_INTERVAL, self._cloud_url,
        )

    async def stop(self) -> None:
        """Stop the background polling task."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Policy sync polling stopped")

    async def _poll_loop(self) -> None:
        """Periodically fetch the current policy from Cloud."""
        while self._running:
            await asyncio.sleep(SYNC_INTERVAL)
            if not self._running:
                break
            await self._sync_policy()

    async def _sync_policy(self) -> None:
        """Fetch current policy and hot-reload if version changed."""
        if self._agent_id is None:
            # Not yet registered — attempt registration first
            registered = await self.register()
            if not registered:
                return

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{self._cloud_url}/api/v1/policies/current",
                    params={"agentId": self._agent_id},
                )
                resp.raise_for_status()
                policy_data = resp.json()
        except httpx.HTTPError as exc:
            logger.warning("Policy sync failed: %s", exc)
            self._log_sync_event("policy_sync", success=False, error=str(exc))
            return

        new_version = policy_data.get("version")
        self._on_sync_timestamp(datetime.now(timezone.utc))

        if new_version and new_version != self._current_version:
            self._apply_policy(policy_data)
            logger.info(
                "Policy updated: %s → %s",
                self._current_version, new_version,
            )
            self._log_sync_event(
                "policy_sync",
                success=True,
                policy_version=new_version,
                previous_version=self._current_version,
                changed=True,
            )
        else:
            logger.debug("Policy unchanged (version=%s)", self._current_version)
            self._log_sync_event(
                "policy_sync",
                success=True,
                policy_version=self._current_version,
                changed=False,
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _apply_policy(self, policy_data: dict[str, Any]) -> None:
        """Parse a Cloud policy response and hot-reload the engine."""
        rules = [
            PolicyRule.model_validate(r)
            for r in policy_data.get("rules", [])
        ]
        policy_set = PolicySet(
            id=policy_data.get("id", "cloud-synced"),
            name=policy_data.get("name", "cloud-policy"),
            description=policy_data.get("description", ""),
            rules=rules,
        )
        self._current_version = policy_set.version
        self._on_policy_update(policy_set)

    def _log_sync_event(
        self,
        event_type: str,
        *,
        success: bool,
        error: str | None = None,
        policy_version: str | None = None,
        previous_version: str | None = None,
        changed: bool | None = None,
    ) -> None:
        """Emit a structured sync log record via the callback."""
        record: dict[str, Any] = {
            "sync_type": event_type,
            "success": success,
            "agent_id": self._agent_id,
            "tenant_id": self._tenant_id,
            "cloud_url": self._cloud_url,
        }
        if error is not None:
            record["error"] = error
        if policy_version is not None:
            record["policy_version"] = policy_version
        if previous_version is not None:
            record["previous_version"] = previous_version
        if changed is not None:
            record["changed"] = changed
        self._on_sync_log(record)
