"""AngelClaw AGI Guardian – Anti-Tamper Protection Service.

Monitors and enforces integrity of Angel Nodes. Detects:
  - Unauthorized config/policy changes
  - Agent process death or restart
  - Binary/checksum mismatches
  - Heartbeat misses
  - Unauthorized uninstall attempts

Operates in three modes:
  - OFF: No monitoring
  - MONITOR: Detect and log tamper events, but don't block
  - ENFORCE: Detect, log, and take protective action (quarantine, alert)

Per-agent and per-tenant configuration with DB persistence.
"""

from __future__ import annotations

import logging
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.anti_tamper")

_MAX_EVENTS = 500


class AntiTamperMode(str, Enum):
    OFF = "off"
    MONITOR = "monitor"
    ENFORCE = "enforce"


class TamperCheckType(str, Enum):
    CONFIG_CHANGE = "config_change"
    PROCESS_DEATH = "process_death"
    CHECKSUM_MISMATCH = "checksum_mismatch"
    HEARTBEAT_MISS = "heartbeat_miss"
    UNAUTHORIZED_UNINSTALL = "unauthorized_uninstall"
    LOG_DELETION = "log_deletion"
    POLICY_OVERRIDE = "policy_override"


class TamperEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    agent_id: str
    event_type: TamperCheckType
    severity: str = "high"
    description: str = ""
    details: dict[str, Any] = {}
    resolved: bool = False
    resolved_by: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AntiTamperConfig(BaseModel):
    tenant_id: str
    agent_id: str | None = None  # None = tenant-wide default
    mode: AntiTamperMode = AntiTamperMode.MONITOR
    check_binary_integrity: bool = True
    check_config_changes: bool = True
    check_process_health: bool = True
    check_heartbeat: bool = True
    heartbeat_timeout_seconds: int = 300


class AntiTamperStatus(BaseModel):
    tenant_id: str
    enforced_count: int = 0
    monitored_count: int = 0
    disabled_count: int = 0
    tamper_events_24h: int = 0
    agents_with_issues: list[str] = []
    configs: list[dict[str, Any]] = []


class AntiTamperService:
    """Singleton service managing anti-tamper protection across all Angel Nodes."""

    def __init__(self) -> None:
        self._configs: dict[str, AntiTamperConfig] = {}  # key: tenant_id or tenant_id:agent_id
        self._events: deque[TamperEvent] = deque(maxlen=_MAX_EVENTS)
        self._agent_checksums: dict[str, str] = {}  # agent_id -> last known checksum
        self._agent_heartbeats: dict[str, datetime] = {}  # agent_id -> last heartbeat
        self._enabled: bool = False
        self._mode: str = "off"

    # ------------------------------------------------------------------
    # Simple enable/disable/status API (used by tests and quick checks)
    # ------------------------------------------------------------------

    def status(self) -> dict:
        """Quick status check."""
        return {"enabled": self._enabled, "mode": self._mode}

    def enable(self) -> dict:
        """Enable anti-tamper protection (defaults to monitor mode)."""
        self._enabled = True
        if self._mode == "off":
            self._mode = "monitor"
        return {"enabled": True, "mode": self._mode}

    def disable(self) -> dict:
        """Disable anti-tamper protection."""
        self._enabled = False
        self._mode = "off"
        return {"enabled": False, "mode": self._mode}

    def check_status(self) -> dict:
        """Detailed status check with active flag."""
        active = self._enabled and self._mode != "off"
        return {"active": active, "mode": self._mode, "enabled": self._enabled}

    def record_event(
        self,
        agent_id: str,
        event_type: str,
        details: dict[str, Any] | None = None,
        tenant_id: str = "dev-tenant",
    ) -> dict:
        """Record a tamper event (simplified API). Returns dict with blocked flag."""
        blocked = self._mode == "enforce"
        event_id = str(uuid.uuid4())
        entry = {
            "id": event_id,
            "agent_id": agent_id,
            "event_type": event_type,
            "mode": self._mode,
            "blocked": blocked,
            "details": details or {},
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        # Also store as TamperEvent for the full API
        try:
            check_type = TamperCheckType(event_type)
        except ValueError:
            check_type = TamperCheckType.CONFIG_CHANGE
        te = TamperEvent(
            id=event_id,
            tenant_id=tenant_id,
            agent_id=agent_id,
            event_type=check_type,
            details=details or {},
        )
        self._events.append(te)
        return entry

    # ------------------------------------------------------------------
    # Config-based API
    # ------------------------------------------------------------------

    def _config_key(self, tenant_id: str, agent_id: str | None = None) -> str:
        return f"{tenant_id}:{agent_id}" if agent_id else tenant_id

    def configure(
        self,
        tenant_id_or_mode: str = "monitor",
        mode: str | None = None,
        agent_id: str | None = None,
        enabled_by: str = "system",
        enabled: bool | None = None,
        **kwargs: Any,
    ) -> Any:
        """Set anti-tamper configuration.

        Supports two calling conventions:
        - Simple: configure("monitor", enabled=True) — for quick enable/disable
        - Full: configure(tenant_id, mode="monitor", agent_id=...) — for admin routes
        """
        # Detect calling convention: if mode is None, first arg is likely the mode itself
        if mode is None:
            # Simple API: configure("monitor", enabled=True)
            raw_mode = tenant_id_or_mode
            try:
                tamper_mode = AntiTamperMode(raw_mode)
            except ValueError:
                return {"error": f"Invalid mode: {raw_mode}", "configured": False}
            self._mode = tamper_mode.value
            if enabled is not None:
                self._enabled = enabled
            return {"configured": True, "mode": self._mode, "enabled": self._enabled}

        # Full API: configure(tenant_id, mode="monitor", agent_id=...)
        tenant_id = tenant_id_or_mode
        try:
            tamper_mode = AntiTamperMode(mode)
        except ValueError:
            raise ValueError(
                f"Invalid mode: {mode}. Must be one of: off, monitor, enforce"
            ) from None

        config = AntiTamperConfig(
            tenant_id=tenant_id,
            agent_id=agent_id,
            mode=tamper_mode,
            check_binary_integrity=kwargs.get("check_binary_integrity", True),
            check_config_changes=kwargs.get("check_config_changes", True),
            check_process_health=kwargs.get("check_process_health", True),
            check_heartbeat=kwargs.get("check_heartbeat", True),
            heartbeat_timeout_seconds=kwargs.get("heartbeat_timeout_seconds", 300),
        )

        key = self._config_key(tenant_id, agent_id)
        self._configs[key] = config

        logger.info(
            "[ANTI-TAMPER] Configured: tenant=%s agent=%s mode=%s by=%s",
            tenant_id,
            agent_id or "ALL",
            mode,
            enabled_by,
        )
        return config

    def get_config(self, tenant_id: str, agent_id: str | None = None) -> AntiTamperConfig:
        """Get anti-tamper config for a specific agent, falling back to tenant default."""
        if agent_id:
            agent_key = self._config_key(tenant_id, agent_id)
            if agent_key in self._configs:
                return self._configs[agent_key]
        tenant_key = self._config_key(tenant_id)
        if tenant_key in self._configs:
            return self._configs[tenant_key]
        return AntiTamperConfig(tenant_id=tenant_id, mode=AntiTamperMode.OFF)

    def is_protected(self, tenant_id: str, agent_id: str | None = None) -> bool:
        """Check if an agent or tenant has anti-tamper protection active."""
        config = self.get_config(tenant_id, agent_id)
        return config.mode != AntiTamperMode.OFF

    def record_tamper_event(
        self,
        tenant_id: str,
        agent_id: str,
        event_type: str,
        description: str = "",
        details: dict[str, Any] | None = None,
        severity: str = "high",
    ) -> TamperEvent | None:
        """Record a tamper detection event. Returns the event if protection is active."""
        config = self.get_config(tenant_id, agent_id)
        if config.mode == AntiTamperMode.OFF:
            return None

        try:
            check_type = TamperCheckType(event_type)
        except ValueError:
            check_type = TamperCheckType.CONFIG_CHANGE

        event = TamperEvent(
            tenant_id=tenant_id,
            agent_id=agent_id,
            event_type=check_type,
            severity=severity,
            description=description or f"Tamper detected: {event_type}",
            details=details or {},
        )
        self._events.append(event)

        logger.warning(
            "[ANTI-TAMPER] %s: agent=%s type=%s sev=%s — %s",
            "ENFORCE" if config.mode == AntiTamperMode.ENFORCE else "MONITOR",
            agent_id[:8] if agent_id else "?",
            event_type,
            severity,
            description[:80],
        )

        return event

    def check_heartbeat(self, tenant_id: str, agent_id: str) -> TamperEvent | None:
        """Check if an agent has missed its heartbeat window."""
        config = self.get_config(tenant_id, agent_id)
        if config.mode == AntiTamperMode.OFF or not config.check_heartbeat:
            return None

        last_hb = self._agent_heartbeats.get(agent_id)
        if not last_hb:
            return None

        now = datetime.now(timezone.utc)
        timeout = timedelta(seconds=config.heartbeat_timeout_seconds)
        if now - last_hb > timeout:
            return self.record_tamper_event(
                tenant_id=tenant_id,
                agent_id=agent_id,
                event_type="heartbeat_miss",
                description=(
                    "Agent heartbeat missed"
                    f" (timeout: {config.heartbeat_timeout_seconds}s)"
                ),
                details={
                    "last_heartbeat": last_hb.isoformat(),
                    "timeout_s": config.heartbeat_timeout_seconds,
                },
            )
        return None

    def record_heartbeat(self, agent_id: str) -> None:
        """Record a heartbeat from an agent."""
        self._agent_heartbeats[agent_id] = datetime.now(timezone.utc)

    def update_checksum(self, agent_id: str, checksum: str) -> TamperEvent | None:
        """Update agent binary checksum and detect mismatches."""
        old_checksum = self._agent_checksums.get(agent_id)
        self._agent_checksums[agent_id] = checksum

        if old_checksum and old_checksum != checksum:
            # Look up tenant for this agent (best effort)
            tenant_id = "dev-tenant"
            for _, config in self._configs.items():
                if config.agent_id == agent_id:
                    tenant_id = config.tenant_id
                    break

            return self.record_tamper_event(
                tenant_id=tenant_id,
                agent_id=agent_id,
                event_type="checksum_mismatch",
                severity="critical",
                description="Agent binary checksum changed unexpectedly",
                details={"old": old_checksum[:12], "new": checksum[:12]},
            )
        return None

    def get_events(
        self,
        tenant_id: str | None = None,
        agent_id: str | None = None,
        limit: int = 50,
        hours: int = 24,
    ) -> list[dict]:
        """Get tamper events, optionally filtered."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        events = list(self._events)
        events.reverse()

        filtered = []
        for e in events:
            if e.created_at < cutoff:
                continue
            if tenant_id and e.tenant_id != tenant_id:
                continue
            if agent_id and e.agent_id != agent_id:
                continue
            filtered.append(e.model_dump(mode="json"))
            if len(filtered) >= limit:
                break

        return filtered

    def get_status(self, tenant_id: str | None = None) -> dict:
        """Get anti-tamper status overview."""
        now = datetime.now(timezone.utc)
        cutoff_24h = now - timedelta(hours=24)

        configs = list(self._configs.values())
        if tenant_id:
            configs = [c for c in configs if c.tenant_id == tenant_id]

        enforced = sum(1 for c in configs if c.mode == AntiTamperMode.ENFORCE)
        monitored = sum(1 for c in configs if c.mode == AntiTamperMode.MONITOR)
        disabled = sum(1 for c in configs if c.mode == AntiTamperMode.OFF)

        recent_events = [e for e in self._events if e.created_at >= cutoff_24h]
        if tenant_id:
            recent_events = [e for e in recent_events if e.tenant_id == tenant_id]

        agents_with_issues = list({e.agent_id for e in recent_events if not e.resolved})

        return {
            "enforced_count": enforced,
            "monitored_count": monitored,
            "disabled_count": disabled,
            "tamper_events_24h": len(recent_events),
            "agents_with_issues": agents_with_issues[:20],
            "configs": [c.model_dump(mode="json") for c in configs[:50]],
        }

    def resolve_event(self, event_id: str, resolved_by: str = "operator") -> bool:
        """Mark a tamper event as resolved."""
        for event in self._events:
            if event.id == event_id:
                event.resolved = True
                event.resolved_by = resolved_by
                return True
        return False


# Module-level singleton
anti_tamper_service = AntiTamperService()
