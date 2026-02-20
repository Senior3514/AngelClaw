"""AngelClaw V5.0 — Transcendence: Deception Technology (Honeypots).

Manages honey tokens, honey credentials, honey files, and canary tokens
for detecting unauthorized access and lateral movement.

Features:
  - Deploy various types of deception tokens
  - Monitor token triggers (access attempts)
  - Trigger history with attacker context
  - Token lifecycle management (activate/deactivate)
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.deception")


class DeceptionToken(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    name: str
    token_type: (
        str  # honey_credential, honey_file, honey_token, canary_dns, canary_url, honey_api_key
    )
    decoy_value: str = ""  # the fake credential/path/URL
    placement: str = ""  # where the token is deployed
    description: str = ""
    active: bool = True
    triggered: bool = False
    trigger_count: int = 0
    triggers: list[dict[str, Any]] = []
    config: dict[str, Any] = {}
    created_by: str = "system"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_triggered_at: datetime | None = None


class DeceptionService:
    """Manages deception tokens and trigger detection."""

    def __init__(self) -> None:
        self._tokens: dict[str, DeceptionToken] = {}
        self._tenant_tokens: dict[str, list[str]] = defaultdict(list)
        # Index by decoy_value for fast trigger lookups
        self._value_index: dict[str, str] = {}  # decoy_value -> token_id

    # -- Token CRUD --

    def deploy_token(
        self,
        tenant_id: str,
        name: str,
        token_type: str,
        decoy_value: str = "",
        placement: str = "",
        description: str = "",
        config: dict | None = None,
        created_by: str = "system",
    ) -> dict:
        if not decoy_value:
            decoy_value = self._generate_decoy(token_type)

        token = DeceptionToken(
            tenant_id=tenant_id,
            name=name,
            token_type=token_type,
            decoy_value=decoy_value,
            placement=placement,
            description=description,
            config=config or {},
            created_by=created_by,
        )
        self._tokens[token.id] = token
        self._tenant_tokens[tenant_id].append(token.id)
        self._value_index[decoy_value] = token.id

        logger.info(
            "[DECEPTION] Deployed %s token '%s' at '%s' for %s",
            token_type,
            name,
            placement,
            tenant_id,
        )
        return token.model_dump(mode="json")

    def get_token(self, token_id: str) -> dict | None:
        token = self._tokens.get(token_id)
        return token.model_dump(mode="json") if token else None

    def list_tokens(
        self,
        tenant_id: str,
        token_type: str | None = None,
        active_only: bool = False,
    ) -> list[dict]:
        results = []
        for tid in self._tenant_tokens.get(tenant_id, []):
            token = self._tokens.get(tid)
            if not token:
                continue
            if token_type and token.token_type != token_type:
                continue
            if active_only and not token.active:
                continue
            results.append(token.model_dump(mode="json"))
        return results

    def deactivate_token(self, token_id: str) -> dict | None:
        token = self._tokens.get(token_id)
        if not token:
            return None
        token.active = False
        if token.decoy_value in self._value_index:
            del self._value_index[token.decoy_value]
        logger.info("[DECEPTION] Deactivated token '%s'", token.name)
        return token.model_dump(mode="json")

    def activate_token(self, token_id: str) -> dict | None:
        token = self._tokens.get(token_id)
        if not token:
            return None
        token.active = True
        self._value_index[token.decoy_value] = token.id
        return token.model_dump(mode="json")

    # -- Trigger Detection --

    def check_trigger(self, decoy_value: str) -> dict:
        """Check whether a given value matches a deployed deception token."""
        token_id = self._value_index.get(decoy_value)
        if not token_id:
            return {"triggered": False, "token_id": None}

        token = self._tokens.get(token_id)
        if not token or not token.active:
            return {"triggered": False, "token_id": token_id}

        return {
            "triggered": True,
            "token_id": token.id,
            "token_name": token.name,
            "token_type": token.token_type,
            "placement": token.placement,
        }

    def record_trigger(
        self,
        token_id: str,
        source_ip: str = "unknown",
        user_agent: str = "",
        context: dict | None = None,
    ) -> dict | None:
        token = self._tokens.get(token_id)
        if not token:
            return None

        now = datetime.now(timezone.utc)
        trigger_record = {
            "id": str(uuid.uuid4()),
            "source_ip": source_ip,
            "user_agent": user_agent,
            "context": context or {},
            "triggered_at": now.isoformat(),
        }

        token.triggered = True
        token.trigger_count += 1
        token.last_triggered_at = now
        token.triggers.append(trigger_record)

        # Cap trigger history
        if len(token.triggers) > 500:
            token.triggers = token.triggers[-500:]

        logger.warning(
            "[DECEPTION] Token '%s' (%s) triggered from %s -- trigger #%d",
            token.name,
            token.token_type,
            source_ip,
            token.trigger_count,
        )
        return token.model_dump(mode="json")

    # -- Stats --

    def get_stats(self, tenant_id: str) -> dict:
        tokens = [
            self._tokens[t] for t in self._tenant_tokens.get(tenant_id, []) if t in self._tokens
        ]
        by_type: dict[str, int] = defaultdict(int)
        total_triggers = 0
        triggered_tokens = 0
        for token in tokens:
            by_type[token.token_type] += 1
            total_triggers += token.trigger_count
            if token.triggered:
                triggered_tokens += 1

        return {
            "total_tokens": len(tokens),
            "active_tokens": sum(1 for t in tokens if t.active),
            "triggered_tokens": triggered_tokens,
            "total_triggers": total_triggers,
            "by_type": dict(by_type),
        }

    # -- Internal --

    def _generate_decoy(self, token_type: str) -> str:
        """Generate a realistic-looking decoy value."""
        uid = uuid.uuid4().hex
        if token_type == "honey_credential":
            return f"svc_backup_{uid[:8]}:P@ssw0rd_{uid[8:16]}"
        elif token_type == "honey_file":
            return f"/opt/backups/db_credentials_{uid[:8]}.enc"
        elif token_type == "honey_api_key":
            return f"ak_{uid[:32]}"
        elif token_type == "canary_dns":
            return f"{uid[:12]}.canary.angelclaw.internal"
        elif token_type == "canary_url":
            return f"https://canary.angelclaw.internal/t/{uid[:16]}"
        return f"decoy_{uid[:16]}"


# Module-level singleton
deception_service = DeceptionService()
