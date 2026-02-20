"""AngelClaw V6.0 — Omniguard: SaaS Shield Service.

Protects SaaS applications through OAuth/SAML monitoring, API abuse
detection, shadow IT discovery, and data flow tracking. Provides a
unified view of SaaS application risk across the organisation.

Features:
  - SaaS application registration (OAuth, SAML, API key)
  - Session monitoring and anomaly detection
  - Shadow IT discovery and classification
  - Risk scoring per application
  - Per-tenant isolation with application analytics
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.saas_shield")

_AUTH_METHODS = {"oauth", "saml", "api_key", "oidc", "basic"}
_APP_TYPES = {"collaboration", "storage", "crm", "devops", "hr", "finance", "custom"}


class SaaSApp(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    app_name: str
    app_type: str = "custom"  # collaboration, storage, crm, devops, hr, finance, custom
    auth_method: str = "oauth"  # oauth, saml, api_key, oidc, basic
    config: dict[str, Any] = {}
    sanctioned: bool = True
    risk_score: float = 0.0
    total_sessions: int = 0
    anomalous_sessions: int = 0
    last_activity_at: datetime | None = None
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SessionEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    app_id: str
    tenant_id: str = "dev-tenant"
    user_id: str
    action: str  # login, logout, data_download, data_upload, api_call, admin_action
    context: dict[str, Any] = {}
    risk_level: str = "low"  # low, medium, high, critical
    anomaly_detected: bool = False
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ShadowITEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    app_name: str
    discovered_source: str = ""  # dns, proxy, endpoint, network
    users_count: int = 1
    risk_level: str = "medium"
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "discovered"  # discovered, under_review, sanctioned, blocked


class SaaSShieldService:
    """SaaS application protection and shadow IT detection."""

    def __init__(self) -> None:
        self._apps: dict[str, SaaSApp] = {}
        self._tenant_apps: dict[str, list[str]] = defaultdict(list)
        self._sessions: dict[str, list[SessionEvent]] = defaultdict(list)
        self._shadow_it: dict[str, list[ShadowITEntry]] = defaultdict(list)

    # ------------------------------------------------------------------
    # App Registration
    # ------------------------------------------------------------------

    def register_app(
        self,
        tenant_id: str,
        app_name: str,
        app_type: str = "custom",
        auth_method: str = "oauth",
        config: dict | None = None,
    ) -> dict:
        """Register a SaaS application for monitoring."""
        app = SaaSApp(
            tenant_id=tenant_id,
            app_name=app_name,
            app_type=app_type if app_type in _APP_TYPES else "custom",
            auth_method=auth_method if auth_method in _AUTH_METHODS else "oauth",
            config=config or {},
        )
        self._apps[app.id] = app
        self._tenant_apps[tenant_id].append(app.id)

        logger.info(
            "[SAAS_SHIELD] Registered app '%s' (%s/%s) for %s",
            app_name,
            app_type,
            auth_method,
            tenant_id,
        )
        return app.model_dump(mode="json")

    def list_apps(self, tenant_id: str) -> list[dict]:
        """List all registered SaaS apps for a tenant."""
        return [
            self._apps[aid].model_dump(mode="json")
            for aid in self._tenant_apps.get(tenant_id, [])
            if aid in self._apps
        ]

    # ------------------------------------------------------------------
    # Session Monitoring
    # ------------------------------------------------------------------

    def monitor_session(
        self,
        app_id: str,
        user_id: str,
        action: str,
        context: dict | None = None,
    ) -> dict:
        """Monitor a user session event on a SaaS app."""
        app = self._apps.get(app_id)
        if not app:
            return {"error": "App not found"}

        ctx = context or {}
        anomaly = self._detect_anomaly(app, user_id, action, ctx)
        risk_level = "high" if anomaly else "low"

        event = SessionEvent(
            app_id=app_id,
            tenant_id=app.tenant_id,
            user_id=user_id,
            action=action,
            context=ctx,
            risk_level=risk_level,
            anomaly_detected=anomaly,
        )

        self._sessions[app.tenant_id].append(event)
        # Cap session history
        if len(self._sessions[app.tenant_id]) > 10000:
            self._sessions[app.tenant_id] = self._sessions[app.tenant_id][-10000:]

        app.total_sessions += 1
        if anomaly:
            app.anomalous_sessions += 1
        app.last_activity_at = datetime.now(timezone.utc)

        # Update risk score
        if app.total_sessions > 0:
            app.risk_score = round(
                (app.anomalous_sessions / app.total_sessions) * 100,
                1,
            )

        logger.debug(
            "[SAAS_SHIELD] Session: app=%s user=%s action=%s anomaly=%s",
            app.app_name,
            user_id,
            action,
            anomaly,
        )
        return event.model_dump(mode="json")

    # ------------------------------------------------------------------
    # Shadow IT
    # ------------------------------------------------------------------

    def detect_shadow_it(
        self,
        tenant_id: str,
        discovered_app: dict,
    ) -> dict:
        """Record a shadow IT discovery."""
        entry = ShadowITEntry(
            tenant_id=tenant_id,
            app_name=discovered_app.get("app_name", "unknown"),
            discovered_source=discovered_app.get("source", "network"),
            users_count=discovered_app.get("users_count", 1),
            risk_level=discovered_app.get("risk_level", "medium"),
        )
        self._shadow_it[tenant_id].append(entry)

        logger.info(
            "[SAAS_SHIELD] Shadow IT discovered: '%s' via %s for %s",
            entry.app_name,
            entry.discovered_source,
            tenant_id,
        )
        return entry.model_dump(mode="json")

    # ------------------------------------------------------------------
    # Risk Summary
    # ------------------------------------------------------------------

    def get_risk_summary(self, tenant_id: str) -> dict:
        """Return risk summary across all SaaS apps for a tenant."""
        apps = [
            self._apps[aid] for aid in self._tenant_apps.get(tenant_id, []) if aid in self._apps
        ]

        high_risk = [a for a in apps if a.risk_score > 50]
        shadow_entries = self._shadow_it.get(tenant_id, [])

        return {
            "tenant_id": tenant_id,
            "total_apps": len(apps),
            "sanctioned_apps": sum(1 for a in apps if a.sanctioned),
            "high_risk_apps": len(high_risk),
            "avg_risk_score": round(
                sum(a.risk_score for a in apps) / max(len(apps), 1),
                1,
            ),
            "total_sessions": sum(a.total_sessions for a in apps),
            "anomalous_sessions": sum(a.anomalous_sessions for a in apps),
            "shadow_it_count": len(shadow_entries),
            "shadow_it_under_review": sum(1 for s in shadow_entries if s.status == "under_review"),
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return SaaS Shield statistics for a tenant."""
        apps = [
            self._apps[aid] for aid in self._tenant_apps.get(tenant_id, []) if aid in self._apps
        ]

        by_type: dict[str, int] = defaultdict(int)
        by_auth: dict[str, int] = defaultdict(int)
        for a in apps:
            by_type[a.app_type] += 1
            by_auth[a.auth_method] += 1

        return {
            "total_apps": len(apps),
            "by_type": dict(by_type),
            "by_auth_method": dict(by_auth),
            "total_sessions": sum(a.total_sessions for a in apps),
            "anomalous_sessions": sum(a.anomalous_sessions for a in apps),
            "shadow_it_discovered": len(self._shadow_it.get(tenant_id, [])),
            "avg_risk_score": round(
                sum(a.risk_score for a in apps) / max(len(apps), 1),
                1,
            ),
        }

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_anomaly(
        app: SaaSApp,
        user_id: str,
        action: str,
        context: dict,
    ) -> bool:
        """Simple anomaly heuristics for session events."""
        # Flag admin actions outside business hours
        if action == "admin_action" and context.get("off_hours", False):
            return True
        # Flag large data downloads
        if action == "data_download" and context.get("size_mb", 0) > 500:
            return True
        # Flag logins from new geolocations
        if action == "login" and context.get("new_geolocation", False):
            return True
        # Flag high API call volume
        if action == "api_call" and context.get("calls_per_minute", 0) > 100:
            return True
        return False


# Module-level singleton
saas_shield_service = SaaSShieldService()
