"""AngelClaw V4.0 — Omniscience: Asset Inventory Service.

Discovers, registers, and classifies assets in the environment.
Links assets to agents, tracks risk scores, and manages lifecycle.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.asset_inventory")


class Asset(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    asset_type: str  # server, workstation, container, cloud_instance, network_device, iot
    name: str
    hostname: str | None = None
    ip_address: str | None = None
    os: str | None = None
    agent_id: str | None = None
    classification: str = "standard"  # critical, high_value, standard, low_value
    owner: str | None = None
    tags: list[str] = []
    risk_score: int = 0
    last_scan_at: datetime | None = None
    status: str = "active"
    metadata: dict[str, Any] = {}
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AssetInventoryService:
    """Asset inventory management with classification and risk scoring."""

    def __init__(self) -> None:
        self._assets: dict[str, Asset] = {}
        self._tenant_assets: dict[str, list[str]] = defaultdict(list)

    def register_asset(
        self,
        tenant_id: str,
        asset_type: str,
        name: str,
        hostname: str | None = None,
        ip_address: str | None = None,
        os: str | None = None,
        agent_id: str | None = None,
        classification: str = "standard",
        owner: str | None = None,
        tags: list[str] | None = None,
        metadata: dict | None = None,
    ) -> dict:
        asset = Asset(
            tenant_id=tenant_id,
            asset_type=asset_type,
            name=name,
            hostname=hostname,
            ip_address=ip_address,
            os=os,
            agent_id=agent_id,
            classification=classification,
            owner=owner,
            tags=tags or [],
            metadata=metadata or {},
        )
        self._assets[asset.id] = asset
        self._tenant_assets[tenant_id].append(asset.id)
        logger.info(
            "[ASSET_INVENTORY] Registered asset '%s' (%s) for %s", name, asset_type, tenant_id
        )
        return asset.model_dump(mode="json")

    def get_asset(self, asset_id: str) -> dict | None:
        asset = self._assets.get(asset_id)
        return asset.model_dump(mode="json") if asset else None

    def list_assets(
        self,
        tenant_id: str,
        asset_type: str | None = None,
        classification: str | None = None,
        status: str | None = None,
        limit: int = 200,
    ) -> list[dict]:
        results = []
        for aid in self._tenant_assets.get(tenant_id, []):
            asset = self._assets.get(aid)
            if not asset:
                continue
            if asset_type and asset.asset_type != asset_type:
                continue
            if classification and asset.classification != classification:
                continue
            if status and asset.status != status:
                continue
            results.append(asset.model_dump(mode="json"))
            if len(results) >= limit:
                break
        return results

    def update_asset(self, asset_id: str, updates: dict) -> dict | None:
        asset = self._assets.get(asset_id)
        if not asset:
            return None
        for key, value in updates.items():
            if hasattr(asset, key) and key not in ("id", "tenant_id", "created_at"):
                setattr(asset, key, value)
        asset.updated_at = datetime.now(timezone.utc)
        return asset.model_dump(mode="json")

    def update_risk_score(self, asset_id: str, risk_score: int) -> dict | None:
        asset = self._assets.get(asset_id)
        if not asset:
            return None
        asset.risk_score = max(0, min(100, risk_score))
        asset.updated_at = datetime.now(timezone.utc)
        return asset.model_dump(mode="json")

    def decommission_asset(self, asset_id: str) -> dict | None:
        asset = self._assets.get(asset_id)
        if not asset:
            return None
        asset.status = "decommissioned"
        asset.updated_at = datetime.now(timezone.utc)
        return asset.model_dump(mode="json")

    def get_risk_heatmap(self, tenant_id: str) -> dict:
        """Generate risk heatmap data for all assets."""
        assets = [
            self._assets[a] for a in self._tenant_assets.get(tenant_id, []) if a in self._assets
        ]
        heatmap: dict[str, list[dict]] = defaultdict(list)
        for asset in assets:
            if asset.status != "active":
                continue
            heatmap[asset.classification].append(
                {
                    "id": asset.id,
                    "name": asset.name,
                    "risk_score": asset.risk_score,
                    "type": asset.asset_type,
                }
            )
        for classification in heatmap:
            heatmap[classification].sort(key=lambda a: a["risk_score"], reverse=True)
        return {
            "heatmap": dict(heatmap),
            "total_assets": len(assets),
            "avg_risk": sum(a.risk_score for a in assets) / max(len(assets), 1),
            "critical_assets": sum(1 for a in assets if a.risk_score >= 80),
        }

    def get_stats(self, tenant_id: str) -> dict:
        assets = [
            self._assets[a] for a in self._tenant_assets.get(tenant_id, []) if a in self._assets
        ]
        by_type: dict[str, int] = defaultdict(int)
        by_class: dict[str, int] = defaultdict(int)
        by_status: dict[str, int] = defaultdict(int)
        for a in assets:
            by_type[a.asset_type] += 1
            by_class[a.classification] += 1
            by_status[a.status] += 1
        return {
            "total": len(assets),
            "by_type": dict(by_type),
            "by_classification": dict(by_class),
            "by_status": dict(by_status),
            "avg_risk_score": round(sum(a.risk_score for a in assets) / max(len(assets), 1), 1),
        }


# Module-level singleton
asset_inventory_service = AssetInventoryService()
