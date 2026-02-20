"""AngelClaw V7.4.0 — Dark Web Radar.

Extended Threat Intelligence & Dark Web Monitoring API routes.
"""

from __future__ import annotations

from fastapi import APIRouter, Header

router = APIRouter(prefix="/api/v1/darkweb", tags=["Dark Web Radar"])


@router.post("/scan-credentials")
def darkweb_scan_credentials(
    domains: list[str], tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")
):
    from cloud.services.darkweb_monitor import darkWebMonitorService_service

    return darkWebMonitorService_service.scan_credentials(tenant_id, domains)


@router.post("/add-watchlist")
def darkweb_add_watchlist(
    keywords: list[str],
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
    watch_type: str = "brand",
):
    from cloud.services.darkweb_monitor import darkWebMonitorService_service

    return darkWebMonitorService_service.add_watchlist(tenant_id, keywords, watch_type)


@router.get("/get-alerts")
def darkweb_get_alerts(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), limit: int = 20):
    from cloud.services.darkweb_monitor import darkWebMonitorService_service

    return darkWebMonitorService_service.get_alerts(tenant_id, limit)


@router.post("/track-actor")
def darkweb_track_actor(actor_id: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.darkweb_monitor import darkWebMonitorService_service

    return darkWebMonitorService_service.track_actor(tenant_id, actor_id)


@router.get("/status")
def darkweb_status(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.darkweb_monitor import darkWebMonitorService_service

    return darkWebMonitorService_service.status(tenant_id)


@router.post("/analyze-sbom")
def darkweb_analyze_sbom(
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), req: dict | None = None
):
    if req is None:
        req = {}
    from cloud.services.supply_chain import supplyChainService_service

    return supplyChainService_service.analyze_sbom(tenant_id, req)


@router.post("/scan-dependencies")
def darkweb_scan_dependencies(
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), req: dict | None = None
):
    if req is None:
        req = {}
    from cloud.services.supply_chain import supplyChainService_service

    return supplyChainService_service.scan_dependencies(tenant_id, req)


@router.post("/assess-vendor")
def darkweb_assess_vendor(
    vendor_name: str,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
    req: dict | None = None,
):
    if req is None:
        req = {}
    from cloud.services.supply_chain import supplyChainService_service

    return supplyChainService_service.assess_vendor(tenant_id, vendor_name, req)


@router.get("/get-risk-report")
def darkweb_get_risk_report(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.supply_chain import supplyChainService_service

    return supplyChainService_service.get_risk_report(tenant_id)


@router.get("/status")
def darkweb_status_2(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.supply_chain import supplyChainService_service

    return supplyChainService_service.status(tenant_id)
