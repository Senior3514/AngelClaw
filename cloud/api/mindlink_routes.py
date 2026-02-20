"""AngelClaw V7.7.0 — Mind Link: Collaborative Intelligence & Reporting API routes."""

from __future__ import annotations

from fastapi import APIRouter, Header

router = APIRouter(prefix="/api/v1/mindlink", tags=["Mind Link"])


@router.post("/publish-intel")
def mindlink_publish_intel(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), req: dict = {}):
    from cloud.services.intel_marketplace import intelMarketplaceService_service
    return intelMarketplaceService_service.publish_intel(tenant_id, req)

@router.post("/search-intel")
def mindlink_search_intel(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), query: str, intel_type: str | None = None):
    from cloud.services.intel_marketplace import intelMarketplaceService_service
    return intelMarketplaceService_service.search_intel(tenant_id, query, intel_type)

@router.post("/download-intel")
def mindlink_download_intel(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), listing_id: str):
    from cloud.services.intel_marketplace import intelMarketplaceService_service
    return intelMarketplaceService_service.download_intel(tenant_id, listing_id)

@router.get("/get-listings")
def mindlink_get_listings(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.intel_marketplace import intelMarketplaceService_service
    return intelMarketplaceService_service.get_listings(tenant_id)

@router.get("/status")
def mindlink_status(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.intel_marketplace import intelMarketplaceService_service
    return intelMarketplaceService_service.status(tenant_id)

@router.post("/generate-executive")
def mindlink_generate_executive(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), time_range_hours: int = 24):
    from cloud.services.report_generator import reportGeneratorService_service
    return reportGeneratorService_service.generate_executive(tenant_id, time_range_hours)

@router.post("/generate-technical")
def mindlink_generate_technical(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), incident_id: str):
    from cloud.services.report_generator import reportGeneratorService_service
    return reportGeneratorService_service.generate_technical(tenant_id, incident_id)

@router.post("/generate-compliance")
def mindlink_generate_compliance(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), framework: str = 'soc2'):
    from cloud.services.report_generator import reportGeneratorService_service
    return reportGeneratorService_service.generate_compliance(tenant_id, framework)

@router.get("/list-reports")
def mindlink_list_reports(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.report_generator import reportGeneratorService_service
    return reportGeneratorService_service.list_reports(tenant_id)

@router.get("/status")
def mindlink_status(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.report_generator import reportGeneratorService_service
    return reportGeneratorService_service.status(tenant_id)
