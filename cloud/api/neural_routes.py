"""AngelClaw V7.2.0 — Neural Mesh: AI-Enhanced Network Intelligence API routes."""

from __future__ import annotations

from fastapi import APIRouter, Header

router = APIRouter(prefix="/api/v1/neural", tags=["Neural Mesh"])


@router.post("/analyze-flow")
def neural_analyze_flow(
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
    req: dict | None = None,
):
    if req is None:
        req = {}
    from cloud.services.traffic_analysis import trafficAnalysisService_service

    return trafficAnalysisService_service.analyze_flow(tenant_id, req)


@router.post("/detect-beaconing")
def neural_detect_beaconing(
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), req: dict | None = None
):
    if req is None:
        req = {}
    from cloud.services.traffic_analysis import trafficAnalysisService_service

    return trafficAnalysisService_service.detect_beaconing(tenant_id, req)


@router.post("/detect-exfiltration")
def neural_detect_exfiltration(
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), req: dict | None = None
):
    if req is None:
        req = {}
    from cloud.services.traffic_analysis import trafficAnalysisService_service

    return trafficAnalysisService_service.detect_exfiltration(tenant_id, req)


@router.post("/detect-lateral-movement")
def neural_detect_lateral_movement(
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), req: dict | None = None
):
    if req is None:
        req = {}
    from cloud.services.traffic_analysis import trafficAnalysisService_service

    return trafficAnalysisService_service.detect_lateral_movement(tenant_id, req)


@router.get("/status")
def neural_status(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.traffic_analysis import trafficAnalysisService_service

    return trafficAnalysisService_service.status(tenant_id)


@router.post("/analyze-query")
def neural_analyze_query(
    domain: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), query_type: str = "A"
):
    from cloud.services.dns_security import dNSSecurityService_service

    return dNSSecurityService_service.analyze_query(tenant_id, domain, query_type)


@router.post("/detect-dga")
def neural_detect_dga(
    domains: list[str], tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")
):
    from cloud.services.dns_security import dNSSecurityService_service

    return dNSSecurityService_service.detect_dga(tenant_id, domains)


@router.post("/detect-tunneling")
def neural_detect_tunneling(
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), req: dict | None = None
):
    if req is None:
        req = {}
    from cloud.services.dns_security import dNSSecurityService_service

    return dNSSecurityService_service.detect_tunneling(tenant_id, req)


@router.get("/get-sinkhole-list")
def neural_get_sinkhole_list(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.dns_security import dNSSecurityService_service

    return dNSSecurityService_service.get_sinkhole_list(tenant_id)


@router.get("/status")
def neural_status_2(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.dns_security import dNSSecurityService_service

    return dNSSecurityService_service.status(tenant_id)
