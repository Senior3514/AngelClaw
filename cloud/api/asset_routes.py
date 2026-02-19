"""AngelClaw V4.0 — Omniscience: Asset & Topology & Vulnerability API routes."""

from __future__ import annotations

from fastapi import APIRouter, Header
from pydantic import BaseModel

from cloud.services.asset_inventory import asset_inventory_service
from cloud.services.topology import topology_service
from cloud.services.vulnerability import vulnerability_service

router = APIRouter(prefix="/api/v1/assets", tags=["Asset Inventory"])


class AssetCreateRequest(BaseModel):
    asset_type: str
    name: str
    hostname: str | None = None
    ip_address: str | None = None
    os: str | None = None
    agent_id: str | None = None
    classification: str = "standard"
    owner: str | None = None
    tags: list[str] = []
    metadata: dict = {}


class AssetUpdateRequest(BaseModel):
    updates: dict


class TopologyLinkRequest(BaseModel):
    source_asset_id: str
    target_asset_id: str
    link_type: str = "network"
    protocol: str | None = None
    port: int | None = None
    direction: str = "bidirectional"


class VulnReportRequest(BaseModel):
    asset_id: str
    title: str
    severity: str = "medium"
    cve_id: str | None = None
    description: str = ""
    cvss_score: str | None = None
    remediation: str = ""


# -- Asset endpoints --

@router.post("")
def register_asset(
    req: AssetCreateRequest,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return asset_inventory_service.register_asset(
        tenant_id=tenant_id, asset_type=req.asset_type, name=req.name,
        hostname=req.hostname, ip_address=req.ip_address, os=req.os,
        agent_id=req.agent_id, classification=req.classification,
        owner=req.owner, tags=req.tags, metadata=req.metadata,
    )


@router.get("")
def list_assets(
    asset_type: str | None = None,
    classification: str | None = None,
    status: str | None = None,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return asset_inventory_service.list_assets(tenant_id, asset_type, classification, status)


@router.get("/{asset_id}")
def get_asset(asset_id: str):
    result = asset_inventory_service.get_asset(asset_id)
    return result or {"error": "Asset not found"}


@router.put("/{asset_id}")
def update_asset(asset_id: str, req: AssetUpdateRequest):
    result = asset_inventory_service.update_asset(asset_id, req.updates)
    return result or {"error": "Asset not found"}


@router.delete("/{asset_id}")
def decommission_asset(asset_id: str):
    result = asset_inventory_service.decommission_asset(asset_id)
    return result or {"error": "Asset not found"}


@router.get("/{asset_id}/risk")
def get_asset_risk(asset_id: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return vulnerability_service.get_asset_risk(tenant_id, asset_id)


@router.get("/analytics/heatmap")
def get_risk_heatmap(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return asset_inventory_service.get_risk_heatmap(tenant_id)


@router.get("/analytics/stats")
def get_asset_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return asset_inventory_service.get_stats(tenant_id)


# -- Topology endpoints --

@router.post("/topology/links")
def add_topology_link(
    req: TopologyLinkRequest,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return topology_service.add_link(
        tenant_id, req.source_asset_id, req.target_asset_id,
        req.link_type, req.protocol, req.port, req.direction,
    )


@router.get("/topology/links")
def get_topology_links(
    asset_id: str | None = None,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return topology_service.get_links(tenant_id, asset_id)


@router.get("/topology/graph")
def get_topology_graph(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return topology_service.get_graph(tenant_id)


@router.get("/topology/critical-nodes")
def get_critical_nodes(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return topology_service.find_critical_nodes(tenant_id)


@router.delete("/topology/links/{link_id}")
def remove_topology_link(link_id: str):
    return {"removed": topology_service.remove_link(link_id)}


# -- Vulnerability endpoints --

@router.post("/vulnerabilities")
def report_vulnerability(
    req: VulnReportRequest,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return vulnerability_service.report_finding(
        tenant_id, req.asset_id, req.title, req.severity,
        req.cve_id, req.description, req.cvss_score, req.remediation,
    )


@router.get("/vulnerabilities")
def list_vulnerabilities(
    asset_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return vulnerability_service.list_findings(tenant_id, asset_id, severity, status)


@router.put("/vulnerabilities/{finding_id}/status")
def update_vuln_status(finding_id: str, status: str = "mitigated"):
    result = vulnerability_service.update_status(finding_id, status)
    return result or {"error": "Finding not found"}


@router.get("/vulnerabilities/stats")
def get_vuln_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return vulnerability_service.get_stats(tenant_id)
