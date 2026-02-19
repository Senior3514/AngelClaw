"""AngelClaw V4.2 — Nexus: SIEM, Container, IaC, CI/CD API routes."""

from __future__ import annotations

from fastapi import APIRouter, Header
from pydantic import BaseModel

from cloud.services.cicd_gate import cicd_gate_service
from cloud.services.container_security import container_security_service
from cloud.services.iac_scanner import iac_scanner_service
from cloud.services.siem_connector import siem_connector_service

router = APIRouter(prefix="/api/v1/integrations", tags=["Integration Hub"])


class SIEMCreateRequest(BaseModel):
    name: str
    siem_type: str
    connection_config: dict = {}
    sync_direction: str = "push"
    event_filter: dict = {}


class SIEMSyncRequest(BaseModel):
    events: list[dict]


class ContainerScanRequest(BaseModel):
    image_name: str
    image_tag: str | None = None
    config: dict = {}


class ContainerRuntimeRequest(BaseModel):
    container_id: str
    runtime_config: dict


class IaCScanRequest(BaseModel):
    source_type: str
    source_path: str
    content: str


class CICDGateRequest(BaseModel):
    pipeline_name: str
    gate_type: str = "pre_deploy"
    artifacts: dict = {}
    pipeline_run_id: str | None = None
    policy_id: str | None = None


# -- SIEM --

@router.post("/siem/connectors")
def create_siem(req: SIEMCreateRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return siem_connector_service.create_connector(
        tenant_id, req.name, req.siem_type, req.connection_config, req.sync_direction, req.event_filter,
    )


@router.get("/siem/connectors")
def list_siem(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return siem_connector_service.list_connectors(tenant_id)


@router.post("/siem/connectors/{connector_id}/sync")
def sync_siem(connector_id: str, req: SIEMSyncRequest):
    return siem_connector_service.sync_events(connector_id, req.events)


@router.post("/siem/connectors/{connector_id}/test")
def test_siem(connector_id: str):
    return siem_connector_service.test_connection(connector_id)


@router.put("/siem/connectors/{connector_id}/toggle")
def toggle_siem(connector_id: str, enabled: bool = True):
    result = siem_connector_service.toggle_connector(connector_id, enabled)
    return result or {"error": "Connector not found"}


@router.delete("/siem/connectors/{connector_id}")
def delete_siem(connector_id: str):
    return {"deleted": siem_connector_service.delete_connector(connector_id)}


@router.get("/siem/stats")
def siem_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return siem_connector_service.get_stats(tenant_id)


# -- Container Security --

@router.post("/containers/scan")
def scan_container(req: ContainerScanRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return container_security_service.scan_image(tenant_id, req.image_name, req.image_tag, req.config)


@router.post("/containers/runtime-scan")
def scan_runtime(req: ContainerRuntimeRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return container_security_service.scan_runtime(tenant_id, req.container_id, req.runtime_config)


@router.get("/containers/scans")
def list_container_scans(scan_type: str | None = None, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return container_security_service.list_scans(tenant_id, scan_type)


@router.get("/containers/stats")
def container_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return container_security_service.get_stats(tenant_id)


# -- IaC Scanner --

@router.post("/iac/scan")
def scan_iac(req: IaCScanRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return iac_scanner_service.scan_content(tenant_id, req.source_type, req.source_path, req.content)


@router.get("/iac/scans")
def list_iac_scans(source_type: str | None = None, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return iac_scanner_service.list_scans(tenant_id, source_type)


@router.get("/iac/stats")
def iac_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return iac_scanner_service.get_stats(tenant_id)


# -- CI/CD Gate --

@router.post("/cicd/evaluate")
def evaluate_gate(req: CICDGateRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return cicd_gate_service.evaluate_gate(
        tenant_id, req.pipeline_name, req.gate_type, req.artifacts, req.pipeline_run_id, req.policy_id,
    )


@router.get("/cicd/results")
def list_cicd_results(pipeline_name: str | None = None, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return cicd_gate_service.list_results(tenant_id, pipeline_name)


@router.get("/cicd/stats")
def cicd_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return cicd_gate_service.get_stats(tenant_id)
