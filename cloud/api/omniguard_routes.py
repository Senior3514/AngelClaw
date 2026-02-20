"""AngelClaw V6.0 — Omniguard: Multi-Cloud Defense Fabric API routes."""

from __future__ import annotations

from fastapi import APIRouter, Header
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/omniguard", tags=["Omniguard"])


class CloudConnectorRequest(BaseModel):
    cloud_provider: str  # aws, azure, gcp, oci, alibaba
    name: str
    config: dict = {}
    regions: list[str] = []


class CSPMScanRequest(BaseModel):
    connector_id: str
    benchmark: str = "cis"


class RemediationRequest(BaseModel):
    finding_id: str
    auto_fix: bool = False


class SaaSAppRequest(BaseModel):
    app_name: str
    app_type: str  # oauth, saml, api_key, custom
    auth_method: str = "oauth"
    config: dict = {}


class SaaSSessionRequest(BaseModel):
    app_id: str
    user_id: str
    action: str
    context: dict = {}


class ShadowITRequest(BaseModel):
    app_name: str
    source: str = "network"
    users_count: int = 1
    risk_level: str = "medium"


class HybridEnvRequest(BaseModel):
    env_name: str
    env_type: str  # on_prem, cloud, edge, hybrid
    endpoint: str = ""
    config: dict = {}


class PolicySyncRequest(BaseModel):
    source_env: str
    target_env: str


class FederateRequest(BaseModel):
    env_ids: list[str]


# -- Cloud Connector --


@router.post("/cloud/connectors")
def add_connector(
    req: CloudConnectorRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")
):
    from cloud.services.cloud_connector import cloud_connector_service

    return cloud_connector_service.add_connector(
        tenant_id=tenant_id,
        cloud_provider=req.cloud_provider,
        name=req.name,
        config=req.config,
        regions=req.regions,
    )


@router.get("/cloud/connectors")
def list_connectors(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.cloud_connector import cloud_connector_service

    return cloud_connector_service.list_connectors(tenant_id)


@router.post("/cloud/connectors/{connector_id}/test")
def test_connector(connector_id: str):
    from cloud.services.cloud_connector import cloud_connector_service

    return cloud_connector_service.test_connector(connector_id)


@router.post("/cloud/connectors/{connector_id}/sync")
def sync_resources(connector_id: str):
    from cloud.services.cloud_connector import cloud_connector_service

    return cloud_connector_service.sync_resources(connector_id)


@router.delete("/cloud/connectors/{connector_id}")
def remove_connector(connector_id: str):
    from cloud.services.cloud_connector import cloud_connector_service

    result = cloud_connector_service.remove_connector(connector_id)
    return result or {"error": "Connector not found"}


@router.get("/cloud/stats")
def cloud_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.cloud_connector import cloud_connector_service

    return cloud_connector_service.get_stats(tenant_id)


# -- CSPM --


@router.post("/cspm/scan")
def cspm_scan(req: CSPMScanRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.cspm import cspm_service

    return cspm_service.run_scan(
        tenant_id=tenant_id, connector_id=req.connector_id, benchmark=req.benchmark
    )


@router.get("/cspm/findings")
def cspm_findings(
    severity: str | None = None,
    provider: str | None = None,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    from cloud.services.cspm import cspm_service

    return cspm_service.get_findings(tenant_id=tenant_id, severity=severity, provider=provider)


@router.post("/cspm/remediate")
def cspm_remediate(req: RemediationRequest):
    from cloud.services.cspm import cspm_service

    return cspm_service.create_remediation(finding_id=req.finding_id, auto_fix=req.auto_fix)


@router.get("/cspm/posture")
def cspm_posture(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.cspm import cspm_service

    return cspm_service.get_posture_score(tenant_id)


@router.get("/cspm/stats")
def cspm_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.cspm import cspm_service

    return cspm_service.get_stats(tenant_id)


# -- SaaS Shield --


@router.post("/saas/apps")
def saas_register(req: SaaSAppRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.saas_shield import saas_shield_service

    return saas_shield_service.register_app(
        tenant_id=tenant_id,
        app_name=req.app_name,
        app_type=req.app_type,
        auth_method=req.auth_method,
        config=req.config,
    )


@router.get("/saas/apps")
def saas_list(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.saas_shield import saas_shield_service

    return saas_shield_service.list_apps(tenant_id)


@router.post("/saas/monitor")
def saas_monitor(
    req: SaaSSessionRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")
):
    from cloud.services.saas_shield import saas_shield_service

    return saas_shield_service.monitor_session(
        app_id=req.app_id,
        user_id=req.user_id,
        action=req.action,
        context=req.context,
    )


@router.post("/saas/shadow-it")
def saas_shadow(req: ShadowITRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.saas_shield import saas_shield_service

    return saas_shield_service.detect_shadow_it(
        tenant_id=tenant_id,
        discovered_app={
            "app_name": req.app_name,
            "source": req.source,
            "users_count": req.users_count,
            "risk_level": req.risk_level,
        },
    )


@router.get("/saas/risk")
def saas_risk(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.saas_shield import saas_shield_service

    return saas_shield_service.get_risk_summary(tenant_id)


@router.get("/saas/stats")
def saas_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.saas_shield import saas_shield_service

    return saas_shield_service.get_stats(tenant_id)


# -- Hybrid Mesh --


@router.post("/hybrid/environments")
def hybrid_register(
    req: HybridEnvRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")
):
    from cloud.services.hybrid_mesh import hybrid_mesh_service

    return hybrid_mesh_service.register_environment(
        tenant_id=tenant_id,
        env_name=req.env_name,
        env_type=req.env_type,
        endpoint=req.endpoint,
        config=req.config,
    )


@router.get("/hybrid/environments")
def hybrid_list(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.hybrid_mesh import hybrid_mesh_service

    return hybrid_mesh_service.get_mesh_status(tenant_id)


@router.post("/hybrid/sync")
def hybrid_sync(req: PolicySyncRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.hybrid_mesh import hybrid_mesh_service

    return hybrid_mesh_service.sync_policies(
        tenant_id=tenant_id,
        source_env=req.source_env,
        target_env=req.target_env,
    )


@router.get("/hybrid/latency")
def hybrid_latency(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.hybrid_mesh import hybrid_mesh_service

    return hybrid_mesh_service.get_latency_map(tenant_id)


@router.post("/hybrid/federate")
def hybrid_federate(
    req: FederateRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")
):
    from cloud.services.hybrid_mesh import hybrid_mesh_service

    return hybrid_mesh_service.federate_nodes(tenant_id=tenant_id, env_ids=req.env_ids)


@router.get("/hybrid/stats")
def hybrid_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.hybrid_mesh import hybrid_mesh_service

    return hybrid_mesh_service.get_stats(tenant_id)


# -- Combined Omniguard Status --


@router.get("/status")
def omniguard_status(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.cloud_connector import cloud_connector_service
    from cloud.services.cspm import cspm_service
    from cloud.services.hybrid_mesh import hybrid_mesh_service
    from cloud.services.saas_shield import saas_shield_service

    return {
        "cloud_connectors": cloud_connector_service.get_stats(tenant_id),
        "cspm": cspm_service.get_stats(tenant_id),
        "saas_shield": saas_shield_service.get_stats(tenant_id),
        "hybrid_mesh": hybrid_mesh_service.get_stats(tenant_id),
    }
