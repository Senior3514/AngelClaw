"""AngelClaw V7.5.0 — Iron Vault: Data Protection & Privacy API routes."""

from __future__ import annotations

from fastapi import APIRouter, Header

router = APIRouter(prefix="/api/v1/vault", tags=["Iron Vault"])


@router.post("/scan-content")
def vault_scan_content(content: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), req: dict = {}):
    from cloud.services.dlp_engine import dLPService_service
    return dLPService_service.scan_content(tenant_id, content, req)

@router.post("/add-policy")
def vault_add_policy(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), req: dict = {}):
    from cloud.services.dlp_engine import dLPService_service
    return dLPService_service.add_policy(tenant_id, req)

@router.get("/get-violations")
def vault_get_violations(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), limit: int = 20):
    from cloud.services.dlp_engine import dLPService_service
    return dLPService_service.get_violations(tenant_id, limit)

@router.get("/get-policies")
def vault_get_policies(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.dlp_engine import dLPService_service
    return dLPService_service.get_policies(tenant_id)

@router.get("/status")
def vault_status(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.dlp_engine import dLPService_service
    return dLPService_service.status(tenant_id)

@router.post("/classify-data")
def vault_classify_data(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), req: dict = {}):
    from cloud.services.data_classification import dataClassificationService_service
    return dataClassificationService_service.classify_data(tenant_id, req)

@router.post("/discover-sensitive")
def vault_discover_sensitive(scan_target: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.data_classification import dataClassificationService_service
    return dataClassificationService_service.discover_sensitive(tenant_id, scan_target)

@router.get("/get-inventory")
def vault_get_inventory(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.data_classification import dataClassificationService_service
    return dataClassificationService_service.get_inventory(tenant_id)

@router.get("/get-lineage")
def vault_get_lineage(asset_id: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.data_classification import dataClassificationService_service
    return dataClassificationService_service.get_lineage(tenant_id, asset_id)

@router.get("/status")
def vault_status_2(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.data_classification import dataClassificationService_service
    return dataClassificationService_service.status(tenant_id)
