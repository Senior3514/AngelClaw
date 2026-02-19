"""AngelClaw V4.5 — Sovereign: Zero Trust API routes."""

from __future__ import annotations

from fastapi import APIRouter, Header
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/zerotrust", tags=["Zero Trust Architecture"])


class SegmentCreateRequest(BaseModel):
    name: str
    segment_type: str = "network"
    source_criteria: dict = {}
    target_criteria: dict = {}
    allowed_protocols: list[str] = []
    action: str = "allow"
    priority: int = 100
    description: str = ""


class IdentityPolicyRequest(BaseModel):
    name: str
    identity_type: str
    identity_pattern: str
    resource_pattern: str
    conditions: dict = {}
    action: str = "allow"
    priority: int = 100


class DeviceAssessRequest(BaseModel):
    device_id: str
    agent_id: str | None = None
    os_version: str | None = None
    patch_level: str | None = None
    encryption_enabled: bool = False
    antivirus_active: bool = False
    firewall_enabled: bool = False


class SessionAssessRequest(BaseModel):
    session_id: str
    user_id: str
    device_id: str | None = None
    geo_location: str | None = None


class AuthEvalRequest(BaseModel):
    session_id: str
    user_id: str
    resource: str
    device_id: str | None = None


# -- Microsegmentation --

@router.post("/segments")
def create_segment(req: SegmentCreateRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.microsegmentation import microsegmentation_engine
    return microsegmentation_engine.create_segment(
        tenant_id, req.name, req.segment_type, req.source_criteria,
        req.target_criteria, req.allowed_protocols, req.action, req.priority, req.description,
    )


@router.get("/segments")
def list_segments(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.microsegmentation import microsegmentation_engine
    return microsegmentation_engine.list_segments(tenant_id)


@router.post("/segments/evaluate")
def evaluate_segment(source: str = "", target: str = "", protocol: str = "tcp",
                     tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.microsegmentation import microsegmentation_engine
    return microsegmentation_engine.evaluate_access(
        tenant_id, {"zone": source} if source else {}, {"zone": target} if target else {}, protocol,
    )


@router.delete("/segments/{segment_id}")
def delete_segment(segment_id: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.microsegmentation import microsegmentation_engine
    return {"deleted": microsegmentation_engine.delete_segment(tenant_id, segment_id)}


@router.get("/segments/stats")
def segment_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.microsegmentation import microsegmentation_engine
    return microsegmentation_engine.get_stats(tenant_id)


# -- Identity Policies --

@router.post("/identity/policies")
def create_identity_policy(req: IdentityPolicyRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.identity_policy import identity_policy_service
    return identity_policy_service.create_policy(
        tenant_id, req.name, req.identity_type, req.identity_pattern,
        req.resource_pattern, req.action, req.conditions, req.priority,
    )


@router.get("/identity/policies")
def list_identity_policies(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.identity_policy import identity_policy_service
    return identity_policy_service.list_policies(tenant_id)


@router.post("/identity/evaluate")
def evaluate_identity(identity_type: str = "", identity: str = "", resource: str = "",
                      tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.identity_policy import identity_policy_service
    return identity_policy_service.evaluate_access(tenant_id, identity_type, identity, resource)


@router.get("/identity/stats")
def identity_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.identity_policy import identity_policy_service
    return identity_policy_service.get_stats(tenant_id)


# -- Device Trust --

@router.post("/devices/assess")
def assess_device(req: DeviceAssessRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.device_trust import device_trust_service
    return device_trust_service.assess_device(
        tenant_id, req.device_id, req.agent_id, req.os_version,
        req.patch_level, req.encryption_enabled, req.antivirus_active, req.firewall_enabled,
    )


@router.get("/devices")
def list_devices(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.device_trust import device_trust_service
    return device_trust_service.list_devices(tenant_id)


@router.get("/devices/{device_id}")
def get_device(device_id: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.device_trust import device_trust_service
    result = device_trust_service.get_device_trust(device_id)
    return result or {"error": "Device not found"}


@router.get("/devices/stats")
def device_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.device_trust import device_trust_service
    return device_trust_service.get_stats(tenant_id)


# -- Session Risk --

@router.post("/sessions/assess")
def assess_session(req: SessionAssessRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.session_risk import session_risk_service
    return session_risk_service.assess_session(
        tenant_id, req.session_id, req.user_id, req.device_id, req.geo_location,
    )


@router.get("/sessions")
def list_sessions(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.session_risk import session_risk_service
    return session_risk_service.list_sessions(tenant_id)


@router.get("/sessions/{session_id}")
def get_session(session_id: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.session_risk import session_risk_service
    result = session_risk_service.get_session(tenant_id, session_id)
    return result or {"error": "Session not found"}


@router.get("/sessions/stats")
def session_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.session_risk import session_risk_service
    return session_risk_service.get_stats(tenant_id)


# -- Adaptive Auth --

@router.post("/auth/evaluate")
def evaluate_auth(req: AuthEvalRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.adaptive_auth import adaptive_auth_service
    return adaptive_auth_service.evaluate_auth_requirement(
        tenant_id, req.session_id, req.user_id, req.resource, req.device_id,
    )


@router.get("/auth/stats")
def auth_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.adaptive_auth import adaptive_auth_service
    return adaptive_auth_service.get_stats(tenant_id)


# -- Combined Zero Trust Status --

@router.get("/status")
def zerotrust_status(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.adaptive_auth import adaptive_auth_service
    from cloud.services.device_trust import device_trust_service
    from cloud.services.identity_policy import identity_policy_service
    from cloud.services.microsegmentation import microsegmentation_engine
    from cloud.services.session_risk import session_risk_service
    return {
        "microsegmentation": microsegmentation_engine.get_stats(tenant_id),
        "identity_policies": identity_policy_service.get_stats(tenant_id),
        "device_trust": device_trust_service.get_stats(tenant_id),
        "session_risk": session_risk_service.get_stats(tenant_id),
        "adaptive_auth": adaptive_auth_service.get_stats(tenant_id),
    }
