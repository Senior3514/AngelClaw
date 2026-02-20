"""AngelClaw V7.1.0 — Quantum Shield: Advanced Behavioral Analytics API routes."""

from __future__ import annotations

from fastapi import APIRouter, Header

router = APIRouter(prefix="/api/v1/quantum", tags=["Quantum Shield"])


@router.post("/profile-user")
def quantum_profile_user(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), user_id: str, req: dict = {}):
    from cloud.services.ueba import uEBAService_service
    return uEBAService_service.profile_user(tenant_id, user_id, req)

@router.post("/detect-anomaly")
def quantum_detect_anomaly(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), user_id: str, req: dict = {}):
    from cloud.services.ueba import uEBAService_service
    return uEBAService_service.detect_anomaly(tenant_id, user_id, req)

@router.get("/get-user-risk")
def quantum_get_user_risk(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), user_id: str):
    from cloud.services.ueba import uEBAService_service
    return uEBAService_service.get_user_risk(tenant_id, user_id)

@router.get("/list-profiles")
def quantum_list_profiles(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.ueba import uEBAService_service
    return uEBAService_service.list_profiles(tenant_id)

@router.get("/get-insider-threats")
def quantum_get_insider_threats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), min_risk: float = 70.0):
    from cloud.services.ueba import uEBAService_service
    return uEBAService_service.get_insider_threats(tenant_id, min_risk)

@router.get("/status")
def quantum_status(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.ueba import uEBAService_service
    return uEBAService_service.status(tenant_id)

@router.post("/score-threat")
def quantum_score_threat(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), req: dict = {}):
    from cloud.services.threat_scoring import threatScoringService_service
    return threatScoringService_service.score_threat(tenant_id, req)

@router.post("/batch-score")
def quantum_batch_score(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), req: dict = {}):
    from cloud.services.threat_scoring import threatScoringService_service
    return threatScoringService_service.batch_score(tenant_id, req)

@router.get("/get-priority-queue")
def quantum_get_priority_queue(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), limit: int = 20):
    from cloud.services.threat_scoring import threatScoringService_service
    return threatScoringService_service.get_priority_queue(tenant_id, limit)

@router.post("/explain-score")
def quantum_explain_score(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), threat_id: str):
    from cloud.services.threat_scoring import threatScoringService_service
    return threatScoringService_service.explain_score(tenant_id, threat_id)

@router.get("/status")
def quantum_status(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.threat_scoring import threatScoringService_service
    return threatScoringService_service.status(tenant_id)
