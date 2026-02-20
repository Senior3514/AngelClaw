"""AngelClaw V7.9.0 — Apex Predator: Automated Offensive Security & Validation API routes."""

from __future__ import annotations

from fastapi import APIRouter, Header

router = APIRouter(prefix="/api/v1/apex", tags=["Apex Predator"])


@router.post("/start-pentest")
def apex_start_pentest(
    target: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), scope: str = "internal"
):
    from cloud.services.pentest_auto import pentestAutoService_service

    return pentestAutoService_service.start_pentest(tenant_id, target, scope)


@router.get("/get-findings")
def apex_get_findings(run_id: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.pentest_auto import pentestAutoService_service

    return pentestAutoService_service.get_findings(tenant_id, run_id)


@router.post("/verify-remediation")
def apex_verify_remediation(
    finding_id: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")
):
    from cloud.services.pentest_auto import pentestAutoService_service

    return pentestAutoService_service.verify_remediation(tenant_id, finding_id)


@router.get("/list-runs")
def apex_list_runs(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.pentest_auto import pentestAutoService_service

    return pentestAutoService_service.list_runs(tenant_id)


@router.get("/status")
def apex_status(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.pentest_auto import pentestAutoService_service

    return pentestAutoService_service.status(tenant_id)


@router.post("/create-campaign")
def apex_create_campaign(
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), req: dict | None = None
):
    if req is None:
        req = {}
    from cloud.services.red_team import redTeamService_service

    return redTeamService_service.create_campaign(tenant_id, req)


@router.post("/execute-phase")
def apex_execute_phase(
    campaign_id: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), phase: int = 0
):
    from cloud.services.red_team import redTeamService_service

    return redTeamService_service.execute_phase(tenant_id, campaign_id, phase)


@router.get("/get-gaps")
def apex_get_gaps(campaign_id: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.red_team import redTeamService_service

    return redTeamService_service.get_gaps(tenant_id, campaign_id)


@router.get("/list-campaigns")
def apex_list_campaigns(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.red_team import redTeamService_service

    return redTeamService_service.list_campaigns(tenant_id)


@router.get("/status")
def apex_status_2(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.red_team import redTeamService_service

    return redTeamService_service.status(tenant_id)
