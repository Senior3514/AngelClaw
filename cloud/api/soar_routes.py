"""AngelClaw V4.0 — Omniscience: SOAR & SLA & Timeline API routes."""

from __future__ import annotations

from fastapi import APIRouter, Header
from pydantic import BaseModel

from cloud.services.incident_timeline import incident_timeline_service
from cloud.services.sla_tracking import sla_tracking_service
from cloud.services.soar import soar_engine

router = APIRouter(prefix="/api/v1/soar", tags=["SOAR Engine"])


class PlaybookCreateRequest(BaseModel):
    name: str
    trigger_type: str
    trigger_config: dict = {}
    actions: list[dict] = []
    description: str = ""
    priority: int = 5
    max_executions_per_hour: int = 10


class PlaybookExecuteRequest(BaseModel):
    trigger_context: dict = {}


class SLAConfigRequest(BaseModel):
    name: str
    severity: str
    response_time_minutes: int
    resolution_time_minutes: int
    escalation_contacts: list[str] = []


class TimelineEntryRequest(BaseModel):
    incident_id: str
    entry_type: str
    title: str
    description: str = ""
    actor: str = "operator"


# -- SOAR Playbook endpoints --

@router.post("/playbooks")
def create_playbook(
    req: PlaybookCreateRequest,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return soar_engine.create_playbook(
        tenant_id, req.name, req.trigger_type, req.trigger_config,
        req.actions, req.description, req.priority, req.max_executions_per_hour,
    )


@router.get("/playbooks")
def list_playbooks(
    trigger_type: str | None = None,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return soar_engine.list_playbooks(tenant_id, trigger_type)


@router.get("/playbooks/{playbook_id}")
def get_playbook(playbook_id: str):
    result = soar_engine.get_playbook(playbook_id)
    return result or {"error": "Playbook not found"}


@router.post("/playbooks/{playbook_id}/execute")
def execute_playbook(playbook_id: str, req: PlaybookExecuteRequest):
    return soar_engine.execute_playbook(playbook_id, req.trigger_context)


@router.put("/playbooks/{playbook_id}/toggle")
def toggle_playbook(playbook_id: str, enabled: bool = True):
    result = soar_engine.toggle_playbook(playbook_id, enabled)
    return result or {"error": "Playbook not found"}


@router.delete("/playbooks/{playbook_id}")
def delete_playbook(playbook_id: str):
    return {"deleted": soar_engine.delete_playbook(playbook_id)}


@router.get("/executions")
def list_executions(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return soar_engine.list_executions(tenant_id)


@router.get("/executions/{execution_id}")
def get_execution(execution_id: str):
    result = soar_engine.get_execution(execution_id)
    return result or {"error": "Execution not found"}


@router.get("/stats")
def soar_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return soar_engine.get_stats(tenant_id)


# -- SLA endpoints --

@router.post("/sla/configs")
def create_sla_config(
    req: SLAConfigRequest,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return sla_tracking_service.create_config(
        tenant_id, req.name, req.severity,
        req.response_time_minutes, req.resolution_time_minutes,
        req.escalation_contacts,
    )


@router.get("/sla/configs")
def list_sla_configs(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return sla_tracking_service.list_configs(tenant_id)


@router.get("/sla/breaches")
def check_sla_breaches(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return sla_tracking_service.check_breaches(tenant_id)


@router.get("/sla/compliance")
def sla_compliance(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return sla_tracking_service.get_compliance_report(tenant_id)


# -- Timeline endpoints --

@router.post("/timeline")
def add_timeline_entry(
    req: TimelineEntryRequest,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return incident_timeline_service.add_entry(
        tenant_id, req.incident_id, req.entry_type,
        req.title, req.description, req.actor,
    )


@router.get("/timeline/{incident_id}")
def get_timeline(incident_id: str, entry_type: str | None = None):
    return incident_timeline_service.get_timeline(incident_id, entry_type)


@router.get("/timeline/stats")
def timeline_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return incident_timeline_service.get_stats(tenant_id)
