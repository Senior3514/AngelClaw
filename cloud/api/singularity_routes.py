"""AngelClaw V7.0 — Empyrion: Full AGI Autonomous Defense API routes."""

from __future__ import annotations

from fastapi import APIRouter, Header
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/empyrion", tags=["Empyrion"])


class ThreatAnalysisRequest(BaseModel):
    events: list[dict]


class RuleValidationRequest(BaseModel):
    rule_id: str
    test_events: list[dict] = []


class AutoDeployRequest(BaseModel):
    rule_id: str


class ResponseTriggerRequest(BaseModel):
    incident_id: str
    response_type: str = "auto"  # auto, containment, eradication, recovery


class ResponseOverrideRequest(BaseModel):
    response_id: str
    operator: str
    reason: str


class FederationJoinRequest(BaseModel):
    org_name: str
    trust_level: str = "basic"  # public, basic, verified, trusted, alliance


class FederationShareRequest(BaseModel):
    indicator_type: str
    indicator_value: str
    anonymize: bool = True


class TriageRequest(BaseModel):
    alert_id: str
    alert_data: dict = {}


class AssignAnalystRequest(BaseModel):
    alert_id: str
    analyst_id: str


# -- AGI Defense --


@router.post("/agi/analyze")
def agi_analyze(
    req: ThreatAnalysisRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")
):
    from cloud.services.agi_defense import agi_defense_service

    return agi_defense_service.analyze_threat_pattern(tenant_id=tenant_id, events=req.events)


@router.post("/agi/generate/{analysis_id}")
def agi_generate(analysis_id: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.agi_defense import agi_defense_service

    return agi_defense_service.generate_defense_rule(tenant_id=tenant_id, analysis_id=analysis_id)


@router.post("/agi/validate")
def agi_validate(req: RuleValidationRequest):
    from cloud.services.agi_defense import agi_defense_service

    return agi_defense_service.validate_rule(rule_id=req.rule_id, test_events=req.test_events)


@router.post("/agi/deploy")
def agi_deploy(req: AutoDeployRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.agi_defense import agi_defense_service

    return agi_defense_service.auto_deploy(tenant_id=tenant_id, rule_id=req.rule_id)


@router.get("/agi/rules")
def agi_rules(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.agi_defense import agi_defense_service

    return agi_defense_service.get_generated_rules(tenant_id)


@router.get("/agi/stats")
def agi_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.agi_defense import agi_defense_service

    return agi_defense_service.get_stats(tenant_id)


# -- Autonomous Response --


@router.post("/response/trigger")
def response_trigger(
    req: ResponseTriggerRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")
):
    from cloud.services.autonomous_response import autonomous_response_service

    return autonomous_response_service.trigger_response(
        tenant_id=tenant_id,
        incident_id=req.incident_id,
        response_type=req.response_type,
    )


@router.post("/response/{response_id}/contain")
def response_contain(response_id: str):
    from cloud.services.autonomous_response import autonomous_response_service

    return autonomous_response_service.execute_containment(response_id)


@router.post("/response/{response_id}/eradicate")
def response_eradicate(response_id: str):
    from cloud.services.autonomous_response import autonomous_response_service

    return autonomous_response_service.execute_eradication(response_id)


@router.post("/response/{response_id}/recover")
def response_recover(response_id: str):
    from cloud.services.autonomous_response import autonomous_response_service

    return autonomous_response_service.execute_recovery(response_id)


@router.post("/response/override")
def response_override(req: ResponseOverrideRequest):
    from cloud.services.autonomous_response import autonomous_response_service

    return autonomous_response_service.override_response(
        response_id=req.response_id,
        operator=req.operator,
        reason=req.reason,
    )


@router.get("/response/history")
def response_history(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.autonomous_response import autonomous_response_service

    return autonomous_response_service.get_response_history(tenant_id)


@router.get("/response/stats")
def response_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.autonomous_response import autonomous_response_service

    return autonomous_response_service.get_stats(tenant_id)


# -- Threat Federation --


@router.post("/federation/join")
def federation_join(
    req: FederationJoinRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")
):
    from cloud.services.threat_federation import threat_federation_service

    return threat_federation_service.join_federation(
        tenant_id=tenant_id,
        org_name=req.org_name,
        trust_level=req.trust_level,
    )


@router.post("/federation/share")
def federation_share(
    req: FederationShareRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")
):
    from cloud.services.threat_federation import threat_federation_service

    return threat_federation_service.share_intelligence(
        tenant_id=tenant_id,
        indicator_type=req.indicator_type,
        indicator_value=req.indicator_value,
        anonymize=req.anonymize,
    )


@router.get("/federation/consume")
def federation_consume(
    min_trust: float = 0.5, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")
):
    from cloud.services.threat_federation import threat_federation_service

    return threat_federation_service.consume_intelligence(tenant_id, min_trust)


@router.get("/federation/status")
def federation_status(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.threat_federation import threat_federation_service

    return threat_federation_service.get_federation_status(tenant_id)


@router.get("/federation/collective")
def federation_collective(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.threat_federation import threat_federation_service

    return threat_federation_service.get_collective_score(tenant_id)


@router.get("/federation/stats")
def federation_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.threat_federation import threat_federation_service

    return threat_federation_service.get_stats(tenant_id)


# -- SOC Autopilot --


@router.post("/soc/triage")
def soc_triage(req: TriageRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.soc_autopilot import soc_autopilot_service

    return soc_autopilot_service.triage_alert(
        tenant_id=tenant_id,
        alert_id=req.alert_id,
        alert_data=req.alert_data,
    )


@router.post("/soc/investigate/{investigation_id}")
def soc_investigate(
    investigation_id: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")
):
    from cloud.services.soc_autopilot import soc_autopilot_service

    return soc_autopilot_service.investigate(tenant_id, investigation_id)


@router.post("/soc/assign")
def soc_assign(
    req: AssignAnalystRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")
):
    from cloud.services.soc_autopilot import soc_autopilot_service

    return soc_autopilot_service.assign_analyst(
        tenant_id=tenant_id,
        alert_id=req.alert_id,
        analyst_id=req.analyst_id,
    )


@router.get("/soc/shift")
def soc_shift(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.soc_autopilot import soc_autopilot_service

    return soc_autopilot_service.get_shift_status(tenant_id)


@router.get("/soc/workload")
def soc_workload(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.soc_autopilot import soc_autopilot_service

    return soc_autopilot_service.get_workload(tenant_id)


@router.get("/soc/handoff")
def soc_handoff(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.soc_autopilot import soc_autopilot_service

    return soc_autopilot_service.generate_handoff(tenant_id)


@router.get("/soc/stats")
def soc_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.soc_autopilot import soc_autopilot_service

    return soc_autopilot_service.get_stats(tenant_id)


# -- Combined Empyrion Status --


@router.get("/status")
def empyrion_status(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.agi_defense import agi_defense_service
    from cloud.services.autonomous_response import autonomous_response_service
    from cloud.services.soc_autopilot import soc_autopilot_service
    from cloud.services.threat_federation import threat_federation_service

    return {
        "agi_defense": agi_defense_service.get_stats(tenant_id),
        "autonomous_response": autonomous_response_service.get_stats(tenant_id),
        "threat_federation": threat_federation_service.get_stats(tenant_id),
        "soc_autopilot": soc_autopilot_service.get_stats(tenant_id),
    }
