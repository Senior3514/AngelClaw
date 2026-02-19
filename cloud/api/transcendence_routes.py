"""AngelClaw V5.0 — Transcendence: AGI Singularity API routes."""

from __future__ import annotations

from fastapi import APIRouter, Header
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/transcendence", tags=["AGI Transcendence"])


class AIModelRegisterRequest(BaseModel):
    name: str
    model_type: str
    provider: str
    endpoint: str | None = None
    capabilities: list[str] = []
    config: dict = {}
    priority: int = 5


class AIRouteRequest(BaseModel):
    capability: str
    payload: dict = {}


class NLPolicyCreateRequest(BaseModel):
    natural_language: str


class IncidentDeclareRequest(BaseModel):
    title: str
    severity: str = "high"
    description: str = ""
    related_incident_ids: list[str] = []


class IncidentUpdateRequest(BaseModel):
    incident_id: str
    status: str | None = None
    update_text: str = ""


class ThreatShareRequest(BaseModel):
    indicator_type: str
    indicator_value: str
    severity: str = "medium"
    context: dict = {}


class DeceptionDeployRequest(BaseModel):
    token_type: str
    name: str
    deployment_location: str
    token_value: str | None = None
    description: str = ""


class ForensicCaseRequest(BaseModel):
    title: str
    description: str = ""
    incident_id: str | None = None
    priority: str = "medium"


class EvidenceRequest(BaseModel):
    case_id: str
    evidence_type: str
    description: str
    data: dict = {}


class ComplianceRuleRequest(BaseModel):
    framework: str
    control_id: str
    title: str
    description: str = ""
    check_type: str = "policy"
    check_config: dict = {}
    severity: str = "medium"


class EvolvingRuleRequest(BaseModel):
    name: str
    rule_type: str
    rule_config: dict
    description: str = ""


class RuleOutcomeRequest(BaseModel):
    rule_id: str
    is_true_positive: bool


# -- AI Model Orchestration --

@router.post("/ai/models")
def register_model(req: AIModelRegisterRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.ai_orchestrator import ai_orchestrator_service
    return ai_orchestrator_service.register_model(
        tenant_id, req.name, req.model_type, req.provider,
        req.endpoint, req.capabilities, req.config, req.priority,
    )


@router.get("/ai/models")
def list_models(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.ai_orchestrator import ai_orchestrator_service
    return ai_orchestrator_service.list_models(tenant_id)


@router.post("/ai/route")
def route_request(req: AIRouteRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.ai_orchestrator import ai_orchestrator_service
    return ai_orchestrator_service.route_request(tenant_id, req.capability, req.payload)


@router.get("/ai/stats")
def ai_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.ai_orchestrator import ai_orchestrator_service
    return ai_orchestrator_service.get_stats(tenant_id)


# -- Natural Language Policies --

@router.post("/policies/nl")
def create_nl_policy(req: NLPolicyCreateRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.nl_policy import nl_policy_service
    return nl_policy_service.create_nl_policy(tenant_id, req.natural_language)


@router.get("/policies/nl")
def list_nl_policies(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.nl_policy import nl_policy_service
    return nl_policy_service.list_policies(tenant_id)


@router.put("/policies/nl/{policy_id}/approve")
def approve_nl_policy(policy_id: str, approved_by: str = "operator"):
    from cloud.services.nl_policy import nl_policy_service
    result = nl_policy_service.approve_policy(policy_id, approved_by)
    return result or {"error": "Policy not found"}


@router.get("/policies/nl/stats")
def nl_policy_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.nl_policy import nl_policy_service
    return nl_policy_service.get_stats(tenant_id)


# -- Incident Commander --

@router.post("/incidents/declare")
def declare_incident(req: IncidentDeclareRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.incident_commander import incident_commander_service
    return incident_commander_service.declare_incident(
        tenant_id, req.title, req.severity, req.description, req.related_incident_ids,
    )


@router.post("/incidents/update")
def update_incident(req: IncidentUpdateRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.incident_commander import incident_commander_service
    return incident_commander_service.add_update(req.incident_id, req.update_text, req.status)


@router.get("/incidents")
def list_major_incidents(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.incident_commander import incident_commander_service
    return incident_commander_service.list_incidents(tenant_id)


@router.get("/incidents/stats")
def incident_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.incident_commander import incident_commander_service
    return incident_commander_service.get_stats(tenant_id)


# -- Threat Sharing --

@router.post("/sharing/indicators")
def share_indicator(req: ThreatShareRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.threat_sharing import threat_sharing_service
    return threat_sharing_service.share_indicator(
        tenant_id, req.indicator_type, req.indicator_value, req.severity, req.context,
    )


@router.get("/sharing/indicators")
def list_shared(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.threat_sharing import threat_sharing_service
    return threat_sharing_service.list_shared(tenant_id)


@router.get("/sharing/stats")
def sharing_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.threat_sharing import threat_sharing_service
    return threat_sharing_service.get_stats(tenant_id)


# -- Deception Technology --

@router.post("/deception/tokens")
def deploy_token(req: DeceptionDeployRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.deception import deception_service
    return deception_service.deploy_token(
        tenant_id=tenant_id,
        name=req.name,
        token_type=req.token_type,
        decoy_value=req.token_value or "",
        placement=req.deployment_location,
        description=req.description,
    )


@router.get("/deception/tokens")
def list_tokens(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.deception import deception_service
    return deception_service.list_tokens(tenant_id)


@router.post("/deception/tokens/{token_id}/check")
def check_trigger(token_id: str):
    from cloud.services.deception import deception_service
    token = deception_service.get_token(token_id)
    if not token:
        return {"error": "Token not found"}
    return deception_service.check_trigger(token["decoy_value"])


@router.put("/deception/tokens/{token_id}/deactivate")
def deactivate_token(token_id: str):
    from cloud.services.deception import deception_service
    result = deception_service.deactivate_token(token_id)
    return result or {"error": "Token not found"}


@router.get("/deception/stats")
def deception_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.deception import deception_service
    return deception_service.get_stats(tenant_id)


# -- Digital Forensics --

@router.post("/forensics/cases")
def create_case(req: ForensicCaseRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.forensics_auto import forensics_service
    return forensics_service.create_case(
        tenant_id=tenant_id,
        title=req.title,
        description=req.description,
        severity=req.priority,
        incident_id=req.incident_id,
    )


@router.post("/forensics/evidence")
def add_evidence(req: EvidenceRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.forensics_auto import forensics_service
    return forensics_service.add_evidence(
        case_id=req.case_id,
        evidence_type=req.evidence_type,
        description=req.description,
        metadata=req.data,
    )


@router.get("/forensics/cases")
def list_cases(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.forensics_auto import forensics_service
    return forensics_service.list_cases(tenant_id)


@router.get("/forensics/cases/{case_id}")
def get_case(case_id: str):
    from cloud.services.forensics_auto import forensics_service
    result = forensics_service.get_case(case_id)
    return result or {"error": "Case not found"}


@router.put("/forensics/cases/{case_id}/close")
def close_case(case_id: str):
    from cloud.services.forensics_auto import forensics_service
    result = forensics_service.close_case(case_id)
    return result or {"error": "Case not found"}


@router.get("/forensics/stats")
def forensics_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.forensics_auto import forensics_service
    return forensics_service.get_stats(tenant_id)


# -- Compliance-as-Code --

@router.post("/compliance/rules")
def create_compliance_rule(req: ComplianceRuleRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.compliance_code import compliance_code_service
    return compliance_code_service.create_rule(
        tenant_id, req.framework, req.control_id, req.title,
        req.description, req.check_type, req.check_config, req.severity,
    )


@router.get("/compliance/rules")
def list_compliance_rules(framework: str | None = None, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.compliance_code import compliance_code_service
    return compliance_code_service.list_rules(tenant_id, framework)


@router.post("/compliance/audit/{framework}")
def run_compliance_audit(framework: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.compliance_code import compliance_code_service
    return compliance_code_service.run_framework_audit(tenant_id, framework)


@router.get("/compliance/report")
def compliance_report(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.compliance_code import compliance_code_service
    return compliance_code_service.get_compliance_report(tenant_id)


@router.get("/compliance/stats")
def compliance_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.compliance_code import compliance_code_service
    return compliance_code_service.get_stats(tenant_id)


# -- Evolving Rules --

@router.post("/rules/evolving")
def create_evolving_rule(req: EvolvingRuleRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.evolving_rules import evolving_rules_service
    return evolving_rules_service.create_rule(
        tenant_id=tenant_id,
        name=req.name,
        category=req.rule_type,
        conditions=req.rule_config,
        description=req.description,
    )


@router.get("/rules/evolving")
def list_evolving_rules(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.evolving_rules import evolving_rules_service
    return evolving_rules_service.list_rules(tenant_id)


@router.post("/rules/evolving/outcome")
def record_rule_outcome(req: RuleOutcomeRequest):
    from cloud.services.evolving_rules import evolving_rules_service
    outcome = "true_positive" if req.is_true_positive else "false_positive"
    return evolving_rules_service.record_outcome(req.rule_id, outcome)


@router.post("/rules/evolving/evolve")
def evolve_rules(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.evolving_rules import evolving_rules_service
    return evolving_rules_service.evolve_rules(tenant_id)


@router.get("/rules/evolving/{rule_id}/lineage")
def get_rule_lineage(rule_id: str):
    from cloud.services.evolving_rules import evolving_rules_service
    return evolving_rules_service.get_lineage(rule_id)


@router.get("/rules/evolving/stats")
def evolving_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.evolving_rules import evolving_rules_service
    return evolving_rules_service.get_stats(tenant_id)


# -- Combined Transcendence Status --

@router.get("/status")
def transcendence_status(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.ai_orchestrator import ai_orchestrator_service
    from cloud.services.compliance_code import compliance_code_service
    from cloud.services.deception import deception_service
    from cloud.services.evolving_rules import evolving_rules_service
    from cloud.services.forensics_auto import forensics_service
    from cloud.services.incident_commander import incident_commander_service
    from cloud.services.nl_policy import nl_policy_service
    from cloud.services.threat_sharing import threat_sharing_service
    return {
        "ai_orchestrator": ai_orchestrator_service.get_stats(tenant_id),
        "nl_policies": nl_policy_service.get_stats(tenant_id),
        "incident_commander": incident_commander_service.get_stats(tenant_id),
        "threat_sharing": threat_sharing_service.get_stats(tenant_id),
        "deception": deception_service.get_stats(tenant_id),
        "forensics": forensics_service.get_stats(tenant_id),
        "compliance": compliance_code_service.get_stats(tenant_id),
        "evolving_rules": evolving_rules_service.get_stats(tenant_id),
    }
