"""AngelClaw V6.5 — Prometheus: Autonomous Threat Hunting API routes."""

from __future__ import annotations

from fastapi import APIRouter, Header
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/prometheus", tags=["Prometheus"])


class HuntCreateRequest(BaseModel):
    name: str
    hypothesis: str
    hunt_type: str = "indicator"  # indicator, behavioral, anomaly, campaign
    config: dict = {}


class HuntPlaybookRequest(BaseModel):
    name: str
    steps: list[dict] = []


class MitreMapRequest(BaseModel):
    event_type: str
    indicators: dict = {}


class MitreTechniqueRequest(BaseModel):
    technique_id: str
    tactic: str
    name: str
    description: str = ""


class ScenarioCreateRequest(BaseModel):
    name: str
    attack_type: str
    mitre_techniques: list[str] = []
    config: dict = {}


class CorrelationRequest(BaseModel):
    event_ids: list[str]
    correlation_type: str = "temporal"  # temporal, behavioral, indicator, campaign


class CampaignAttributionRequest(BaseModel):
    indicator_ids: list[str]


# -- Threat Hunter --

@router.post("/hunts")
def create_hunt(req: HuntCreateRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.threat_hunter import threat_hunter_service
    return threat_hunter_service.create_hunt(
        tenant_id=tenant_id,
        name=req.name,
        hypothesis=req.hypothesis,
        hunt_type=req.hunt_type,
        config=req.config,
    )


@router.post("/hunts/{hunt_id}/execute")
def execute_hunt(hunt_id: str):
    from cloud.services.threat_hunter import threat_hunter_service
    return threat_hunter_service.execute_hunt(hunt_id)


@router.get("/hunts")
def list_hunts(status: str | None = None, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.threat_hunter import threat_hunter_service
    return threat_hunter_service.list_hunts(tenant_id, status)


@router.get("/hunts/{hunt_id}/results")
def hunt_results(hunt_id: str):
    from cloud.services.threat_hunter import threat_hunter_service
    return threat_hunter_service.get_hunt_results(hunt_id)


@router.post("/hunts/playbooks")
def create_playbook(req: HuntPlaybookRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.threat_hunter import threat_hunter_service
    return threat_hunter_service.create_playbook(tenant_id=tenant_id, name=req.name, steps=req.steps)


@router.get("/hunts/stats")
def hunt_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.threat_hunter import threat_hunter_service
    return threat_hunter_service.get_stats(tenant_id)


# -- MITRE ATT&CK Mapper --

@router.post("/mitre/map")
def mitre_map(req: MitreMapRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.mitre_mapper import mitre_attack_mapper
    return mitre_attack_mapper.map_event(tenant_id=tenant_id, event_type=req.event_type, indicators=req.indicators)


@router.get("/mitre/coverage")
def mitre_coverage(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.mitre_mapper import mitre_attack_mapper
    return mitre_attack_mapper.get_coverage(tenant_id)


@router.get("/mitre/gaps")
def mitre_gaps(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.mitre_mapper import mitre_attack_mapper
    return mitre_attack_mapper.get_gaps(tenant_id)


@router.get("/mitre/kill-chain/{incident_id}")
def mitre_kill_chain(incident_id: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.mitre_mapper import mitre_attack_mapper
    return mitre_attack_mapper.get_kill_chain(tenant_id, incident_id)


@router.post("/mitre/techniques")
def mitre_add_technique(req: MitreTechniqueRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.mitre_mapper import mitre_attack_mapper
    return mitre_attack_mapper.add_technique(
        tenant_id=tenant_id,
        technique_id=req.technique_id,
        tactic=req.tactic,
        name=req.name,
        description=req.description,
    )


@router.get("/mitre/stats")
def mitre_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.mitre_mapper import mitre_attack_mapper
    return mitre_attack_mapper.get_stats(tenant_id)


# -- Adversary Simulation --

@router.post("/adversary/scenarios")
def create_scenario(req: ScenarioCreateRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.adversary_sim import adversary_sim_service
    return adversary_sim_service.create_scenario(
        tenant_id=tenant_id,
        name=req.name,
        attack_type=req.attack_type,
        mitre_techniques=req.mitre_techniques,
        config=req.config,
    )


@router.post("/adversary/scenarios/{scenario_id}/run")
def run_simulation(scenario_id: str):
    from cloud.services.adversary_sim import adversary_sim_service
    return adversary_sim_service.run_simulation(scenario_id)


@router.get("/adversary/scenarios")
def list_scenarios(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.adversary_sim import adversary_sim_service
    return adversary_sim_service.list_scenarios(tenant_id)


@router.get("/adversary/scenarios/{scenario_id}/results")
def simulation_results(scenario_id: str):
    from cloud.services.adversary_sim import adversary_sim_service
    return adversary_sim_service.get_simulation_results(scenario_id)


@router.post("/adversary/validate/{technique_id}")
def validate_defense(technique_id: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.adversary_sim import adversary_sim_service
    return adversary_sim_service.validate_defense(tenant_id, technique_id)


@router.get("/adversary/stats")
def adversary_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.adversary_sim import adversary_sim_service
    return adversary_sim_service.get_stats(tenant_id)


# -- Intel Correlation --

@router.post("/correlation/events")
def correlate_events(req: CorrelationRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.intel_correlation import intel_correlation_service
    return intel_correlation_service.correlate_events(
        tenant_id=tenant_id,
        event_ids=req.event_ids,
        correlation_type=req.correlation_type,
    )


@router.get("/correlation/patterns")
def discover_patterns(
    time_window_hours: int = 24,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    from cloud.services.intel_correlation import intel_correlation_service
    return intel_correlation_service.discover_patterns(tenant_id, time_window_hours)


@router.post("/correlation/campaigns")
def attribute_campaign(req: CampaignAttributionRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.intel_correlation import intel_correlation_service
    return intel_correlation_service.attribute_campaign(tenant_id, req.indicator_ids)


@router.get("/correlation")
def list_correlations(
    min_confidence: float = 0.5,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    from cloud.services.intel_correlation import intel_correlation_service
    return intel_correlation_service.get_correlations(tenant_id, min_confidence)


@router.get("/correlation/stats")
def correlation_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.intel_correlation import intel_correlation_service
    return intel_correlation_service.get_stats(tenant_id)


# -- Combined Prometheus Status --

@router.get("/status")
def prometheus_status(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.adversary_sim import adversary_sim_service
    from cloud.services.intel_correlation import intel_correlation_service
    from cloud.services.mitre_mapper import mitre_attack_mapper
    from cloud.services.threat_hunter import threat_hunter_service
    return {
        "threat_hunter": threat_hunter_service.get_stats(tenant_id),
        "mitre_mapper": mitre_attack_mapper.get_stats(tenant_id),
        "adversary_sim": adversary_sim_service.get_stats(tenant_id),
        "intel_correlation": intel_correlation_service.get_stats(tenant_id),
    }
