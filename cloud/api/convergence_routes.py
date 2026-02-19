"""AngelClaw V5.5 — Convergence: Real-Time Defense Fabric API routes."""

from __future__ import annotations

from fastapi import APIRouter, Header
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/convergence", tags=["Convergence"])


class EventIngestRequest(BaseModel):
    event_type: str
    severity: str = "medium"
    source: str = ""
    details: dict = {}


class HaloScoreDimensions(BaseModel):
    threat_posture: float = 80.0
    compliance: float = 85.0
    vulnerability: float = 75.0
    incident_response: float = 90.0
    endpoint_health: float = 95.0
    policy_coverage: float = 88.0


class FleetNodeRegisterRequest(BaseModel):
    hostname: str
    os_type: str
    version: str = "7.0.0"
    tags: list[str] = []


class FleetHealthUpdateRequest(BaseModel):
    node_id: str
    health_pct: float
    metrics: dict = {}


class FleetCommandRequest(BaseModel):
    node_ids: list[str]
    command: str
    params: dict = {}


# -- Real-Time Engine --

@router.post("/realtime/ingest")
def realtime_ingest(req: EventIngestRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.realtime_engine import realtime_engine_service
    return realtime_engine_service.ingest_event(
        tenant_id=tenant_id,
        event_type=req.event_type,
        severity=req.severity,
        source=req.source,
        details=req.details,
    )


@router.get("/realtime/metrics")
def realtime_metrics(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.realtime_engine import realtime_engine_service
    return realtime_engine_service.get_live_metrics(tenant_id)


@router.get("/realtime/window/{window}")
def realtime_window(window: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.realtime_engine import realtime_engine_service
    return realtime_engine_service.get_sliding_window(tenant_id, window)


@router.get("/realtime/stats")
def realtime_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.realtime_engine import realtime_engine_service
    return realtime_engine_service.get_stats(tenant_id)


# -- Halo Score Engine --

@router.post("/halo/compute")
def halo_compute(req: HaloScoreDimensions, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.halo_engine import halo_score_engine
    return halo_score_engine.compute_score(
        tenant_id=tenant_id,
        dimensions=req.model_dump(),
    )


@router.get("/halo/current")
def halo_current(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.halo_engine import halo_score_engine
    return halo_score_engine.get_current_score(tenant_id)


@router.get("/halo/history")
def halo_history(limit: int = 50, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.halo_engine import halo_score_engine
    return halo_score_engine.get_score_history(tenant_id, limit)


@router.get("/halo/breakdown")
def halo_breakdown(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.halo_engine import halo_score_engine
    return halo_score_engine.get_dimension_breakdown(tenant_id)


@router.get("/halo/stats")
def halo_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.halo_engine import halo_score_engine
    return halo_score_engine.get_stats(tenant_id)


# -- Fleet Orchestrator --

@router.post("/fleet/nodes")
def fleet_register(req: FleetNodeRegisterRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.fleet_orchestrator import fleet_orchestrator_service
    return fleet_orchestrator_service.register_node(
        tenant_id=tenant_id,
        hostname=req.hostname,
        os_type=req.os_type,
        version=req.version,
        tags=req.tags,
    )


@router.get("/fleet/nodes")
def fleet_list(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.fleet_orchestrator import fleet_orchestrator_service
    return fleet_orchestrator_service.get_fleet_status(tenant_id)


@router.put("/fleet/health")
def fleet_health(req: FleetHealthUpdateRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.fleet_orchestrator import fleet_orchestrator_service
    return fleet_orchestrator_service.update_node_health(
        tenant_id=tenant_id,
        node_id=req.node_id,
        health_pct=req.health_pct,
        metrics=req.metrics,
    )


@router.get("/fleet/os-distribution")
def fleet_os(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.fleet_orchestrator import fleet_orchestrator_service
    return fleet_orchestrator_service.get_os_distribution(tenant_id)


@router.post("/fleet/dispatch")
def fleet_dispatch(req: FleetCommandRequest, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.fleet_orchestrator import fleet_orchestrator_service
    return fleet_orchestrator_service.dispatch_command(
        tenant_id=tenant_id,
        node_ids=req.node_ids,
        command=req.command,
        params=req.params,
    )


@router.get("/fleet/stats")
def fleet_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.fleet_orchestrator import fleet_orchestrator_service
    return fleet_orchestrator_service.get_stats(tenant_id)


# -- Dashboard Aggregator --

@router.get("/dashboard/command-center")
def dashboard_command_center(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.dashboard_aggregator import dashboard_aggregator_service
    return dashboard_aggregator_service.get_command_center(tenant_id)


@router.get("/dashboard/wingspan")
def dashboard_wingspan(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.dashboard_aggregator import dashboard_aggregator_service
    return dashboard_aggregator_service.get_wingspan_stats(tenant_id)


@router.get("/dashboard/threats")
def dashboard_threats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.dashboard_aggregator import dashboard_aggregator_service
    return dashboard_aggregator_service.get_threat_landscape(tenant_id)


@router.get("/dashboard/predictive")
def dashboard_predictive(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.dashboard_aggregator import dashboard_aggregator_service
    return dashboard_aggregator_service.get_predictive_stats(tenant_id)


# -- Combined Convergence Status --

@router.get("/status")
def convergence_status(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.dashboard_aggregator import dashboard_aggregator_service
    from cloud.services.fleet_orchestrator import fleet_orchestrator_service
    from cloud.services.halo_engine import halo_score_engine
    from cloud.services.realtime_engine import realtime_engine_service
    return {
        "realtime": realtime_engine_service.get_stats(tenant_id),
        "halo_score": halo_score_engine.get_stats(tenant_id),
        "fleet": fleet_orchestrator_service.get_stats(tenant_id),
        "dashboard": dashboard_aggregator_service.get_stats(tenant_id),
    }
