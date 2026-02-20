"""AngelClaw V4.1 — Prophecy: ML & Behavioral Analysis API routes."""

from __future__ import annotations

from fastapi import APIRouter, Header
from pydantic import BaseModel

from cloud.services.attack_path import attack_path_engine
from cloud.services.behavior_profile import behavior_profile_service
from cloud.services.ml_anomaly import ml_anomaly_engine
from cloud.services.risk_forecast import risk_forecast_engine

router = APIRouter(prefix="/api/v1/ml", tags=["ML & Predictive Analysis"])


class BaselineUpdateRequest(BaseModel):
    entity_id: str
    metrics: dict[str, float]


class AnomalyDetectRequest(BaseModel):
    entity_id: str
    current_metrics: dict[str, float]
    threshold: float = 2.0


class ProfileRequest(BaseModel):
    entity_type: str = "agent"
    entity_id: str


class ProfileUpdateRequest(BaseModel):
    entity_id: str
    events: list[dict]


class DeviationCheckRequest(BaseModel):
    entity_id: str
    current_metrics: dict


class AttackPathRequest(BaseModel):
    topology_links: list[dict]
    asset_risks: dict[str, int] = {}
    critical_assets: list[str] = []


class ForecastRequest(BaseModel):
    horizons: list[int] = [1, 6, 24]


# -- Anomaly Detection endpoints --


@router.post("/anomaly/baseline")
def update_baseline(req: BaselineUpdateRequest):
    return ml_anomaly_engine.update_baseline(req.entity_id, req.metrics)


@router.post("/anomaly/detect")
def detect_anomalies(req: AnomalyDetectRequest):
    return ml_anomaly_engine.detect_anomalies(req.entity_id, req.current_metrics, req.threshold)


@router.get("/anomaly/baseline/{entity_id}")
def get_baseline(entity_id: str):
    result = ml_anomaly_engine.get_baseline(entity_id)
    return result or {"error": "No baseline found"}


@router.get("/anomaly/detections")
def get_detections(entity_id: str | None = None, limit: int = 50):
    return ml_anomaly_engine.get_recent_detections(entity_id, limit)


@router.get("/anomaly/stats")
def anomaly_stats():
    return ml_anomaly_engine.get_stats()


# -- Behavior Profile endpoints --


@router.post("/profiles")
def create_profile(
    req: ProfileRequest,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return behavior_profile_service.get_or_create_profile(tenant_id, req.entity_type, req.entity_id)


@router.post("/profiles/update")
def update_profile(req: ProfileUpdateRequest):
    result = behavior_profile_service.update_profile(req.entity_id, req.events)
    return result or {"error": "Profile not found"}


@router.post("/profiles/check-deviation")
def check_deviation(req: DeviationCheckRequest):
    return behavior_profile_service.check_deviation(req.entity_id, req.current_metrics)


@router.get("/profiles")
def list_profiles(
    status: str | None = None,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return behavior_profile_service.list_profiles(tenant_id, status)


@router.get("/profiles/stats")
def profile_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return behavior_profile_service.get_stats(tenant_id)


# -- Attack Path endpoints --


@router.post("/attack-paths/compute")
def compute_attack_paths(
    req: AttackPathRequest,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return attack_path_engine.compute_paths(
        tenant_id,
        req.topology_links,
        req.asset_risks,
        req.critical_assets,
    )


@router.get("/attack-paths")
def list_attack_paths(
    min_risk: int = 0,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return attack_path_engine.get_paths(tenant_id, min_risk)


@router.put("/attack-paths/{path_id}/mitigate")
def mitigate_path(path_id: str):
    result = attack_path_engine.mitigate_path(path_id)
    return result or {"error": "Path not found"}


@router.get("/attack-paths/stats")
def attack_path_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return attack_path_engine.get_stats(tenant_id)


# -- Risk Forecast endpoints --


@router.post("/forecasts/generate")
def generate_forecasts(
    req: ForecastRequest,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return risk_forecast_engine.generate_forecasts(tenant_id, req.horizons)


@router.get("/forecasts")
def list_forecasts(
    forecast_type: str | None = None,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return risk_forecast_engine.get_forecasts(tenant_id, forecast_type)


@router.get("/forecasts/accuracy")
def forecast_accuracy(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return risk_forecast_engine.get_accuracy_report(tenant_id)
