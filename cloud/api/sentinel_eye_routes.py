"""AngelClaw V7.3.0 — Sentinel Eye: Advanced Observability & Log Intelligence API routes."""

from __future__ import annotations

from fastapi import APIRouter, Header

router = APIRouter(prefix="/api/v1/sentinel_eye", tags=["Sentinel Eye"])


@router.post("/ingest-logs")
def sentinel_eye_ingest_logs(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), req: dict = {}):
    from cloud.services.log_analytics import logAnalyticsService_service
    return logAnalyticsService_service.ingest_logs(tenant_id, req)

@router.post("/detect-anomalies")
def sentinel_eye_detect_anomalies(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), time_window_minutes: int = 60):
    from cloud.services.log_analytics import logAnalyticsService_service
    return logAnalyticsService_service.detect_anomalies(tenant_id, time_window_minutes)

@router.post("/search-logs")
def sentinel_eye_search_logs(query: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), limit: int = 50):
    from cloud.services.log_analytics import logAnalyticsService_service
    return logAnalyticsService_service.search_logs(tenant_id, query, limit)

@router.get("/get-clusters")
def sentinel_eye_get_clusters(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.log_analytics import logAnalyticsService_service
    return logAnalyticsService_service.get_clusters(tenant_id)

@router.get("/status")
def sentinel_eye_status(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.log_analytics import logAnalyticsService_service
    return logAnalyticsService_service.status(tenant_id)

@router.post("/create-span")
def sentinel_eye_create_span(trace_id: str, service: str, operation: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"), parent_span_id: str | None = None):
    from cloud.services.distributed_tracing import distributedTracingService_service
    return distributedTracingService_service.create_span(tenant_id, trace_id, service, operation, parent_span_id)

@router.get("/get-trace")
def sentinel_eye_get_trace(trace_id: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.distributed_tracing import distributedTracingService_service
    return distributedTracingService_service.get_trace(tenant_id, trace_id)

@router.post("/correlate-events")
def sentinel_eye_correlate_events(event_ids: list[str], tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.distributed_tracing import distributedTracingService_service
    return distributedTracingService_service.correlate_events(tenant_id, event_ids)

@router.get("/get-service-map")
def sentinel_eye_get_service_map(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.distributed_tracing import distributedTracingService_service
    return distributedTracingService_service.get_service_map(tenant_id)

@router.get("/status")
def sentinel_eye_status_2(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.distributed_tracing import distributedTracingService_service
    return distributedTracingService_service.status(tenant_id)
