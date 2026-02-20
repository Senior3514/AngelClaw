"""Tests for V7.3.0 Sentinel Eye: Advanced Observability & Log Intelligence."""

from __future__ import annotations

from cloud.services.distributed_tracing import DistributedTracingService
from cloud.services.log_analytics import LogAnalyticsService

TENANT = "test-tenant"


class TestLogAnalyticsService:
    """LogAnalyticsService tests."""

    def test_ingest_logs(self):
        svc = LogAnalyticsService()
        result = svc.ingest_logs(TENANT, [{"level": "error", "message": "test"}])
        assert "id" in result
        assert result["tenant_id"] == TENANT

    def test_detect_anomalies_empty(self):
        svc = LogAnalyticsService()
        result = svc.detect_anomalies(TENANT)
        assert isinstance(result, list)

    def test_search_logs_empty(self):
        svc = LogAnalyticsService()
        result = svc.search_logs(TENANT, "error")
        assert isinstance(result, list)

    def test_get_clusters_empty(self):
        svc = LogAnalyticsService()
        result = svc.get_clusters(TENANT)
        assert isinstance(result, list)

    def test_status(self):
        svc = LogAnalyticsService()
        result = svc.status(TENANT)
        assert result["tenant_id"] == TENANT
        assert result["service"] == "LogAnalyticsService"
        assert result["version"] == "7.3.0"


class TestDistributedTracingService:
    """DistributedTracingService tests."""

    def test_create_span(self):
        svc = DistributedTracingService()
        result = svc.create_span(TENANT, "trace-1", "api-gateway", "auth-check")
        assert "id" in result
        assert result["tenant_id"] == TENANT

    def test_create_span_creates_unique_ids(self):
        svc = DistributedTracingService()
        r1 = svc.create_span(TENANT, "t1", "svc-a", "op-1")
        r2 = svc.create_span(TENANT, "t2", "svc-b", "op-2")
        assert r1["id"] != r2["id"]

    def test_get_trace(self):
        svc = DistributedTracingService()
        result = svc.get_trace(TENANT, "trace-1")
        assert isinstance(result, (dict, list))

    def test_correlate_events(self):
        svc = DistributedTracingService()
        result = svc.correlate_events(TENANT, ["evt-1", "evt-2"])
        assert isinstance(result, (dict, list))

    def test_get_service_map(self):
        svc = DistributedTracingService()
        result = svc.get_service_map(TENANT)
        assert isinstance(result, (dict, list))

    def test_status(self):
        svc = DistributedTracingService()
        result = svc.status(TENANT)
        assert result["tenant_id"] == TENANT
        assert result["service"] == "DistributedTracingService"
        assert result["version"] == "7.3.0"
