"""AngelClaw V3.5 — Sentinel: Threat Intelligence API routes."""

from __future__ import annotations

from fastapi import APIRouter, Header
from pydantic import BaseModel

from cloud.services.ioc_engine import ioc_engine
from cloud.services.reputation import reputation_service
from cloud.services.threat_intel import threat_intel_service

router = APIRouter(prefix="/api/v1/intel", tags=["Threat Intelligence"])


class FeedCreateRequest(BaseModel):
    name: str
    feed_type: str = "stix"
    url: str | None = None
    poll_interval_minutes: int = 60
    config: dict = {}


class IOCIngestRequest(BaseModel):
    feed_id: str
    iocs: list[dict]


class IOCSearchRequest(BaseModel):
    ioc_type: str | None = None
    value: str | None = None
    severity: str | None = None
    feed_id: str | None = None
    limit: int = 100


class ReputationLookupRequest(BaseModel):
    entity_type: str  # ip, domain, hash, email
    entity_value: str


class ReputationBulkRequest(BaseModel):
    entities: list[dict]


class ReputationUpdateRequest(BaseModel):
    entity_type: str
    entity_value: str
    score_delta: int
    source: str = "manual"
    category: str | None = None


# -- Feed endpoints --

@router.post("/feeds")
def create_feed(
    req: FeedCreateRequest,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return threat_intel_service.create_feed(
        tenant_id=tenant_id,
        name=req.name,
        feed_type=req.feed_type,
        url=req.url,
        poll_interval_minutes=req.poll_interval_minutes,
        config=req.config,
    )


@router.get("/feeds")
def list_feeds(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return threat_intel_service.list_feeds(tenant_id)


@router.get("/feeds/{feed_id}")
def get_feed(feed_id: str):
    feed = threat_intel_service.get_feed(feed_id)
    if not feed:
        return {"error": "Feed not found"}
    return feed


@router.put("/feeds/{feed_id}/toggle")
def toggle_feed(feed_id: str, enabled: bool = True):
    result = threat_intel_service.toggle_feed(feed_id, enabled)
    if not result:
        return {"error": "Feed not found"}
    return result


@router.delete("/feeds/{feed_id}")
def delete_feed(feed_id: str):
    ok = threat_intel_service.delete_feed(feed_id)
    return {"deleted": ok}


# -- IOC endpoints --

@router.post("/iocs/ingest")
def ingest_iocs(
    req: IOCIngestRequest,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return threat_intel_service.ingest_iocs(tenant_id, req.feed_id, req.iocs)


@router.post("/iocs/search")
def search_iocs(
    req: IOCSearchRequest,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return threat_intel_service.search_iocs(
        tenant_id,
        ioc_type=req.ioc_type,
        value=req.value,
        severity=req.severity,
        feed_id=req.feed_id,
        limit=req.limit,
    )


@router.get("/iocs/matches")
def get_ioc_matches(
    limit: int = 100,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return ioc_engine.get_matches(tenant_id, limit=limit)


@router.put("/iocs/matches/{match_id}/acknowledge")
def acknowledge_match(match_id: str):
    ok = ioc_engine.acknowledge_match(match_id)
    return {"acknowledged": ok}


# -- Reputation endpoints --

@router.post("/reputation/lookup")
def reputation_lookup(
    req: ReputationLookupRequest,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return reputation_service.lookup(tenant_id, req.entity_type, req.entity_value)


@router.post("/reputation/bulk")
def reputation_bulk(
    req: ReputationBulkRequest,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return reputation_service.bulk_lookup(tenant_id, req.entities)


@router.post("/reputation/update")
def reputation_update(
    req: ReputationUpdateRequest,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return reputation_service.update_score(
        tenant_id, req.entity_type, req.entity_value,
        req.score_delta, req.source, req.category,
    )


@router.get("/reputation/worst")
def reputation_worst(
    limit: int = 20,
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    return reputation_service.get_worst(tenant_id, limit=limit)


# -- Stats --

@router.get("/stats")
def intel_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    return {
        "threat_intel": threat_intel_service.get_stats(tenant_id),
        "ioc_matches": ioc_engine.get_stats(tenant_id),
        "reputation": reputation_service.get_stats(tenant_id),
    }
