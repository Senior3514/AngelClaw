"""AngelClaw Cloud – Audit Export API Routes."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Header, Query
from sqlalchemy.orm import Session

from cloud.db.session import get_db
from cloud.services.export import export_service

logger = logging.getLogger("angelgrid.cloud.api.export")

router = APIRouter(prefix="/api/v1/export", tags=["Export"])


@router.get("/events")
def export_events(
    format: str = Query("json", description="Export format: json or csv"),
    hours: int = Query(24, ge=1, le=8760),
    category: str | None = Query(None),
    severity: str | None = Query(None),
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Export events as JSON or CSV."""
    filters = {}
    if category:
        filters["category"] = category
    if severity:
        filters["severity"] = severity
    return export_service.export_events(db, hours=hours, format=format, filters=filters)


@router.get("/audit-trail")
def export_audit_trail(
    hours: int = Query(24, ge=1, le=8760),
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Export audit trail (guardian changes)."""
    return export_service.export_audit_trail(db, hours=hours)


@router.get("/alerts")
def export_alerts(
    hours: int = Query(24, ge=1, le=8760),
    severity: str | None = Query(None),
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Export guardian alerts."""
    return export_service.export_alerts(db, hours=hours, severity=severity)


@router.get("/policies")
def export_policies(
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Export all policy sets."""
    return export_service.export_policies(db)
