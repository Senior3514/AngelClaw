"""AngelClaw Cloud – Enhanced Metrics V2 API Routes."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, Query
from sqlalchemy.orm import Session

from cloud.db.models import EventRow, GuardianAlertRow, IncidentRow
from cloud.db.session import get_db

logger = logging.getLogger("angelgrid.cloud.api.metrics_v2")

router = APIRouter(prefix="/api/v1/metrics/v2", tags=["Metrics V2"])


@router.get("/summary")
def metrics_summary(
    hours: int = Query(24, ge=1, le=720),
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Enhanced metrics summary with trends."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    events = db.query(EventRow).filter(EventRow.timestamp >= cutoff).all()
    alerts = db.query(GuardianAlertRow).filter(GuardianAlertRow.created_at >= cutoff).all()
    incidents = db.query(IncidentRow).filter(IncidentRow.created_at >= cutoff).all()

    # Events by category
    by_category: dict[str, int] = {}
    for e in events:
        by_category[e.category] = by_category.get(e.category, 0) + 1

    # Events by severity
    by_severity: dict[str, int] = {}
    for e in events:
        by_severity[e.severity] = by_severity.get(e.severity, 0) + 1

    # Alerts by type
    alerts_by_type: dict[str, int] = {}
    for a in alerts:
        alerts_by_type[a.alert_type] = alerts_by_type.get(a.alert_type, 0) + 1

    # Hourly event rate
    hourly_counts: dict[str, int] = {}
    for e in events:
        if e.timestamp:
            hour_key = e.timestamp.strftime("%Y-%m-%d %H:00")
            hourly_counts[hour_key] = hourly_counts.get(hour_key, 0) + 1

    return {
        "period_hours": hours,
        "total_events": len(events),
        "total_alerts": len(alerts),
        "total_incidents": len(incidents),
        "events_by_category": by_category,
        "events_by_severity": by_severity,
        "alerts_by_type": alerts_by_type,
        "hourly_event_rate": hourly_counts,
        "avg_events_per_hour": round(len(events) / max(hours, 1), 2),
    }


@router.get("/trends")
def metrics_trends(
    hours: int = Query(24, ge=1, le=720),
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Get trend analysis from predictive engine."""
    from cloud.services.predictive import predict_trends

    return predict_trends(db, lookback_hours=hours)


@router.get("/predictions")
def metrics_predictions(
    hours: int = Query(24, ge=1, le=720),
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Get current threat predictions."""
    from cloud.services.predictive import predict_threat_vectors

    preds = predict_threat_vectors(db, lookback_hours=hours)
    return [
        {
            "vector_name": p.vector_name,
            "confidence": p.confidence,
            "rationale": p.rationale,
            "contributing_categories": p.contributing_categories,
            "event_count": p.event_count,
        }
        for p in preds
    ]
