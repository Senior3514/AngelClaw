"""AngelClaw Cloud – Threat Hunting Service.

Provides a DSL-based query engine for threat hunting across events.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from cloud.db.models import EventRow, ThreatHuntQueryRow

logger = logging.getLogger("angelgrid.cloud.threat_hunting")


class ThreatHuntingService:
    """Executes threat hunting queries against the event store."""

    def execute_query(self, db: Session, tenant_id: str, query_dsl: dict) -> dict:
        """Execute a threat hunting query.

        query_dsl example:
        {
            "filters": {"category": "shell", "severity": ["high", "critical"]},
            "time_range_hours": 48,
            "group_by": "agent_id",
            "order_by": "timestamp",
            "limit": 100
        }
        """
        filters = query_dsl.get("filters", {})
        time_range = query_dsl.get("time_range_hours", 24)
        group_by = query_dsl.get("group_by")
        limit = min(query_dsl.get("limit", 100), 1000)

        cutoff = datetime.now(timezone.utc) - timedelta(hours=time_range)
        query = db.query(EventRow).filter(EventRow.timestamp >= cutoff)

        # Apply filters
        if "category" in filters:
            cat = filters["category"]
            if isinstance(cat, list):
                query = query.filter(EventRow.category.in_(cat))
            else:
                query = query.filter(EventRow.category == cat)

        if "severity" in filters:
            sev = filters["severity"]
            if isinstance(sev, list):
                query = query.filter(EventRow.severity.in_(sev))
            else:
                query = query.filter(EventRow.severity == sev)

        if "agent_id" in filters:
            query = query.filter(EventRow.agent_id == filters["agent_id"])

        if "type" in filters:
            etype = filters["type"]
            if isinstance(etype, list):
                query = query.filter(EventRow.type.in_(etype))
            else:
                query = query.filter(EventRow.type == etype)

        query = query.order_by(EventRow.timestamp.desc()).limit(limit)
        events = query.all()

        results = [
            {
                "id": e.id,
                "agent_id": e.agent_id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "category": e.category,
                "type": e.type,
                "severity": e.severity,
                "details": e.details,
                "source": e.source,
            }
            for e in events
        ]

        # Group if requested
        grouped = {}
        if group_by and group_by in ("agent_id", "category", "severity", "type"):
            for r in results:
                key = r.get(group_by, "unknown")
                grouped.setdefault(key, []).append(r)

        return {
            "total_matches": len(results),
            "events": results,
            "grouped": grouped if grouped else None,
            "query": query_dsl,
        }

    def save_query(
        self, db: Session, tenant_id: str, name: str, description: str, query_dsl: dict,
        created_by: str = "system",
    ) -> dict:
        """Save a threat hunting query for reuse."""
        query_id = str(uuid.uuid4())
        row = ThreatHuntQueryRow(
            id=query_id,
            tenant_id=tenant_id,
            name=name,
            description=description,
            query_dsl=query_dsl,
            created_by=created_by,
        )
        db.add(row)
        db.commit()
        return {"id": query_id, "name": name, "saved": True}

    def list_saved_queries(self, db: Session, tenant_id: str) -> list[dict]:
        """List saved hunting queries."""
        rows = (
            db.query(ThreatHuntQueryRow)
            .filter_by(tenant_id=tenant_id)
            .order_by(ThreatHuntQueryRow.created_at.desc())
            .all()
        )
        return [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "query_dsl": r.query_dsl,
                "last_result_count": r.last_result_count,
                "last_run_at": r.last_run_at.isoformat() if r.last_run_at else None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]

    def run_saved_query(self, db: Session, tenant_id: str, query_id: str) -> dict:
        """Execute a saved query and update its stats."""
        row = db.query(ThreatHuntQueryRow).filter_by(id=query_id, tenant_id=tenant_id).first()
        if not row:
            return {"error": "Query not found"}
        result = self.execute_query(db, tenant_id, row.query_dsl)
        row.last_result_count = result["total_matches"]
        row.last_run_at = datetime.now(timezone.utc)
        db.commit()
        return result


threat_hunting_service = ThreatHuntingService()
