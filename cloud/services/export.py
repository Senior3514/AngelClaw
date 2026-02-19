"""AngelClaw Cloud -- Audit Export Service.

Exports events, alerts, policies, and audit trail data in JSON or CSV
format.  All exported data is redacted through the secret scanner to
ensure no credentials or tokens leak into export files.

SECURITY: Every exported record is passed through redact_dict before
serialization.  This is a non-negotiable requirement.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime
from typing import Any

from cloud.db.models import EventRow, GuardianAlertRow, PolicySetRow
from shared.security.secret_scanner import redact_dict

logger = logging.getLogger("angelgrid.cloud.services.export")


class AuditExportService:
    """Export security data in JSON or CSV with automatic secret redaction."""

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def export_events(
        self,
        db: Any,
        tenant_id: str,
        format: str = "json",
        start: datetime | None = None,
        end: datetime | None = None,
        severity: str | None = None,
        category: str | None = None,
        limit: int = 10000,
    ) -> tuple[str, str]:
        """Export events matching the given filters.

        Args:
            db: SQLAlchemy session.
            tenant_id: Tenant to filter by (via agent_id prefix or all).
            format: Output format -- 'json' or 'csv'.
            start: Earliest timestamp (inclusive).
            end: Latest timestamp (inclusive).
            severity: Filter by severity level.
            category: Filter by event category.
            limit: Maximum number of records to export.

        Returns:
            Tuple of (content_string, content_type).
        """
        query = db.query(EventRow)

        if start is not None:
            query = query.filter(EventRow.timestamp >= start)
        if end is not None:
            query = query.filter(EventRow.timestamp <= end)
        if severity is not None:
            query = query.filter(EventRow.severity == severity)
        if category is not None:
            query = query.filter(EventRow.category == category)

        rows = query.order_by(EventRow.timestamp.desc()).limit(limit).all()

        records = []
        for row in rows:
            details = redact_dict(row.details) if row.details else {}
            records.append({
                "id": row.id,
                "agent_id": row.agent_id,
                "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                "category": row.category,
                "type": row.type,
                "severity": row.severity,
                "details": details,
                "source": row.source,
            })

        logger.info(
            "Exported %d events for tenant '%s' (format=%s)",
            len(records),
            tenant_id,
            format,
        )
        return self._serialize(records, format)

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def export_alerts(
        self,
        db: Any,
        tenant_id: str,
        format: str = "json",
        start: datetime | None = None,
        end: datetime | None = None,
        severity: str | None = None,
        limit: int = 5000,
    ) -> tuple[str, str]:
        """Export guardian alerts matching the given filters.

        Returns:
            Tuple of (content_string, content_type).
        """
        query = db.query(GuardianAlertRow).filter(
            GuardianAlertRow.tenant_id == tenant_id,
        )

        if start is not None:
            query = query.filter(GuardianAlertRow.created_at >= start)
        if end is not None:
            query = query.filter(GuardianAlertRow.created_at <= end)
        if severity is not None:
            query = query.filter(GuardianAlertRow.severity == severity)

        rows = query.order_by(GuardianAlertRow.created_at.desc()).limit(limit).all()

        records = []
        for row in rows:
            details = redact_dict(row.details) if row.details else {}
            records.append({
                "id": row.id,
                "tenant_id": row.tenant_id,
                "alert_type": row.alert_type,
                "title": row.title,
                "severity": row.severity,
                "details": details,
                "related_event_ids": row.related_event_ids or [],
                "related_agent_ids": row.related_agent_ids or [],
                "created_at": row.created_at.isoformat() if row.created_at else None,
            })

        logger.info(
            "Exported %d alerts for tenant '%s' (format=%s)",
            len(records),
            tenant_id,
            format,
        )
        return self._serialize(records, format)

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def export_policies(
        self,
        db: Any,
        format: str = "json",
    ) -> tuple[str, str]:
        """Export all policy sets.

        Returns:
            Tuple of (content_string, content_type).
        """
        rows = db.query(PolicySetRow).order_by(PolicySetRow.created_at.desc()).all()

        records = []
        for row in rows:
            rules = row.rules_json or []
            # Redact each rule dict individually
            redacted_rules = [redact_dict(r) if isinstance(r, dict) else r for r in rules]
            records.append({
                "id": row.id,
                "name": row.name,
                "description": row.description or "",
                "rules_json": redacted_rules,
                "version_hash": row.version_hash,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            })

        logger.info("Exported %d policy sets (format=%s)", len(records), format)
        return self._serialize(records, format)

    # ------------------------------------------------------------------
    # Audit Trail
    # ------------------------------------------------------------------

    def export_audit_trail(
        self,
        db: Any,
        tenant_id: str,
        format: str = "json",
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 5000,
    ) -> tuple[str, str]:
        """Export the action audit trail for a tenant.

        Returns:
            Tuple of (content_string, content_type).
        """
        from cloud.angelclaw.actions import ActionLogRow

        query = db.query(ActionLogRow).filter(
            ActionLogRow.tenant_id == tenant_id,
        )

        if start is not None:
            query = query.filter(ActionLogRow.created_at >= start)
        if end is not None:
            query = query.filter(ActionLogRow.created_at <= end)

        rows = query.order_by(ActionLogRow.created_at.desc()).limit(limit).all()

        records = []
        for row in rows:
            before = redact_dict(row.before_state) if row.before_state else {}
            after = redact_dict(row.after_state) if row.after_state else {}
            params = redact_dict(row.params) if row.params else {}
            records.append({
                "id": row.id,
                "tenant_id": row.tenant_id,
                "action_type": row.action_type,
                "description": row.description or "",
                "params": params,
                "triggered_by": row.triggered_by,
                "trigger_context": row.trigger_context or "",
                "status": row.status,
                "before_state": before,
                "after_state": after,
                "error": row.error,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "applied_at": row.applied_at.isoformat() if row.applied_at else None,
            })

        logger.info(
            "Exported %d audit trail entries for tenant '%s' (format=%s)",
            len(records),
            tenant_id,
            format,
        )
        return self._serialize(records, format)

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------

    def _serialize(self, records: list[dict], format: str) -> tuple[str, str]:
        """Serialize a list of record dicts to the requested format.

        Returns:
            Tuple of (content_string, content_type).
        """
        if format == "csv":
            return self._to_csv(records), "text/csv"
        return self._to_json(records), "application/json"

    @staticmethod
    def _to_json(records: list[dict]) -> str:
        """Serialize records to a pretty-printed JSON string."""
        return json.dumps(records, indent=2, default=str, ensure_ascii=False)

    @staticmethod
    def _to_csv(records: list[dict]) -> str:
        """Serialize records to CSV.

        Nested dicts/lists are JSON-encoded within their cells.
        """
        if not records:
            return ""

        # Collect all unique keys across records for header row
        fieldnames: list[str] = []
        seen: set[str] = set()
        for rec in records:
            for key in rec:
                if key not in seen:
                    fieldnames.append(key)
                    seen.add(key)

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for rec in records:
            # Convert non-scalar values to JSON strings for CSV cells
            flat = {}
            for k, v in rec.items():
                if isinstance(v, (dict, list)):
                    flat[k] = json.dumps(v, default=str)
                else:
                    flat[k] = v
            writer.writerow(flat)

        return output.getvalue()


# ---------------------------------------------------------------------------
# Module singleton
# ---------------------------------------------------------------------------

export_service = AuditExportService()
