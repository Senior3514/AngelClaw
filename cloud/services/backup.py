"""AngelClaw Cloud – Backup & Restore Service.

Creates JSON archives of all tables, validates, and restores.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from cloud.db.models import (
    AgentNodeRow,
    BackupRecordRow,
    EventRow,
    GuardianAlertRow,
    GuardianChangeRow,
    GuardianReportRow,
    IncidentRow,
    PolicySetRow,
)

logger = logging.getLogger("angelgrid.cloud.backup")

_BACKUP_DIR = Path("/tmp/angelclaw_backups")

# Tables included in backups
_BACKUP_TABLES = {
    "agent_nodes": AgentNodeRow,
    "events": EventRow,
    "incidents": IncidentRow,
    "policy_sets": PolicySetRow,
    "guardian_reports": GuardianReportRow,
    "guardian_alerts": GuardianAlertRow,
    "guardian_changes": GuardianChangeRow,
}


class BackupService:
    """Manages system backups and restores."""

    def __init__(self, backup_dir: Path | None = None) -> None:
        self._backup_dir = backup_dir or _BACKUP_DIR
        self._backup_dir.mkdir(parents=True, exist_ok=True)

    def create_backup(
        self, db: Session, tenant_id: str, *, created_by: str = "system"
    ) -> dict:
        """Create a JSON backup of all tables."""
        backup_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc)
        filename = f"backup_{timestamp.strftime('%Y%m%d_%H%M%S')}_{backup_id[:8]}.json"

        data: dict[str, list] = {}
        total_rows = 0

        for table_name, model_cls in _BACKUP_TABLES.items():
            rows = db.query(model_cls).all()
            table_data = []
            for row in rows:
                row_dict = {}
                for col in row.__table__.columns:
                    val = getattr(row, col.name)
                    if isinstance(val, datetime):
                        val = val.isoformat()
                    row_dict[col.name] = val
                table_data.append(row_dict)
            data[table_name] = table_data
            total_rows += len(table_data)

        backup_content = {
            "backup_id": backup_id,
            "created_at": timestamp.isoformat(),
            "tenant_id": tenant_id,
            "tables": data,
            "table_counts": {k: len(v) for k, v in data.items()},
        }

        filepath = self._backup_dir / filename
        filepath.write_text(json.dumps(backup_content, indent=2, default=str), encoding="utf-8")
        size_bytes = filepath.stat().st_size

        record = BackupRecordRow(
            id=backup_id,
            tenant_id=tenant_id,
            filename=filename,
            size_bytes=size_bytes,
            tables_included=list(data.keys()),
            created_by=created_by,
            status="completed",
        )
        db.add(record)
        db.commit()

        return {
            "id": backup_id,
            "filename": filename,
            "size_bytes": size_bytes,
            "tables_included": list(data.keys()),
            "total_rows": total_rows,
            "created_at": timestamp.isoformat(),
        }

    def list_backups(self, db: Session, tenant_id: str) -> list[dict]:
        """List all backups for a tenant."""
        rows = (
            db.query(BackupRecordRow)
            .filter_by(tenant_id=tenant_id)
            .order_by(BackupRecordRow.created_at.desc())
            .all()
        )
        return [
            {
                "id": r.id,
                "filename": r.filename,
                "size_bytes": r.size_bytes,
                "tables_included": r.tables_included,
                "created_by": r.created_by,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "status": r.status,
            }
            for r in rows
        ]

    def restore_backup(self, db: Session, backup_id: str, tenant_id: str) -> dict:
        """Restore from a backup file."""
        record = db.query(BackupRecordRow).filter_by(id=backup_id, tenant_id=tenant_id).first()
        if not record:
            return {"error": "Backup not found", "restored": False}

        filepath = self._backup_dir / record.filename
        if not filepath.exists():
            return {"error": "Backup file missing", "restored": False}

        content = json.loads(filepath.read_text(encoding="utf-8"))
        tables = content.get("tables", {})
        restored_counts: dict[str, int] = {}

        for table_name, rows_data in tables.items():
            model_cls = _BACKUP_TABLES.get(table_name)
            if not model_cls:
                continue
            for row_data in rows_data:
                existing = db.query(model_cls).filter_by(id=row_data.get("id")).first()
                if not existing:
                    obj = model_cls(**{k: v for k, v in row_data.items() if hasattr(model_cls, k)})
                    db.add(obj)
            restored_counts[table_name] = len(rows_data)

        db.commit()
        return {
            "restored": True,
            "backup_id": backup_id,
            "tables_restored": restored_counts,
            "total_rows": sum(restored_counts.values()),
        }

    def delete_backup(self, db: Session, backup_id: str, tenant_id: str) -> bool:
        """Delete a backup record and file."""
        record = db.query(BackupRecordRow).filter_by(id=backup_id, tenant_id=tenant_id).first()
        if not record:
            return False
        filepath = self._backup_dir / record.filename
        if filepath.exists():
            filepath.unlink()
        db.delete(record)
        db.commit()
        return True


backup_service = BackupService()
