"""Tests for V2.5 Backup & Restore."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from cloud.db.models import BackupRecordRow, EventRow
from cloud.services.backup import BackupService


@pytest.fixture
def backup_svc(tmp_path):
    return BackupService(backup_dir=tmp_path)


class TestBackupService:
    def test_create_backup(self, db, backup_svc):
        result = backup_svc.create_backup(db, "dev-tenant")
        assert "id" in result
        assert "filename" in result
        assert result["size_bytes"] > 0

    def test_list_backups(self, db, backup_svc):
        backup_svc.create_backup(db, "dev-tenant")
        backups = backup_svc.list_backups(db, "dev-tenant")
        assert len(backups) >= 1

    def test_restore_backup(self, db, backup_svc):
        # Seed some data
        db.add(
            EventRow(
                id=str(uuid.uuid4()),
                agent_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                category="shell",
                type="shell.exec",
                severity="low",
            )
        )
        db.commit()
        backup = backup_svc.create_backup(db, "dev-tenant")
        result = backup_svc.restore_backup(db, backup["id"], "dev-tenant")
        assert result.get("restored") is True

    def test_delete_backup(self, db, backup_svc):
        backup = backup_svc.create_backup(db, "dev-tenant")
        deleted = backup_svc.delete_backup(db, backup["id"], "dev-tenant")
        assert deleted is True

    def test_restore_nonexistent(self, db, backup_svc):
        result = backup_svc.restore_backup(db, "fake-id", "dev-tenant")
        assert result.get("restored") is False

    def test_delete_nonexistent(self, db, backup_svc):
        result = backup_svc.delete_backup(db, "fake-id", "dev-tenant")
        assert result is False

    def test_backup_has_tables(self, db, backup_svc):
        result = backup_svc.create_backup(db, "dev-tenant")
        assert "tables_included" in result
        assert len(result["tables_included"]) > 0

    def test_backup_record_in_db(self, db, backup_svc):
        backup_svc.create_backup(db, "dev-tenant")
        record = db.query(BackupRecordRow).first()
        assert record is not None
        assert record.status == "completed"

    def test_multiple_backups(self, db, backup_svc):
        backup_svc.create_backup(db, "dev-tenant")
        backup_svc.create_backup(db, "dev-tenant")
        backups = backup_svc.list_backups(db, "dev-tenant")
        assert len(backups) >= 2
