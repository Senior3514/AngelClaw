"""AngelClaw Cloud – Backup & Restore API Routes."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from cloud.db.session import get_db
from cloud.services.backup import backup_service

logger = logging.getLogger("angelgrid.cloud.api.backup")

router = APIRouter(prefix="/api/v1/backups", tags=["Backup & Restore"])


@router.post("")
def create_backup(
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Create a system backup."""
    return backup_service.create_backup(db, tenant_id)


@router.get("")
def list_backups(
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """List all backups."""
    return backup_service.list_backups(db, tenant_id)


@router.post("/{backup_id}/restore")
def restore_backup(
    backup_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Restore from a backup."""
    result = backup_service.restore_backup(db, backup_id, tenant_id)
    if not result.get("restored"):
        raise HTTPException(status_code=404, detail=result.get("error", "Restore failed"))
    return result


@router.delete("/{backup_id}")
def delete_backup(
    backup_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID"),
):
    """Delete a backup."""
    if not backup_service.delete_backup(db, backup_id, tenant_id):
        raise HTTPException(status_code=404, detail="Backup not found")
    return {"deleted": True}
