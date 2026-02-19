"""AngelClaw Cloud -- API Key Service.

Provides service-to-service API key authentication with SHA-256 hashing,
scoped permissions, expiration, rotation, and revocation.

SECURITY RULES:
  - Raw API keys are returned ONLY once at creation time.
  - Keys are stored as SHA-256 hashes; the original value is never persisted.
  - Revoked or expired keys are rejected immediately on validation.
  - Key prefixes (first 12 chars) are stored for identification only.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any

from cloud.db.models import ApiKeyRow

logger = logging.getLogger("angelgrid.cloud.auth.api_keys")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_KEY_PREFIX = "aclk_"
_KEY_LENGTH = 40  # random hex characters after the prefix


class ApiKeyService:
    """Manage service-to-service API keys with hashed storage."""

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create_key(
        self,
        db: Any,
        tenant_id: str,
        name: str,
        scopes: list[str],
        created_by: str,
        expires_at: datetime | None = None,
    ) -> dict:
        """Generate a new API key, hash it, and persist the record.

        The raw key is returned **only once** in the response dict.
        Callers must present it to the end-user immediately; it cannot
        be recovered later.

        Returns:
            dict with keys: key_id, raw_key, prefix, name, scopes.
        """
        raw_key = _KEY_PREFIX + secrets.token_hex(_KEY_LENGTH // 2)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        key_prefix = raw_key[:12]
        key_id = str(uuid.uuid4())

        row = ApiKeyRow(
            id=key_id,
            tenant_id=tenant_id,
            name=name,
            key_hash=key_hash,
            key_prefix=key_prefix,
            scopes=scopes,
            created_by=created_by,
            expires_at=expires_at,
            revoked="false",
        )
        db.add(row)
        try:
            db.commit()
            db.refresh(row)
        except Exception:
            db.rollback()
            logger.exception("Failed to create API key '%s' for tenant '%s'", name, tenant_id)
            raise

        logger.info(
            "API key created: id=%s name='%s' tenant=%s scopes=%s",
            key_id,
            name,
            tenant_id,
            scopes,
        )

        return {
            "key_id": key_id,
            "raw_key": raw_key,
            "prefix": key_prefix,
            "name": name,
            "scopes": scopes,
        }

    # ------------------------------------------------------------------
    # Validate
    # ------------------------------------------------------------------

    def validate_key(self, db: Any, raw_key: str) -> dict | None:
        """Validate an API key against the database.

        Hashes the provided raw key, looks up the matching record, and
        verifies that the key is neither revoked nor expired.  On
        success the last_used_at timestamp is updated.

        Returns:
            dict with key_id, tenant_id, name, scopes -- or None if
            the key is invalid, revoked, or expired.
        """
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        row = db.query(ApiKeyRow).filter(ApiKeyRow.key_hash == key_hash).first()
        if row is None:
            logger.debug("API key validation failed: hash not found")
            return None

        # Check revocation
        if row.revoked == "true":
            logger.warning("Rejected revoked API key: id=%s name='%s'", row.id, row.name)
            return None

        # Check expiration
        if row.expires_at is not None:
            now = datetime.now(timezone.utc)
            expires = row.expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if now > expires:
                logger.warning("Rejected expired API key: id=%s name='%s'", row.id, row.name)
                return None

        # Update last-used timestamp
        row.last_used_at = datetime.now(timezone.utc)
        try:
            db.commit()
        except Exception:
            db.rollback()

        return {
            "key_id": row.id,
            "tenant_id": row.tenant_id,
            "name": row.name,
            "scopes": row.scopes or [],
        }

    # ------------------------------------------------------------------
    # Revoke
    # ------------------------------------------------------------------

    def revoke_key(self, db: Any, key_id: str) -> bool:
        """Revoke an API key so it can no longer be used.

        Returns:
            True if the key was found and revoked, False otherwise.
        """
        row = db.query(ApiKeyRow).filter(ApiKeyRow.id == key_id).first()
        if row is None:
            logger.warning("Revoke failed: API key '%s' not found", key_id)
            return False

        if row.revoked == "true":
            logger.info("API key '%s' is already revoked", key_id)
            return True

        row.revoked = "true"
        row.revoked_at = datetime.now(timezone.utc)
        try:
            db.commit()
        except Exception:
            db.rollback()
            logger.exception("Failed to revoke API key '%s'", key_id)
            raise

        logger.info("API key revoked: id=%s name='%s'", key_id, row.name)
        return True

    # ------------------------------------------------------------------
    # Rotate
    # ------------------------------------------------------------------

    def rotate_key(self, db: Any, key_id: str, rotated_by: str) -> dict | None:
        """Rotate an API key: revoke the old one and create a replacement.

        The new key inherits the same name, scopes, and tenant from the
        original.  The old key is immediately revoked.

        Returns:
            The same dict as create_key for the new key, or None
            if the original key was not found.
        """
        row = db.query(ApiKeyRow).filter(ApiKeyRow.id == key_id).first()
        if row is None:
            logger.warning("Rotate failed: API key '%s' not found", key_id)
            return None

        # Preserve attributes before revoking
        tenant_id = row.tenant_id
        name = row.name
        scopes = list(row.scopes or [])
        expires_at = row.expires_at

        # Revoke old key
        self.revoke_key(db, key_id)

        # Create replacement
        new_key = self.create_key(
            db,
            tenant_id=tenant_id,
            name=name,
            scopes=scopes,
            created_by=rotated_by,
            expires_at=expires_at,
        )

        logger.info(
            "API key rotated: old=%s -> new=%s name='%s'",
            key_id,
            new_key["key_id"],
            name,
        )
        return new_key

    # ------------------------------------------------------------------
    # List
    # ------------------------------------------------------------------

    def list_keys(self, db: Any, tenant_id: str) -> list[dict]:
        """List all API keys for a tenant.

        SECURITY: Never returns raw keys or hashes -- only the prefix
        is included for identification.

        Returns:
            List of dicts with key metadata.
        """
        rows = (
            db.query(ApiKeyRow)
            .filter(ApiKeyRow.tenant_id == tenant_id)
            .order_by(ApiKeyRow.created_at.desc())
            .all()
        )

        return [
            {
                "key_id": row.id,
                "tenant_id": row.tenant_id,
                "name": row.name,
                "prefix": row.key_prefix,
                "scopes": row.scopes or [],
                "created_by": row.created_by,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "expires_at": row.expires_at.isoformat() if row.expires_at else None,
                "last_used_at": row.last_used_at.isoformat() if row.last_used_at else None,
                "revoked": row.revoked == "true",
                "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
            }
            for row in rows
        ]

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def delete_expired(self, db: Any) -> int:
        """Delete all API keys that have passed their expiration date.

        Returns:
            The number of keys deleted.
        """
        now = datetime.now(timezone.utc)
        expired_rows = (
            db.query(ApiKeyRow)
            .filter(
                ApiKeyRow.expires_at.isnot(None),
                ApiKeyRow.expires_at < now,
            )
            .all()
        )

        count = len(expired_rows)
        for row in expired_rows:
            db.delete(row)

        try:
            db.commit()
        except Exception:
            db.rollback()
            logger.exception("Failed to delete expired API keys")
            raise

        if count > 0:
            logger.info("Deleted %d expired API key(s)", count)
        return count


# ---------------------------------------------------------------------------
# Module singleton
# ---------------------------------------------------------------------------

api_key_service = ApiKeyService()
