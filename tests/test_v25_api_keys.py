"""Tests for V2.5 API Key Authentication."""

from __future__ import annotations

import pytest

from cloud.auth.api_keys import ApiKeyService
from cloud.db.models import ApiKeyRow


@pytest.fixture
def key_service():
    return ApiKeyService()


class TestApiKeyService:
    def test_create_key(self, db, key_service):
        result = key_service.create_key(
            db, "dev-tenant", name="test-key", scopes=["read"], created_by="test"
        )
        assert "key_id" in result

    def test_validate_key(self, db, key_service):
        created = key_service.create_key(
            db, "dev-tenant", name="validate-key", scopes=["read"], created_by="test"
        )
        raw_key = created["raw_key"]
        info = key_service.validate_key(db, raw_key)
        assert info is not None

    def test_revoke_key(self, db, key_service):
        created = key_service.create_key(
            db, "dev-tenant", name="revoke-key", scopes=["read"], created_by="test"
        )
        key_id = created["key_id"]
        result = key_service.revoke_key(db, key_id)
        assert result is True

    def test_list_keys(self, db, key_service):
        key_service.create_key(
            db, "dev-tenant", name="list-key", scopes=["read"], created_by="test"
        )
        keys = key_service.list_keys(db, "dev-tenant")
        assert len(keys) >= 1

    def test_rotate_key(self, db, key_service):
        created = key_service.create_key(
            db, "dev-tenant", name="rotate-key", scopes=["read"], created_by="test"
        )
        key_id = created["key_id"]
        result = key_service.rotate_key(db, key_id, "test")
        assert result is not None

    def test_key_has_prefix(self, db, key_service):
        created = key_service.create_key(
            db, "dev-tenant", name="prefix-key", scopes=["read"], created_by="test"
        )
        key_id = created["key_id"]
        row = db.query(ApiKeyRow).filter_by(id=key_id).first()
        assert row is not None
        assert row.key_prefix is not None

    def test_key_hash_stored(self, db, key_service):
        created = key_service.create_key(
            db, "dev-tenant", name="hash-key", scopes=["read"], created_by="test"
        )
        key_id = created["key_id"]
        row = db.query(ApiKeyRow).filter_by(id=key_id).first()
        assert row is not None
        assert row.key_hash is not None
        assert len(row.key_hash) >= 32

    def test_revoked_key_invalid(self, db, key_service):
        created = key_service.create_key(
            db, "dev-tenant", name="invalid-key", scopes=["read"], created_by="test"
        )
        key_id = created["key_id"]
        raw_key = created["raw_key"]
        key_service.revoke_key(db, key_id)
        info = key_service.validate_key(db, raw_key)
        # Revoked key should return None
        assert info is None

    def test_create_key_with_scopes(self, db, key_service):
        created = key_service.create_key(
            db, "dev-tenant", name="scoped-key",
            scopes=["read", "write", "admin"],
            created_by="test"
        )
        assert created is not None
