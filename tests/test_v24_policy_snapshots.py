"""Tests for V2.4 Policy Snapshots & Rollback."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.orm import Session

from cloud.db.models import PolicySetRow, PolicySnapshotRow
from cloud.services.policy_snapshots import PolicySnapshotService


@pytest.fixture
def policy_service():
    return PolicySnapshotService()


@pytest.fixture
def sample_policy(db: Session):
    ps = PolicySetRow(
        id=str(uuid.uuid4()),
        name="test-policy",
        description="Test policy",
        rules_json=[{"id": "r1", "action": "block", "category": "shell"}],
        version_hash="abc123",
    )
    db.add(ps)
    db.commit()
    return ps


class TestPolicySnapshots:
    def test_create_snapshot(self, db, policy_service, sample_policy):
        result = policy_service.create_snapshot(
            db, "dev-tenant", "test-snap"
        )
        assert result.name == "test-snap"
        assert result.id is not None

    def test_list_snapshots(self, db, policy_service, sample_policy):
        policy_service.create_snapshot(db, "dev-tenant", "snap-1")
        policy_service.create_snapshot(db, "dev-tenant", "snap-2")
        snapshots = policy_service.list_snapshots(db, "dev-tenant")
        assert len(snapshots) >= 2

    def test_snapshot_contains_rules(self, db, policy_service, sample_policy):
        result = policy_service.create_snapshot(
            db, "dev-tenant", "rules-snap"
        )
        snap = db.query(PolicySnapshotRow).filter_by(id=result.id).first()
        assert snap is not None
        assert snap.rules_json is not None
        assert len(snap.rules_json) > 0

    def test_diff_snapshots(self, db, policy_service, sample_policy):
        snap1 = policy_service.create_snapshot(db, "dev-tenant", "before")
        # Modify policy
        sample_policy.rules_json = [
            {"id": "r1", "action": "block", "category": "shell"},
            {"id": "r2", "action": "allow", "category": "network"},
        ]
        db.commit()
        snap2 = policy_service.create_snapshot(db, "dev-tenant", "after")
        diff = policy_service.diff_snapshots(db, snap1.id, snap2.id)
        assert diff is not None

    def test_rollback(self, db, policy_service, sample_policy):
        original_rules = sample_policy.rules_json[:]
        snap = policy_service.create_snapshot(db, "dev-tenant", "rollback-point")
        sample_policy.rules_json = [{"id": "r99", "action": "allow", "category": "all"}]
        db.commit()
        result = policy_service.rollback_to(db, "dev-tenant", snap.id)
        assert result is not None
        assert result.rules_json == original_rules

    def test_snapshot_not_found(self, db, policy_service):
        snapshots = policy_service.list_snapshots(db, "nonexistent-tenant")
        assert snapshots == []

    def test_create_snapshot_with_description(self, db, policy_service, sample_policy):
        result = policy_service.create_snapshot(
            db, "dev-tenant", "described-snap", description="A test snapshot"
        )
        assert result.name == "described-snap"

    def test_snapshot_preserves_version_hash(self, db, policy_service, sample_policy):
        result = policy_service.create_snapshot(
            db, "dev-tenant", "hash-snap"
        )
        snap = db.query(PolicySnapshotRow).filter_by(id=result.id).first()
        assert snap.version_hash is not None
        assert len(snap.version_hash) > 0
