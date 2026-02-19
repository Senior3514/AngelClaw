"""AngelClaw Cloud – Policy Snapshot Service.

Provides snapshot creation, listing, diffing, and rollback for policy sets.
Each snapshot captures the full rules_json of a PolicySetRow at a point in
time, enabling historical comparison and one-click rollback.

Module singleton: ``snapshot_service``
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from cloud.db.models import GuardianChangeRow, PolicySetRow, PolicySnapshotRow

logger = logging.getLogger("angelgrid.cloud.policy_snapshots")


class PolicySnapshotService:
    """Manages policy snapshot lifecycle — create, list, diff, rollback."""

    # ------------------------------------------------------------------
    # create_snapshot
    # ------------------------------------------------------------------

    def create_snapshot(
        self,
        db: Session,
        tenant_id: str,
        name: str,
        description: str = "",
        created_by: str = "system",
    ) -> PolicySnapshotRow:
        """Read the most recent PolicySetRow and persist a named snapshot.

        Raises ``ValueError`` if no policy set exists for the tenant.
        """
        policy_set: PolicySetRow | None = (
            db.query(PolicySetRow)
            .order_by(PolicySetRow.created_at.desc())
            .first()
        )
        if policy_set is None:
            raise ValueError(
                f"No policy set found for tenant '{tenant_id}'; "
                "cannot create snapshot"
            )

        rules = policy_set.rules_json or []
        version_hash = hashlib.sha256(
            json.dumps(rules, sort_keys=True).encode()
        ).hexdigest()

        snapshot = PolicySnapshotRow(
            id=str(uuid4()),
            tenant_id=tenant_id,
            name=name,
            description=description,
            policy_set_id=policy_set.id,
            rules_json=rules,
            version_hash=version_hash,
            rule_count=len(rules) if isinstance(rules, list) else 0,
            created_by=created_by,
            created_at=datetime.now(timezone.utc),
        )
        db.add(snapshot)
        db.commit()
        db.refresh(snapshot)

        logger.info(
            "Snapshot '%s' created (id=%s, rules=%d, hash=%s)",
            name,
            snapshot.id,
            snapshot.rule_count,
            version_hash[:12],
        )
        return snapshot

    # ------------------------------------------------------------------
    # list_snapshots
    # ------------------------------------------------------------------

    def list_snapshots(
        self,
        db: Session,
        tenant_id: str,
        limit: int = 50,
    ) -> list[PolicySnapshotRow]:
        """Return snapshots for *tenant_id*, newest first."""
        return (
            db.query(PolicySnapshotRow)
            .filter(PolicySnapshotRow.tenant_id == tenant_id)
            .order_by(PolicySnapshotRow.created_at.desc())
            .limit(limit)
            .all()
        )

    # ------------------------------------------------------------------
    # get_snapshot
    # ------------------------------------------------------------------

    def get_snapshot(
        self,
        db: Session,
        snapshot_id: str,
    ) -> PolicySnapshotRow | None:
        """Return a single snapshot by primary key, or ``None``."""
        return (
            db.query(PolicySnapshotRow)
            .filter(PolicySnapshotRow.id == snapshot_id)
            .first()
        )

    # ------------------------------------------------------------------
    # diff_snapshots
    # ------------------------------------------------------------------

    def diff_snapshots(
        self,
        db: Session,
        id_a: str,
        id_b: str,
    ) -> dict[str, Any]:
        """Compare two snapshots and return added / removed / modified rules.

        Rules are matched by their ``id`` field (if present); rules without
        an ``id`` are treated as opaque JSON objects matched by equality.

        Returns::

            {
                "snapshot_a": "<id_a>",
                "snapshot_b": "<id_b>",
                "added":    [<rules in B but not A>],
                "removed":  [<rules in A but not B>],
                "modified": [{"rule_id": ..., "before": ..., "after": ...}],
            }
        """
        snap_a = self.get_snapshot(db, id_a)
        snap_b = self.get_snapshot(db, id_b)
        if snap_a is None:
            raise ValueError(f"Snapshot '{id_a}' not found")
        if snap_b is None:
            raise ValueError(f"Snapshot '{id_b}' not found")

        rules_a: list[dict] = snap_a.rules_json or []
        rules_b: list[dict] = snap_b.rules_json or []

        # Index rules by id where available
        map_a = {r["id"]: r for r in rules_a if isinstance(r, dict) and "id" in r}
        map_b = {r["id"]: r for r in rules_b if isinstance(r, dict) and "id" in r}

        # Rules without an id — compare by serialised equality
        anon_a = [r for r in rules_a if not (isinstance(r, dict) and "id" in r)]
        anon_b = [r for r in rules_b if not (isinstance(r, dict) and "id" in r)]

        added: list[dict] = []
        removed: list[dict] = []
        modified: list[dict] = []

        # Named rules
        for rid, rule in map_b.items():
            if rid not in map_a:
                added.append(rule)
            elif rule != map_a[rid]:
                modified.append(
                    {"rule_id": rid, "before": map_a[rid], "after": rule}
                )
        for rid, rule in map_a.items():
            if rid not in map_b:
                removed.append(rule)

        # Anonymous rules (simple set difference via JSON serialisation)
        ser_a = {json.dumps(r, sort_keys=True) for r in anon_a}
        ser_b = {json.dumps(r, sort_keys=True) for r in anon_b}
        added.extend(json.loads(s) for s in ser_b - ser_a)
        removed.extend(json.loads(s) for s in ser_a - ser_b)

        return {
            "snapshot_a": id_a,
            "snapshot_b": id_b,
            "added": added,
            "removed": removed,
            "modified": modified,
        }

    # ------------------------------------------------------------------
    # rollback_to
    # ------------------------------------------------------------------

    def rollback_to(
        self,
        db: Session,
        tenant_id: str,
        snapshot_id: str,
        rolled_back_by: str = "system",
    ) -> PolicySetRow:
        """Create a new PolicySetRow from a snapshot's rules and record the change.

        Returns the newly created PolicySetRow.
        Raises ``ValueError`` if the snapshot does not exist.
        """
        snapshot = self.get_snapshot(db, snapshot_id)
        if snapshot is None:
            raise ValueError(f"Snapshot '{snapshot_id}' not found")

        rules = snapshot.rules_json or []
        version_hash = hashlib.sha256(
            json.dumps(rules, sort_keys=True).encode()
        ).hexdigest()
        now = datetime.now(timezone.utc)

        # Capture the current latest policy set id for the change record
        current_policy: PolicySetRow | None = (
            db.query(PolicySetRow)
            .order_by(PolicySetRow.created_at.desc())
            .first()
        )
        before_snapshot_id = current_policy.id if current_policy else None

        new_policy = PolicySetRow(
            id=str(uuid4()),
            name=f"Rollback to snapshot '{snapshot.name}'",
            description=(
                f"Rolled back by {rolled_back_by} from snapshot "
                f"{snapshot.id} ({snapshot.name})"
            ),
            rules_json=rules,
            version_hash=version_hash,
            created_at=now,
        )
        db.add(new_policy)

        change = GuardianChangeRow(
            id=str(uuid4()),
            tenant_id=tenant_id,
            change_type="policy_rollback",
            description=(
                f"Policy rolled back to snapshot '{snapshot.name}' "
                f"(snapshot {snapshot.id})"
            ),
            before_snapshot=before_snapshot_id,
            after_snapshot=new_policy.id,
            changed_by=rolled_back_by,
            details={
                "snapshot_id": snapshot.id,
                "snapshot_name": snapshot.name,
                "version_hash": version_hash,
                "rule_count": len(rules) if isinstance(rules, list) else 0,
            },
            created_at=now,
        )
        db.add(change)

        db.commit()
        db.refresh(new_policy)

        logger.info(
            "Policy rolled back to snapshot '%s' (new policy_set=%s, hash=%s) "
            "by %s",
            snapshot.name,
            new_policy.id,
            version_hash[:12],
            rolled_back_by,
        )
        return new_policy


# ---------------------------------------------------------------------------
# Module singleton
# ---------------------------------------------------------------------------
snapshot_service = PolicySnapshotService()
