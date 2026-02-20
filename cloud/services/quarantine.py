"""AngelClaw Cloud -- Quarantine Manager Service.

Provides agent quarantine lifecycle management: quarantine, release,
timed auto-release, and event suppression tracking.  Used by the
quarantine API routes and internally by the Guardian orchestrator
when an agent is deemed compromised or misbehaving.

Quarantine states:
  - active   -- agent is quarantined, events are suppressed
  - released -- agent has been manually or automatically released
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from cloud.db.models import QuarantineRecordRow

logger = logging.getLogger("angelgrid.cloud.quarantine")


class QuarantineManager:
    """Manages agent quarantine records with timed release support."""

    # ------------------------------------------------------------------
    # Quarantine an agent
    # ------------------------------------------------------------------

    def quarantine_agent(
        self,
        db: Session,
        tenant_id: str,
        agent_id: str,
        reason: str,
        quarantined_by: str,
        release_at: Optional[datetime] = None,
    ) -> QuarantineRecordRow:
        """Place an agent under quarantine.

        If the agent already has an active quarantine record the existing
        record is returned unchanged -- duplicate quarantines are not created.

        Args:
            db: Active database session.
            tenant_id: Owning tenant identifier.
            agent_id: Agent to quarantine.
            reason: Human-readable justification.
            quarantined_by: User or system identity performing the action.
            release_at: Optional future timestamp for automatic release.

        Returns:
            The newly created (or existing) QuarantineRecordRow.
        """
        # Prevent duplicate active quarantines for the same agent
        existing = (
            db.query(QuarantineRecordRow)
            .filter(
                QuarantineRecordRow.agent_id == agent_id,
                QuarantineRecordRow.status == "active",
            )
            .first()
        )
        if existing:
            logger.info(
                "[QUARANTINE] Agent %s already quarantined (record %s)",
                agent_id[:8],
                existing.id[:8],
            )
            return existing

        record = QuarantineRecordRow(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            agent_id=agent_id,
            reason=reason,
            quarantined_by=quarantined_by,
            quarantined_at=datetime.now(timezone.utc),
            release_at=release_at,
            status="active",
            suppressed_events=0,
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        logger.warning(
            "[QUARANTINE] Agent %s quarantined by %s -- reason: %s | release_at: %s",
            agent_id[:8],
            quarantined_by,
            reason,
            release_at.isoformat() if release_at else "manual",
        )
        return record

    # ------------------------------------------------------------------
    # Release an agent
    # ------------------------------------------------------------------

    def release_agent(
        self,
        db: Session,
        tenant_id: str,
        agent_id: str,
        released_by: str,
    ) -> Optional[QuarantineRecordRow]:
        """Release an agent from quarantine.

        Args:
            db: Active database session.
            tenant_id: Owning tenant identifier.
            agent_id: Agent to release.
            released_by: User or system identity performing the release.

        Returns:
            The updated QuarantineRecordRow, or None if no active record
            was found.
        """
        record = (
            db.query(QuarantineRecordRow)
            .filter(
                QuarantineRecordRow.agent_id == agent_id,
                QuarantineRecordRow.tenant_id == tenant_id,
                QuarantineRecordRow.status == "active",
            )
            .first()
        )
        if not record:
            logger.info(
                "[QUARANTINE] No active quarantine found for agent %s in tenant %s",
                agent_id[:8],
                tenant_id,
            )
            return None

        record.status = "released"
        record.released_at = datetime.now(timezone.utc)
        record.released_by = released_by
        db.commit()
        db.refresh(record)

        logger.info(
            "[QUARANTINE] Agent %s released by %s (suppressed %d events)",
            agent_id[:8],
            released_by,
            record.suppressed_events,
        )
        return record

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def is_quarantined(self, db: Session, agent_id: str) -> bool:
        """Return True if the agent has an active quarantine record.

        Args:
            db: Active database session.
            agent_id: Agent to check.

        Returns:
            True when quarantined, False otherwise.
        """
        exists = (
            db.query(QuarantineRecordRow)
            .filter(
                QuarantineRecordRow.agent_id == agent_id,
                QuarantineRecordRow.status == "active",
            )
            .first()
        )
        return exists is not None

    def get_quarantine_status(self, db: Session, agent_id: str) -> Optional[QuarantineRecordRow]:
        """Return the active quarantine record for an agent, or None.

        Args:
            db: Active database session.
            agent_id: Agent to look up.

        Returns:
            The active QuarantineRecordRow or None.
        """
        return (
            db.query(QuarantineRecordRow)
            .filter(
                QuarantineRecordRow.agent_id == agent_id,
                QuarantineRecordRow.status == "active",
            )
            .first()
        )

    def list_quarantined(self, db: Session, tenant_id: str) -> list[QuarantineRecordRow]:
        """Return all active quarantine records for a tenant.

        Args:
            db: Active database session.
            tenant_id: Tenant to scope the query.

        Returns:
            List of active QuarantineRecordRow entries.
        """
        return (
            db.query(QuarantineRecordRow)
            .filter(
                QuarantineRecordRow.tenant_id == tenant_id,
                QuarantineRecordRow.status == "active",
            )
            .order_by(QuarantineRecordRow.quarantined_at.desc())
            .all()
        )

    # ------------------------------------------------------------------
    # Timed auto-release
    # ------------------------------------------------------------------

    def check_timed_releases(self, db: Session) -> list[QuarantineRecordRow]:
        """Find and auto-release quarantine records whose release_at has passed.

        Called periodically (e.g. by a background task or heartbeat loop).

        Args:
            db: Active database session.

        Returns:
            List of records that were auto-released during this call.
        """
        now = datetime.now(timezone.utc)
        expired = (
            db.query(QuarantineRecordRow)
            .filter(
                QuarantineRecordRow.status == "active",
                QuarantineRecordRow.release_at.isnot(None),
                QuarantineRecordRow.release_at <= now,
            )
            .all()
        )

        released: list[QuarantineRecordRow] = []
        for record in expired:
            record.status = "released"
            record.released_at = now
            record.released_by = "system:timed_release"
            released.append(record)
            logger.info(
                "[QUARANTINE] Timed release for agent %s (record %s, suppressed %d events)",
                record.agent_id[:8],
                record.id[:8],
                record.suppressed_events,
            )

        if released:
            db.commit()
            logger.info(
                "[QUARANTINE] Auto-released %d quarantine record(s)",
                len(released),
            )

        return released

    # ------------------------------------------------------------------
    # Event suppression counter
    # ------------------------------------------------------------------

    def suppress_event(self, db: Session, agent_id: str) -> bool:
        """Increment the suppressed-events counter for a quarantined agent.

        Called when the event bus would normally process an event from a
        quarantined agent but skips it instead.

        Args:
            db: Active database session.
            agent_id: Agent whose event was suppressed.

        Returns:
            True if the counter was incremented, False if the agent is not
            quarantined.
        """
        record = (
            db.query(QuarantineRecordRow)
            .filter(
                QuarantineRecordRow.agent_id == agent_id,
                QuarantineRecordRow.status == "active",
            )
            .first()
        )
        if not record:
            return False

        record.suppressed_events = (record.suppressed_events or 0) + 1
        db.commit()
        logger.debug(
            "[QUARANTINE] Suppressed event for agent %s (total: %d)",
            agent_id[:8],
            record.suppressed_events,
        )
        return True


# Module-level singleton
quarantine_manager = QuarantineManager()
