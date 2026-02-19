"""AngelClaw Cloud – Event Replay Service (V3.0 Dominion).

Replays historical events through the detection pipeline (pattern
detector, anomaly detector, correlation engine) to discover indicators
that may have been missed in real-time processing.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from cloud.db.models import EventReplayRow, EventRow
from cloud.guardian.detection.anomaly import anomaly_detector
from cloud.guardian.detection.correlator import correlation_engine
from cloud.guardian.detection.patterns import pattern_detector

logger = logging.getLogger("angelgrid.cloud.services.event_replay")


class EventReplayService:
    """Create, execute and manage event-replay sessions."""

    # -- Create ---------------------------------------------------------------

    def create_replay(
        self,
        db: Any,
        tenant_id: str,
        name: str,
        source_filter: dict,
        created_by: str = "system",
    ) -> dict:
        """Create a new replay session with status ``pending``."""
        row = EventReplayRow(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            name=name,
            status="pending",
            event_count=0,
            indicators_found=0,
            source_filter=source_filter,
            results={},
            created_by=created_by,
            started_at=None,
            completed_at=None,
            created_at=datetime.now(timezone.utc),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        logger.info("Created replay session '%s' (id=%s)", name, row.id)
        return self._row_to_dict(row)

    # -- Run ------------------------------------------------------------------

    def run_replay(self, db: Any, replay_id: str) -> dict:
        """Execute a replay session: query matching events, run detectors.

        Sets status to ``running`` while processing and ``completed`` (or
        ``failed``) when done.  Results are persisted on the row.
        """
        row = db.query(EventReplayRow).filter(EventReplayRow.id == replay_id).first()
        if not row:
            raise ValueError(f"Replay session '{replay_id}' not found")

        row.status = "running"
        row.started_at = datetime.now(timezone.utc)
        db.commit()

        try:
            events = self._query_events(db, row.source_filter or {})
            row.event_count = len(events)

            # --- Detection pipeline ---
            pattern_indicators = pattern_detector.detect(events)
            anomaly_indicators = anomaly_detector.detect(events)
            correlation_chains = correlation_engine.correlate(events)

            total_indicators = (
                len(pattern_indicators) + len(anomaly_indicators) + len(correlation_chains)
            )
            row.indicators_found = total_indicators

            results: dict[str, Any] = {
                "event_count": len(events),
                "pattern_indicators": [
                    {
                        "pattern": ind.pattern_name,
                        "severity": ind.severity,
                        "description": ind.description,
                        "event_ids": ind.event_ids,
                    }
                    for ind in pattern_indicators
                ],
                "anomaly_indicators": [
                    {
                        "agent_id": ind.agent_id,
                        "score": ind.score,
                        "description": ind.description,
                    }
                    for ind in anomaly_indicators
                ],
                "correlation_chains": [
                    {
                        "chain_id": chain.chain_id,
                        "tactics": chain.tactics,
                        "event_ids": chain.event_ids,
                        "description": chain.description,
                    }
                    for chain in correlation_chains
                ],
                "total_indicators": total_indicators,
            }

            row.results = results
            row.status = "completed"
            row.completed_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(row)
            logger.info(
                "Replay '%s' completed: %d events, %d indicators",
                row.name,
                len(events),
                total_indicators,
            )

        except Exception as exc:
            row.status = "failed"
            row.results = {"error": str(exc)}
            row.completed_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(row)
            logger.exception("Replay '%s' failed", row.name)

        return self._row_to_dict(row)

    # -- Read -----------------------------------------------------------------

    def get_replay(self, db: Any, replay_id: str) -> dict | None:
        """Return a single replay session or ``None``."""
        row = db.query(EventReplayRow).filter(EventReplayRow.id == replay_id).first()
        if row:
            return self._row_to_dict(row)
        return None

    def list_replays(self, db: Any, tenant_id: str, limit: int = 50) -> list[dict]:
        """List replay sessions for a tenant, newest first."""
        rows = (
            db.query(EventReplayRow)
            .filter(EventReplayRow.tenant_id == tenant_id)
            .order_by(EventReplayRow.created_at.desc())
            .limit(limit)
            .all()
        )
        return [self._row_to_dict(r) for r in rows]

    # -- Delete ---------------------------------------------------------------

    def delete_replay(self, db: Any, replay_id: str) -> bool:
        """Delete a replay session.  Returns ``True`` if deleted."""
        row = db.query(EventReplayRow).filter(EventReplayRow.id == replay_id).first()
        if not row:
            return False
        db.delete(row)
        db.commit()
        logger.info("Deleted replay session '%s' (id=%s)", row.name, replay_id)
        return True

    # -- Internal helpers -----------------------------------------------------

    @staticmethod
    def _query_events(db: Any, source_filter: dict) -> list[EventRow]:
        """Build a SQLAlchemy query from the source_filter dict.

        Supported filter keys:
          - ``start``     ISO datetime string (inclusive lower bound)
          - ``end``       ISO datetime string (inclusive upper bound)
          - ``severity``  exact match
          - ``category``  exact match
          - ``agent_id``  exact match
        """
        q = db.query(EventRow)

        start = source_filter.get("start")
        if start:
            try:
                start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
                q = q.filter(EventRow.timestamp >= start_dt)
            except (ValueError, AttributeError):
                pass

        end = source_filter.get("end")
        if end:
            try:
                end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
                q = q.filter(EventRow.timestamp <= end_dt)
            except (ValueError, AttributeError):
                pass

        severity = source_filter.get("severity")
        if severity:
            q = q.filter(EventRow.severity == severity)

        category = source_filter.get("category")
        if category:
            q = q.filter(EventRow.category == category)

        agent_id = source_filter.get("agent_id")
        if agent_id:
            q = q.filter(EventRow.agent_id == agent_id)

        return q.order_by(EventRow.timestamp.asc()).all()

    @staticmethod
    def _row_to_dict(row: EventReplayRow) -> dict:
        return {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "name": row.name,
            "status": row.status,
            "event_count": row.event_count or 0,
            "indicators_found": row.indicators_found or 0,
            "source_filter": row.source_filter or {},
            "results": row.results or {},
            "created_by": row.created_by or "system",
            "started_at": row.started_at.isoformat() if row.started_at else None,
            "completed_at": row.completed_at.isoformat() if row.completed_at else None,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

replay_service = EventReplayService()
