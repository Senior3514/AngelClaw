"""AngelClaw V4.5 \u2014 Sovereign: Microsegmentation Engine.

Manages network microsegments with source/target criteria, allowed
protocols, priority-based evaluation, and hit counting.  Enforces
zero-trust lateral movement controls by evaluating every connection
request against the active segment ruleset.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("angelclaw.microsegmentation")

# Default protocols that are always denied unless explicitly allowed
_SENSITIVE_PROTOCOLS = {"smb", "rdp", "ssh", "telnet", "vnc"}


class Microsegment:
    def __init__(
        self,
        tenant_id: str,
        name: str,
        source_criteria: dict[str, Any],
        target_criteria: dict[str, Any],
        allowed_protocols: list[str],
        priority: int = 100,
        action: str = "allow",
        enabled: bool = True,
        description: str = "",
    ) -> None:
        self.id = str(uuid.uuid4())
        self.tenant_id = tenant_id
        self.name = name
        self.source_criteria = source_criteria
        self.target_criteria = target_criteria
        self.allowed_protocols = allowed_protocols
        self.priority = priority
        self.action = action
        self.enabled = enabled
        self.description = description
        self.hit_count = 0
        self.last_hit_at: datetime | None = None
        self.created_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "source_criteria": self.source_criteria,
            "target_criteria": self.target_criteria,
            "allowed_protocols": self.allowed_protocols,
            "priority": self.priority,
            "action": self.action,
            "enabled": self.enabled,
            "description": self.description,
            "hit_count": self.hit_count,
            "last_hit_at": self.last_hit_at.isoformat() if self.last_hit_at else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class MicrosegmentationEngine:
    """Microsegmentation engine with priority-based evaluation."""

    def __init__(self) -> None:
        self._segments: dict[str, Microsegment] = {}
        self._tenant_segments: dict[str, list[str]] = defaultdict(list)
        self._evaluation_count: int = 0

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create_segment(
        self,
        tenant_id: str,
        name: str,
        source_criteria: dict[str, Any],
        target_criteria: dict[str, Any],
        allowed_protocols: list[str],
        priority: int = 100,
        action: str = "allow",
        enabled: bool = True,
        description: str = "",
    ) -> dict:
        """Create a new microsegment rule."""
        segment = Microsegment(
            tenant_id=tenant_id,
            name=name,
            source_criteria=source_criteria,
            target_criteria=target_criteria,
            allowed_protocols=allowed_protocols,
            priority=priority,
            action=action,
            enabled=enabled,
            description=description,
        )
        self._segments[segment.id] = segment
        self._tenant_segments[tenant_id].append(segment.id)
        logger.info(
            "[MICROSEG] Created segment %s (%s) for tenant %s \u2014 priority %d, action=%s",
            segment.id[:8], name, tenant_id, priority, action,
        )
        return segment.to_dict()

    def list_segments(
        self,
        tenant_id: str,
        enabled_only: bool = False,
    ) -> list[dict]:
        """List all microsegments for a tenant, sorted by priority."""
        results = []
        for sid in self._tenant_segments.get(tenant_id, []):
            seg = self._segments.get(sid)
            if not seg:
                continue
            if enabled_only and not seg.enabled:
                continue
            results.append(seg.to_dict())
        results.sort(key=lambda s: s["priority"])
        return results

    def update_segment(
        self,
        segment_id: str,
        **kwargs: Any,
    ) -> dict | None:
        """Update fields on an existing microsegment."""
        segment = self._segments.get(segment_id)
        if not segment:
            return None
        allowed_fields = {
            "name", "source_criteria", "target_criteria",
            "allowed_protocols", "priority", "action",
            "enabled", "description",
        }
        for key, value in kwargs.items():
            if key in allowed_fields:
                setattr(segment, key, value)
        segment.updated_at = datetime.now(timezone.utc)
        logger.info("[MICROSEG] Updated segment %s", segment_id[:8])
        return segment.to_dict()

    def delete_segment(self, tenant_id: str, segment_id: str) -> bool:
        """Delete a microsegment rule."""
        segment = self._segments.get(segment_id)
        if not segment or segment.tenant_id != tenant_id:
            return False
        del self._segments[segment_id]
        tenant_list = self._tenant_segments.get(tenant_id, [])
        if segment_id in tenant_list:
            tenant_list.remove(segment_id)
        logger.info("[MICROSEG] Deleted segment %s for tenant %s", segment_id[:8], tenant_id)
        return True

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate_access(
        self,
        tenant_id: str,
        source: dict[str, Any],
        target: dict[str, Any],
        protocol: str,
    ) -> dict:
        """Evaluate whether a connection is allowed by the segment rules.

        Checks segments in priority order (lowest number = highest priority).
        First matching segment determines the outcome.  If no segment matches
        the default policy is **deny** (zero-trust).

        Args:
            tenant_id: Owning tenant.
            source: Source attributes (zone, labels, ip, ...).
            target: Target attributes (zone, labels, ip, ...).
            protocol: Requested protocol (e.g. "https", "tcp/5432").

        Returns:
            Evaluation result dict with decision, matched segment, etc.
        """
        self._evaluation_count += 1
        segments = self._get_sorted_segments(tenant_id)

        for seg in segments:
            if not seg.enabled:
                continue
            if not self._matches_criteria(source, seg.source_criteria):
                continue
            if not self._matches_criteria(target, seg.target_criteria):
                continue

            # Check protocol match
            protocol_match = (
                protocol in seg.allowed_protocols
                or "*" in seg.allowed_protocols
            )
            if not protocol_match:
                continue

            # Match found
            seg.hit_count += 1
            seg.last_hit_at = datetime.now(timezone.utc)

            decision = seg.action
            logger.debug(
                "[MICROSEG] %s connection %s -> %s [%s] \u2014 matched segment %s (%s)",
                decision.upper(), source, target, protocol, seg.id[:8], seg.name,
            )
            return {
                "decision": decision,
                "matched_segment_id": seg.id,
                "matched_segment_name": seg.name,
                "priority": seg.priority,
                "protocol": protocol,
                "source": source,
                "target": target,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        # No segment matched \u2014 default deny (zero trust)
        logger.info(
            "[MICROSEG] DENY (default) connection %s -> %s [%s] \u2014 no matching segment",
            source, target, protocol,
        )
        return {
            "decision": "deny",
            "matched_segment_id": None,
            "matched_segment_name": None,
            "priority": None,
            "protocol": protocol,
            "source": source,
            "target": target,
            "reason": "no_matching_segment",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return statistics for microsegmentation in a tenant."""
        segments = [
            self._segments[sid]
            for sid in self._tenant_segments.get(tenant_id, [])
            if sid in self._segments
        ]
        by_action: dict[str, int] = defaultdict(int)
        total_hits = 0
        for seg in segments:
            by_action[seg.action] += 1
            total_hits += seg.hit_count
        return {
            "total_segments": len(segments),
            "enabled": sum(1 for s in segments if s.enabled),
            "disabled": sum(1 for s in segments if not s.enabled),
            "by_action": dict(by_action),
            "total_hits": total_hits,
            "total_evaluations": self._evaluation_count,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_sorted_segments(self, tenant_id: str) -> list[Microsegment]:
        """Get segments sorted by priority (ascending = highest priority first)."""
        segments = [
            self._segments[sid]
            for sid in self._tenant_segments.get(tenant_id, [])
            if sid in self._segments
        ]
        segments.sort(key=lambda s: s.priority)
        return segments

    @staticmethod
    def _matches_criteria(attributes: dict[str, Any], criteria: dict[str, Any]) -> bool:
        """Check whether attributes satisfy the segment criteria.

        Supports:
        - Exact match on scalar values (zone, ip)
        - Subset match on list values (labels)
        - Wildcard "*" matches anything
        """
        for key, required in criteria.items():
            if required == "*":
                continue
            actual = attributes.get(key)
            if actual is None:
                return False
            if isinstance(required, list):
                if isinstance(actual, list):
                    if not set(required).issubset(set(actual)):
                        return False
                elif actual not in required:
                    return False
            else:
                if actual != required:
                    return False
        return True


# Module-level singleton
microsegmentation_engine = MicrosegmentationEngine()
