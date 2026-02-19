"""AngelClaw V4.5 — Sovereign: Continuous Session Risk Assessment.

Provides continuous risk scoring for active user sessions.  Each session
is evaluated against contextual signals — geographic anomalies, unknown
devices, off-hours access, and concurrent session counts — producing a
composite risk score (0-100) with an associated risk level and
recommended action.  Sessions can be reassessed as conditions change
and terminated when risk becomes unacceptable.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("angelclaw.session_risk")

# Risk factor weights
_RISK_WEIGHTS = {
    "geo_anomaly": 30,
    "unknown_device": 25,
    "multiple_sessions": 20,
    "off_hours": 15,
}

# Known geolocations considered baseline (simplified)
_BASELINE_GEOLOCATIONS = {
    "us-east", "us-west", "eu-west", "eu-central",
    "ap-southeast", "ap-northeast",
}

# Business hours window (UTC)
_BUSINESS_HOURS_START = 8
_BUSINESS_HOURS_END = 20


class SessionRiskAssessment:
    """Snapshot of a session risk evaluation."""

    def __init__(
        self,
        session_id: str,
        tenant_id: str,
        user_id: str,
        device_id: str,
        geo_location: str = "unknown",
    ) -> None:
        self.id = str(uuid.uuid4())
        self.session_id = session_id
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.device_id = device_id
        self.geo_location = geo_location
        self.risk_score: int = 0
        self.risk_level: str = "low"           # low | medium | high | critical
        self.risk_factors: list[str] = []
        self.recommended_action: str = "allow"  # allow | step_up | terminate
        self.assessed_at = datetime.now(timezone.utc)
        self.reassessment_count: int = 0
        self.terminated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "device_id": self.device_id,
            "geo_location": self.geo_location,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "risk_factors": list(self.risk_factors),
            "recommended_action": self.recommended_action,
            "assessed_at": self.assessed_at.isoformat(),
            "reassessment_count": self.reassessment_count,
            "terminated": self.terminated,
        }


class SessionRiskService:
    """Continuous session risk assessment engine."""

    def __init__(self) -> None:
        self._sessions: dict[str, SessionRiskAssessment] = {}           # session_id -> assessment
        self._tenant_sessions: dict[str, list[str]] = defaultdict(list)  # tenant_id -> [session_id, ...]
        self._known_devices: dict[str, set[str]] = defaultdict(set)      # tenant_id -> {device_id, ...}

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def assess_session(
        self,
        tenant_id: str,
        session_id: str,
        user_id: str,
        device_id: str,
        geo_location: str = "unknown",
    ) -> dict:
        """Assess risk for a new or existing session.

        Risk signals evaluated:
          - geo_anomaly:       +30 if geo_location not in baseline set
          - unknown_device:    +25 if device_id has not been seen in tenant
          - multiple_sessions: +20 if user already has active sessions
          - off_hours:         +15 if current UTC hour is outside business hours

        Risk levels:
          - low:      score < 20
          - medium:   20 <= score < 50
          - high:     50 <= score < 80
          - critical: score >= 80

        Recommended actions:
          - allow:     risk_level in (low, medium)
          - step_up:   risk_level == high
          - terminate: risk_level == critical
        """
        assessment = SessionRiskAssessment(
            session_id=session_id,
            tenant_id=tenant_id,
            user_id=user_id,
            device_id=device_id,
            geo_location=geo_location,
        )

        risk_score, risk_factors = self._compute_risk(
            tenant_id=tenant_id,
            user_id=user_id,
            device_id=device_id,
            geo_location=geo_location,
        )
        assessment.risk_score = risk_score
        assessment.risk_factors = risk_factors
        assessment.risk_level = self._risk_level(risk_score)
        assessment.recommended_action = self._recommended_action(assessment.risk_level)

        # Register the session and mark the device as known
        is_new = session_id not in self._sessions
        self._sessions[session_id] = assessment
        if is_new:
            self._tenant_sessions[tenant_id].append(session_id)
        self._known_devices[tenant_id].add(device_id)

        logger.info(
            "[SESSION_RISK] Assessed session %s — score=%d, level=%s, action=%s, factors=%s",
            session_id[:8], risk_score, assessment.risk_level,
            assessment.recommended_action, risk_factors,
        )
        return assessment.to_dict()

    def list_sessions(self, tenant_id: str) -> list[dict]:
        """List all tracked sessions for a tenant."""
        results = []
        for sid in self._tenant_sessions.get(tenant_id, []):
            assessment = self._sessions.get(sid)
            if assessment:
                results.append(assessment.to_dict())
        results.sort(key=lambda s: s["risk_score"], reverse=True)
        return results

    def get_session(self, tenant_id: str, session_id: str) -> dict | None:
        """Get risk assessment for a specific session."""
        assessment = self._sessions.get(session_id)
        if not assessment or assessment.tenant_id != tenant_id:
            return None
        return assessment.to_dict()

    def reassess_session(self, tenant_id: str, session_id: str) -> dict | None:
        """Reassess an existing session with current contextual signals.

        Increments the reassessment counter and recomputes risk based on
        the session's current attributes.
        """
        assessment = self._sessions.get(session_id)
        if not assessment or assessment.tenant_id != tenant_id:
            return None
        if assessment.terminated:
            return assessment.to_dict()

        assessment.reassessment_count += 1
        risk_score, risk_factors = self._compute_risk(
            tenant_id=tenant_id,
            user_id=assessment.user_id,
            device_id=assessment.device_id,
            geo_location=assessment.geo_location,
        )
        assessment.risk_score = risk_score
        assessment.risk_factors = risk_factors
        assessment.risk_level = self._risk_level(risk_score)
        assessment.recommended_action = self._recommended_action(assessment.risk_level)
        assessment.assessed_at = datetime.now(timezone.utc)

        logger.info(
            "[SESSION_RISK] Reassessed session %s (#%d) — score=%d, level=%s",
            session_id[:8], assessment.reassessment_count,
            risk_score, assessment.risk_level,
        )
        return assessment.to_dict()

    def terminate_session(self, tenant_id: str, session_id: str) -> dict | None:
        """Terminate a tracked session."""
        assessment = self._sessions.get(session_id)
        if not assessment or assessment.tenant_id != tenant_id:
            return None
        assessment.terminated = True
        assessment.recommended_action = "terminate"
        assessment.assessed_at = datetime.now(timezone.utc)
        logger.info(
            "[SESSION_RISK] Terminated session %s in tenant %s",
            session_id[:8], tenant_id,
        )
        return assessment.to_dict()

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return statistics for session risk in a tenant."""
        sessions = [
            self._sessions[sid]
            for sid in self._tenant_sessions.get(tenant_id, [])
            if sid in self._sessions
        ]
        by_risk_level: dict[str, int] = defaultdict(int)
        total_reassessments = 0
        for s in sessions:
            by_risk_level[s.risk_level] += 1
            total_reassessments += s.reassessment_count
        scores = [s.risk_score for s in sessions]
        return {
            "total_sessions": len(sessions),
            "by_risk_level": dict(by_risk_level),
            "avg_risk_score": round(sum(scores) / max(len(scores), 1), 1),
            "total_reassessments": total_reassessments,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_risk(
        self,
        tenant_id: str,
        user_id: str,
        device_id: str,
        geo_location: str,
    ) -> tuple[int, list[str]]:
        """Compute a composite risk score (0-100) and collect risk factors."""
        score = 0
        risk_factors: list[str] = []

        # Geo anomaly: +30
        if geo_location.lower() not in _BASELINE_GEOLOCATIONS:
            score += _RISK_WEIGHTS["geo_anomaly"]
            risk_factors.append("geo_anomaly")

        # Unknown device: +25
        if device_id not in self._known_devices.get(tenant_id, set()):
            score += _RISK_WEIGHTS["unknown_device"]
            risk_factors.append("unknown_device")

        # Off-hours access: +15
        current_hour = datetime.now(timezone.utc).hour
        if current_hour < _BUSINESS_HOURS_START or current_hour >= _BUSINESS_HOURS_END:
            score += _RISK_WEIGHTS["off_hours"]
            risk_factors.append("off_hours_access")

        # Multiple active sessions for the same user: +20
        active_sessions = [
            s for s in self._sessions.values()
            if s.tenant_id == tenant_id
            and s.user_id == user_id
            and not s.terminated
        ]
        if len(active_sessions) > 1:
            score += _RISK_WEIGHTS["multiple_sessions"]
            risk_factors.append("multiple_active_sessions")

        return max(0, min(100, score)), risk_factors

    @staticmethod
    def _risk_level(score: int) -> str:
        """Derive risk level from score."""
        if score >= 80:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 20:
            return "medium"
        return "low"

    @staticmethod
    def _recommended_action(risk_level: str) -> str:
        """Map risk level to a recommended action."""
        if risk_level == "critical":
            return "terminate"
        elif risk_level == "high":
            return "step_up"
        return "allow"


# Module-level singleton
session_risk_service = SessionRiskService()
