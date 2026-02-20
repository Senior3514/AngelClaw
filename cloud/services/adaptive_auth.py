"""AngelClaw V4.5 — Sovereign: Adaptive Authentication Engine.

Determines the required authentication level for resource access based
on real-time risk signals from the session risk and device trust
services.  Auth levels escalate with risk: password for low risk, MFA
for moderate, biometric for high, and impossible-travel block for
critical risk scores.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("angelclaw.adaptive_auth")

# Auth level thresholds based on combined risk score
_AUTH_THRESHOLDS = [
    (80, "impossible_travel_block"),
    (50, "biometric"),
    (20, "mfa"),
    (0, "password"),
]


class AuthDecision:
    """Snapshot of an adaptive authentication decision."""

    def __init__(
        self,
        tenant_id: str,
        session_id: str,
        user_id: str,
        resource: str,
        required_auth_level: str = "password",
        risk_score: int = 0,
        factors: list[str] | None = None,
    ) -> None:
        self.id = str(uuid.uuid4())
        self.tenant_id = tenant_id
        self.session_id = session_id
        self.user_id = user_id
        self.resource = resource
        self.required_auth_level = required_auth_level
        self.risk_score = risk_score
        self.factors: list[str] = factors or []
        self.decided_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "resource": self.resource,
            "required_auth_level": self.required_auth_level,
            "risk_score": self.risk_score,
            "factors": list(self.factors),
            "decided_at": self.decided_at.isoformat(),
        }


class AdaptiveAuthService:
    """Adaptive authentication engine combining session risk and device trust."""

    def __init__(self) -> None:
        self._decisions: dict[str, list[AuthDecision]] = defaultdict(
            list
        )  # tenant_id -> [decisions]

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def evaluate_auth_requirement(
        self,
        tenant_id: str,
        session_id: str,
        user_id: str,
        resource: str,
        device_id: str,
    ) -> dict:
        """Evaluate the required authentication level for a resource request.

        Imports the session risk and device trust singleton services to
        gather contextual signals.  The combined risk score determines
        the required auth level:

          - risk < 20:     password
          - 20 <= risk < 50:  mfa
          - 50 <= risk < 80:  biometric
          - risk >= 80:    impossible_travel_block

        The combined risk is calculated as a weighted blend of the session
        risk score (60 %) and the inverse device trust score (40 %).
        """
        from cloud.services.device_trust import device_trust_service
        from cloud.services.session_risk import session_risk_service

        factors: list[str] = []
        session_risk_score = 0
        device_trust_score = 100  # default fully trusted if unknown

        # Gather session risk context
        session_data = session_risk_service.get_session(tenant_id, session_id)
        if session_data:
            session_risk_score = session_data["risk_score"]
            factors.extend(session_data.get("risk_factors", []))
        else:
            factors.append("session_not_found")

        # Gather device trust context
        device_data = device_trust_service.get_device_trust(device_id)
        if device_data:
            device_trust_score = device_data["trust_score"]
            factors.extend(device_data.get("risk_factors", []))
        else:
            factors.append("device_not_assessed")
            device_trust_score = 0  # unknown device = zero trust

        # Combined risk: 60 % session risk + 40 % inverse device trust
        inverse_device_trust = 100 - device_trust_score
        combined_risk = int(session_risk_score * 0.6 + inverse_device_trust * 0.4)
        combined_risk = max(0, min(100, combined_risk))

        # Determine auth level
        required_auth_level = "password"
        for threshold, level in _AUTH_THRESHOLDS:
            if combined_risk >= threshold:
                required_auth_level = level
                break

        decision = AuthDecision(
            tenant_id=tenant_id,
            session_id=session_id,
            user_id=user_id,
            resource=resource,
            required_auth_level=required_auth_level,
            risk_score=combined_risk,
            factors=factors,
        )
        self._decisions[tenant_id].append(decision)

        logger.info(
            "[ADAPTIVE_AUTH] %s for user %s on %s"
            " — risk=%d (session=%d, device_trust=%d),"
            " level=%s",
            required_auth_level.upper(),
            user_id,
            resource,
            combined_risk,
            session_risk_score,
            device_trust_score,
            required_auth_level,
        )
        return decision.to_dict()

    def list_decisions(self, tenant_id: str, limit: int = 50) -> list[dict]:
        """List recent authentication decisions for a tenant.

        Returns the most recent decisions first, up to *limit* entries.
        """
        decisions = self._decisions.get(tenant_id, [])
        recent = sorted(decisions, key=lambda d: d.decided_at, reverse=True)[:limit]
        return [d.to_dict() for d in recent]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return statistics for adaptive auth evaluations in a tenant."""
        decisions = self._decisions.get(tenant_id, [])
        by_auth_level: dict[str, int] = defaultdict(int)
        for d in decisions:
            by_auth_level[d.required_auth_level] += 1
        scores = [d.risk_score for d in decisions]
        return {
            "total_evaluations": len(decisions),
            "by_auth_level": dict(by_auth_level),
            "average_risk_score": round(sum(scores) / max(len(scores), 1), 1),
        }


# Module-level singleton
adaptive_auth_service = AdaptiveAuthService()
