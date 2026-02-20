"""AngelClaw V4.5 — Sovereign: Device Trust Assessment Service.

Tracks and assesses device trust scores (0-100) based on security
posture factors: OS version, patch level, encryption status, antivirus
presence, and firewall status.  Trust scores are deterministic and
recomputed on every assessment update.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("angelclaw.device_trust")

# Weight configuration for trust score computation
_FACTOR_WEIGHTS = {
    "os_supported": 20,
    "patch_level": 25,
    "encryption_enabled": 20,
    "antivirus_active": 20,
    "firewall_enabled": 15,
}

# OS versions considered supported (simplified baseline)
_SUPPORTED_OS_VERSIONS = {
    "windows": ["10", "11", "2019", "2022"],
    "macos": ["13", "14", "15"],
    "linux": ["ubuntu-22", "ubuntu-24", "rhel-9", "debian-12"],
}


class DeviceAssessment:
    def __init__(
        self,
        tenant_id: str,
        device_id: str,
        device_name: str = "",
        os_family: str = "unknown",
        os_version: str = "unknown",
        patch_level: str = "unknown",
        encryption_enabled: bool = False,
        antivirus_active: bool = False,
        firewall_enabled: bool = False,
        extra_factors: dict[str, Any] | None = None,
    ) -> None:
        self.id = str(uuid.uuid4())
        self.tenant_id = tenant_id
        self.device_id = device_id
        self.device_name = device_name
        self.os_family = os_family
        self.os_version = os_version
        self.patch_level = patch_level  # current | behind_1 | behind_2 | outdated
        self.encryption_enabled = encryption_enabled
        self.antivirus_active = antivirus_active
        self.firewall_enabled = firewall_enabled
        self.extra_factors = extra_factors or {}
        self.trust_score: int = 0
        self.risk_level: str = "unknown"
        self.last_assessed_at = datetime.now(timezone.utc)
        self.created_at = datetime.now(timezone.utc)
        self.assessment_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "device_id": self.device_id,
            "device_name": self.device_name,
            "os_family": self.os_family,
            "os_version": self.os_version,
            "patch_level": self.patch_level,
            "encryption_enabled": self.encryption_enabled,
            "antivirus_active": self.antivirus_active,
            "firewall_enabled": self.firewall_enabled,
            "extra_factors": self.extra_factors,
            "trust_score": self.trust_score,
            "risk_level": self.risk_level,
            "last_assessed_at": self.last_assessed_at.isoformat(),
            "created_at": self.created_at.isoformat(),
            "assessment_count": self.assessment_count,
        }


class DeviceTrustService:
    """Device trust assessment engine with deterministic scoring."""

    def __init__(self) -> None:
        self._devices: dict[str, DeviceAssessment] = {}  # device_id -> assessment
        self._tenant_devices: dict[str, list[str]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def assess_device(
        self,
        tenant_id: str,
        device_id: str,
        device_name: str = "",
        os_family: str = "unknown",
        os_version: str = "unknown",
        patch_level: str = "unknown",
        encryption_enabled: bool = False,
        antivirus_active: bool = False,
        firewall_enabled: bool = False,
        extra_factors: dict[str, Any] | None = None,
    ) -> dict:
        """Assess or re-assess a device and compute its trust score.

        If the device has been seen before, its assessment is updated.
        Otherwise a new assessment record is created.
        """
        existing = self._devices.get(device_id)
        if existing:
            existing.os_family = os_family
            existing.os_version = os_version
            existing.patch_level = patch_level
            existing.encryption_enabled = encryption_enabled
            existing.antivirus_active = antivirus_active
            existing.firewall_enabled = firewall_enabled
            existing.extra_factors = extra_factors or existing.extra_factors
            existing.device_name = device_name or existing.device_name
            existing.assessment_count += 1
            existing.last_assessed_at = datetime.now(timezone.utc)
            existing.trust_score = self.compute_trust_score(existing)
            existing.risk_level = self._risk_level(existing.trust_score)
            logger.info(
                "[DEVICE_TRUST] Re-assessed device %s \u2014 score=%d (%s)",
                device_id[:8],
                existing.trust_score,
                existing.risk_level,
            )
            return existing.to_dict()

        assessment = DeviceAssessment(
            tenant_id=tenant_id,
            device_id=device_id,
            device_name=device_name,
            os_family=os_family,
            os_version=os_version,
            patch_level=patch_level,
            encryption_enabled=encryption_enabled,
            antivirus_active=antivirus_active,
            firewall_enabled=firewall_enabled,
            extra_factors=extra_factors,
        )
        assessment.assessment_count = 1
        assessment.trust_score = self.compute_trust_score(assessment)
        assessment.risk_level = self._risk_level(assessment.trust_score)

        self._devices[device_id] = assessment
        self._tenant_devices[tenant_id].append(device_id)
        logger.info(
            "[DEVICE_TRUST] Assessed new device %s \u2014 score=%d (%s)",
            device_id[:8],
            assessment.trust_score,
            assessment.risk_level,
        )
        return assessment.to_dict()

    def update_assessment(
        self,
        device_id: str,
        **kwargs: Any,
    ) -> dict | None:
        """Partially update a device assessment and recompute score."""
        assessment = self._devices.get(device_id)
        if not assessment:
            return None
        allowed_fields = {
            "device_name",
            "os_family",
            "os_version",
            "patch_level",
            "encryption_enabled",
            "antivirus_active",
            "firewall_enabled",
            "extra_factors",
        }
        for key, value in kwargs.items():
            if key in allowed_fields:
                setattr(assessment, key, value)
        assessment.last_assessed_at = datetime.now(timezone.utc)
        assessment.assessment_count += 1
        assessment.trust_score = self.compute_trust_score(assessment)
        assessment.risk_level = self._risk_level(assessment.trust_score)
        logger.info(
            "[DEVICE_TRUST] Updated device %s \u2014 score=%d (%s)",
            device_id[:8],
            assessment.trust_score,
            assessment.risk_level,
        )
        return assessment.to_dict()

    def get_device_trust(self, device_id: str) -> dict | None:
        """Get trust assessment for a specific device."""
        assessment = self._devices.get(device_id)
        return assessment.to_dict() if assessment else None

    def list_devices(
        self,
        tenant_id: str,
        min_trust: int | None = None,
        max_trust: int | None = None,
    ) -> list[dict]:
        """List all device assessments for a tenant, optionally filtered by trust range."""
        results = []
        for did in self._tenant_devices.get(tenant_id, []):
            assessment = self._devices.get(did)
            if not assessment:
                continue
            if min_trust is not None and assessment.trust_score < min_trust:
                continue
            if max_trust is not None and assessment.trust_score > max_trust:
                continue
            results.append(assessment.to_dict())
        results.sort(key=lambda d: d["trust_score"])
        return results

    # ------------------------------------------------------------------
    # Trust score computation
    # ------------------------------------------------------------------

    @staticmethod
    def compute_trust_score(assessment: DeviceAssessment) -> int:
        """Compute a deterministic trust score (0-100) based on device factors.

        Scoring breakdown (total = 100):
          - OS supported:       20 pts (supported version) or 0
          - Patch level:        25 pts (current) / 18 (behind_1) / 10 (behind_2) / 0 (outdated)
          - Encryption:         20 pts if enabled
          - Antivirus:          20 pts if active
          - Firewall:           15 pts if enabled
        """
        score = 0

        # OS supported check
        supported_versions = _SUPPORTED_OS_VERSIONS.get(assessment.os_family.lower(), [])
        os_ok = any(ver in assessment.os_version.lower() for ver in supported_versions)
        if os_ok:
            score += _FACTOR_WEIGHTS["os_supported"]

        # Patch level
        patch_scores = {"current": 25, "behind_1": 18, "behind_2": 10, "outdated": 0, "unknown": 5}
        score += patch_scores.get(assessment.patch_level, 5)

        # Binary factors
        if assessment.encryption_enabled:
            score += _FACTOR_WEIGHTS["encryption_enabled"]
        if assessment.antivirus_active:
            score += _FACTOR_WEIGHTS["antivirus_active"]
        if assessment.firewall_enabled:
            score += _FACTOR_WEIGHTS["firewall_enabled"]

        return max(0, min(100, score))

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return statistics for device trust in a tenant."""
        devices = [
            self._devices[did]
            for did in self._tenant_devices.get(tenant_id, [])
            if did in self._devices
        ]
        by_risk: dict[str, int] = defaultdict(int)
        by_os: dict[str, int] = defaultdict(int)
        for d in devices:
            by_risk[d.risk_level] += 1
            by_os[d.os_family] += 1
        scores = [d.trust_score for d in devices]
        return {
            "total_devices": len(devices),
            "avg_trust_score": round(sum(scores) / max(len(scores), 1), 1),
            "min_trust_score": min(scores) if scores else 0,
            "max_trust_score": max(scores) if scores else 0,
            "by_risk_level": dict(by_risk),
            "by_os_family": dict(by_os),
            "total_assessments": sum(d.assessment_count for d in devices),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _risk_level(score: int) -> str:
        if score >= 80:
            return "trusted"
        elif score >= 60:
            return "moderate"
        elif score >= 40:
            return "low_trust"
        elif score >= 20:
            return "untrusted"
        return "critical"


# Module-level singleton
device_trust_service = DeviceTrustService()
