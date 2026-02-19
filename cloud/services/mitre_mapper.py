"""AngelClaw V6.5 — Prometheus: MITRE ATT&CK Mapper.

Maps security events and incidents to the MITRE ATT&CK framework,
providing technique/tactic classification, coverage analysis, gap
identification, and kill chain visualisation data.

Features:
  - Event-to-technique mapping with confidence scoring
  - Technique registry with tactic classification
  - ATT&CK coverage analysis per tenant
  - Gap identification for unmapped tactics
  - Kill chain reconstruction for incidents
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.mitre_mapper")

# MITRE ATT&CK tactics in kill chain order
_TACTICS_ORDER = [
    "reconnaissance", "resource_development", "initial_access",
    "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery",
    "lateral_movement", "collection", "command_and_control",
    "exfiltration", "impact",
]


class MitreTechnique(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    technique_id: str  # e.g., T1059, T1566.001
    tactic: str  # MITRE tactic name
    name: str
    description: str = ""
    severity: str = "medium"
    detection_coverage: float = 0.0  # 0-100 percent
    times_observed: int = 0
    last_observed_at: datetime | None = None
    added_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TechniqueMapping(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    event_type: str
    technique_id: str
    tactic: str
    confidence: float = 0.0  # 0-100
    indicators: dict[str, Any] = {}
    mapped_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class MitreAttackMapper:
    """MITRE ATT&CK framework mapping and coverage analysis."""

    def __init__(self) -> None:
        self._techniques: dict[str, MitreTechnique] = {}
        self._tenant_techniques: dict[str, list[str]] = defaultdict(list)
        self._mappings: dict[str, list[TechniqueMapping]] = defaultdict(list)
        # Index: technique_id -> internal ID for fast lookup
        self._tech_index: dict[str, dict[str, str]] = defaultdict(dict)

    # ------------------------------------------------------------------
    # Technique Registry
    # ------------------------------------------------------------------

    def add_technique(
        self,
        tenant_id: str,
        technique_id: str,
        tactic: str,
        name: str,
        description: str = "",
        severity: str = "medium",
    ) -> dict:
        """Add a MITRE ATT&CK technique to the tenant registry."""
        tech = MitreTechnique(
            tenant_id=tenant_id,
            technique_id=technique_id,
            tactic=tactic.lower(),
            name=name,
            description=description,
            severity=severity,
        )
        self._techniques[tech.id] = tech
        self._tenant_techniques[tenant_id].append(tech.id)
        self._tech_index[tenant_id][technique_id] = tech.id

        logger.info(
            "[MITRE] Added technique %s (%s) — tactic=%s for %s",
            technique_id, name, tactic, tenant_id,
        )
        return tech.model_dump(mode="json")

    def list_techniques(
        self,
        tenant_id: str,
        tactic: str | None = None,
    ) -> list[dict]:
        """List registered techniques with optional tactic filter."""
        results = []
        for tid in self._tenant_techniques.get(tenant_id, []):
            tech = self._techniques.get(tid)
            if not tech:
                continue
            if tactic and tech.tactic != tactic.lower():
                continue
            results.append(tech.model_dump(mode="json"))
        return results

    # ------------------------------------------------------------------
    # Event Mapping
    # ------------------------------------------------------------------

    def map_event(
        self,
        tenant_id: str,
        event_type: str,
        indicators: dict | None = None,
    ) -> dict:
        """Map a security event to MITRE ATT&CK techniques.

        Uses indicator heuristics to determine the most likely technique
        and tactic classification.
        """
        indicators = indicators or {}
        matched_techniques = self._match_indicators(tenant_id, event_type, indicators)

        mappings_created = []
        for tech_id, tactic, confidence in matched_techniques:
            mapping = TechniqueMapping(
                tenant_id=tenant_id,
                event_type=event_type,
                technique_id=tech_id,
                tactic=tactic,
                confidence=confidence,
                indicators=indicators,
            )
            self._mappings[tenant_id].append(mapping)
            mappings_created.append(mapping.model_dump(mode="json"))

            # Update technique observation count
            internal_id = self._tech_index.get(tenant_id, {}).get(tech_id)
            if internal_id:
                tech = self._techniques.get(internal_id)
                if tech:
                    tech.times_observed += 1
                    tech.last_observed_at = datetime.now(timezone.utc)

        # Cap mapping history
        if len(self._mappings[tenant_id]) > 10000:
            self._mappings[tenant_id] = self._mappings[tenant_id][-10000:]

        logger.info(
            "[MITRE] Mapped event '%s' to %d techniques for %s",
            event_type, len(mappings_created), tenant_id,
        )
        return {
            "event_type": event_type,
            "mappings": mappings_created,
            "techniques_matched": len(mappings_created),
        }

    # ------------------------------------------------------------------
    # Coverage & Gap Analysis
    # ------------------------------------------------------------------

    def get_coverage(self, tenant_id: str) -> dict:
        """Analyse ATT&CK coverage across all tactics."""
        techniques = [
            self._techniques[tid]
            for tid in self._tenant_techniques.get(tenant_id, [])
            if tid in self._techniques
        ]

        by_tactic: dict[str, list[dict]] = defaultdict(list)
        for tech in techniques:
            by_tactic[tech.tactic].append({
                "technique_id": tech.technique_id,
                "name": tech.name,
                "detection_coverage": tech.detection_coverage,
                "times_observed": tech.times_observed,
            })

        tactic_coverage = {}
        for tactic in _TACTICS_ORDER:
            techs = by_tactic.get(tactic, [])
            avg_coverage = (
                round(sum(t["detection_coverage"] for t in techs) / len(techs), 1)
                if techs else 0.0
            )
            tactic_coverage[tactic] = {
                "techniques_count": len(techs),
                "avg_detection_coverage": avg_coverage,
                "techniques": techs,
            }

        total_coverage = (
            round(
                sum(t.detection_coverage for t in techniques) / max(len(techniques), 1),
                1,
            )
            if techniques else 0.0
        )

        return {
            "tenant_id": tenant_id,
            "total_techniques": len(techniques),
            "total_coverage_pct": total_coverage,
            "tactics_covered": sum(
                1 for t in _TACTICS_ORDER if by_tactic.get(t)
            ),
            "total_tactics": len(_TACTICS_ORDER),
            "by_tactic": tactic_coverage,
        }

    def get_gaps(self, tenant_id: str) -> dict:
        """Identify gaps in ATT&CK coverage."""
        techniques = [
            self._techniques[tid]
            for tid in self._tenant_techniques.get(tenant_id, [])
            if tid in self._techniques
        ]

        covered_tactics = {t.tactic for t in techniques}
        missing_tactics = [t for t in _TACTICS_ORDER if t not in covered_tactics]

        low_coverage = [
            {
                "technique_id": t.technique_id,
                "name": t.name,
                "tactic": t.tactic,
                "detection_coverage": t.detection_coverage,
            }
            for t in techniques
            if t.detection_coverage < 30.0
        ]

        never_observed = [
            {
                "technique_id": t.technique_id,
                "name": t.name,
                "tactic": t.tactic,
            }
            for t in techniques
            if t.times_observed == 0
        ]

        return {
            "tenant_id": tenant_id,
            "missing_tactics": missing_tactics,
            "low_coverage_techniques": low_coverage,
            "never_observed_techniques": never_observed,
            "gap_score": round(
                (len(missing_tactics) / max(len(_TACTICS_ORDER), 1)) * 100, 1,
            ),
        }

    # ------------------------------------------------------------------
    # Kill Chain
    # ------------------------------------------------------------------

    def get_kill_chain(self, tenant_id: str, incident_id: str) -> dict:
        """Reconstruct a kill chain from mapped events for an incident."""
        mappings = self._mappings.get(tenant_id, [])

        # Filter mappings related to the incident (via indicators)
        incident_mappings = [
            m for m in mappings
            if m.indicators.get("incident_id") == incident_id
        ]

        # Order by tactic position in kill chain
        tactic_order = {t: i for i, t in enumerate(_TACTICS_ORDER)}
        incident_mappings.sort(
            key=lambda m: tactic_order.get(m.tactic, 99),
        )

        chain = []
        for m in incident_mappings:
            chain.append({
                "tactic": m.tactic,
                "tactic_position": tactic_order.get(m.tactic, 99),
                "technique_id": m.technique_id,
                "event_type": m.event_type,
                "confidence": m.confidence,
                "mapped_at": m.mapped_at.isoformat(),
            })

        return {
            "incident_id": incident_id,
            "tenant_id": tenant_id,
            "chain_length": len(chain),
            "tactics_involved": list({m["tactic"] for m in chain}),
            "kill_chain": chain,
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return MITRE ATT&CK mapper statistics for a tenant."""
        techniques = [
            self._techniques[tid]
            for tid in self._tenant_techniques.get(tenant_id, [])
            if tid in self._techniques
        ]
        mappings = self._mappings.get(tenant_id, [])

        by_tactic: dict[str, int] = defaultdict(int)
        for t in techniques:
            by_tactic[t.tactic] += 1

        return {
            "total_techniques": len(techniques),
            "by_tactic": dict(by_tactic),
            "tactics_covered": len(by_tactic),
            "total_mappings": len(mappings),
            "total_observations": sum(t.times_observed for t in techniques),
            "avg_detection_coverage": round(
                sum(t.detection_coverage for t in techniques) / max(len(techniques), 1),
                1,
            ),
        }

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _match_indicators(
        self,
        tenant_id: str,
        event_type: str,
        indicators: dict,
    ) -> list[tuple[str, str, float]]:
        """Match event indicators to registered techniques.

        Returns list of (technique_id, tactic, confidence).
        """
        matches = []
        techniques = [
            self._techniques[tid]
            for tid in self._tenant_techniques.get(tenant_id, [])
            if tid in self._techniques
        ]

        # Simple keyword-based matching (production would use ML models)
        event_lower = event_type.lower()
        indicator_str = " ".join(str(v) for v in indicators.values()).lower()

        for tech in techniques:
            confidence = 0.0
            name_lower = tech.name.lower()
            desc_lower = tech.description.lower()

            # Check event type similarity
            if event_lower in name_lower or event_lower in desc_lower:
                confidence += 40.0
            # Check indicator overlap
            if any(kw in indicator_str for kw in name_lower.split()):
                confidence += 30.0
            # Check tactic relevance
            if tech.tactic in indicator_str:
                confidence += 20.0

            if confidence >= 30.0:
                matches.append((tech.technique_id, tech.tactic, min(confidence, 100.0)))

        # Sort by confidence descending
        matches.sort(key=lambda m: m[2], reverse=True)
        return matches[:5]  # Top 5 matches


# Module-level singleton
mitre_attack_mapper = MitreAttackMapper()
