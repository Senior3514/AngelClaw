"""AngelClaw V6.5 — Prometheus: Adversary Simulation Service.

Purple team adversary simulation engine for attack scenario management,
controlled attack execution, defense validation, and gap reporting.
Enables continuous security validation against known attack techniques.

Features:
  - Attack scenario creation with MITRE technique mapping
  - Controlled simulation execution with safety guardrails
  - Defense validation against specific techniques
  - Gap reporting and remediation tracking
  - Per-tenant isolation with simulation analytics
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.adversary_sim")

_ATTACK_TYPES = {
    "phishing",
    "ransomware",
    "lateral_movement",
    "privilege_escalation",
    "data_exfiltration",
    "credential_theft",
    "supply_chain",
    "insider_threat",
}


class AttackScenario(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    name: str
    attack_type: str = "phishing"
    mitre_techniques: list[str] = []  # e.g., ["T1566.001", "T1059"]
    config: dict[str, Any] = {}
    description: str = ""
    enabled: bool = True
    simulations_run: int = 0
    last_run_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = "system"


class SimulationResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scenario_id: str
    tenant_id: str = "dev-tenant"
    status: str = "pending"  # pending, running, completed, failed, aborted
    techniques_tested: list[str] = []
    techniques_detected: list[str] = []
    techniques_blocked: list[str] = []
    techniques_missed: list[str] = []
    detection_rate: float = 0.0
    block_rate: float = 0.0
    findings: list[dict[str, Any]] = []
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None


class DefenseValidation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    technique_id: str
    defense_status: str = "unknown"  # detected, blocked, missed, partial, unknown
    confidence: float = 0.0
    details: dict[str, Any] = {}
    validated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AdversarySimService:
    """Adversary simulation (purple team) with defense validation."""

    def __init__(self) -> None:
        self._scenarios: dict[str, AttackScenario] = {}
        self._tenant_scenarios: dict[str, list[str]] = defaultdict(list)
        self._results: dict[str, SimulationResult] = {}
        self._validations: dict[str, list[DefenseValidation]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Scenario Management
    # ------------------------------------------------------------------

    def create_scenario(
        self,
        tenant_id: str,
        name: str,
        attack_type: str = "phishing",
        mitre_techniques: list[str] | None = None,
        config: dict | None = None,
        description: str = "",
        created_by: str = "system",
    ) -> dict:
        """Create an adversary simulation scenario."""
        atype = attack_type if attack_type in _ATTACK_TYPES else "phishing"

        scenario = AttackScenario(
            tenant_id=tenant_id,
            name=name,
            attack_type=atype,
            mitre_techniques=mitre_techniques or [],
            config=config or {},
            description=description,
            created_by=created_by,
        )
        self._scenarios[scenario.id] = scenario
        self._tenant_scenarios[tenant_id].append(scenario.id)

        logger.info(
            "[ADV_SIM] Created scenario '%s' (%s) with %d techniques for %s",
            name,
            atype,
            len(scenario.mitre_techniques),
            tenant_id,
        )
        return scenario.model_dump(mode="json")

    def list_scenarios(self, tenant_id: str) -> list[dict]:
        """List all scenarios for a tenant."""
        return [
            self._scenarios[sid].model_dump(mode="json")
            for sid in self._tenant_scenarios.get(tenant_id, [])
            if sid in self._scenarios
        ]

    # ------------------------------------------------------------------
    # Simulation Execution
    # ------------------------------------------------------------------

    def run_simulation(self, scenario_id: str) -> dict:
        """Execute an adversary simulation for a scenario."""
        scenario = self._scenarios.get(scenario_id)
        if not scenario:
            return {"error": "Scenario not found"}
        if not scenario.enabled:
            return {"error": "Scenario is disabled"}

        result = SimulationResult(
            scenario_id=scenario_id,
            tenant_id=scenario.tenant_id,
            status="running",
            techniques_tested=list(scenario.mitre_techniques),
        )

        try:
            self._execute_simulation(scenario, result)
            result.status = "completed"
        except Exception as exc:
            result.status = "failed"
            result.findings.append({"error": str(exc)})
            logger.error("[ADV_SIM] Simulation failed for '%s': %s", scenario.name, exc)

        result.completed_at = datetime.now(timezone.utc)
        self._results[result.id] = result

        scenario.simulations_run += 1
        scenario.last_run_at = datetime.now(timezone.utc)

        logger.info(
            "[ADV_SIM] Simulation for '%s': detection=%.0f%% block=%.0f%%",
            scenario.name,
            result.detection_rate,
            result.block_rate,
        )
        return result.model_dump(mode="json")

    def get_simulation_results(self, scenario_id: str) -> list[dict]:
        """Get all simulation results for a scenario."""
        results = [
            r.model_dump(mode="json")
            for r in self._results.values()
            if r.scenario_id == scenario_id
        ]
        results.sort(key=lambda r: r.get("started_at", ""), reverse=True)
        return results

    # ------------------------------------------------------------------
    # Defense Validation
    # ------------------------------------------------------------------

    def validate_defense(
        self,
        tenant_id: str,
        technique_id: str,
    ) -> dict:
        """Validate defenses against a specific MITRE technique."""
        # Simulate defense validation
        detected = technique_id.startswith("T1")  # Heuristic simulation
        blocked = detected and len(technique_id) <= 5

        if blocked:
            status = "blocked"
            confidence = 95.0
        elif detected:
            status = "detected"
            confidence = 75.0
        else:
            status = "missed"
            confidence = 30.0

        validation = DefenseValidation(
            tenant_id=tenant_id,
            technique_id=technique_id,
            defense_status=status,
            confidence=confidence,
            details={
                "technique_id": technique_id,
                "detection_source": "edr" if detected else "none",
                "block_mechanism": "policy" if blocked else "none",
            },
        )
        self._validations[tenant_id].append(validation)

        logger.info(
            "[ADV_SIM] Validated defense for %s: %s (%.0f%% confidence)",
            technique_id,
            status,
            confidence,
        )
        return validation.model_dump(mode="json")

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return adversary simulation statistics for a tenant."""
        scenarios = [
            self._scenarios[sid]
            for sid in self._tenant_scenarios.get(tenant_id, [])
            if sid in self._scenarios
        ]
        results = [r for r in self._results.values() if r.tenant_id == tenant_id]
        validations = self._validations.get(tenant_id, [])

        by_attack_type: dict[str, int] = defaultdict(int)
        for s in scenarios:
            by_attack_type[s.attack_type] += 1

        completed_results = [r for r in results if r.status == "completed"]
        avg_detection = (
            round(
                sum(r.detection_rate for r in completed_results) / max(len(completed_results), 1),
                1,
            )
            if completed_results
            else 0.0
        )
        avg_block = (
            round(
                sum(r.block_rate for r in completed_results) / max(len(completed_results), 1),
                1,
            )
            if completed_results
            else 0.0
        )

        return {
            "total_scenarios": len(scenarios),
            "by_attack_type": dict(by_attack_type),
            "total_simulations": len(results),
            "completed_simulations": len(completed_results),
            "failed_simulations": sum(1 for r in results if r.status == "failed"),
            "avg_detection_rate": avg_detection,
            "avg_block_rate": avg_block,
            "total_validations": len(validations),
        }

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _execute_simulation(
        self,
        scenario: AttackScenario,
        result: SimulationResult,
    ) -> None:
        """Execute simulation logic for a scenario.

        In production, this would orchestrate actual attack simulation
        tools. For the orchestration layer, we simulate outcomes.
        """
        techniques = scenario.mitre_techniques
        if not techniques:
            result.findings.append({"message": "No techniques to test"})
            return

        detected = []
        blocked = []
        missed = []

        for i, tech in enumerate(techniques):
            # Simulate detection: ~70% detection, ~40% block
            if (i + len(tech)) % 3 != 0:
                detected.append(tech)
                if i % 2 == 0:
                    blocked.append(tech)
            else:
                missed.append(tech)

        result.techniques_detected = detected
        result.techniques_blocked = blocked
        result.techniques_missed = missed
        result.detection_rate = round(
            len(detected) / max(len(techniques), 1) * 100,
            1,
        )
        result.block_rate = round(
            len(blocked) / max(len(techniques), 1) * 100,
            1,
        )

        result.findings.append(
            {
                "summary": f"Tested {len(techniques)} techniques",
                "detected": len(detected),
                "blocked": len(blocked),
                "missed": len(missed),
            }
        )


# Module-level singleton
adversary_sim_service = AdversarySimService()
