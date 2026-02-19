"""AngelClaw V4.2 — Nexus: CI/CD Security Gate Service.

Provides security gate checks for CI/CD pipelines with pass/fail/warn
decisions based on configurable policies.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.cicd_gate")


class CICDGateResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    pipeline_name: str
    pipeline_run_id: str | None = None
    gate_type: str  # pre_deploy, post_build, pre_merge, runtime
    decision: str = "pass"  # pass, fail, warn
    checks_passed: int = 0
    checks_failed: int = 0
    findings: list[dict[str, Any]] = []
    policy_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CICDGateService:
    """CI/CD pipeline security gate engine."""

    def __init__(self) -> None:
        self._results: dict[str, CICDGateResult] = {}
        self._tenant_results: dict[str, list[str]] = defaultdict(list)
        self._policies: dict[str, dict] = {}  # policy_id -> policy config

    def create_policy(self, tenant_id: str, name: str, rules: list[dict]) -> dict:
        policy_id = str(uuid.uuid4())
        policy = {
            "id": policy_id,
            "tenant_id": tenant_id,
            "name": name,
            "rules": rules,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._policies[policy_id] = policy
        return policy

    def evaluate_gate(
        self,
        tenant_id: str,
        pipeline_name: str,
        gate_type: str,
        artifacts: dict,
        pipeline_run_id: str | None = None,
        policy_id: str | None = None,
    ) -> dict:
        """Evaluate a CI/CD security gate check."""
        findings = []
        passed = 0
        failed = 0

        # Built-in checks
        checks = [
            ("No critical vulnerabilities", artifacts.get("critical_vulns", 0) == 0, "critical"),
            ("No high vulnerabilities", artifacts.get("high_vulns", 0) <= 2, "high"),
            ("No secrets in code", not artifacts.get("secrets_found", False), "critical"),
            ("Dependencies up to date", not artifacts.get("outdated_deps", False), "medium"),
            ("Container scan passed", artifacts.get("container_scan_pass", True), "high"),
            ("IaC scan passed", artifacts.get("iac_scan_pass", True), "high"),
            ("Unit tests passed", artifacts.get("tests_passed", True), "medium"),
            ("Code coverage adequate", artifacts.get("coverage", 100) >= 70, "low"),
        ]

        for title, passes, severity in checks:
            if passes:
                passed += 1
            else:
                failed += 1
                findings.append({"title": title, "severity": severity, "status": "failed"})

        # Decision logic
        critical_fails = sum(1 for f in findings if f["severity"] == "critical")
        high_fails = sum(1 for f in findings if f["severity"] == "high")
        if critical_fails > 0:
            decision = "fail"
        elif high_fails > 0:
            decision = "warn"
        else:
            decision = "pass"

        result = CICDGateResult(
            tenant_id=tenant_id,
            pipeline_name=pipeline_name,
            pipeline_run_id=pipeline_run_id,
            gate_type=gate_type,
            decision=decision,
            checks_passed=passed,
            checks_failed=failed,
            findings=findings,
            policy_id=policy_id,
        )
        self._results[result.id] = result
        self._tenant_results[tenant_id].append(result.id)
        logger.info("[CICD] Gate %s for %s: %s (%d pass, %d fail)", gate_type, pipeline_name, decision, passed, failed)
        return result.model_dump(mode="json")

    def get_result(self, result_id: str) -> dict | None:
        r = self._results.get(result_id)
        return r.model_dump(mode="json") if r else None

    def list_results(self, tenant_id: str, pipeline_name: str | None = None, limit: int = 100) -> list[dict]:
        results = []
        for rid in reversed(self._tenant_results.get(tenant_id, [])):
            r = self._results.get(rid)
            if not r:
                continue
            if pipeline_name and r.pipeline_name != pipeline_name:
                continue
            results.append(r.model_dump(mode="json"))
            if len(results) >= limit:
                break
        return results

    def get_stats(self, tenant_id: str) -> dict:
        results = [self._results[r] for r in self._tenant_results.get(tenant_id, []) if r in self._results]
        return {
            "total_evaluations": len(results),
            "passed": sum(1 for r in results if r.decision == "pass"),
            "warned": sum(1 for r in results if r.decision == "warn"),
            "failed": sum(1 for r in results if r.decision == "fail"),
            "pass_rate": round(sum(1 for r in results if r.decision == "pass") / max(len(results), 1) * 100, 1),
        }


# Module-level singleton
cicd_gate_service = CICDGateService()
