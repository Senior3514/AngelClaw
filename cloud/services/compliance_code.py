"""AngelClaw V5.0 — Transcendence: Compliance-as-Code Engine.

Manages compliance rules for frameworks (GDPR, HIPAA, PCI-DSS, SOC2, NIST,
ISO27001, CIS) with automated check execution and audit reporting.

Features:
  - Define compliance rules per framework and control
  - Run individual checks against system state
  - Execute full framework audits
  - Generate compliance reports with pass/fail summaries
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.compliance_code")

SUPPORTED_FRAMEWORKS = {
    "GDPR",
    "HIPAA",
    "PCI-DSS",
    "SOC2",
    "NIST",
    "ISO27001",
    "CIS",
}


class ComplianceRule(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    framework: str  # GDPR, HIPAA, PCI-DSS, SOC2, NIST, ISO27001, CIS
    control_id: str  # e.g., "HIPAA-164.312(a)(1)", "PCI-DSS-3.4"
    title: str
    description: str = ""
    severity: str = "medium"  # low, medium, high, critical
    check_type: str = "policy"  # policy, config, access, encryption, logging, network
    check_config: dict[str, Any] = {}  # rule parameters for evaluation
    enabled: bool = True
    last_result: str | None = None  # pass, fail, error, skipped
    last_checked_at: datetime | None = None
    created_by: str = "system"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CheckResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    rule_id: str
    framework: str
    control_id: str
    result: str  # pass, fail, error, skipped
    details: str = ""
    evidence: dict[str, Any] = {}
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ComplianceCodeService:
    """Compliance-as-code engine with rule management and audit execution."""

    def __init__(self) -> None:
        self._rules: dict[str, ComplianceRule] = {}
        self._tenant_rules: dict[str, list[str]] = defaultdict(list)
        self._results: dict[str, list[CheckResult]] = defaultdict(list)

    # -- Rule CRUD --

    def create_rule(
        self,
        tenant_id: str,
        framework: str,
        control_id: str,
        title: str,
        description: str = "",
        severity: str = "medium",
        check_type: str = "policy",
        check_config: dict | None = None,
        created_by: str = "system",
    ) -> dict:
        if framework not in SUPPORTED_FRAMEWORKS:
            return {
                "error": (
                    f"Unsupported framework: {framework}."
                    f" Supported: {sorted(SUPPORTED_FRAMEWORKS)}"
                )
            }

        rule = ComplianceRule(
            tenant_id=tenant_id,
            framework=framework,
            control_id=control_id,
            title=title,
            description=description,
            severity=severity,
            check_type=check_type,
            check_config=check_config or {},
            created_by=created_by,
        )
        self._rules[rule.id] = rule
        self._tenant_rules[tenant_id].append(rule.id)
        logger.info(
            "[COMPLIANCE] Created rule '%s' [%s/%s] for %s",
            title,
            framework,
            control_id,
            tenant_id,
        )
        return rule.model_dump(mode="json")

    def get_rule(self, rule_id: str) -> dict | None:
        rule = self._rules.get(rule_id)
        return rule.model_dump(mode="json") if rule else None

    def list_rules(
        self,
        tenant_id: str,
        framework: str | None = None,
        check_type: str | None = None,
    ) -> list[dict]:
        results = []
        for rid in self._tenant_rules.get(tenant_id, []):
            rule = self._rules.get(rid)
            if not rule:
                continue
            if framework and rule.framework != framework:
                continue
            if check_type and rule.check_type != check_type:
                continue
            results.append(rule.model_dump(mode="json"))
        results.sort(key=lambda r: (r.get("framework", ""), r.get("control_id", "")))
        return results

    def toggle_rule(self, rule_id: str, enabled: bool) -> dict | None:
        rule = self._rules.get(rule_id)
        if not rule:
            return None
        rule.enabled = enabled
        return rule.model_dump(mode="json")

    # -- Check Execution --

    def run_check(
        self,
        rule_id: str,
        system_state: dict | None = None,
    ) -> dict:
        """Evaluate a single compliance rule against provided system state."""
        rule = self._rules.get(rule_id)
        if not rule:
            return {"error": "Rule not found"}
        if not rule.enabled:
            return {"error": "Rule is disabled"}

        state = system_state or {}
        result, details, evidence = self._evaluate_rule(rule, state)

        check_result = CheckResult(
            tenant_id=rule.tenant_id,
            rule_id=rule.id,
            framework=rule.framework,
            control_id=rule.control_id,
            result=result,
            details=details,
            evidence=evidence,
        )

        self._results[rule.tenant_id].append(check_result)
        # Cap results per tenant
        if len(self._results[rule.tenant_id]) > 5000:
            self._results[rule.tenant_id] = self._results[rule.tenant_id][-5000:]

        rule.last_result = result
        rule.last_checked_at = datetime.now(timezone.utc)

        logger.info(
            "[COMPLIANCE] Check %s/%s: %s",
            rule.framework,
            rule.control_id,
            result,
        )
        return check_result.model_dump(mode="json")

    def run_framework_audit(
        self,
        tenant_id: str,
        framework: str,
        system_state: dict | None = None,
    ) -> dict:
        """Run all enabled rules for a framework and return aggregated results."""
        state = system_state or {}
        rules = [
            self._rules[rid]
            for rid in self._tenant_rules.get(tenant_id, [])
            if rid in self._rules
            and self._rules[rid].framework == framework
            and self._rules[rid].enabled
        ]

        if not rules:
            return {
                "framework": framework,
                "total_rules": 0,
                "results": [],
                "summary": {},
            }

        results = []
        for rule in rules:
            result, details, evidence = self._evaluate_rule(rule, state)
            check_result = CheckResult(
                tenant_id=tenant_id,
                rule_id=rule.id,
                framework=rule.framework,
                control_id=rule.control_id,
                result=result,
                details=details,
                evidence=evidence,
            )
            self._results[tenant_id].append(check_result)
            rule.last_result = result
            rule.last_checked_at = datetime.now(timezone.utc)
            results.append(check_result.model_dump(mode="json"))

        # Summarize
        summary: dict[str, int] = defaultdict(int)
        for r in results:
            summary[r["result"]] += 1

        total = len(results)
        passed = summary.get("pass", 0)
        compliance_pct = round(passed / max(total, 1) * 100, 1)

        logger.info(
            "[COMPLIANCE] Audit %s for %s: %d/%d passed (%.1f%%)",
            framework,
            tenant_id,
            passed,
            total,
            compliance_pct,
        )
        return {
            "framework": framework,
            "total_rules": total,
            "compliance_percentage": compliance_pct,
            "summary": dict(summary),
            "results": results,
        }

    def get_compliance_report(
        self,
        tenant_id: str,
        framework: str | None = None,
    ) -> dict:
        """Generate a compliance report from the latest check results."""
        rules = [
            self._rules[rid] for rid in self._tenant_rules.get(tenant_id, []) if rid in self._rules
        ]
        if framework:
            rules = [r for r in rules if r.framework == framework]

        frameworks_data: dict[str, dict] = defaultdict(
            lambda: {
                "total": 0,
                "pass": 0,
                "fail": 0,
                "error": 0,
                "skipped": 0,
                "unchecked": 0,
            }
        )

        for rule in rules:
            fw = frameworks_data[rule.framework]
            fw["total"] += 1
            if rule.last_result is None:
                fw["unchecked"] += 1
            elif rule.last_result in fw:
                fw[rule.last_result] += 1

        report_frameworks = {}
        for fw_name, counts in frameworks_data.items():
            checked = counts["total"] - counts["unchecked"]
            pct = round(counts["pass"] / max(checked, 1) * 100, 1)
            report_frameworks[fw_name] = {
                **counts,
                "compliance_percentage": pct,
            }

        return {
            "tenant_id": tenant_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "frameworks": report_frameworks,
            "total_rules": len(rules),
        }

    # -- Stats --

    def get_stats(self, tenant_id: str) -> dict:
        rules = [self._rules[r] for r in self._tenant_rules.get(tenant_id, []) if r in self._rules]
        by_framework: dict[str, int] = defaultdict(int)
        by_result: dict[str, int] = defaultdict(int)
        for rule in rules:
            by_framework[rule.framework] += 1
            if rule.last_result:
                by_result[rule.last_result] += 1

        total_checks = len(self._results.get(tenant_id, []))

        return {
            "total_rules": len(rules),
            "enabled_rules": sum(1 for r in rules if r.enabled),
            "by_framework": dict(by_framework),
            "latest_results": dict(by_result),
            "total_checks_run": total_checks,
        }

    # -- Internal Evaluation --

    def _evaluate_rule(
        self,
        rule: ComplianceRule,
        state: dict,
    ) -> tuple[str, str, dict]:
        """Evaluate a compliance rule against system state.

        Returns (result, details, evidence).
        """
        cfg = rule.check_config
        check_type = rule.check_type

        try:
            if check_type == "policy":
                return self._check_policy(cfg, state)
            elif check_type == "config":
                return self._check_config(cfg, state)
            elif check_type == "access":
                return self._check_access(cfg, state)
            elif check_type == "encryption":
                return self._check_encryption(cfg, state)
            elif check_type == "logging":
                return self._check_logging(cfg, state)
            elif check_type == "network":
                return self._check_network(cfg, state)
            else:
                return ("skipped", f"Unknown check type: {check_type}", {})
        except Exception as exc:
            return ("error", f"Check failed: {exc}", {"exception": str(exc)})

    def _check_policy(self, cfg: dict, state: dict) -> tuple[str, str, dict]:
        required_field = cfg.get("required_field", "")
        expected_value = cfg.get("expected_value")

        if not required_field:
            return ("skipped", "No required_field configured", {})

        actual = state.get(required_field)
        if actual is None:
            return (
                "fail",
                f"Field '{required_field}' not found in system state",
                {"field": required_field},
            )

        if expected_value is not None and str(actual) != str(expected_value):
            return (
                "fail",
                f"Field '{required_field}' is '{actual}', expected '{expected_value}'",
                {"field": required_field, "actual": actual, "expected": expected_value},
            )
        return (
            "pass",
            f"Field '{required_field}' = '{actual}'",
            {"field": required_field, "value": actual},
        )

    def _check_config(self, cfg: dict, state: dict) -> tuple[str, str, dict]:
        setting = cfg.get("setting", "")
        min_value = cfg.get("min_value")
        max_value = cfg.get("max_value")

        actual = state.get(setting)
        if actual is None:
            return ("fail", f"Setting '{setting}' not found", {"setting": setting})

        try:
            num_actual = float(actual)
        except (ValueError, TypeError):
            return ("fail", f"Setting '{setting}' is not numeric: {actual}", {"setting": setting})

        if min_value is not None and num_actual < float(min_value):
            return (
                "fail",
                f"'{setting}' = {actual} (min: {min_value})",
                {"setting": setting, "actual": actual},
            )
        if max_value is not None and num_actual > float(max_value):
            return (
                "fail",
                f"'{setting}' = {actual} (max: {max_value})",
                {"setting": setting, "actual": actual},
            )

        return (
            "pass",
            f"'{setting}' = {actual} within bounds",
            {"setting": setting, "value": actual},
        )

    def _check_access(self, cfg: dict, state: dict) -> tuple[str, str, dict]:
        required_mfa = cfg.get("require_mfa", False)
        max_session_hours = cfg.get("max_session_hours")

        mfa_enabled = state.get("mfa_enabled", False)
        session_hours = state.get("session_timeout_hours")

        if required_mfa and not mfa_enabled:
            return ("fail", "MFA is not enabled", {"mfa_enabled": False})
        if max_session_hours and session_hours is not None:
            if float(session_hours) > float(max_session_hours):
                return (
                    "fail",
                    f"Session timeout {session_hours}h exceeds max {max_session_hours}h",
                    {},
                )

        return ("pass", "Access controls compliant", {"mfa_enabled": mfa_enabled})

    def _check_encryption(self, cfg: dict, state: dict) -> tuple[str, str, dict]:
        require_at_rest = cfg.get("require_at_rest", False)
        require_in_transit = cfg.get("require_in_transit", False)

        at_rest = state.get("encryption_at_rest", False)
        in_transit = state.get("encryption_in_transit", False)

        failures = []
        if require_at_rest and not at_rest:
            failures.append("encryption_at_rest is disabled")
        if require_in_transit and not in_transit:
            failures.append("encryption_in_transit is disabled")

        if failures:
            return ("fail", "; ".join(failures), {"at_rest": at_rest, "in_transit": in_transit})
        return (
            "pass",
            "Encryption requirements met",
            {"at_rest": at_rest, "in_transit": in_transit},
        )

    def _check_logging(self, cfg: dict, state: dict) -> tuple[str, str, dict]:
        required_sources = cfg.get("required_sources", [])
        min_retention_days = cfg.get("min_retention_days")

        active_sources = state.get("log_sources", [])
        retention_days = state.get("log_retention_days")

        missing = [s for s in required_sources if s not in active_sources]
        if missing:
            return ("fail", f"Missing log sources: {missing}", {"missing": missing})

        if min_retention_days and retention_days is not None:
            if int(retention_days) < int(min_retention_days):
                return ("fail", f"Retention {retention_days}d < required {min_retention_days}d", {})

        return ("pass", "Logging requirements met", {"sources": active_sources})

    def _check_network(self, cfg: dict, state: dict) -> tuple[str, str, dict]:
        blocked_ports = cfg.get("blocked_ports", [])
        open_ports = state.get("open_ports", [])

        violations = [p for p in blocked_ports if p in open_ports]
        if violations:
            return ("fail", f"Prohibited ports open: {violations}", {"violations": violations})
        return ("pass", "Network controls compliant", {"open_ports": open_ports})


# Module-level singleton
compliance_code_service = ComplianceCodeService()
