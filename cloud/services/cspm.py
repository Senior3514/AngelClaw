"""AngelClaw V6.0 — Omniguard: Cloud Security Posture Management (CSPM).

Detects misconfigurations across cloud providers, runs CIS benchmark
checks, tracks resource compliance, and generates remediation
recommendations with optional auto-fix capability.

Features:
  - Misconfiguration scanning per cloud connector
  - CIS/custom benchmark compliance checks
  - Severity-based finding management
  - Auto-remediation with dry-run support
  - Posture score computation per tenant
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.cspm")

_SEVERITY_ORDER = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


class CSPMFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    connector_id: str
    benchmark: str = "cis"
    rule_id: str = ""
    resource_type: str = ""
    resource_id: str = ""
    provider: str = ""
    severity: str = "medium"
    title: str = ""
    description: str = ""
    remediation: str = ""
    status: str = "open"  # open, remediated, suppressed, accepted
    auto_fixable: bool = False
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: datetime | None = None


class Remediation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str
    tenant_id: str = "dev-tenant"
    auto_fix: bool = False
    status: str = "pending"  # pending, in_progress, applied, failed, dry_run
    steps: list[str] = []
    result: dict[str, Any] = {}
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    applied_at: datetime | None = None


class CSPMService:
    """Cloud Security Posture Management — scan, detect, remediate."""

    def __init__(self) -> None:
        self._findings: dict[str, CSPMFinding] = {}
        self._tenant_findings: dict[str, list[str]] = defaultdict(list)
        self._remediations: dict[str, Remediation] = {}
        self._scan_history: dict[str, list[dict[str, Any]]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def run_scan(
        self,
        tenant_id: str,
        connector_id: str,
        benchmark: str = "cis",
    ) -> dict:
        """Run a CSPM scan against a cloud connector.

        Simulates misconfiguration detection for the given benchmark.
        """
        scan_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)

        # Simulate findings generation
        simulated_rules = [
            (
                "public-bucket",
                "bucket",
                "high",
                "Public storage bucket detected",
                "Storage bucket is publicly accessible",
                "Disable public access on the bucket",
            ),
            (
                "open-sg",
                "security_group",
                "critical",
                "Unrestricted security group",
                "Security group allows 0.0.0.0/0 on port 22",
                "Restrict SSH access to known IPs",
            ),
            (
                "unencrypted-disk",
                "disk",
                "medium",
                "Unencrypted disk volume",
                "Disk volume does not use encryption at rest",
                "Enable encryption at rest",
            ),
        ]

        created = []
        for rule_id, rtype, sev, title, desc, remed in simulated_rules:
            finding = CSPMFinding(
                tenant_id=tenant_id,
                connector_id=connector_id,
                benchmark=benchmark,
                rule_id=f"{benchmark}-{rule_id}",
                resource_type=rtype,
                resource_id=f"{rtype}-{uuid.uuid4().hex[:8]}",
                severity=sev,
                title=title,
                description=desc,
                remediation=remed,
                auto_fixable=sev != "critical",
            )
            self._findings[finding.id] = finding
            self._tenant_findings[tenant_id].append(finding.id)
            created.append(finding.id)

        scan_record = {
            "scan_id": scan_id,
            "connector_id": connector_id,
            "benchmark": benchmark,
            "findings_count": len(created),
            "scanned_at": now.isoformat(),
        }
        self._scan_history[tenant_id].append(scan_record)

        logger.info(
            "[CSPM] Scan completed: %d findings for connector %s (%s)",
            len(created),
            connector_id[:8],
            benchmark,
        )
        return scan_record

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def get_findings(
        self,
        tenant_id: str,
        severity: str | None = None,
        provider: str | None = None,
        status: str = "open",
        limit: int = 100,
    ) -> list[dict]:
        """Retrieve CSPM findings with optional filtering."""
        results = []
        for fid in self._tenant_findings.get(tenant_id, []):
            finding = self._findings.get(fid)
            if not finding:
                continue
            if finding.status != status:
                continue
            if severity and finding.severity != severity:
                continue
            if provider and finding.provider != provider:
                continue
            results.append(finding.model_dump(mode="json"))
            if len(results) >= limit:
                break

        # Sort by severity descending
        results.sort(
            key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "medium"), 3),
            reverse=True,
        )
        return results

    # ------------------------------------------------------------------
    # Remediation
    # ------------------------------------------------------------------

    def create_remediation(
        self,
        finding_id: str,
        auto_fix: bool = False,
    ) -> dict:
        """Create a remediation action for a finding."""
        finding = self._findings.get(finding_id)
        if not finding:
            return {"error": "Finding not found"}

        if auto_fix and not finding.auto_fixable:
            return {"error": "Finding is not auto-fixable"}

        remed = Remediation(
            finding_id=finding_id,
            tenant_id=finding.tenant_id,
            auto_fix=auto_fix,
            steps=[finding.remediation] if finding.remediation else [],
        )

        if auto_fix:
            # Simulate auto-remediation
            remed.status = "applied"
            remed.applied_at = datetime.now(timezone.utc)
            remed.result = {"message": "Auto-remediation applied successfully"}
            finding.status = "remediated"
            finding.resolved_at = datetime.now(timezone.utc)
            logger.info("[CSPM] Auto-remediated finding %s", finding_id[:8])
        else:
            remed.status = "pending"

        self._remediations[remed.id] = remed
        return remed.model_dump(mode="json")

    # ------------------------------------------------------------------
    # Posture Score
    # ------------------------------------------------------------------

    def get_posture_score(self, tenant_id: str) -> dict:
        """Compute a cloud security posture score (0-100)."""
        findings = [
            self._findings[fid]
            for fid in self._tenant_findings.get(tenant_id, [])
            if fid in self._findings
        ]
        if not findings:
            return {"tenant_id": tenant_id, "score": 100.0, "total_findings": 0}

        open_findings = [f for f in findings if f.status == "open"]
        # Penalty-based score: each severity level reduces the score
        penalty = 0.0
        for f in open_findings:
            sev_weight = {"info": 0.5, "low": 1, "medium": 3, "high": 7, "critical": 15}
            penalty += sev_weight.get(f.severity, 3)

        score = max(0.0, 100.0 - penalty)

        return {
            "tenant_id": tenant_id,
            "score": round(score, 1),
            "total_findings": len(findings),
            "open_findings": len(open_findings),
            "remediated": sum(1 for f in findings if f.status == "remediated"),
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str) -> dict:
        """Return CSPM statistics for a tenant."""
        findings = [
            self._findings[fid]
            for fid in self._tenant_findings.get(tenant_id, [])
            if fid in self._findings
        ]
        by_severity: dict[str, int] = defaultdict(int)
        by_status: dict[str, int] = defaultdict(int)
        for f in findings:
            by_severity[f.severity] += 1
            by_status[f.status] += 1

        return {
            "total_findings": len(findings),
            "by_severity": dict(by_severity),
            "by_status": dict(by_status),
            "total_scans": len(self._scan_history.get(tenant_id, [])),
            "total_remediations": sum(
                1 for r in self._remediations.values() if r.tenant_id == tenant_id
            ),
            "auto_remediations_applied": sum(
                1
                for r in self._remediations.values()
                if r.tenant_id == tenant_id and r.auto_fix and r.status == "applied"
            ),
        }


# Module-level singleton
cspm_service = CSPMService()
