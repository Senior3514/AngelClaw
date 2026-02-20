"""AngelClaw V4.2 — Nexus: Infrastructure-as-Code Security Scanner.

Scans Terraform, CloudFormation, Kubernetes YAML, Ansible, and Dockerfiles
for security misconfigurations and policy violations.
"""

from __future__ import annotations

import logging
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.iac_scanner")

# Built-in IaC security checks (pattern-based)
_IAC_RULES = [
    {
        "id": "IAC001",
        "title": "Wildcard IAM permissions",
        "severity": "critical",
        "pattern": r'"Action"\s*:\s*"\*"',
    },
    {
        "id": "IAC002",
        "title": "Public S3 bucket",
        "severity": "critical",
        "pattern": r"acl\s*=\s*\"public",
    },
    {
        "id": "IAC003",
        "title": "Unencrypted storage",
        "severity": "high",
        "pattern": r"encrypted\s*=\s*false",
    },
    {
        "id": "IAC004",
        "title": "Open security group (0.0.0.0/0)",
        "severity": "high",
        "pattern": r"0\.0\.0\.0/0",
    },
    {
        "id": "IAC005",
        "title": "Hardcoded secret in config",
        "severity": "critical",
        "pattern": r"(password|secret|api_key)\s*=\s*\"[^\"]{8,}\"",
    },
    {
        "id": "IAC006",
        "title": "Missing logging configuration",
        "severity": "medium",
        "pattern": r"logging\s*\{\s*\}",
    },
    {
        "id": "IAC007",
        "title": "Privileged container in K8s",
        "severity": "critical",
        "pattern": r"privileged:\s*true",
    },
    {
        "id": "IAC008",
        "title": "Root user in Dockerfile",
        "severity": "high",
        "pattern": r"USER\s+root",
    },
    {
        "id": "IAC009",
        "title": "Latest tag in container image",
        "severity": "medium",
        "pattern": r":latest",
    },
    {
        "id": "IAC010",
        "title": "Missing resource limits",
        "severity": "medium",
        "pattern": r"resources:\s*\{\s*\}",
    },
]


class IaCScanResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    source_type: str  # terraform, cloudformation, kubernetes, ansible, dockerfile
    source_path: str
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    findings: list[dict[str, Any]] = []
    passed_checks: int = 0
    failed_checks: int = 0
    status: str = "completed"
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IaCScannerService:
    """IaC security scanning engine."""

    def __init__(self) -> None:
        self._scans: dict[str, IaCScanResult] = {}
        self._tenant_scans: dict[str, list[str]] = defaultdict(list)

    def scan_content(
        self,
        tenant_id: str,
        source_type: str,
        source_path: str,
        content: str,
    ) -> dict:
        """Scan IaC content for security issues."""
        findings = []
        passed = 0
        for rule in _IAC_RULES:
            if re.search(rule["pattern"], content, re.IGNORECASE):
                findings.append(
                    {
                        "rule_id": rule["id"],
                        "title": rule["title"],
                        "severity": rule["severity"],
                        "line_hint": self._find_line(content, rule["pattern"]),
                    }
                )
            else:
                passed += 1

        critical = sum(1 for f in findings if f["severity"] == "critical")
        high = sum(1 for f in findings if f["severity"] == "high")

        result = IaCScanResult(
            tenant_id=tenant_id,
            source_type=source_type,
            source_path=source_path,
            findings_count=len(findings),
            critical_count=critical,
            high_count=high,
            findings=findings,
            passed_checks=passed,
            failed_checks=len(findings),
        )
        self._scans[result.id] = result
        self._tenant_scans[tenant_id].append(result.id)
        logger.info(
            "[IAC] Scanned %s (%s) — %d finding(s)", source_path, source_type, len(findings)
        )
        return result.model_dump(mode="json")

    def get_scan(self, scan_id: str) -> dict | None:
        s = self._scans.get(scan_id)
        return s.model_dump(mode="json") if s else None

    def list_scans(
        self, tenant_id: str, source_type: str | None = None, limit: int = 100
    ) -> list[dict]:
        results = []
        for sid in reversed(self._tenant_scans.get(tenant_id, [])):
            s = self._scans.get(sid)
            if not s:
                continue
            if source_type and s.source_type != source_type:
                continue
            results.append(s.model_dump(mode="json"))
            if len(results) >= limit:
                break
        return results

    def get_stats(self, tenant_id: str) -> dict:
        scans = [self._scans[s] for s in self._tenant_scans.get(tenant_id, []) if s in self._scans]
        return {
            "total_scans": len(scans),
            "total_findings": sum(s.findings_count for s in scans),
            "critical": sum(s.critical_count for s in scans),
            "high": sum(s.high_count for s in scans),
            "pass_rate": round(
                sum(s.passed_checks for s in scans)
                / max(sum(s.passed_checks + s.failed_checks for s in scans), 1)
                * 100,
                1,
            ),
        }

    def _find_line(self, content: str, pattern: str) -> int | None:
        for i, line in enumerate(content.split("\n"), 1):
            if re.search(pattern, line, re.IGNORECASE):
                return i
        return None


# Module-level singleton
iac_scanner_service = IaCScannerService()
