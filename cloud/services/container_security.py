"""AngelClaw V4.2 — Nexus: Container Security Service.

Scans container images and runtime configurations for vulnerabilities,
policy violations, and misconfigurations.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.container_security")

# Built-in container policy checks
_CONTAINER_CHECKS = [
    {
        "id": "CS001",
        "title": "Running as root",
        "severity": "high",
        "check": lambda c: c.get("user") == "root",
    },
    {
        "id": "CS002",
        "title": "Privileged mode enabled",
        "severity": "critical",
        "check": lambda c: c.get("privileged", False),
    },
    {
        "id": "CS003",
        "title": "Host network mode",
        "severity": "high",
        "check": lambda c: c.get("network_mode") == "host",
    },
    {
        "id": "CS004",
        "title": "No resource limits",
        "severity": "medium",
        "check": lambda c: not c.get("resource_limits"),
    },
    {
        "id": "CS005",
        "title": "Writable root filesystem",
        "severity": "medium",
        "check": lambda c: not c.get("read_only_rootfs", False),
    },
    {
        "id": "CS006",
        "title": "No health check",
        "severity": "low",
        "check": lambda c: not c.get("healthcheck"),
    },
    {
        "id": "CS007",
        "title": "Host PID namespace",
        "severity": "high",
        "check": lambda c: c.get("pid_mode") == "host",
    },
    {
        "id": "CS008",
        "title": "Sensitive mount detected",
        "severity": "critical",
        "check": lambda c: any("/etc" in m or "/var/run/docker" in m for m in c.get("mounts", [])),
    },
]


class ContainerScan(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    image_name: str
    image_tag: str | None = None
    image_digest: str | None = None
    scan_type: str = "image"  # image, runtime, config
    vulnerabilities_found: int = 0
    critical_count: int = 0
    high_count: int = 0
    findings: list[dict[str, Any]] = []
    policy_violations: list[dict[str, Any]] = []
    status: str = "completed"
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ContainerSecurityService:
    """Container image and runtime security scanning."""

    def __init__(self) -> None:
        self._scans: dict[str, ContainerScan] = {}
        self._tenant_scans: dict[str, list[str]] = defaultdict(list)

    def scan_image(
        self,
        tenant_id: str,
        image_name: str,
        image_tag: str | None = None,
        config: dict | None = None,
    ) -> dict:
        """Scan a container image for vulnerabilities and policy violations."""
        config = config or {}
        violations = []
        for check in _CONTAINER_CHECKS:
            if check["check"](config):
                violations.append(
                    {
                        "check_id": check["id"],
                        "title": check["title"],
                        "severity": check["severity"],
                    }
                )

        critical = sum(1 for v in violations if v["severity"] == "critical")
        high = sum(1 for v in violations if v["severity"] == "high")

        scan = ContainerScan(
            tenant_id=tenant_id,
            image_name=image_name,
            image_tag=image_tag,
            scan_type="image",
            vulnerabilities_found=len(violations),
            critical_count=critical,
            high_count=high,
            findings=[],
            policy_violations=violations,
        )
        self._scans[scan.id] = scan
        self._tenant_scans[tenant_id].append(scan.id)
        logger.info(
            "[CONTAINER] Scanned %s:%s — %d violation(s)",
            image_name,
            image_tag or "latest",
            len(violations),
        )
        return scan.model_dump(mode="json")

    def scan_runtime(
        self,
        tenant_id: str,
        container_id: str,
        runtime_config: dict,
    ) -> dict:
        """Scan a running container's runtime configuration."""
        violations = []
        for check in _CONTAINER_CHECKS:
            if check["check"](runtime_config):
                violations.append(
                    {
                        "check_id": check["id"],
                        "title": check["title"],
                        "severity": check["severity"],
                    }
                )

        scan = ContainerScan(
            tenant_id=tenant_id,
            image_name=runtime_config.get("image", container_id),
            scan_type="runtime",
            vulnerabilities_found=len(violations),
            critical_count=sum(1 for v in violations if v["severity"] == "critical"),
            high_count=sum(1 for v in violations if v["severity"] == "high"),
            policy_violations=violations,
        )
        self._scans[scan.id] = scan
        self._tenant_scans[tenant_id].append(scan.id)
        return scan.model_dump(mode="json")

    def get_scan(self, scan_id: str) -> dict | None:
        s = self._scans.get(scan_id)
        return s.model_dump(mode="json") if s else None

    def list_scans(
        self, tenant_id: str, scan_type: str | None = None, limit: int = 100
    ) -> list[dict]:
        results = []
        for sid in reversed(self._tenant_scans.get(tenant_id, [])):
            s = self._scans.get(sid)
            if not s:
                continue
            if scan_type and s.scan_type != scan_type:
                continue
            results.append(s.model_dump(mode="json"))
            if len(results) >= limit:
                break
        return results

    def get_stats(self, tenant_id: str) -> dict:
        scans = [self._scans[s] for s in self._tenant_scans.get(tenant_id, []) if s in self._scans]
        return {
            "total_scans": len(scans),
            "total_violations": sum(s.vulnerabilities_found for s in scans),
            "critical_findings": sum(s.critical_count for s in scans),
            "high_findings": sum(s.high_count for s in scans),
            "by_type": {
                t: sum(1 for s in scans if s.scan_type == t) for t in ("image", "runtime", "config")
            },
        }


# Module-level singleton
container_security_service = ContainerSecurityService()
