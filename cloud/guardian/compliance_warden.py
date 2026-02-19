"""AngelClaw – Compliance Warden (Paladin).

Monitors for regulatory compliance violations: unencrypted transfers,
access control issues, retention breaches, and encryption gaps.
Part of the Angel Legion.
"""

from __future__ import annotations

import logging
import re
from collections import Counter

from cloud.guardian.base_agent import SubAgent
from cloud.guardian.models import (
    AgentResult,
    AgentTask,
    AgentType,
    Permission,
    ThreatIndicator,
)

logger = logging.getLogger("angelgrid.cloud.guardian.compliance_warden")

_UNENCRYPTED_RE = re.compile(
    r"(?i)(http://|ftp://|telnet://|plain.?text|unencrypted|no.?tls|no.?ssl)"
)
_ACCESS_VIOLATION_RE = re.compile(
    r"(?i)(unauthori[sz]ed|access.denied|permission.denied|forbidden|privilege.escalat)"
)
_RETENTION_RE = re.compile(
    r"(?i)(retention.breach|data.delet|purge.fail|expir.policy|retention.violat)"
)
_ENCRYPTION_GAP_RE = re.compile(
    r"(?i)(weak.cipher|deprecated.algo|md5|sha1[^0-9]|des[^c]|rc4|no.encrypt)"
)

_COMPLIANCE_TYPES = frozenset({
    "compliance.unencrypted_transfer",
    "compliance.access_violation",
    "compliance.retention_breach",
    "compliance.encryption_gap",
    "compliance.audit_gap",
    "compliance.data_exposure",
    "compliance.policy_violation",
})


class ComplianceWarden(SubAgent):
    """Paladin — watches for regulatory and compliance violations."""

    def __init__(self) -> None:
        super().__init__(
            agent_type=AgentType.COMPLIANCE,
            permissions={
                Permission.READ_EVENTS,
                Permission.READ_AGENTS,
                Permission.READ_COMPLIANCE,
            },
        )

    async def handle_task(self, task: AgentTask) -> AgentResult:
        """Analyze events for compliance violations.

        Expected payload:
            events: list[dict] — serialized events
            window_seconds: int
        """
        events = task.payload.get("events", [])
        indicators: list[ThreatIndicator] = []

        compliance_events = [
            e for e in events
            if e.get("category") == "compliance" or e.get("type", "") in _COMPLIANCE_TYPES
        ]

        # Check for unencrypted data transfers
        unencrypted = []
        for e in events:
            details_str = str(e.get("details", {}))
            cmd = (e.get("details") or {}).get("command", "") or ""
            source = e.get("source", "") or ""
            combined = f"{details_str} {cmd} {source}"
            if _UNENCRYPTED_RE.search(combined):
                unencrypted.append(e)

        if unencrypted:
            indicators.append(ThreatIndicator(
                indicator_type="compliance_violation",
                pattern_name="unencrypted_transfer",
                severity="high",
                confidence=0.85,
                description=(
                    f"Detected {len(unencrypted)} event(s) involving unencrypted "
                    "data transfers. This may violate data protection regulations "
                    "(GDPR Art. 32, HIPAA, PCI DSS)."
                ),
                related_event_ids=[e.get("id", "") for e in unencrypted[:5]],
                metadata={
                    "title": "Unencrypted Data Transfer Detected",
                    "category": "compliance",
                    "mitigations": [
                        "Enforce TLS/SSL for all data transfers",
                        "Audit and upgrade deprecated protocols",
                        "Enable encryption-in-transit policies",
                    ],
                },
            ))

        # Check for access control violations
        access_violations = []
        for e in events:
            details_str = str(e.get("details", {}))
            etype = e.get("type", "") or ""
            combined = f"{details_str} {etype}"
            if _ACCESS_VIOLATION_RE.search(combined):
                access_violations.append(e)

        if len(access_violations) >= 2:
            indicators.append(ThreatIndicator(
                indicator_type="compliance_violation",
                pattern_name="access_control_violation",
                severity="high" if len(access_violations) >= 5 else "medium",
                confidence=0.80,
                description=(
                    f"Detected {len(access_violations)} access control violation(s). "
                    "Repeated unauthorized access attempts may indicate "
                    "privilege escalation or misconfigured permissions."
                ),
                related_event_ids=[e.get("id", "") for e in access_violations[:5]],
                metadata={
                    "title": "Access Control Violations Detected",
                    "category": "compliance",
                    "mitigations": [
                        "Review and tighten RBAC permissions",
                        "Audit user access patterns",
                        "Implement principle of least privilege",
                    ],
                },
            ))

        # Check for retention policy breaches
        retention_issues = []
        for e in events:
            details_str = str(e.get("details", {}))
            etype = e.get("type", "") or ""
            if _RETENTION_RE.search(f"{details_str} {etype}"):
                retention_issues.append(e)

        if retention_issues:
            indicators.append(ThreatIndicator(
                indicator_type="compliance_violation",
                pattern_name="retention_breach",
                severity="medium",
                confidence=0.75,
                description=(
                    f"Detected {len(retention_issues)} event(s) indicating data retention "
                    "policy violations. Data may be retained beyond required periods "
                    "or deleted prematurely."
                ),
                related_event_ids=[e.get("id", "") for e in retention_issues[:5]],
                metadata={
                    "title": "Data Retention Policy Breach",
                    "category": "compliance",
                    "mitigations": [
                        "Review data retention policies",
                        "Implement automated data lifecycle management",
                        "Audit data deletion processes",
                    ],
                },
            ))

        # Check for encryption gaps
        encryption_gaps = []
        for e in events:
            details_str = str(e.get("details", {}))
            cmd = (e.get("details") or {}).get("command", "") or ""
            if _ENCRYPTION_GAP_RE.search(f"{details_str} {cmd}"):
                encryption_gaps.append(e)

        if encryption_gaps:
            indicators.append(ThreatIndicator(
                indicator_type="compliance_violation",
                pattern_name="encryption_gap",
                severity="high",
                confidence=0.85,
                description=(
                    f"Detected {len(encryption_gaps)} event(s) with weak or deprecated "
                    "encryption. Weak ciphers (MD5, SHA1, DES, RC4) violate "
                    "modern security standards."
                ),
                related_event_ids=[e.get("id", "") for e in encryption_gaps[:5]],
                metadata={
                    "title": "Encryption Compliance Gap",
                    "category": "compliance",
                    "mitigations": [
                        "Upgrade to AES-256 or ChaCha20 encryption",
                        "Replace SHA1/MD5 with SHA-256 or better",
                        "Enforce minimum TLS 1.2",
                    ],
                },
            ))

        # Check for audit logging gaps
        cat_counter: Counter[str] = Counter(e.get("category", "") for e in events)
        if len(events) >= 10 and cat_counter.get("auth", 0) >= 3:
            auth_events_with_logs = [
                e for e in events
                if e.get("category") == "auth" and (e.get("details") or {}).get("logged")
            ]
            if len(auth_events_with_logs) < cat_counter["auth"] * 0.5:
                indicators.append(ThreatIndicator(
                    indicator_type="compliance_violation",
                    pattern_name="audit_logging_gap",
                    severity="medium",
                    confidence=0.70,
                    description=(
                        "Less than 50% of authentication events have proper audit logging. "
                        "This may violate SOC 2, HIPAA, and PCI DSS audit trail requirements."
                    ),
                    related_event_ids=[],
                    metadata={
                        "title": "Audit Logging Gap Detected",
                        "category": "compliance",
                        "mitigations": [
                            "Enable comprehensive audit logging for all auth events",
                            "Configure SIEM integration",
                            "Review log retention policies",
                        ],
                    },
                ))

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            agent_type=self.agent_type.value,
            result_data={
                "indicators": [ind.model_dump(mode="json") for ind in indicators],
                "summary": (
                    f"Compliance scan: {len(indicators)} issue(s)"
                    f" found across {len(events)} events"
                ),
                "stats": {
                    "unencrypted_transfers": len(unencrypted),
                    "access_violations": len(access_violations),
                    "retention_issues": len(retention_issues),
                    "encryption_gaps": len(encryption_gaps),
                    "compliance_events": len(compliance_events),
                },
            },
        )
