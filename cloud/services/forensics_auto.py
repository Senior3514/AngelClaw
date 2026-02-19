"""AngelClaw V5.0 — Transcendence: Digital Forensics Automation.

Manages forensic investigation cases with evidence collection, chain of
custody tracking, and timeline reconstruction for incident analysis.

Features:
  - Case lifecycle management (create, investigate, close)
  - Evidence collection with chain-of-custody metadata
  - Automated timeline reconstruction from evidence
  - Integrity hashing for evidence items
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("angelclaw.forensics_auto")


class EvidenceItem(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    evidence_type: str  # log, pcap, memory_dump, disk_image, screenshot, artifact, config
    source: str = ""
    description: str = ""
    hash_sha256: str = ""
    size_bytes: int = 0
    collected_by: str = "system"
    chain_of_custody: list[dict[str, Any]] = []
    tags: list[str] = []
    metadata: dict[str, Any] = {}
    timestamp: datetime | None = None  # when the evidence was generated/captured
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ForensicCase(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "dev-tenant"
    title: str
    description: str = ""
    status: str = "open"  # open, investigating, analysis, review, closed
    severity: str = "medium"
    incident_id: str | None = None  # linked incident
    lead_investigator: str = ""
    evidence_ids: list[str] = []
    findings: list[str] = []
    tags: list[str] = []
    timeline: list[dict[str, Any]] = []
    created_by: str = "system"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    closed_at: datetime | None = None


class ForensicsService:
    """Digital forensics case and evidence management."""

    def __init__(self) -> None:
        self._cases: dict[str, ForensicCase] = {}
        self._evidence: dict[str, EvidenceItem] = {}
        self._tenant_cases: dict[str, list[str]] = defaultdict(list)

    # -- Case CRUD --

    def create_case(
        self,
        tenant_id: str,
        title: str,
        description: str = "",
        severity: str = "medium",
        incident_id: str | None = None,
        lead_investigator: str = "",
        tags: list[str] | None = None,
        created_by: str = "system",
    ) -> dict:
        case = ForensicCase(
            tenant_id=tenant_id,
            title=title,
            description=description,
            severity=severity,
            incident_id=incident_id,
            lead_investigator=lead_investigator,
            tags=tags or [],
            created_by=created_by,
        )
        self._cases[case.id] = case
        self._tenant_cases[tenant_id].append(case.id)
        logger.info(
            "[FORENSICS] Created case '%s' severity=%s for %s",
            title, severity, tenant_id,
        )
        return case.model_dump(mode="json")

    def get_case(self, case_id: str) -> dict | None:
        case = self._cases.get(case_id)
        return case.model_dump(mode="json") if case else None

    def list_cases(
        self,
        tenant_id: str,
        status: str | None = None,
    ) -> list[dict]:
        results = []
        for cid in self._tenant_cases.get(tenant_id, []):
            case = self._cases.get(cid)
            if not case:
                continue
            if status and case.status != status:
                continue
            results.append(case.model_dump(mode="json"))
        results.sort(key=lambda c: c.get("created_at", ""), reverse=True)
        return results

    def update_case(
        self,
        case_id: str,
        status: str | None = None,
        lead_investigator: str | None = None,
        findings: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> dict | None:
        case = self._cases.get(case_id)
        if not case:
            return None

        if status:
            case.status = status
        if lead_investigator is not None:
            case.lead_investigator = lead_investigator
        if findings is not None:
            case.findings = findings
        if tags is not None:
            case.tags = tags
        case.updated_at = datetime.now(timezone.utc)

        logger.info("[FORENSICS] Updated case %s", case_id[:8])
        return case.model_dump(mode="json")

    def close_case(
        self,
        case_id: str,
        final_findings: list[str] | None = None,
    ) -> dict | None:
        case = self._cases.get(case_id)
        if not case:
            return None

        case.status = "closed"
        case.closed_at = datetime.now(timezone.utc)
        case.updated_at = datetime.now(timezone.utc)
        if final_findings:
            case.findings.extend(final_findings)

        logger.info("[FORENSICS] Closed case '%s'", case.title)
        return case.model_dump(mode="json")

    # -- Evidence Management --

    def add_evidence(
        self,
        case_id: str,
        evidence_type: str,
        source: str = "",
        description: str = "",
        data_content: str = "",
        size_bytes: int = 0,
        collected_by: str = "system",
        tags: list[str] | None = None,
        metadata: dict | None = None,
        timestamp: datetime | None = None,
    ) -> dict | None:
        case = self._cases.get(case_id)
        if not case:
            return None

        # Compute integrity hash from content
        hash_value = ""
        if data_content:
            hash_value = hashlib.sha256(data_content.encode()).hexdigest()

        evidence = EvidenceItem(
            case_id=case_id,
            evidence_type=evidence_type,
            source=source,
            description=description,
            hash_sha256=hash_value,
            size_bytes=size_bytes or len(data_content.encode()),
            collected_by=collected_by,
            tags=tags or [],
            metadata=metadata or {},
            timestamp=timestamp,
        )

        # Initial chain of custody entry
        evidence.chain_of_custody.append({
            "action": "collected",
            "by": collected_by,
            "at": datetime.now(timezone.utc).isoformat(),
            "hash_sha256": hash_value,
            "notes": f"Evidence collected from {source}",
        })

        self._evidence[evidence.id] = evidence
        case.evidence_ids.append(evidence.id)
        case.updated_at = datetime.now(timezone.utc)

        logger.info(
            "[FORENSICS] Added %s evidence to case %s from %s",
            evidence_type, case_id[:8], source,
        )
        return evidence.model_dump(mode="json")

    def get_evidence(self, evidence_id: str) -> dict | None:
        evidence = self._evidence.get(evidence_id)
        return evidence.model_dump(mode="json") if evidence else None

    def list_evidence(self, case_id: str) -> list[dict]:
        case = self._cases.get(case_id)
        if not case:
            return []
        return [
            self._evidence[eid].model_dump(mode="json")
            for eid in case.evidence_ids
            if eid in self._evidence
        ]

    def add_custody_entry(
        self,
        evidence_id: str,
        action: str,
        by: str,
        notes: str = "",
    ) -> dict | None:
        evidence = self._evidence.get(evidence_id)
        if not evidence:
            return None

        evidence.chain_of_custody.append({
            "action": action,
            "by": by,
            "at": datetime.now(timezone.utc).isoformat(),
            "notes": notes,
        })
        return evidence.model_dump(mode="json")

    # -- Timeline Reconstruction --

    def build_timeline(self, case_id: str) -> list[dict]:
        """Reconstruct a chronological timeline from all evidence in a case."""
        case = self._cases.get(case_id)
        if not case:
            return []

        events: list[dict[str, Any]] = []

        for eid in case.evidence_ids:
            evidence = self._evidence.get(eid)
            if not evidence:
                continue

            # Use evidence timestamp if available, else collection time
            ts = evidence.timestamp or evidence.collected_at
            events.append({
                "timestamp": ts.isoformat(),
                "sort_key": ts,
                "evidence_id": evidence.id,
                "evidence_type": evidence.evidence_type,
                "source": evidence.source,
                "description": evidence.description,
                "tags": evidence.tags,
            })

            # Add events from metadata if present
            for meta_event in evidence.metadata.get("events", []):
                meta_ts = meta_event.get("timestamp", ts.isoformat())
                try:
                    parsed_ts = datetime.fromisoformat(meta_ts) if isinstance(meta_ts, str) else ts
                except (ValueError, TypeError):
                    parsed_ts = ts
                events.append({
                    "timestamp": meta_ts,
                    "sort_key": parsed_ts,
                    "evidence_id": evidence.id,
                    "evidence_type": evidence.evidence_type,
                    "source": evidence.source,
                    "description": meta_event.get("description", ""),
                    "tags": meta_event.get("tags", []),
                })

        # Sort chronologically
        events.sort(key=lambda e: e["sort_key"])

        # Remove sort_key before returning
        timeline = [{k: v for k, v in e.items() if k != "sort_key"} for e in events]

        # Store on case
        case.timeline = timeline
        case.updated_at = datetime.now(timezone.utc)

        logger.info("[FORENSICS] Built timeline with %d events for case %s", len(timeline), case_id[:8])
        return timeline

    # -- Stats --

    def get_stats(self, tenant_id: str) -> dict:
        cases = [
            self._cases[c]
            for c in self._tenant_cases.get(tenant_id, [])
            if c in self._cases
        ]

        by_status: dict[str, int] = defaultdict(int)
        by_severity: dict[str, int] = defaultdict(int)
        total_evidence = 0
        for case in cases:
            by_status[case.status] += 1
            by_severity[case.severity] += 1
            total_evidence += len(case.evidence_ids)

        open_cases = sum(1 for c in cases if c.status != "closed")

        return {
            "total_cases": len(cases),
            "open_cases": open_cases,
            "by_status": dict(by_status),
            "by_severity": dict(by_severity),
            "total_evidence_items": total_evidence,
        }


# Module-level singleton
forensics_service = ForensicsService()
