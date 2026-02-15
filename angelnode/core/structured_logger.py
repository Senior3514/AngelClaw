"""ANGELGRID – Structured JSON Logger.

All policy decisions and sync events are logged as single-line JSON records
to a local log file.  This format is designed for easy parsing by
Wazuh/Filebeat/Fluentd and for forensic review.

The logger includes correlation_id when present in event.details,
enabling end-to-end tracing from the AI shield adapter through the
decision log and into Wazuh/SIEM.

Record types (distinguished by the "record_type" field):
  - "decision" — policy evaluation result
  - "cloud_sync" — Cloud registration or policy sync result
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shared.models.decision import Decision
from shared.models.event import Event

DEFAULT_LOG_PATH = Path("/var/log/angelgrid/decisions.jsonl")


class DecisionLogger:
    """Appends structured JSON records to a log file."""

    def __init__(self, log_path: Path | str | None = None) -> None:
        self._path = Path(log_path) if log_path else DEFAULT_LOG_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._logger = logging.getLogger("angelnode.decisions")
        self._logger.info("Decision log path: %s", self._path)

    def log(self, event: Event, decision: Decision) -> None:
        """Write a policy-decision record."""
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "record_type": "decision",
            "event_id": event.id,
            "agent_id": event.agent_id,
            "category": event.category.value,
            "type": event.type,
            "severity": event.severity.value,
            "action": decision.action.value,
            "reason": decision.reason,
            "matched_rule_id": decision.matched_rule_id,
            "risk_level": decision.risk_level.value,
            "source": event.source,
            # Include correlation_id when present (set by AI shield adapter)
            "correlation_id": event.details.get("correlation_id"),
        }
        self._write(record)

    def log_sync(self, details: dict[str, Any]) -> None:
        """Write a cloud-sync record (registration or policy poll result)."""
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "record_type": "cloud_sync",
            **details,
        }
        self._write(record)

    def _write(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, separators=(",", ":"))
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
