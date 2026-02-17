"""AngelClaw Cloud – Threat Vector Prediction (Rule-Based).

Deterministic pattern rules for predicting attack vectors. No LLM or ML —
purely based on event category correlations observed in the lookback window.

Patterns:
  - shell + network → data exfiltration risk
  - ai_tool + secrets access → lateral movement risk
  - auth spikes → privilege escalation risk
  - file + shell → persistence risk
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from cloud.ai_assistant.models import ThreatPrediction
from cloud.db.models import EventRow

logger = logging.getLogger("angelgrid.cloud.predictive")


def predict_threat_vectors(
    db: Session,
    lookback_hours: int = 24,
) -> list[ThreatPrediction]:
    """Analyze recent events and predict threat vectors using deterministic rules."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    events = db.query(EventRow).filter(EventRow.timestamp >= cutoff).all()

    if not events:
        return []

    # Aggregate counts
    cat_counter: Counter[str] = Counter(e.category for e in events)
    _sev_counter: Counter[str] = Counter(e.severity for e in events)
    secret_events = [e for e in events if (e.details or {}).get("accesses_secrets")]

    predictions: list[ThreatPrediction] = []

    # Pattern: shell + network → data exfiltration
    shell_count = cat_counter.get("shell", 0)
    network_count = cat_counter.get("network", 0)
    if shell_count > 0 and network_count > 0:
        combined = shell_count + network_count
        confidence = min(0.9, combined / (len(events) + 1) + 0.2)
        predictions.append(
            ThreatPrediction(
                vector_name="data_exfiltration",
                confidence=round(confidence, 2),
                rationale=(
                    f"Detected {shell_count} shell and {network_count} network events — "
                    "combination suggests potential data staging and exfiltration."
                ),
                contributing_categories=["shell", "network"],
                event_count=combined,
            )
        )

    # Pattern: ai_tool + secrets → lateral movement
    ai_count = cat_counter.get("ai_tool", 0)
    if ai_count > 0 and len(secret_events) > 0:
        confidence = min(0.85, len(secret_events) / (ai_count + 1) + 0.3)
        predictions.append(
            ThreatPrediction(
                vector_name="lateral_movement",
                confidence=round(confidence, 2),
                rationale=(
                    f"Detected {ai_count} AI tool calls with"
                    f" {len(secret_events)} secret-access attempts"
                    " — pattern suggests lateral movement via AI"
                    " agent credential harvesting."
                ),
                contributing_categories=["ai_tool", "secrets"],
                event_count=ai_count + len(secret_events),
            )
        )

    # Pattern: auth spikes → privilege escalation
    auth_count = cat_counter.get("auth", 0)
    if auth_count >= 3:
        confidence = min(0.8, auth_count / 10 + 0.2)
        predictions.append(
            ThreatPrediction(
                vector_name="privilege_escalation",
                confidence=round(confidence, 2),
                rationale=(
                    f"Detected {auth_count} auth events in {lookback_hours}h — "
                    "elevated authentication activity may indicate privilege escalation attempts."
                ),
                contributing_categories=["auth"],
                event_count=auth_count,
            )
        )

    # Pattern: file + shell → persistence
    file_count = cat_counter.get("file", 0)
    if file_count > 0 and shell_count > 0:
        combined = file_count + shell_count
        confidence = min(0.75, combined / (len(events) + 1) + 0.15)
        predictions.append(
            ThreatPrediction(
                vector_name="persistence",
                confidence=round(confidence, 2),
                rationale=(
                    f"Detected {file_count} file and {shell_count} shell events — "
                    "file modifications combined with shell activity"
                    " may indicate persistence mechanisms."
                ),
                contributing_categories=["file", "shell"],
                event_count=combined,
            )
        )

    # Sort by confidence descending
    predictions.sort(key=lambda p: p.confidence, reverse=True)
    return predictions
