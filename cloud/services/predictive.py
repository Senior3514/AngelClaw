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

    # V2.2 — New predictive threat vectors

    # Pattern: multiple agents + same high-severity type → coordinated attack
    agent_ids = {e.agent_id for e in events}
    if len(agent_ids) >= 3:
        high_sev = [e for e in events if e.severity in ("high", "critical")]
        if len(high_sev) >= 5:
            confidence = min(0.85, len(high_sev) / (len(events) + 1) + 0.25)
            predictions.append(
                ThreatPrediction(
                    vector_name="coordinated_attack",
                    confidence=round(confidence, 2),
                    rationale=(
                        f"Detected {len(high_sev)} high/critical events across "
                        f"{len(agent_ids)} agents — pattern suggests coordinated "
                        "multi-agent attack campaign."
                    ),
                    contributing_categories=["multi_agent"],
                    event_count=len(high_sev),
                )
            )

    # Pattern: secret access + network + encoding → supply chain compromise
    encoding_events = [
        e for e in events
        if any(k in ((e.details or {}).get("command", "") or "").lower()
               for k in ("base64", "gzip", "tar", "zip", "encode"))
    ]
    if len(secret_events) > 0 and network_count > 0 and len(encoding_events) > 0:
        confidence = min(0.90, 0.4 + len(secret_events) * 0.1 + len(encoding_events) * 0.05)
        predictions.append(
            ThreatPrediction(
                vector_name="supply_chain_compromise",
                confidence=round(confidence, 2),
                rationale=(
                    f"Detected {len(secret_events)} secret access, "
                    f"{len(encoding_events)} encoding, and {network_count} network events "
                    "— pattern suggests data encoding for supply chain exfiltration."
                ),
                contributing_categories=["secrets", "network", "encoding"],
                event_count=len(secret_events) + len(encoding_events) + network_count,
            )
        )

    # Pattern: ai_tool + shell + auth → insider threat / compromised agent
    if ai_count > 0 and shell_count > 0 and auth_count > 0:
        combined = ai_count + shell_count + auth_count
        confidence = min(0.80, combined / (len(events) + 1) + 0.20)
        predictions.append(
            ThreatPrediction(
                vector_name="insider_threat",
                confidence=round(confidence, 2),
                rationale=(
                    f"Detected {ai_count} AI tool, {shell_count} shell, and "
                    f"{auth_count} auth events from the same timeframe — "
                    "combination suggests compromised agent or insider threat."
                ),
                contributing_categories=["ai_tool", "shell", "auth"],
                event_count=combined,
            )
        )

    # Pattern: config/policy events → configuration tampering
    config_count = cat_counter.get("config", 0) + cat_counter.get("policy", 0)
    if config_count >= 2:
        confidence = min(0.75, config_count / 5 + 0.25)
        predictions.append(
            ThreatPrediction(
                vector_name="configuration_tampering",
                confidence=round(confidence, 2),
                rationale=(
                    f"Detected {config_count} configuration/policy events — "
                    "elevated configuration activity may indicate "
                    "defense evasion via policy tampering."
                ),
                contributing_categories=["config", "policy"],
                event_count=config_count,
            )
        )

    # Sort by confidence descending
    predictions.sort(key=lambda p: p.confidence, reverse=True)
    return predictions
