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
        e
        for e in events
        if any(
            k in ((e.details or {}).get("command", "") or "").lower()
            for k in ("base64", "gzip", "tar", "zip", "encode")
        )
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

    # V2.5 — Enhanced predictive patterns

    # Pattern: zero-day exploitation (novel event types spike)
    type_counter: Counter[str] = Counter(e.type for e in events)
    novel_types = [t for t, c in type_counter.items() if c == 1]
    if len(novel_types) >= 5 and len(events) >= 10:
        confidence = min(0.80, len(novel_types) / len(events) + 0.2)
        predictions.append(
            ThreatPrediction(
                vector_name="zero_day_exploitation",
                confidence=round(confidence, 2),
                rationale=(
                    f"Detected {len(novel_types)} novel event types out of "
                    f"{len(events)} events — spike in unseen patterns may indicate "
                    "zero-day exploitation or novel attack technique."
                ),
                contributing_categories=["novel_types"],
                event_count=len(novel_types),
            )
        )

    # Pattern: account takeover (auth + password change + new session)
    password_events = [
        e
        for e in events
        if any(
            k in ((e.details or {}).get("command", "") or (e.type or "")).lower()
            for k in ("password", "passwd", "reset", "change_pass", "credentials")
        )
    ]
    if auth_count >= 2 and len(password_events) >= 1:
        confidence = min(0.85, 0.4 + auth_count * 0.05 + len(password_events) * 0.1)
        predictions.append(
            ThreatPrediction(
                vector_name="account_takeover",
                confidence=round(confidence, 2),
                rationale=(
                    f"Detected {auth_count} auth events and "
                    f"{len(password_events)} credential-change events — "
                    "pattern suggests account takeover in progress."
                ),
                contributing_categories=["auth", "credentials"],
                event_count=auth_count + len(password_events),
            )
        )

    # Pattern: API key compromise (api_security + new source IPs)
    api_sec_count = cat_counter.get("api_security", 0)
    if api_sec_count >= 3:
        api_sources = {
            (e.details or {}).get("source_ip", "")
            for e in events
            if e.category == "api_security" and (e.details or {}).get("source_ip")
        }
        if len(api_sources) >= 2:
            confidence = min(0.80, 0.3 + api_sec_count * 0.05 + len(api_sources) * 0.1)
            predictions.append(
                ThreatPrediction(
                    vector_name="api_key_compromise",
                    confidence=round(confidence, 2),
                    rationale=(
                        f"Detected {api_sec_count} API security events from "
                        f"{len(api_sources)} distinct source IPs — "
                        "pattern suggests compromised API key usage."
                    ),
                    contributing_categories=["api_security"],
                    event_count=api_sec_count,
                )
            )

    # Pattern: warden evasion (rapid low-severity followed by high-severity)
    sorted_events = sorted(events, key=lambda e: e.timestamp if e.timestamp else datetime.min)
    if len(sorted_events) >= 10:
        first_half = sorted_events[: len(sorted_events) // 2]
        second_half = sorted_events[len(sorted_events) // 2 :]
        sev_map = {"info": 0, "low": 1, "warn": 2, "medium": 2, "high": 3, "critical": 4}
        avg_first = sum(sev_map.get(e.severity, 0) for e in first_half) / max(len(first_half), 1)
        avg_second = sum(sev_map.get(e.severity, 0) for e in second_half) / max(len(second_half), 1)
        if avg_second - avg_first >= 1.5:
            confidence = min(0.75, 0.3 + (avg_second - avg_first) * 0.15)
            predictions.append(
                ThreatPrediction(
                    vector_name="warden_evasion",
                    confidence=round(confidence, 2),
                    rationale=(
                        f"Severity escalation detected: avg severity rose from "
                        f"{avg_first:.1f} to {avg_second:.1f} — "
                        "gradual escalation may indicate warden evasion strategy."
                    ),
                    contributing_categories=["severity_escalation"],
                    event_count=len(events),
                )
            )

    # V2.5 — Apply confidence calibration from learning engine
    try:
        from cloud.guardian.learning import learning_engine

        for pred in predictions:
            calibrated = learning_engine.get_confidence_threshold(pred.vector_name, default=None)
            if calibrated is not None and pred.confidence < calibrated:
                pred.confidence = 0.0  # Suppress low-confidence predictions
        predictions = [p for p in predictions if p.confidence > 0]
    except Exception:
        pass

    # Sort by confidence descending
    predictions.sort(key=lambda p: p.confidence, reverse=True)
    return predictions


def predict_trends(
    db: Session,
    lookback_hours: int = 24,
    compare_hours: int = 48,
) -> list[dict]:
    """V2.5 — Compare current period to previous period for trend analysis."""
    now = datetime.now(timezone.utc)
    current_cutoff = now - timedelta(hours=lookback_hours)
    previous_cutoff = now - timedelta(hours=compare_hours)

    current_events = db.query(EventRow).filter(EventRow.timestamp >= current_cutoff).all()
    previous_events = (
        db.query(EventRow)
        .filter(EventRow.timestamp >= previous_cutoff, EventRow.timestamp < current_cutoff)
        .all()
    )

    if not current_events and not previous_events:
        return []

    cur_cats: Counter[str] = Counter(e.category for e in current_events)
    prev_cats: Counter[str] = Counter(e.category for e in previous_events)
    trends = []
    all_cats = set(cur_cats.keys()) | set(prev_cats.keys())
    for cat in all_cats:
        cur = cur_cats.get(cat, 0)
        prev = prev_cats.get(cat, 0)
        if prev == 0:
            direction = "new" if cur > 0 else "stable"
            magnitude = cur
        else:
            change = (cur - prev) / prev
            direction = (
                "escalating" if change > 0.2 else ("declining" if change < -0.2 else "stable")
            )
            magnitude = round(abs(change), 2)
        trends.append(
            {
                "category": cat,
                "current_count": cur,
                "previous_count": prev,
                "trend_direction": direction,
                "trend_magnitude": magnitude,
            }
        )

    sev_map = {"info": 0, "low": 1, "warn": 2, "medium": 2, "high": 3, "critical": 4}
    cur_avg_sev = sum(sev_map.get(e.severity, 0) for e in current_events) / max(
        len(current_events), 1
    )
    prev_avg_sev = sum(sev_map.get(e.severity, 0) for e in previous_events) / max(
        len(previous_events), 1
    )

    overall_direction = (
        "escalating"
        if cur_avg_sev > prev_avg_sev + 0.3
        else ("declining" if cur_avg_sev < prev_avg_sev - 0.3 else "stable")
    )

    return [
        {
            "overall_direction": overall_direction,
            "current_avg_severity": round(cur_avg_sev, 2),
            "previous_avg_severity": round(prev_avg_sev, 2),
            "current_event_count": len(current_events),
            "previous_event_count": len(previous_events),
            "by_category": sorted(trends, key=lambda t: t["current_count"], reverse=True),
        }
    ]
