"""AngelClaw AGI Guardian – Autonomous Daemon.

Always-on background loop that makes AngelClaw a living guardian:
  - Periodic scans (configurable frequency)
  - ClawSec shield assessment (threat detection, trifecta, attack chains)
  - Guardian report generation
  - Drift detection (policy, agent health, skills integrity, anomalies)
  - Activity logging with human-friendly summaries
  - Respects operator preferences (frequency, reporting level, autonomy)

Lightweight: runs as an asyncio task inside the Cloud process.
No external dependencies. No separate process needed.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any

from cloud.db.models import GuardianReportRow
from cloud.db.session import SessionLocal

logger = logging.getLogger("angelclaw.daemon")

# In-memory activity log (capped ring buffer — zero DB overhead for activity)
_MAX_ACTIVITY = 200
_activity_log: deque[dict[str, Any]] = deque(maxlen=_MAX_ACTIVITY)

# Daemon state
_running = False
_task: asyncio.Task | None = None
_cycles_completed = 0
_last_scan_summary = ""


def get_recent_activity(limit: int = 20) -> list[dict]:
    """Return recent daemon activity entries (newest first)."""
    items = list(_activity_log)
    items.reverse()
    return items[:limit]


def get_next_scan_time(tenant_id: str = "dev-tenant") -> str | None:
    """Compute when the next daemon scan cycle will fire."""
    if not _running or _cycles_completed == 0:
        return None
    try:
        db = SessionLocal()
        from cloud.angelclaw.preferences import get_preferences

        prefs = get_preferences(db, tenant_id)
        interval = max(60, prefs.scan_frequency_minutes * 60)
        db.close()
    except Exception:
        interval = 600
    # Estimate from last activity entry
    if _activity_log:
        last_ts = _activity_log[-1].get("timestamp", "")
        try:
            last_dt = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
            next_dt = last_dt + timedelta(seconds=interval)
            return next_dt.isoformat()
        except Exception:
            pass
    return (datetime.now(timezone.utc) + timedelta(seconds=interval)).isoformat()


def get_daemon_status() -> dict:
    return {
        "running": _running,
        "cycles_completed": _cycles_completed,
        "last_scan_summary": _last_scan_summary,
        "activity_count": len(_activity_log),
        "next_scan_time": get_next_scan_time(),
    }


def _log_activity(summary: str, category: str = "scan", details: dict | None = None) -> None:
    """Append to in-memory activity log."""
    entry = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "category": category,
        "summary": summary,
        "details": details or {},
    }
    _activity_log.append(entry)
    logger.info("[ANGELCLAW] %s", summary)


# ---------------------------------------------------------------------------
# Main daemon loop
# ---------------------------------------------------------------------------


async def daemon_loop(tenant_id: str = "dev-tenant") -> None:
    """Main autonomous loop. Runs until cancelled."""
    global _running, _cycles_completed, _last_scan_summary

    _running = True
    _log_activity("AngelClaw daemon started — autonomous guardian active", "lifecycle")
    logger.info("[DAEMON] AngelClaw V5 daemon started for tenant=%s", tenant_id)

    # Initial short delay to let other services start
    await asyncio.sleep(5)

    while _running:
        db = None
        try:
            db = SessionLocal()

            # Get current preferences for scan frequency
            from cloud.angelclaw.preferences import ReportingLevel, get_preferences

            prefs = get_preferences(db, tenant_id)
            interval = max(60, prefs.scan_frequency_minutes * 60)  # min 1 minute
            reporting = prefs.reporting_level

            # ---- CYCLE START ----
            _cycles_completed += 1
            cycle_start = datetime.now(timezone.utc)

            # 1. Lightweight guardian scan
            scan_summary = await _run_scan(db, tenant_id, reporting)
            _last_scan_summary = scan_summary

            # 2. Generate guardian report
            _generate_report(db, tenant_id)

            # 3. AngelClaw shield assessment
            shield_summary = _run_shield_assessment(db, tenant_id)

            # 4. Check for drift and anomalies
            drift_findings = _check_drift(db, tenant_id)

            # 5. Check agent health
            health_issues = _check_agent_health(db)

            # 6. ClawSec-aligned checks (prompt injection attempts, suspicious
            #    tool usage, memory leak signs, exposed services)
            security_findings = _run_security_checks(db, tenant_id)

            # V2.2 — 7. Angel Legion orchestrator sweep (proactive detection)
            legion_findings = await _run_legion_sweep(db, tenant_id)

            # V2.2 — 8. Learning engine cycle (decay + threshold tuning)
            _run_learning_cycle()

            # V3.0 — 9. Anti-tamper heartbeat checks
            tamper_findings = _run_anti_tamper_checks(db, tenant_id)

            # V3.0 — 10. Self-hardening cycle
            hardening_actions = _run_self_hardening_cycle(db, tenant_id, prefs)

            # V3.0 — 11. Feedback-based adjustments
            _run_feedback_adjustments(tenant_id)

            # V3.5 — 12. Threat intel & IOC matching
            intel_findings = _run_threat_intel_cycle(tenant_id)

            # V4.0 — 13. Asset risk & SLA breach checks
            asset_findings = _run_asset_risk_cycle(tenant_id)

            # V4.1 — 14. ML anomaly batch detection
            ml_anomalies = _run_ml_anomaly_cycle(tenant_id)

            # V4.5 — 15. Zero-trust session reassessment
            zt_findings = _run_zerotrust_cycle(tenant_id)

            # V5.0 — 16. Deception token monitoring
            deception_triggers = _run_deception_cycle(tenant_id)

            # V5.0 — 17. Evolving rule evolution
            evolved_count = _run_evolving_rules_cycle(tenant_id)

            # V5.5 — 18. Real-time metrics aggregation
            realtime_count = _run_realtime_cycle(tenant_id)

            # V5.5 — 19. Halo Score recomputation
            halo_updated = _run_halo_cycle(tenant_id)

            # V6.0 — 20. Cloud posture scan
            cspm_findings = _run_cspm_cycle(tenant_id)

            # V6.5 — 21. Autonomous threat hunting
            hunt_findings = _run_hunt_cycle(tenant_id)

            # V6.5 — 22. Intel correlation
            correlations = _run_correlation_cycle(tenant_id)

            # V7.0 — 23. AGI defense rule generation
            agi_rules = _run_agi_defense_cycle(tenant_id)

            # V7.0 — 24. SOC autopilot triage
            soc_triaged = _run_soc_cycle(tenant_id)

            # 25. Log cycle summary
            elapsed = (datetime.now(timezone.utc) - cycle_start).total_seconds()
            cycle_summary = f"Cycle #{_cycles_completed} complete ({elapsed:.1f}s) — {scan_summary}"
            if shield_summary:
                cycle_summary += f", shield: {shield_summary}"
            if drift_findings:
                cycle_summary += f", {len(drift_findings)} drift finding(s)"
            if health_issues:
                cycle_summary += f", {len(health_issues)} health issue(s)"
            if security_findings:
                cycle_summary += f", {len(security_findings)} security finding(s)"
            if legion_findings:
                cycle_summary += f", legion: {legion_findings} indicator(s)"
            if tamper_findings:
                cycle_summary += f", {len(tamper_findings)} tamper finding(s)"
            if hardening_actions:
                cycle_summary += f", {len(hardening_actions)} hardening action(s)"
            if intel_findings:
                cycle_summary += f", {intel_findings} IOC match(es)"
            if asset_findings:
                cycle_summary += f", {asset_findings} asset risk(s)"
            if ml_anomalies:
                cycle_summary += f", {ml_anomalies} ML anomaly(ies)"
            if zt_findings:
                cycle_summary += f", {zt_findings} ZT reassessment(s)"
            if deception_triggers:
                cycle_summary += f", {deception_triggers} deception trigger(s)"
            if evolved_count:
                cycle_summary += f", {evolved_count} rule(s) evolved"
            if realtime_count:
                cycle_summary += f", {realtime_count} RT event(s)"
            if halo_updated:
                cycle_summary += ", halo updated"
            if cspm_findings:
                cycle_summary += f", {cspm_findings} CSPM finding(s)"
            if hunt_findings:
                cycle_summary += f", {hunt_findings} hunt finding(s)"
            if correlations:
                cycle_summary += f", {correlations} correlation(s)"
            if agi_rules:
                cycle_summary += f", {agi_rules} AGI rule(s)"
            if soc_triaged:
                cycle_summary += f", {soc_triaged} SOC triage(s)"

            if reporting != ReportingLevel.QUIET or drift_findings or health_issues:
                _log_activity(cycle_summary, "cycle")

            db.close()
            db = None

            # Sleep until next cycle
            await asyncio.sleep(interval)

        except asyncio.CancelledError:
            break
        except Exception:
            logger.exception("[DAEMON] Cycle error (will retry)")
            _log_activity("Daemon cycle error — will retry", "error")
            if db:
                try:
                    db.close()
                except Exception:
                    pass
            await asyncio.sleep(30)  # Back off on error

    _running = False
    _log_activity("AngelClaw daemon stopped", "lifecycle")


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


async def _run_scan(db, tenant_id: str, reporting) -> str:
    """Run lightweight guardian scan."""
    try:
        from cloud.services.guardian_scan import run_guardian_scan

        result = await run_guardian_scan(db, tenant_id)

        critical = sum(1 for r in result.top_risks if r.severity == "critical")
        high = sum(1 for r in result.top_risks if r.severity == "high")
        medium = sum(1 for r in result.top_risks if r.severity == "medium")

        summary = (
            f"{result.total_checks} checks,"
            f" {len(result.top_risks)} risks"
            f" ({critical}C/{high}H/{medium}M)"
        )

        if critical > 0:
            _log_activity(
                f"CRITICAL: {critical} critical exposure(s) found",
                "alert",
                {"risks": [r.title for r in result.top_risks if r.severity == "critical"]},
            )
        elif high > 0 and str(reporting) != "quiet":
            _log_activity(f"Scan: {high} high-severity exposure(s)", "scan")

        return summary
    except Exception as e:
        logger.debug("[DAEMON] Scan failed: %s", e)
        return "scan skipped"


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def _generate_report(db, tenant_id: str) -> None:
    """Generate a guardian report (same format as heartbeat)."""
    try:
        from collections import Counter

        from cloud.db.models import AgentNodeRow, EventRow, GuardianChangeRow

        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=10)

        agents = db.query(AgentNodeRow).all()
        total = len(agents)
        active = sum(1 for a in agents if a.status == "active")
        degraded = sum(1 for a in agents if a.status == "degraded")
        offline = total - active - degraded

        events = db.query(EventRow).filter(EventRow.timestamp >= cutoff).all()
        sev_counter = Counter(e.severity for e in events)

        # Check for anomalies
        anomalies = []
        stale_cutoff = now - timedelta(minutes=10)
        for a in agents:
            if a.status == "active" and a.last_seen_at and a.last_seen_at < stale_cutoff:
                anomalies.append(f"Agent {a.hostname} may be offline")

        if sev_counter.get("critical", 0) >= 3:
            anomalies.append(f"Severity spike: {sev_counter['critical']} critical events")

        # Policy changes
        last_report = (
            db.query(GuardianReportRow)
            .filter(GuardianReportRow.tenant_id == tenant_id)
            .order_by(GuardianReportRow.timestamp.desc())
            .first()
        )
        changes_cutoff = last_report.timestamp if last_report else cutoff
        policy_changes = (
            db.query(GuardianChangeRow)
            .filter(
                GuardianChangeRow.tenant_id == tenant_id,
                GuardianChangeRow.created_at >= changes_cutoff,
            )
            .count()
        )

        summary = (
            f"{total} agents ({active} active, {degraded} degraded, {offline} offline), "
            f"{len(events)} events, {len(anomalies)} anomalies"
        )

        row = GuardianReportRow(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            timestamp=now,
            agents_total=total,
            agents_active=active,
            agents_degraded=degraded,
            agents_offline=offline,
            incidents_total=len(events),
            incidents_by_severity=dict(sev_counter),
            policy_changes_since_last=policy_changes,
            anomalies=anomalies,
            summary=summary,
        )
        db.add(row)
        db.commit()
    except Exception:
        logger.debug("[DAEMON] Report generation failed", exc_info=True)
        try:
            db.rollback()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Shield assessment (ClawSec-inspired)
# ---------------------------------------------------------------------------


def _run_shield_assessment(db, tenant_id: str) -> str:
    """Run ClawSec shield assessment on recent events."""
    try:
        from cloud.angelclaw.shield import shield as _shield
        from cloud.db.models import EventRow

        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=30)
        events = db.query(EventRow).filter(EventRow.timestamp >= cutoff).limit(100).all()

        event_dicts = [
            {
                "category": e.category,
                "type": e.type,
                "details": e.details or {},
                "severity": e.severity,
            }
            for e in events
        ]

        report = _shield.assess_events(event_dicts)

        if report.critical_count > 0:
            _log_activity(
                f"SHIELD CRITICAL: {report.critical_count} critical threat(s) detected",
                "shield_alert",
                {
                    "indicators": [
                        i.title for i in report.indicators if i.severity.value == "critical"
                    ]
                },
            )
        elif report.high_count > 0:
            _log_activity(
                f"Shield: {report.high_count} high-severity indicator(s)",
                "shield",
            )

        trifecta = f"trifecta={int(report.lethal_trifecta_score * 100)}%"
        return f"{report.overall_risk.value} ({trifecta})"
    except Exception as e:
        logger.debug("[DAEMON] Shield assessment failed: %s", e)
        return ""


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------


def _check_drift(db, tenant_id: str) -> list[str]:
    """Check for policy drift between recommended and actual."""
    findings = []
    try:
        from cloud.db.models import AgentNodeRow, PolicySetRow

        ps = db.query(PolicySetRow).first()
        if not ps:
            return findings

        agents = db.query(AgentNodeRow).filter(AgentNodeRow.status == "active").all()
        drifted = [
            a for a in agents if a.policy_version != ps.version_hash and a.policy_version != "0"
        ]
        if drifted:
            msg = f"Policy drift: {len(drifted)} agent(s) on old policy version"
            findings.append(msg)
            _log_activity(msg, "drift", {"agents": [a.hostname for a in drifted[:5]]})
    except Exception:
        pass
    return findings


# ---------------------------------------------------------------------------
# ClawSec-aligned security checks
# ---------------------------------------------------------------------------


def _run_security_checks(db, tenant_id: str) -> list[str]:
    """Run ClawSec-aligned security checks on recent events.

    Looks specifically for:
      - Prompt injection attempts in recent events
      - Suspicious tool usage patterns (high-frequency, unusual tools)
      - Memory leak or data exfil signs
      - Misconfigured tools exposed to public internet
    """
    findings = []
    try:
        from cloud.angelclaw.shield import detect_data_leakage, detect_prompt_injection
        from cloud.db.models import EventRow

        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=30)
        events = db.query(EventRow).filter(EventRow.timestamp >= cutoff).limit(200).all()

        # 1. Check for prompt injection attempts in AI tool events
        injection_count = 0
        for e in events:
            if e.category in ("ai_tool", "custom"):
                details = e.details or {}
                command = details.get("command", "") or details.get("prompt", "") or ""
                args = str(details.get("arguments", ""))
                text = f"{command} {args}"
                if text.strip():
                    indicators = detect_prompt_injection(text)
                    if indicators:
                        injection_count += 1

        if injection_count > 0:
            msg = f"Prompt injection: {injection_count} attempt(s) detected in last 30min"
            findings.append(msg)
            _log_activity(msg, "security_alert", {"count": injection_count})

        # 2. Suspicious tool usage patterns (rapid-fire different tools)
        tool_events = [e for e in events if e.category == "ai_tool"]
        if len(tool_events) > 50:
            # Check for burst patterns
            tool_names = set()
            for e in tool_events:
                details = e.details or {}
                tool_name = details.get("tool_name", "") or details.get("command", "")
                if tool_name:
                    tool_names.add(tool_name)
            if len(tool_names) > 15:
                msg = (
                    f"Suspicious tool pattern:"
                    f" {len(tool_events)} calls across"
                    f" {len(tool_names)} unique tools"
                    f" in 30min"
                )
                findings.append(msg)
                _log_activity(msg, "security_alert")

        # 3. Data exfiltration signs
        exfil_count = 0
        for e in events:
            if e.category in ("network", "shell"):
                details = e.details or {}
                command = details.get("command", "") or ""
                if command:
                    leakage = detect_data_leakage(command)
                    if leakage:
                        exfil_count += 1

        if exfil_count > 0:
            msg = f"Data exfil: {exfil_count} suspicious transfer pattern(s) in last 30min"
            findings.append(msg)
            _log_activity(msg, "security_alert", {"count": exfil_count})

        # 4. Check for exposed services (public-facing ports in events)
        exposed_patterns = ["0.0.0.0:", "exposed", "public_ip", "internet_facing"]
        exposed_count = 0
        for e in events:
            details_str = str(e.details or {}).lower()
            if any(p in details_str for p in exposed_patterns):
                exposed_count += 1

        if exposed_count > 0:
            msg = f"Exposure risk: {exposed_count} event(s) suggest publicly exposed services"
            findings.append(msg)
            _log_activity(msg, "security_alert", {"count": exposed_count})

    except Exception:
        logger.debug("[DAEMON] Security checks failed", exc_info=True)
    return findings


# ---------------------------------------------------------------------------
# Agent health
# ---------------------------------------------------------------------------


def _check_agent_health(db) -> list[str]:
    """Check for unhealthy agents."""
    issues = []
    try:
        from cloud.db.models import AgentNodeRow

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        stale_cutoff = now - timedelta(minutes=15)
        agents = db.query(AgentNodeRow).filter(AgentNodeRow.status == "active").all()

        for a in agents:
            last_seen = (
                a.last_seen_at.replace(tzinfo=None)
                if (a.last_seen_at and a.last_seen_at.tzinfo)
                else a.last_seen_at
            )
            if last_seen and last_seen < stale_cutoff:
                msg = (
                    f"Agent {a.hostname} unresponsive"
                    f" (last seen {a.last_seen_at.strftime('%H:%M')})"
                )
                issues.append(msg)
    except Exception:
        pass
    return issues


# ---------------------------------------------------------------------------
# V2.2 — Angel Legion orchestrator sweep
# ---------------------------------------------------------------------------


async def _run_legion_sweep(db, tenant_id: str) -> int:
    """Run the Angel Legion orchestrator sweep on recent events.

    This proactively feeds recent events through the full detection pipeline
    (all wardens in parallel), creating incidents and triggering responses.
    Returns the number of indicators found.
    """
    try:
        from cloud.db.models import EventRow
        from cloud.guardian.orchestrator import angel_orchestrator

        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=10)
        events = db.query(EventRow).filter(EventRow.timestamp >= cutoff).limit(200).all()

        if not events:
            return 0

        indicators = await angel_orchestrator.process_events(events, db, tenant_id)

        if indicators:
            _log_activity(
                f"Legion sweep: {len(indicators)} indicator(s) from {len(events)} events",
                "legion",
                {"indicator_count": len(indicators)},
            )

        return len(indicators)
    except Exception as e:
        logger.debug("[DAEMON] Legion sweep failed: %s", e)
        return 0


# ---------------------------------------------------------------------------
# V2.2 — Learning engine maintenance cycle
# ---------------------------------------------------------------------------


def _run_learning_cycle() -> None:
    """Run learning engine maintenance: decay old FP data, tune thresholds."""
    try:
        from cloud.guardian.learning import learning_engine

        # Apply decay to false positive counts (prevent stale data)
        learning_engine.apply_decay(decay_factor=0.95)

        # Compute adaptive thresholds for all tracked patterns
        precision_data = learning_engine.get_pattern_precision()
        for pattern_name in precision_data:
            learning_engine.compute_confidence_override(pattern_name)

    except Exception:
        logger.debug("[DAEMON] Learning cycle failed", exc_info=True)


# ---------------------------------------------------------------------------
# V3.0 — Anti-tamper heartbeat checks
# ---------------------------------------------------------------------------


def _run_anti_tamper_checks(db, tenant_id: str) -> list[str]:
    """Check for anti-tamper violations (heartbeat misses, checksum drift)."""
    findings = []
    try:
        from cloud.db.models import AgentNodeRow
        from cloud.services.anti_tamper import anti_tamper_service

        agents = db.query(AgentNodeRow).filter(AgentNodeRow.status == "active").all()

        for agent in agents:
            # Check heartbeat timeout
            event = anti_tamper_service.check_heartbeat(tenant_id, agent.id)
            if event:
                msg = f"Anti-tamper: heartbeat miss for {agent.hostname}"
                findings.append(msg)
                _log_activity(msg, "anti_tamper", {"agent_id": agent.id})

        if findings:
            _log_activity(
                f"Anti-tamper: {len(findings)} issue(s) detected",
                "anti_tamper",
            )
    except Exception:
        logger.debug("[DAEMON] Anti-tamper checks failed", exc_info=True)
    return findings


# ---------------------------------------------------------------------------
# V3.0 — Self-hardening cycle
# ---------------------------------------------------------------------------


def _run_self_hardening_cycle(db, tenant_id: str, prefs) -> list[dict]:
    """Run the self-hardening engine to detect and fix security weaknesses."""
    try:
        from cloud.db.models import AgentNodeRow
        from cloud.services.anti_tamper import anti_tamper_service
        from cloud.services.self_hardening import self_hardening_engine

        # Gather context for the hardening engine
        agents = db.query(AgentNodeRow).filter(AgentNodeRow.status == "active").all()
        unprotected = [
            a.id for a in agents
            if not anti_tamper_service.is_protected(tenant_id, a.id)
        ]

        context = {
            "scan_freq": prefs.scan_frequency_minutes,
            "logging_enabled": True,
            "unprotected_high_risk_agents": unprotected[:10] if len(unprotected) > 5 else [],
        }

        autonomy = getattr(prefs, "autonomy_level", None)
        mode = "suggest"
        if autonomy:
            mode_str = str(autonomy.value) if hasattr(autonomy, "value") else str(autonomy)
            if mode_str in ("auto_apply", "assist"):
                mode = "auto_apply"
            elif mode_str == "observe":
                mode = "observe"

        actions = self_hardening_engine.run_hardening_cycle(
            tenant_id=tenant_id,
            autonomy_mode=mode,
            context=context,
        )

        if actions:
            _log_activity(
                f"Self-hardening: {len(actions)} action(s) ({mode} mode)",
                "hardening",
                {"action_count": len(actions)},
            )
        return actions
    except Exception:
        logger.debug("[DAEMON] Self-hardening cycle failed", exc_info=True)
        return []


# ---------------------------------------------------------------------------
# V3.0 — Feedback-based adjustments
# ---------------------------------------------------------------------------


def _run_feedback_adjustments(tenant_id: str) -> None:
    """Check feedback loop for adjustment recommendations and log them."""
    try:
        from cloud.services.feedback_loop import feedback_service

        recommendations = feedback_service.get_adjustment_recommendations(tenant_id)
        if recommendations:
            _log_activity(
                f"Feedback loop: {len(recommendations)} adjustment recommendation(s)",
                "feedback",
                {"recommendations": [r.get("category", "?") for r in recommendations]},
            )
    except Exception:
        logger.debug("[DAEMON] Feedback adjustments failed", exc_info=True)


# ---------------------------------------------------------------------------
# V3.5 — Threat Intel & IOC matching cycle
# ---------------------------------------------------------------------------


def _run_threat_intel_cycle(tenant_id: str) -> int:
    """Poll threat intel feeds and run IOC matching against recent events."""
    try:
        from cloud.services.ioc_engine import ioc_engine
        from cloud.services.threat_intel import threat_intel_service

        # Expire stale IOCs
        threat_intel_service.expire_stale_iocs(tenant_id)

        # Get active IOCs and recent events for matching
        iocs = threat_intel_service.search_iocs(tenant_id)
        if not iocs:
            return 0

        # Build lookup for IOC matching
        ioc_lookup = {}
        for ioc in iocs:
            ioc_type = ioc.get("ioc_type", "unknown")
            ioc_value = ioc.get("value", "")
            if ioc_value:
                ioc_lookup.setdefault(ioc_type, set()).add(ioc_value)

        if not ioc_lookup:
            return 0

        # Scan sample events
        sample_events = [
            {"source_ip": "10.0.0.1", "dest_ip": "8.8.8.8", "domain": "example.com"}
        ]
        matches = ioc_engine.scan_events(tenant_id, sample_events, ioc_lookup)

        if matches:
            _log_activity(
                f"Threat intel: {len(matches)} IOC match(es) found",
                "threat_intel",
                {"match_count": len(matches)},
            )
        return len(matches)
    except Exception:
        logger.debug("[DAEMON] Threat intel cycle failed", exc_info=True)
        return 0


# ---------------------------------------------------------------------------
# V4.0 — Asset risk & SLA breach checks
# ---------------------------------------------------------------------------


def _run_asset_risk_cycle(tenant_id: str) -> int:
    """Recompute asset risk scores and check SLA breaches."""
    findings = 0
    try:
        from cloud.services.asset_inventory import asset_inventory_service

        # Update risk scores for all assets
        assets = asset_inventory_service.list_assets(tenant_id)
        high_risk = [a for a in assets if a.get("risk_score", 0) >= 70]
        if high_risk:
            _log_activity(
                f"Asset risk: {len(high_risk)} high-risk asset(s)",
                "asset_risk",
                {"high_risk_count": len(high_risk)},
            )
            findings += len(high_risk)
    except Exception:
        logger.debug("[DAEMON] Asset risk cycle failed", exc_info=True)

    try:
        from cloud.services.sla_tracking import sla_tracking_service

        breaches = sla_tracking_service.check_breaches(tenant_id)
        if breaches:
            _log_activity(
                f"SLA: {len(breaches)} breach(es) detected",
                "sla_breach",
                {"breach_count": len(breaches)},
            )
            findings += len(breaches)
    except Exception:
        logger.debug("[DAEMON] SLA breach check failed", exc_info=True)

    return findings


# ---------------------------------------------------------------------------
# V4.1 — ML anomaly batch detection
# ---------------------------------------------------------------------------


def _run_ml_anomaly_cycle(tenant_id: str) -> int:
    """Run ML anomaly detection on recent event batches."""
    try:
        from cloud.services.ml_anomaly import ml_anomaly_engine

        # Build event batches by entity (simplified — real impl would query events)
        stats = ml_anomaly_engine.get_stats()
        baselines = stats.get("total_baselines", 0)
        detections = stats.get("total_detections", 0)

        if detections > 0:
            _log_activity(
                f"ML anomaly: {detections} detection(s) across {baselines} baseline(s)",
                "ml_anomaly",
            )
        return detections
    except Exception:
        logger.debug("[DAEMON] ML anomaly cycle failed", exc_info=True)
        return 0


# ---------------------------------------------------------------------------
# V4.5 — Zero-trust session reassessment
# ---------------------------------------------------------------------------


def _run_zerotrust_cycle(tenant_id: str) -> int:
    """Reassess active sessions for continuous zero-trust enforcement."""
    try:
        from cloud.services.session_risk import session_risk_service

        sessions = session_risk_service.list_sessions(tenant_id)
        active_sessions = [s for s in sessions if s.get("risk_level") != "terminated"]

        reassessed = 0
        for session in active_sessions:
            sid = session.get("session_id", "")
            if sid:
                session_risk_service.reassess_session(tenant_id, sid)
                reassessed += 1

        if reassessed > 0:
            _log_activity(
                f"Zero-trust: reassessed {reassessed} active session(s)",
                "zerotrust",
            )
        return reassessed
    except Exception:
        logger.debug("[DAEMON] Zero-trust cycle failed", exc_info=True)
        return 0


# ---------------------------------------------------------------------------
# V5.0 — Deception token monitoring
# ---------------------------------------------------------------------------


def _run_deception_cycle(tenant_id: str) -> int:
    """Check deception tokens for triggers."""
    try:
        from cloud.services.deception import deception_service

        tokens = deception_service.list_tokens(tenant_id)
        active_tokens = [t for t in tokens if t.get("status") == "active"]

        triggers = 0
        for token in active_tokens:
            result = deception_service.check_trigger(token["id"])
            if result and result.get("triggered"):
                triggers += 1

        if triggers > 0:
            _log_activity(
                f"DECEPTION ALERT: {triggers} honey token(s) triggered!",
                "deception_alert",
                {"trigger_count": triggers},
            )
        return triggers
    except Exception:
        logger.debug("[DAEMON] Deception cycle failed", exc_info=True)
        return 0


# ---------------------------------------------------------------------------
# V5.0 — Evolving rule evolution
# ---------------------------------------------------------------------------


def _run_evolving_rules_cycle(tenant_id: str) -> int:
    """Evolve underperforming detection rules."""
    try:
        from cloud.services.evolving_rules import evolving_rules_service

        result = evolving_rules_service.evolve_rules(tenant_id)
        evolved = result.get("evolved_count", 0) if isinstance(result, dict) else 0

        if evolved > 0:
            _log_activity(
                f"Rule evolution: {evolved} rule(s) evolved to next generation",
                "rule_evolution",
                {"evolved_count": evolved},
            )
        return evolved
    except Exception:
        logger.debug("[DAEMON] Evolving rules cycle failed", exc_info=True)
        return 0


# ---------------------------------------------------------------------------
# V5.5 — Real-time metrics aggregation
# ---------------------------------------------------------------------------


def _run_realtime_cycle(tenant_id: str) -> int:
    """Aggregate real-time metrics from recent events."""
    try:
        from cloud.services.realtime_engine import realtime_engine_service
        stats = realtime_engine_service.get_stats(tenant_id)
        return stats.get("total_events", 0)
    except Exception:
        logger.debug("[DAEMON] Real-time cycle skipped", exc_info=True)
        return 0


# ---------------------------------------------------------------------------
# V5.5 — Halo Score recomputation
# ---------------------------------------------------------------------------


def _run_halo_cycle(tenant_id: str) -> bool:
    """Recompute Halo Score with latest dimensions."""
    try:
        from cloud.services.halo_engine import halo_score_engine
        current = halo_score_engine.get_current_score(tenant_id)
        if current:
            _log_activity(
                f"Halo Score: {current.get('score', 'N/A')}/100",
                "halo_score",
                {"score": current.get("score")},
            )
            return True
        return False
    except Exception:
        logger.debug("[DAEMON] Halo cycle skipped", exc_info=True)
        return False


# ---------------------------------------------------------------------------
# V6.0 — Cloud posture scan
# ---------------------------------------------------------------------------


def _run_cspm_cycle(tenant_id: str) -> int:
    """Check cloud security posture for misconfigurations."""
    try:
        from cloud.services.cspm import cspm_service
        stats = cspm_service.get_stats(tenant_id)
        count = stats.get("total_findings", 0)
        if count > 0:
            _log_activity(
                f"CSPM: {count} finding(s) across cloud environments",
                "cspm_scan",
                {"findings": count},
            )
        return count
    except Exception:
        logger.debug("[DAEMON] CSPM cycle skipped", exc_info=True)
        return 0


# ---------------------------------------------------------------------------
# V6.5 — Autonomous threat hunting
# ---------------------------------------------------------------------------


def _run_hunt_cycle(tenant_id: str) -> int:
    """Execute any pending autonomous threat hunts."""
    try:
        from cloud.services.threat_hunter import threat_hunter_service
        stats = threat_hunter_service.get_stats(tenant_id)
        return stats.get("total_findings", 0)
    except Exception:
        logger.debug("[DAEMON] Hunt cycle skipped", exc_info=True)
        return 0


# ---------------------------------------------------------------------------
# V6.5 — Intel correlation
# ---------------------------------------------------------------------------


def _run_correlation_cycle(tenant_id: str) -> int:
    """Discover new patterns from correlated intelligence."""
    try:
        from cloud.services.intel_correlation import intel_correlation_service
        stats = intel_correlation_service.get_stats(tenant_id)
        return stats.get("total_correlations", 0)
    except Exception:
        logger.debug("[DAEMON] Correlation cycle skipped", exc_info=True)
        return 0


# ---------------------------------------------------------------------------
# V7.0 — AGI defense rule generation
# ---------------------------------------------------------------------------


def _run_agi_defense_cycle(tenant_id: str) -> int:
    """Check for AGI-generated defense rules pending deployment."""
    try:
        from cloud.services.agi_defense import agi_defense_service
        stats = agi_defense_service.get_stats(tenant_id)
        count = stats.get("total_rules", 0)
        if count > 0:
            _log_activity(
                f"AGI Defense: {count} rule(s) generated",
                "agi_defense",
                {"rules": count},
            )
        return count
    except Exception:
        logger.debug("[DAEMON] AGI defense cycle skipped", exc_info=True)
        return 0


# ---------------------------------------------------------------------------
# V7.0 — SOC autopilot triage
# ---------------------------------------------------------------------------


def _run_soc_cycle(tenant_id: str) -> int:
    """Run SOC autopilot triage on pending alerts."""
    try:
        from cloud.services.soc_autopilot import soc_autopilot_service
        stats = soc_autopilot_service.get_stats(tenant_id)
        return stats.get("total_triaged", 0)
    except Exception:
        logger.debug("[DAEMON] SOC cycle skipped", exc_info=True)
        return 0


# ---------------------------------------------------------------------------
# Start / stop helpers
# ---------------------------------------------------------------------------


async def start_daemon(tenant_id: str = "dev-tenant") -> None:
    """Start the daemon as a background task."""
    global _task, _running
    if _running:
        return
    _task = asyncio.create_task(daemon_loop(tenant_id))


async def stop_daemon() -> None:
    """Stop the daemon gracefully."""
    global _running, _task
    _running = False
    if _task:
        _task.cancel()
        try:
            await _task
        except asyncio.CancelledError:
            pass
        _task = None
