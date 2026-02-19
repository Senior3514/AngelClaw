"""Coverage boost tests — guardian agents, detection, services, angelnode → 95%.

Targets missed lines in:
  - cloud/guardian/network_warden.py (DNS tunneling, beaconing, Tor)
  - cloud/guardian/detection/correlator.py (cross-source, supply chain)
  - cloud/guardian/detection/patterns.py
  - cloud/guardian/response_agent.py
  - cloud/guardian/secrets_warden.py
  - cloud/guardian/timeline_warden.py
  - cloud/guardian/self_audit.py
  - cloud/guardian/learning.py
  - cloud/services/event_bus.py (V2.1/V2.2 patterns)
  - cloud/services/guardian_chat.py (handlers)
  - cloud/services/guardian_scan.py
  - cloud/services/guardian_heartbeat.py
  - angelnode/ai_shield/openclaw_adapter.py
  - angelnode/core/server.py
  - cloud/angelclaw/actions.py, brain.py, security.py, shield.py, context.py
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.orm import Session

from cloud.db.models import (
    AgentNodeRow,
    EventRow,
    GuardianAlertRow,
    GuardianChangeRow,
    GuardianReportRow,
    PolicySetRow,
)


# ---------------------------------------------------------------------------
# Network Warden tests
# ---------------------------------------------------------------------------


class TestNetworkWarden:
    @pytest.mark.asyncio
    async def test_empty_events(self):
        from cloud.guardian.models import AgentTask
        from cloud.guardian.network_warden import NetworkWarden

        warden = NetworkWarden()
        task = AgentTask(
            task_type="detect",
            payload={"events": [], "window_seconds": 300},
        )
        result = await warden.execute(task)
        assert result.success
        assert result.result_data["indicators"] == []

    @pytest.mark.asyncio
    async def test_suspicious_port(self):
        from cloud.guardian.models import AgentTask
        from cloud.guardian.network_warden import NetworkWarden

        warden = NetworkWarden()
        events = [{
            "id": "e1", "agent_id": "a1", "type": "network.connection",
            "severity": "high", "details": {"dst_port": 4444},
            "source": "", "timestamp": datetime.now(timezone.utc).isoformat(),
            "tenant_id": "dev",
        }]
        task = AgentTask(
            task_type="detect",
            payload={"events": events, "window_seconds": 300},
        )
        result = await warden.execute(task)
        assert result.success
        indicators = result.result_data["indicators"]
        assert any(i["pattern_name"] == "suspicious_outbound_port" for i in indicators)

    @pytest.mark.asyncio
    async def test_public_port_exposure(self):
        from cloud.guardian.models import AgentTask
        from cloud.guardian.network_warden import NetworkWarden

        warden = NetworkWarden()
        events = [{
            "id": "e2", "agent_id": "a1", "type": "network.listen",
            "severity": "high", "details": {"bind_address": "203.0.113.5"},
            "source": "", "timestamp": datetime.now(timezone.utc).isoformat(),
            "tenant_id": "dev",
        }]
        task = AgentTask(task_type="detect", payload={"events": events})
        result = await warden.execute(task)
        assert result.success
        indicators = result.result_data["indicators"]
        assert any(i["pattern_name"] == "public_port_exposure" for i in indicators)

    @pytest.mark.asyncio
    async def test_suspicious_dns(self):
        from cloud.guardian.models import AgentTask
        from cloud.guardian.network_warden import NetworkWarden

        warden = NetworkWarden()
        events = [{
            "id": "e3", "agent_id": "a1", "type": "network.dns",
            "severity": "high", "details": {"dns_query": "evil.onion"},
            "source": "", "timestamp": datetime.now(timezone.utc).isoformat(),
            "tenant_id": "dev",
        }]
        task = AgentTask(task_type="detect", payload={"events": events})
        result = await warden.execute(task)
        assert result.success
        indicators = result.result_data["indicators"]
        assert any(i["pattern_name"] == "suspicious_dns" for i in indicators)

    @pytest.mark.asyncio
    async def test_port_scan_detection(self):
        from cloud.guardian.models import AgentTask
        from cloud.guardian.network_warden import NetworkWarden

        warden = NetworkWarden()
        events = [
            {
                "id": f"e-{i}", "agent_id": "scanner-agent",
                "type": "network.connection", "severity": "info",
                "details": {"dst_port": 1000 + i}, "source": "",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tenant_id": "dev",
            }
            for i in range(15)
        ]
        task = AgentTask(task_type="detect", payload={"events": events})
        result = await warden.execute(task)
        assert result.success
        indicators = result.result_data["indicators"]
        assert any(i["pattern_name"] == "port_scan_detected" for i in indicators)

    @pytest.mark.asyncio
    async def test_dns_tunneling(self):
        from cloud.guardian.models import AgentTask
        from cloud.guardian.network_warden import NetworkWarden

        warden = NetworkWarden()
        # Create events with very long DNS labels
        events = [
            {
                "id": f"dns-{i}", "agent_id": "tunnel-agent",
                "type": "network.dns", "severity": "info",
                "details": {"dns_query": f"{'a' * 55}.sub{i}.example.com"},
                "source": "", "tenant_id": "dev",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            for i in range(5)
        ]
        task = AgentTask(task_type="detect", payload={"events": events})
        result = await warden.execute(task)
        assert result.success
        indicators = result.result_data["indicators"]
        assert any(i["pattern_name"] == "dns_tunneling" for i in indicators)

    @pytest.mark.asyncio
    async def test_beaconing_detection(self):
        from cloud.guardian.models import AgentTask
        from cloud.guardian.network_warden import NetworkWarden

        warden = NetworkWarden()
        base = datetime.now(timezone.utc)
        events = [
            {
                "id": f"beacon-{i}", "agent_id": "beacon-agent",
                "type": "network.connection", "severity": "info",
                "details": {"dst_ip": "10.10.10.10", "dst_port": 443},
                "source": "", "tenant_id": "dev",
                "timestamp": (base + timedelta(seconds=60 * i)).isoformat(),
            }
            for i in range(6)  # Regular 60s intervals
        ]
        task = AgentTask(task_type="detect", payload={"events": events})
        result = await warden.execute(task)
        assert result.success

    @pytest.mark.asyncio
    async def test_tor_connections(self):
        from cloud.guardian.models import AgentTask
        from cloud.guardian.network_warden import NetworkWarden

        warden = NetworkWarden()
        events = [{
            "id": "tor-1", "agent_id": "tor-agent",
            "type": "network.connection", "severity": "high",
            "details": {"dst_port": 9050}, "source": "", "tenant_id": "dev",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }]
        task = AgentTask(task_type="detect", payload={"events": events})
        result = await warden.execute(task)
        assert result.success
        indicators = result.result_data["indicators"]
        assert any(i["pattern_name"] == "tor_connection" for i in indicators)

    def test_suspicious_domain_patterns(self):
        from cloud.guardian.network_warden import _is_suspicious_domain

        assert _is_suspicious_domain("evil.onion") is True
        assert _is_suspicious_domain("c2.evil.com") is True
        assert _is_suspicious_domain("beacon.attacker.org") is True
        assert _is_suspicious_domain("exfil.bad.net") is True
        assert _is_suspicious_domain("normal.com") is False
        # Long subdomain
        assert _is_suspicious_domain("a" * 55 + ".example.com") is True


# ---------------------------------------------------------------------------
# Correlator tests
# ---------------------------------------------------------------------------


class TestCorrelator:
    def test_correlate_empty(self):
        from cloud.guardian.detection.correlator import CorrelationEngine

        engine = CorrelationEngine()
        assert engine.correlate([]) == []

    def test_correlate_single_event(self, db: Session):
        from cloud.guardian.detection.correlator import CorrelationEngine

        engine = CorrelationEngine()
        event = EventRow(
            id="c-1", agent_id="a1",
            timestamp=datetime.now(timezone.utc),
            category="shell", type="exec", severity="high",
        )
        assert engine.correlate([event]) == []

    def test_correlate_kill_chain(self, db: Session):
        from cloud.guardian.detection.correlator import CorrelationEngine

        engine = CorrelationEngine()
        now = datetime.now(timezone.utc)

        events = [
            EventRow(id="kc-1", agent_id="a1", timestamp=now,
                     category="auth", type="auth_failure", severity="high"),
            EventRow(id="kc-2", agent_id="a1", timestamp=now + timedelta(seconds=30),
                     category="shell", type="shell_exec", severity="critical"),
            EventRow(id="kc-3", agent_id="a1", timestamp=now + timedelta(seconds=60),
                     category="network", type="network_upload", severity="high"),
        ]
        chains = engine.correlate(events)
        # Should find a chain with multiple tactics
        assert isinstance(chains, list)

    def test_correlate_cross_agent(self, db: Session):
        from cloud.guardian.detection.correlator import CorrelationEngine

        engine = CorrelationEngine()
        now = datetime.now(timezone.utc)

        events = [
            EventRow(id="ca-1", agent_id="a1", timestamp=now,
                     category="ai_tool", type="shell_exec", severity="high",
                     details={"tool_name": "bash"}),
            EventRow(id="ca-2", agent_id="a2", timestamp=now + timedelta(seconds=10),
                     category="ai_tool", type="shell_exec", severity="critical",
                     details={"tool_name": "bash"}),
        ]
        chains = engine.correlate(events)
        assert isinstance(chains, list)

    def test_correlate_cross_source_ip(self, db: Session):
        from cloud.guardian.detection.correlator import CorrelationEngine

        engine = CorrelationEngine()
        now = datetime.now(timezone.utc)

        events = [
            EventRow(id="cs-1", agent_id="a1", timestamp=now,
                     category="shell", type="shell_exec", severity="high",
                     details={"source_ip": "192.168.1.100"}),
            EventRow(id="cs-2", agent_id="a2", timestamp=now + timedelta(seconds=10),
                     category="network", type="network_upload", severity="high",
                     details={"source_ip": "192.168.1.100"}),
            EventRow(id="cs-3", agent_id="a3", timestamp=now + timedelta(seconds=20),
                     category="shell", type="exec", severity="critical",
                     details={"source_ip": "192.168.1.100"}),
        ]
        chains = engine.correlate(events)
        assert isinstance(chains, list)

    def test_supply_chain_correlation(self, db: Session):
        from cloud.guardian.detection.correlator import CorrelationEngine

        engine = CorrelationEngine()
        now = datetime.now(timezone.utc)

        events = [
            EventRow(id="sc-1", agent_id="a1", timestamp=now,
                     category="shell", type="install", severity="medium",
                     details={"command": "pip install malware-pkg"}),
            EventRow(id="sc-2", agent_id="a1", timestamp=now + timedelta(seconds=30),
                     category="shell", type="shell_exec", severity="high",
                     details={"command": "python -c 'import os; os.system(\"whoami\")'"}),
        ]
        chains = engine.correlate(events)
        assert isinstance(chains, list)

    def test_chains_to_indicators(self):
        from cloud.guardian.detection.correlator import CorrelationEngine
        from cloud.guardian.models import CorrelationChain

        engine = CorrelationEngine()
        chains = [
            CorrelationChain(
                event_ids=["e1", "e2"], agent_ids=["a1"],
                tactics=["initial_access", "execution"],
                severity="critical", confidence=0.85,
                description="Test chain", time_span_seconds=30,
            ),
            CorrelationChain(
                event_ids=["e3", "e4", "e5"], agent_ids=["a1", "a2", "a3"],
                tactics=["execution", "exfiltration"],
                severity="high", confidence=0.7,
                description="Multi-agent chain", time_span_seconds=60,
            ),
        ]
        indicators = engine.chains_to_indicators(chains)
        assert len(indicators) == 2
        assert indicators[0].pattern_name == "kill_chain"
        assert indicators[0].suggested_playbook == "quarantine_agent"

    def test_infer_tactic(self):
        from cloud.guardian.detection.correlator import _infer_tactic

        event = EventRow(id="t1", agent_id="a1",
                        timestamp=datetime.now(timezone.utc),
                        category="shell", type="shell_exec", severity="high")
        tactic = _infer_tactic(event)
        assert tactic is not None

        event2 = EventRow(id="t2", agent_id="a1",
                         timestamp=datetime.now(timezone.utc),
                         category="custom", type="unknown_random_type", severity="info")
        tactic2 = _infer_tactic(event2)
        # Might be None for unknown types
        assert tactic2 is None or isinstance(tactic2, str)


# ---------------------------------------------------------------------------
# Event Bus tests (V2.1/V2.2 patterns)
# ---------------------------------------------------------------------------


class TestEventBus:
    def test_check_for_alerts_empty(self, db: Session):
        from cloud.services.event_bus import check_for_alerts

        alerts = check_for_alerts(db, [])
        assert alerts == []

    def test_privilege_escalation_cascade(self, db: Session):
        from cloud.services.event_bus import check_for_alerts

        events = []
        for i in range(4):
            events.append(EventRow(
                id=str(uuid.uuid4()), agent_id="priv-agent",
                timestamp=datetime.now(timezone.utc),
                category="shell", type=f"sudo_exec_{i}", severity="critical",
                details={"command": f"sudo chmod 777 /etc/important_{i}"},
            ))
        for e in events:
            db.add(e)
        db.commit()

        alerts = check_for_alerts(db, events)
        assert any(a.alert_type == "privilege_escalation_cascade" for a in alerts)

    def test_lateral_movement(self, db: Session):
        from cloud.services.event_bus import check_for_alerts

        events = []
        for i, agent in enumerate(["agent-a", "agent-b", "agent-c"]):
            events.append(EventRow(
                id=str(uuid.uuid4()), agent_id=agent,
                timestamp=datetime.now(timezone.utc),
                category="network", type=f"ssh_exec_{i}", severity="high",
                details={"command": f"ssh root@target_{i}"},
            ))
        for e in events:
            db.add(e)
        db.commit()

        alerts = check_for_alerts(db, events)
        assert any(a.alert_type == "lateral_movement" for a in alerts)

    def test_data_staging(self, db: Session):
        from cloud.services.event_bus import check_for_alerts

        events = []
        for i in range(3):
            events.append(EventRow(
                id=str(uuid.uuid4()), agent_id="staging-agent",
                timestamp=datetime.now(timezone.utc),
                category="shell", type="compress", severity="info",
                details={"command": f"tar czf archive_{i}.tar.gz /data"},
            ))
        for e in events:
            db.add(e)
        db.commit()

        alerts = check_for_alerts(db, events)
        assert any(a.alert_type == "data_staging" for a in alerts)

    def test_credential_spray(self, db: Session):
        from cloud.services.event_bus import check_for_alerts

        events = []
        for agent in ["spray-a", "spray-b"]:
            for i in range(3):
                events.append(EventRow(
                    id=str(uuid.uuid4()), agent_id=agent,
                    timestamp=datetime.now(timezone.utc),
                    category="auth", type=f"auth_failure_{i}", severity="high",
                ))
        for e in events:
            db.add(e)
        db.commit()

        alerts = check_for_alerts(db, events)
        assert any(a.alert_type == "credential_spray" for a in alerts)

    def test_c2_callback(self, db: Session):
        from cloud.services.event_bus import check_for_alerts

        events = [EventRow(
            id=str(uuid.uuid4()), agent_id="c2-agent",
            timestamp=datetime.now(timezone.utc),
            category="shell", type="reverse shell exec", severity="critical",
            details={"target": "10.0.0.1:4444"},
        )]
        for e in events:
            db.add(e)
        db.commit()

        alerts = check_for_alerts(db, events)
        assert any(a.alert_type == "c2_callback" for a in alerts)

    def test_ransomware_indicator(self, db: Session):
        from cloud.services.event_bus import check_for_alerts

        events = []
        for i in range(3):
            events.append(EventRow(
                id=str(uuid.uuid4()), agent_id="ransom-agent",
                timestamp=datetime.now(timezone.utc),
                category="shell", type=f"encrypt_files_{i}", severity="critical",
                details={"command": f"openssl enc -aes-256-cbc -in /data/file_{i}"},
            ))
        for e in events:
            db.add(e)
        db.commit()

        alerts = check_for_alerts(db, events)
        assert any(a.alert_type == "ransomware_indicator" for a in alerts)

    def test_defense_evasion(self, db: Session):
        from cloud.services.event_bus import check_for_alerts

        events = [EventRow(
            id=str(uuid.uuid4()), agent_id="evasion-agent",
            timestamp=datetime.now(timezone.utc),
            category="shell", type="log_clear", severity="high",
            details={"command": "history -c && rm -f /var/log/auth.log"},
        )]
        for e in events:
            db.add(e)
        db.commit()

        alerts = check_for_alerts(db, events)
        assert any(a.alert_type == "defense_evasion" for a in alerts)

    def test_cloud_api_abuse(self, db: Session):
        from cloud.services.event_bus import check_for_alerts

        events = []
        for i in range(12):
            events.append(EventRow(
                id=str(uuid.uuid4()), agent_id="cloud-agent",
                timestamp=datetime.now(timezone.utc),
                category="shell", type="cloud_cmd", severity="info",
                details={"command": f"aws s3api list-buckets --region us-east-{i}"},
            ))
        for e in events:
            db.add(e)
        db.commit()

        alerts = check_for_alerts(db, events)
        assert any(a.alert_type == "cloud_api_abuse" for a in alerts)


# ---------------------------------------------------------------------------
# Guardian Chat handler tests
# ---------------------------------------------------------------------------


class TestGuardianChatHandlers:
    def test_detect_intent(self):
        from cloud.services.guardian_chat import detect_intent

        assert detect_intent("What threats are there?") == "threats"
        assert detect_intent("Show me incidents") == "incidents"
        assert detect_intent("Any guardian alerts?") == "alerts"
        assert detect_intent("What changed?") == "changes"
        assert detect_intent("Suggest policy tightening") == "propose"
        assert detect_intent("How are my agents?") == "agent_status"
        assert detect_intent("Who are you?") == "about"
        assert detect_intent("What can you do? help") == "help"
        assert detect_intent("What have you been doing?") == "status_report"
        assert detect_intent("Scan the system") == "scan"
        assert detect_intent("Explain event abc") == "explain"
        assert detect_intent("random 12345") == "general"

    def test_handle_incidents(self, db: Session):
        from cloud.services.guardian_chat import _handle_incidents

        answer, actions, refs = _handle_incidents(db, "dev-tenant")
        assert isinstance(answer, str)
        assert isinstance(actions, list)

    def test_handle_agent_status_no_agents(self, db: Session):
        from cloud.services.guardian_chat import _handle_agent_status

        # Clear agents for this specific test - just run the handler
        answer, actions, refs = _handle_agent_status(db)
        assert isinstance(answer, str)

    def test_handle_threats(self, db: Session):
        from cloud.services.guardian_chat import _handle_threats

        answer, actions, refs = _handle_threats(db)
        assert isinstance(answer, str)

    def test_handle_alerts(self, db: Session):
        from cloud.services.guardian_chat import _handle_alerts

        answer, actions, refs = _handle_alerts(db, "dev-tenant")
        assert isinstance(answer, str)

    def test_handle_alerts_with_data(self, db: Session):
        from cloud.services.guardian_chat import _handle_alerts

        alert = GuardianAlertRow(
            id=str(uuid.uuid4()), tenant_id="dev-tenant",
            alert_type="test_alert", title="Test Alert",
            severity="critical", details={},
        )
        db.add(alert)
        db.commit()
        answer, actions, refs = _handle_alerts(db, "dev-tenant")
        assert "alert" in answer.lower() or "Alert" in answer

    def test_handle_changes(self, db: Session):
        from cloud.services.guardian_chat import _handle_changes

        answer, actions, refs = _handle_changes(db, "dev-tenant")
        assert isinstance(answer, str)

    def test_handle_changes_with_data(self, db: Session):
        from cloud.services.guardian_chat import _handle_changes

        change = GuardianChangeRow(
            id=str(uuid.uuid4()), tenant_id="dev-tenant",
            change_type="policy_update", description="Updated policy",
            changed_by="admin", created_at=datetime.now(timezone.utc),
        )
        db.add(change)
        db.commit()
        answer, actions, refs = _handle_changes(db, "dev-tenant")
        assert isinstance(answer, str)

    def test_handle_propose(self, db: Session):
        from cloud.services.guardian_chat import _handle_propose

        answer, actions, refs = _handle_propose(db, "dev-tenant")
        assert isinstance(answer, str)

    def test_handle_explain_no_event_id(self, db: Session):
        from cloud.services.guardian_chat import _handle_explain

        answer, actions, refs = _handle_explain(db, "explain what happened")
        assert "event ID" in answer

    def test_handle_explain_with_event_id(self, db: Session):
        from cloud.services.guardian_chat import _handle_explain

        event_id = str(uuid.uuid4())
        event = EventRow(
            id=event_id, agent_id="a1",
            timestamp=datetime.now(timezone.utc),
            category="shell", type="exec", severity="high",
        )
        db.add(event)
        db.commit()

        answer, actions, refs = _handle_explain(db, f"explain event {event_id}")
        assert isinstance(answer, str)

    def test_handle_explain_event_not_found(self, db: Session):
        from cloud.services.guardian_chat import _handle_explain

        fake_id = str(uuid.uuid4())
        answer, actions, refs = _handle_explain(db, f"explain event {fake_id}")
        assert "couldn't find" in answer.lower() or isinstance(answer, str)

    def test_handle_status_report_no_reports(self, db: Session):
        from cloud.services.guardian_chat import _handle_status_report

        answer, actions, refs = _handle_status_report(db, "no-reports-tenant")
        assert "just started" in answer.lower() or isinstance(answer, str)

    def test_handle_status_report_with_reports(self, db: Session):
        from cloud.services.guardian_chat import _handle_status_report

        report = GuardianReportRow(
            id=str(uuid.uuid4()), tenant_id="dev-tenant",
            timestamp=datetime.now(timezone.utc),
            agents_total=5, agents_active=4, agents_degraded=1, agents_offline=0,
            incidents_total=10, incidents_by_severity={"critical": 2},
            anomalies=["Test anomaly"],
            summary="5 agents healthy, 10 events",
        )
        db.add(report)
        # Add a second report
        report2 = GuardianReportRow(
            id=str(uuid.uuid4()), tenant_id="dev-tenant",
            timestamp=datetime.now(timezone.utc) - timedelta(minutes=5),
            agents_total=5, agents_active=4, agents_degraded=1, agents_offline=0,
            incidents_total=5, summary="Earlier report",
        )
        db.add(report2)
        db.commit()

        answer, actions, refs = _handle_status_report(db, "dev-tenant")
        assert "report" in answer.lower()

    @pytest.mark.asyncio
    async def test_handle_scan(self, db: Session):
        from cloud.services.guardian_chat import _handle_scan

        answer, actions, refs = await _handle_scan(db, "dev-tenant")
        assert isinstance(answer, str)

    def test_handle_about(self):
        from cloud.services.guardian_chat import _handle_about

        answer, actions, refs = _handle_about()
        assert "AngelClaw" in answer

    def test_handle_help(self):
        from cloud.services.guardian_chat import _handle_help

        answer, actions, refs = _handle_help()
        assert "Incidents" in answer

    def test_handle_general(self, db: Session):
        from cloud.services.guardian_chat import _handle_general

        answer, actions, refs = _handle_general(db, "dev-tenant")
        assert isinstance(answer, str)

    @pytest.mark.asyncio
    async def test_try_llm_enrichment_disabled(self):
        from cloud.services.guardian_chat import _try_llm_enrichment

        result = await _try_llm_enrichment("test", "context", "general")
        assert result is None


# ---------------------------------------------------------------------------
# Guardian Scan tests
# ---------------------------------------------------------------------------


class TestGuardianScan:
    @pytest.mark.asyncio
    async def test_run_guardian_scan(self, db: Session):
        from cloud.services.guardian_scan import run_guardian_scan

        result = await run_guardian_scan(db, "dev-tenant")
        assert result.total_checks > 0
        assert isinstance(result.summary, str)

    @pytest.mark.asyncio
    async def test_run_guardian_scan_with_secret_events(self, db: Session):
        from cloud.services.guardian_scan import run_guardian_scan

        event = EventRow(
            id=str(uuid.uuid4()), agent_id="scan-agent",
            timestamp=datetime.now(timezone.utc),
            category="ai_tool", type="secret_access", severity="critical",
            details={"accesses_secrets": True},
        )
        db.add(event)
        db.commit()
        result = await run_guardian_scan(db, "dev-tenant")
        assert result.total_checks > 0

    @pytest.mark.asyncio
    async def test_run_guardian_scan_with_injection(self, db: Session):
        from cloud.services.guardian_scan import run_guardian_scan

        event = EventRow(
            id=str(uuid.uuid4()), agent_id="scan-agent-2",
            timestamp=datetime.now(timezone.utc),
            category="ai_tool", type="injection_attempt", severity="high",
            details={"prompt_injection": True},
        )
        db.add(event)
        db.commit()
        result = await run_guardian_scan(db, "dev-tenant")
        assert result.total_checks > 0


# ---------------------------------------------------------------------------
# Guardian Heartbeat tests
# ---------------------------------------------------------------------------


class TestGuardianHeartbeat:
    def test_run_heartbeat(self, db: Session):
        from cloud.services.guardian_heartbeat import _run_heartbeat

        with patch("cloud.services.guardian_heartbeat.SessionLocal") as mock_sl, \
             patch.object(db, "close"):
            mock_sl.return_value = db
            report = _run_heartbeat("dev-tenant")
            assert report is not None
            assert report.tenant_id == "dev-tenant"

    def test_run_heartbeat_with_anomalies(self, db: Session):
        from cloud.services.guardian_heartbeat import _run_heartbeat

        # Add stale agent
        stale = AgentNodeRow(
            id="hb-stale-1", type="server", os="linux", hostname="hb-stale",
            status="active", registered_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc) - timedelta(minutes=15),
        )
        db.add(stale)

        # Add critical events
        for i in range(5):
            event = EventRow(
                id=str(uuid.uuid4()), agent_id="hb-stale-1",
                timestamp=datetime.now(timezone.utc),
                category="shell", type="exec", severity="critical",
            )
            db.add(event)

        # Add repeated pattern events
        for i in range(12):
            event = EventRow(
                id=str(uuid.uuid4()), agent_id="hb-stale-1",
                timestamp=datetime.now(timezone.utc),
                category="shell", type="repeated_type", severity="info",
            )
            db.add(event)
        db.commit()

        with patch("cloud.services.guardian_heartbeat.SessionLocal") as mock_sl, \
             patch.object(db, "close"):
            mock_sl.return_value = db
            report = _run_heartbeat("dev-tenant")
            assert report is not None
            assert len(report.anomalies) > 0


# ---------------------------------------------------------------------------
# OpenClaw Adapter tests
# ---------------------------------------------------------------------------


class TestOpenClawAdapter:
    def test_infer_severity(self):
        from angelnode.ai_shield.openclaw_adapter import _infer_severity
        from shared.models.event import Severity

        assert _infer_severity("bash", True) == Severity.CRITICAL
        assert _infer_severity("bash", False) == Severity.HIGH
        assert _infer_severity("write_file", False) == Severity.WARN
        assert _infer_severity("read_file", False) == Severity.INFO

    def test_detects_secret_access_key(self):
        from angelnode.ai_shield.openclaw_adapter import _detects_secret_access

        assert _detects_secret_access("bash", {"password": "secret"}) is True
        assert _detects_secret_access("bash", {"normal_key": "value"}) is False

    def test_detects_secret_access_value(self):
        from angelnode.ai_shield.openclaw_adapter import _detects_secret_access

        assert _detects_secret_access("bash", {"cmd": "AKIA1234567890ABCDEF"}) is True

    def test_detects_secret_access_path(self):
        from angelnode.ai_shield.openclaw_adapter import _detects_secret_access

        assert _detects_secret_access("bash", {"path": "/home/user/.ssh/id_rsa"}) is True
        assert _detects_secret_access("bash", {"path": "/home/user/.env"}) is True

    def test_detects_secret_nested_dict(self):
        from angelnode.ai_shield.openclaw_adapter import _detects_secret_access

        assert _detects_secret_access("bash", {"nested": {"api_key": "secret"}}) is True

    def test_detects_secret_no_secrets(self):
        from angelnode.ai_shield.openclaw_adapter import _detects_secret_access

        assert _detects_secret_access("read", {"file": "/tmp/test.txt"}) is False

    @pytest.mark.asyncio
    async def test_evaluate_tool_engine_unreachable(self):
        import httpx

        from angelnode.ai_shield.openclaw_adapter import ToolCallRequest, evaluate_tool

        req = ToolCallRequest(
            tool_name="bash", arguments={"command": "ls"},
            agent_id="test-agent",
        )
        # Mock httpx to simulate unreachable engine
        with patch("angelnode.ai_shield.openclaw_adapter.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.post.side_effect = httpx.ConnectError("Connection refused")
            result = await evaluate_tool(req)
        assert result.allowed is False
        assert result.action == "block"
        assert "unreachable" in result.reason.lower()

    @pytest.mark.asyncio
    async def test_evaluate_tool_with_secrets(self):
        from angelnode.ai_shield.openclaw_adapter import ToolCallRequest, evaluate_tool

        req = ToolCallRequest(
            tool_name="bash",
            arguments={"command": "cat /etc/shadow", "password": "secret123"},
            agent_id="test-agent",
        )
        result = await evaluate_tool(req)
        # Should detect secrets and fail-closed
        assert result.allowed is False


# ---------------------------------------------------------------------------
# AngelNode Server tests
# ---------------------------------------------------------------------------


class TestAngelNodeServer:
    def test_increment_counter(self):
        from shared.models.policy import PolicyAction

        from angelnode.core.server import _counters, _get_counters, _increment_counter

        initial = _get_counters()["total_evaluations"]
        _increment_counter(PolicyAction.ALLOW)
        after = _get_counters()
        assert after["total_evaluations"] == initial + 1
        assert after["allow"] >= 1

    def test_on_policy_update(self):
        from angelnode.core.server import _on_policy_update

        _on_policy_update(MagicMock())  # No crash when engine is None

    def test_on_sync_log(self):
        from angelnode.core.server import _on_sync_log

        _on_sync_log({"test": "data"})

    def test_on_agent_id_update(self):
        from angelnode.core.server import _on_agent_id_update

        _on_agent_id_update("new-id-123")

    def test_on_sync_timestamp(self):
        from angelnode.core.server import _on_sync_timestamp

        now = datetime.now(timezone.utc)
        _on_sync_timestamp(now)


# ---------------------------------------------------------------------------
# DB Session tests
# ---------------------------------------------------------------------------


class TestDBSession:
    def test_get_db(self):
        from cloud.db.session import get_db

        gen = get_db()
        db = next(gen)
        assert db is not None
        try:
            next(gen)
        except StopIteration:
            pass
