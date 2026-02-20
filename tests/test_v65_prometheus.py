"""Tests for V6.5 Prometheus: Threat Hunter, MITRE ATT&CK Mapper,
Adversary Simulation, Intelligence Correlation."""

from __future__ import annotations

import pytest

from cloud.services.adversary_sim import AdversarySimService
from cloud.services.intel_correlation import IntelCorrelationService
from cloud.services.mitre_mapper import MitreAttackMapper
from cloud.services.threat_hunter import ThreatHunterService

TENANT = "test-tenant"


# ===========================================================================
# ThreatHunterService
# ===========================================================================


class TestThreatHunterCreateHunt:
    """Hunt creation and basic field assertions."""

    def test_create_hunt_basic(self):
        svc = ThreatHunterService()
        hunt = svc.create_hunt(TENANT, "DNS-tunnel hunt")
        assert hunt["name"] == "DNS-tunnel hunt"
        assert hunt["tenant_id"] == TENANT
        assert hunt["status"] == "created"
        assert hunt["hunt_type"] == "hypothesis"
        assert hunt["findings_count"] == 0

    def test_create_hunt_with_hypothesis(self):
        svc = ThreatHunterService()
        hunt = svc.create_hunt(
            TENANT,
            "APT hunt",
            hypothesis="Adversary is using DNS tunneling for C2",
        )
        assert hunt["hypothesis"] == "Adversary is using DNS tunneling for C2"

    @pytest.mark.parametrize(
        "hunt_type",
        [
            "hypothesis",
            "ioc_sweep",
            "behavioral",
            "anomaly",
            "network",
            "endpoint",
        ],
    )
    def test_create_hunt_valid_types(self, hunt_type):
        svc = ThreatHunterService()
        hunt = svc.create_hunt(TENANT, f"hunt-{hunt_type}", hunt_type=hunt_type)
        assert hunt["hunt_type"] == hunt_type

    def test_create_hunt_invalid_type_defaults_hypothesis(self):
        svc = ThreatHunterService()
        hunt = svc.create_hunt(TENANT, "bad type", hunt_type="invalid_xyz")
        assert hunt["hunt_type"] == "hypothesis"

    def test_create_hunt_with_config(self):
        svc = ThreatHunterService()
        cfg = {"sources": ["siem", "edr"], "depth": 3}
        hunt = svc.create_hunt(TENANT, "configured", config=cfg)
        assert hunt["config"] == cfg

    def test_create_hunt_created_by(self):
        svc = ThreatHunterService()
        hunt = svc.create_hunt(TENANT, "analyst hunt", created_by="alice")
        assert hunt["created_by"] == "alice"

    def test_create_hunt_has_unique_id(self):
        svc = ThreatHunterService()
        h1 = svc.create_hunt(TENANT, "hunt1")
        h2 = svc.create_hunt(TENANT, "hunt2")
        assert h1["id"] != h2["id"]


class TestThreatHunterListHunts:
    """Listing and filtering hunts."""

    def test_list_hunts_empty(self):
        svc = ThreatHunterService()
        assert svc.list_hunts(TENANT) == []

    def test_list_hunts_returns_created(self):
        svc = ThreatHunterService()
        svc.create_hunt(TENANT, "h1")
        svc.create_hunt(TENANT, "h2")
        hunts = svc.list_hunts(TENANT)
        assert len(hunts) == 2

    def test_list_hunts_tenant_isolation(self):
        svc = ThreatHunterService()
        svc.create_hunt(TENANT, "mine")
        svc.create_hunt("other-tenant", "theirs")
        assert len(svc.list_hunts(TENANT)) == 1
        assert len(svc.list_hunts("other-tenant")) == 1

    def test_list_hunts_status_filter(self):
        svc = ThreatHunterService()
        svc.create_hunt(TENANT, "a")
        hunt_b = svc.create_hunt(TENANT, "b")
        svc.execute_hunt(hunt_b["id"])
        completed = svc.list_hunts(TENANT, status="completed")
        created = svc.list_hunts(TENANT, status="created")
        assert len(completed) == 1
        assert len(created) == 1

    def test_list_hunts_status_filter_no_match(self):
        svc = ThreatHunterService()
        svc.create_hunt(TENANT, "a")
        assert svc.list_hunts(TENANT, status="running") == []


class TestThreatHunterExecute:
    """Hunt execution and result tracking."""

    def test_execute_hunt_completes(self):
        svc = ThreatHunterService()
        hunt = svc.create_hunt(TENANT, "exec-hunt")
        result = svc.execute_hunt(hunt["id"])
        assert result["status"] == "completed"
        assert result["started_at"] is not None
        assert result["completed_at"] is not None

    def test_execute_hunt_not_found(self):
        svc = ThreatHunterService()
        result = svc.execute_hunt("nonexistent-id")
        assert result == {"error": "Hunt not found"}

    def test_execute_hunt_already_running(self):
        svc = ThreatHunterService()
        hunt = svc.create_hunt(TENANT, "run-twice")
        # First execution completes, but let's simulate running state
        svc._hunts[hunt["id"]].status = "running"
        result = svc.execute_hunt(hunt["id"])
        assert result == {"error": "Hunt is already running"}

    @pytest.mark.parametrize(
        "hunt_type,expected_step",
        [
            ("ioc_sweep", "ioc_sweep"),
            ("behavioral", "behavioral_analysis"),
            ("anomaly", "anomaly_detection"),
            ("hypothesis", "hypothesis_test"),
        ],
    )
    def test_execute_hunt_type_logic(self, hunt_type, expected_step):
        svc = ThreatHunterService()
        hunt = svc.create_hunt(TENANT, f"exec-{hunt_type}", hunt_type=hunt_type)
        result = svc.execute_hunt(hunt["id"])
        assert result["results"][0]["step"] == expected_step

    def test_execute_ioc_sweep_has_findings(self):
        svc = ThreatHunterService()
        hunt = svc.create_hunt(TENANT, "ioc", hunt_type="ioc_sweep")
        result = svc.execute_hunt(hunt["id"])
        assert result["findings_count"] == 1
        assert result["iocs_matched"] == 1

    def test_execute_anomaly_no_findings(self):
        svc = ThreatHunterService()
        hunt = svc.create_hunt(TENANT, "anomaly", hunt_type="anomaly")
        result = svc.execute_hunt(hunt["id"])
        assert result["findings_count"] == 0

    def test_execute_records_events_analysed(self):
        svc = ThreatHunterService()
        hunt = svc.create_hunt(TENANT, "sweep", hunt_type="ioc_sweep")
        result = svc.execute_hunt(hunt["id"])
        assert result["events_analysed"] == 5000


class TestThreatHunterGetResults:
    """Retrieve hunt results."""

    def test_get_results_for_completed_hunt(self):
        svc = ThreatHunterService()
        hunt = svc.create_hunt(TENANT, "results-hunt")
        svc.execute_hunt(hunt["id"])
        results = svc.get_hunt_results(hunt["id"])
        assert results is not None
        assert results["hunt_id"] == hunt["id"]
        assert results["status"] == "completed"

    def test_get_results_not_found(self):
        svc = ThreatHunterService()
        assert svc.get_hunt_results("bogus-id") is None

    def test_get_results_includes_hypothesis(self):
        svc = ThreatHunterService()
        hunt = svc.create_hunt(TENANT, "h", hypothesis="test hypo")
        svc.execute_hunt(hunt["id"])
        results = svc.get_hunt_results(hunt["id"])
        assert results["hypothesis"] == "test hypo"


class TestThreatHunterPlaybook:
    """Hunt playbook CRUD."""

    def test_create_playbook(self):
        svc = ThreatHunterService()
        pb = svc.create_playbook(
            TENANT,
            "Lateral movement hunt",
            steps=[{"action": "query_logs"}, {"action": "correlate"}],
            description="Detect lateral movement",
            hunt_type="behavioral",
            tags=["lateral", "network"],
        )
        assert pb["name"] == "Lateral movement hunt"
        assert len(pb["steps"]) == 2
        assert pb["hunt_type"] == "behavioral"
        assert pb["tags"] == ["lateral", "network"]

    def test_create_playbook_invalid_type_defaults(self):
        svc = ThreatHunterService()
        pb = svc.create_playbook(TENANT, "bad-type", hunt_type="zzzz")
        assert pb["hunt_type"] == "hypothesis"

    def test_list_playbooks(self):
        svc = ThreatHunterService()
        svc.create_playbook(TENANT, "pb1")
        svc.create_playbook(TENANT, "pb2")
        pbs = svc.list_playbooks(TENANT)
        assert len(pbs) == 2

    def test_list_playbooks_empty(self):
        svc = ThreatHunterService()
        assert svc.list_playbooks(TENANT) == []

    def test_list_playbooks_tenant_isolation(self):
        svc = ThreatHunterService()
        svc.create_playbook(TENANT, "mine")
        svc.create_playbook("other", "theirs")
        assert len(svc.list_playbooks(TENANT)) == 1
        assert len(svc.list_playbooks("other")) == 1

    def test_playbook_created_by(self):
        svc = ThreatHunterService()
        pb = svc.create_playbook(TENANT, "pb", created_by="bob")
        assert pb["created_by"] == "bob"


class TestThreatHunterStats:
    """Statistics endpoint."""

    def test_stats_empty(self):
        svc = ThreatHunterService()
        stats = svc.get_stats(TENANT)
        assert stats["total_hunts"] == 0
        assert stats["total_playbooks"] == 0
        assert stats["total_findings"] == 0
        assert stats["total_iocs_matched"] == 0

    def test_stats_after_hunts(self):
        svc = ThreatHunterService()
        h1 = svc.create_hunt(TENANT, "a", hunt_type="ioc_sweep")
        svc.execute_hunt(h1["id"])
        h2 = svc.create_hunt(TENANT, "b", hunt_type="anomaly")
        svc.execute_hunt(h2["id"])
        svc.create_playbook(TENANT, "pb1")
        stats = svc.get_stats(TENANT)
        assert stats["total_hunts"] == 2
        assert stats["total_playbooks"] == 1
        assert stats["by_status"]["completed"] == 2
        assert stats["by_type"]["ioc_sweep"] == 1
        assert stats["by_type"]["anomaly"] == 1
        assert stats["total_findings"] >= 1
        assert stats["total_iocs_matched"] >= 1

    def test_stats_avg_findings_per_hunt(self):
        svc = ThreatHunterService()
        h = svc.create_hunt(TENANT, "x", hunt_type="ioc_sweep")
        svc.execute_hunt(h["id"])
        stats = svc.get_stats(TENANT)
        assert stats["avg_findings_per_hunt"] == stats["total_findings"] / 1


# ===========================================================================
# MitreAttackMapper
# ===========================================================================


class TestMitreAddTechnique:
    """Technique registration in the MITRE registry."""

    def test_add_technique_basic(self):
        svc = MitreAttackMapper()
        tech = svc.add_technique(
            TENANT,
            "T1059",
            "execution",
            "Command and Scripting Interpreter",
        )
        assert tech["technique_id"] == "T1059"
        assert tech["tactic"] == "execution"
        assert tech["name"] == "Command and Scripting Interpreter"
        assert tech["severity"] == "medium"
        assert tech["detection_coverage"] == 0.0
        assert tech["times_observed"] == 0

    def test_add_technique_tactic_lowered(self):
        svc = MitreAttackMapper()
        tech = svc.add_technique(TENANT, "T1566", "Initial_Access", "Phishing")
        assert tech["tactic"] == "initial_access"

    def test_add_technique_custom_severity(self):
        svc = MitreAttackMapper()
        tech = svc.add_technique(
            TENANT,
            "T1059",
            "execution",
            "CSI",
            severity="critical",
        )
        assert tech["severity"] == "critical"

    def test_add_technique_with_description(self):
        svc = MitreAttackMapper()
        tech = svc.add_technique(
            TENANT,
            "T1078",
            "persistence",
            "Valid Accounts",
            description="Adversaries may steal credentials",
        )
        assert tech["description"] == "Adversaries may steal credentials"


class TestMitreListTechniques:
    """Listing and filtering techniques."""

    def test_list_techniques_empty(self):
        svc = MitreAttackMapper()
        assert svc.list_techniques(TENANT) == []

    def test_list_techniques_returns_all(self):
        svc = MitreAttackMapper()
        svc.add_technique(TENANT, "T1059", "execution", "CSI")
        svc.add_technique(TENANT, "T1566", "initial_access", "Phishing")
        techs = svc.list_techniques(TENANT)
        assert len(techs) == 2

    def test_list_techniques_tactic_filter(self):
        svc = MitreAttackMapper()
        svc.add_technique(TENANT, "T1059", "execution", "CSI")
        svc.add_technique(TENANT, "T1566", "initial_access", "Phishing")
        techs = svc.list_techniques(TENANT, tactic="execution")
        assert len(techs) == 1
        assert techs[0]["technique_id"] == "T1059"

    def test_list_techniques_tactic_filter_case_insensitive(self):
        svc = MitreAttackMapper()
        svc.add_technique(TENANT, "T1059", "execution", "CSI")
        techs = svc.list_techniques(TENANT, tactic="Execution")
        assert len(techs) == 1

    def test_list_techniques_tenant_isolation(self):
        svc = MitreAttackMapper()
        svc.add_technique(TENANT, "T1059", "execution", "CSI")
        svc.add_technique("other", "T1566", "initial_access", "Phishing")
        assert len(svc.list_techniques(TENANT)) == 1
        assert len(svc.list_techniques("other")) == 1


class TestMitreMapEvent:
    """Event-to-technique mapping."""

    def test_map_event_with_match(self):
        svc = MitreAttackMapper()
        svc.add_technique(TENANT, "T1059", "execution", "Command Scripting")
        result = svc.map_event(TENANT, "command", indicators={"detail": "scripting"})
        assert result["event_type"] == "command"
        assert result["techniques_matched"] >= 1

    def test_map_event_no_techniques_registered(self):
        svc = MitreAttackMapper()
        result = svc.map_event(TENANT, "some_event")
        assert result["techniques_matched"] == 0
        assert result["mappings"] == []

    def test_map_event_updates_observation_count(self):
        svc = MitreAttackMapper()
        svc.add_technique(TENANT, "T1059", "execution", "Command Scripting")
        svc.map_event(TENANT, "command", indicators={"detail": "scripting"})
        updated = svc.list_techniques(TENANT)
        assert updated[0]["times_observed"] >= 1

    def test_map_event_no_indicators(self):
        svc = MitreAttackMapper()
        svc.add_technique(TENANT, "T1059", "execution", "CSI")
        result = svc.map_event(TENANT, "random_event")
        assert isinstance(result["mappings"], list)

    def test_map_event_tactic_in_indicators(self):
        svc = MitreAttackMapper()
        svc.add_technique(TENANT, "T1059", "execution", "CSI")
        result = svc.map_event(
            TENANT,
            "alert",
            indicators={"info": "execution related activity"},
        )
        # The tactic keyword "execution" appears in indicators -> confidence boost
        assert isinstance(result["techniques_matched"], int)


class TestMitreCoverage:
    """ATT&CK coverage and gap analysis."""

    def test_coverage_empty(self):
        svc = MitreAttackMapper()
        cov = svc.get_coverage(TENANT)
        assert cov["total_techniques"] == 0
        assert cov["total_coverage_pct"] == 0.0
        assert cov["tactics_covered"] == 0
        assert cov["total_tactics"] == 14

    def test_coverage_with_techniques(self):
        svc = MitreAttackMapper()
        svc.add_technique(TENANT, "T1059", "execution", "CSI")
        svc.add_technique(TENANT, "T1566", "initial_access", "Phishing")
        cov = svc.get_coverage(TENANT)
        assert cov["total_techniques"] == 2
        assert cov["tactics_covered"] == 2
        assert "execution" in cov["by_tactic"]
        assert cov["by_tactic"]["execution"]["techniques_count"] == 1

    def test_gaps_all_missing(self):
        svc = MitreAttackMapper()
        gaps = svc.get_gaps(TENANT)
        assert len(gaps["missing_tactics"]) == 14
        assert gaps["gap_score"] == 100.0

    def test_gaps_with_some_coverage(self):
        svc = MitreAttackMapper()
        svc.add_technique(TENANT, "T1059", "execution", "CSI")
        gaps = svc.get_gaps(TENANT)
        assert "execution" not in gaps["missing_tactics"]
        assert gaps["gap_score"] < 100.0

    def test_gaps_low_coverage_detection(self):
        svc = MitreAttackMapper()
        svc.add_technique(TENANT, "T1059", "execution", "CSI")
        # detection_coverage defaults to 0.0 which is < 30.0
        gaps = svc.get_gaps(TENANT)
        assert len(gaps["low_coverage_techniques"]) == 1
        assert gaps["low_coverage_techniques"][0]["technique_id"] == "T1059"

    def test_gaps_never_observed(self):
        svc = MitreAttackMapper()
        svc.add_technique(TENANT, "T1059", "execution", "CSI")
        gaps = svc.get_gaps(TENANT)
        assert len(gaps["never_observed_techniques"]) == 1


class TestMitreKillChain:
    """Kill chain reconstruction from mapped events."""

    def test_kill_chain_empty(self):
        svc = MitreAttackMapper()
        chain = svc.get_kill_chain(TENANT, "inc-1")
        assert chain["chain_length"] == 0
        assert chain["kill_chain"] == []

    def test_kill_chain_with_incident_mappings(self):
        svc = MitreAttackMapper()
        svc.add_technique(TENANT, "T1566", "initial_access", "Phishing")
        svc.add_technique(TENANT, "T1059", "execution", "Command Scripting")
        svc.map_event(
            TENANT,
            "phishing",
            indicators={"incident_id": "inc-42", "detail": "phishing email"},
        )
        svc.map_event(
            TENANT,
            "command",
            indicators={"incident_id": "inc-42", "detail": "scripting"},
        )
        chain = svc.get_kill_chain(TENANT, "inc-42")
        assert chain["incident_id"] == "inc-42"
        assert chain["chain_length"] >= 1

    def test_kill_chain_orders_by_tactic(self):
        svc = MitreAttackMapper()
        svc.add_technique(TENANT, "T1059", "execution", "Command Scripting")
        svc.add_technique(TENANT, "T1566", "initial_access", "Phishing")
        svc.map_event(
            TENANT,
            "command",
            indicators={"incident_id": "inc-1", "detail": "scripting"},
        )
        svc.map_event(
            TENANT,
            "phishing",
            indicators={"incident_id": "inc-1", "detail": "phishing email"},
        )
        chain = svc.get_kill_chain(TENANT, "inc-1")
        if chain["chain_length"] >= 2:
            positions = [e["tactic_position"] for e in chain["kill_chain"]]
            assert positions == sorted(positions)


class TestMitreStats:
    """MITRE mapper statistics."""

    def test_stats_empty(self):
        svc = MitreAttackMapper()
        stats = svc.get_stats(TENANT)
        assert stats["total_techniques"] == 0
        assert stats["tactics_covered"] == 0
        assert stats["total_mappings"] == 0
        assert stats["total_observations"] == 0
        assert stats["avg_detection_coverage"] == 0.0

    def test_stats_after_activity(self):
        svc = MitreAttackMapper()
        svc.add_technique(TENANT, "T1059", "execution", "Command Scripting")
        svc.add_technique(TENANT, "T1566", "initial_access", "Phishing")
        svc.map_event(TENANT, "command", indicators={"detail": "scripting"})
        stats = svc.get_stats(TENANT)
        assert stats["total_techniques"] == 2
        assert stats["tactics_covered"] == 2
        assert stats["by_tactic"]["execution"] == 1
        assert stats["by_tactic"]["initial_access"] == 1


# ===========================================================================
# AdversarySimService
# ===========================================================================


class TestAdversarySimCreateScenario:
    """Scenario creation."""

    def test_create_scenario_basic(self):
        svc = AdversarySimService()
        sc = svc.create_scenario(TENANT, "Phish Test")
        assert sc["name"] == "Phish Test"
        assert sc["attack_type"] == "phishing"
        assert sc["enabled"] is True
        assert sc["simulations_run"] == 0

    @pytest.mark.parametrize(
        "attack_type",
        [
            "phishing",
            "ransomware",
            "lateral_movement",
            "privilege_escalation",
            "data_exfiltration",
            "credential_theft",
            "supply_chain",
            "insider_threat",
        ],
    )
    def test_create_scenario_valid_types(self, attack_type):
        svc = AdversarySimService()
        sc = svc.create_scenario(TENANT, f"sc-{attack_type}", attack_type=attack_type)
        assert sc["attack_type"] == attack_type

    def test_create_scenario_invalid_type_defaults(self):
        svc = AdversarySimService()
        sc = svc.create_scenario(TENANT, "bad", attack_type="fake_type")
        assert sc["attack_type"] == "phishing"

    def test_create_scenario_with_techniques(self):
        svc = AdversarySimService()
        sc = svc.create_scenario(
            TENANT,
            "APT sim",
            mitre_techniques=["T1566.001", "T1059", "T1078"],
        )
        assert sc["mitre_techniques"] == ["T1566.001", "T1059", "T1078"]

    def test_create_scenario_with_config(self):
        svc = AdversarySimService()
        cfg = {"scope": "internal", "max_time": 3600}
        sc = svc.create_scenario(TENANT, "cfg", config=cfg)
        assert sc["config"] == cfg

    def test_create_scenario_description(self):
        svc = AdversarySimService()
        sc = svc.create_scenario(
            TENANT,
            "described",
            description="Test ransomware resilience",
        )
        assert sc["description"] == "Test ransomware resilience"

    def test_create_scenario_created_by(self):
        svc = AdversarySimService()
        sc = svc.create_scenario(TENANT, "by-alice", created_by="alice")
        assert sc["created_by"] == "alice"

    def test_create_scenario_unique_ids(self):
        svc = AdversarySimService()
        s1 = svc.create_scenario(TENANT, "s1")
        s2 = svc.create_scenario(TENANT, "s2")
        assert s1["id"] != s2["id"]


class TestAdversarySimListScenarios:
    """Listing scenarios."""

    def test_list_scenarios_empty(self):
        svc = AdversarySimService()
        assert svc.list_scenarios(TENANT) == []

    def test_list_scenarios(self):
        svc = AdversarySimService()
        svc.create_scenario(TENANT, "a")
        svc.create_scenario(TENANT, "b")
        assert len(svc.list_scenarios(TENANT)) == 2

    def test_list_scenarios_tenant_isolation(self):
        svc = AdversarySimService()
        svc.create_scenario(TENANT, "mine")
        svc.create_scenario("other", "theirs")
        assert len(svc.list_scenarios(TENANT)) == 1
        assert len(svc.list_scenarios("other")) == 1


class TestAdversarySimRunSimulation:
    """Simulation execution."""

    def test_run_simulation_completes(self):
        svc = AdversarySimService()
        sc = svc.create_scenario(
            TENANT,
            "run-test",
            mitre_techniques=["T1566.001", "T1059"],
        )
        result = svc.run_simulation(sc["id"])
        assert result["status"] == "completed"
        assert result["completed_at"] is not None

    def test_run_simulation_not_found(self):
        svc = AdversarySimService()
        result = svc.run_simulation("nonexistent")
        assert result == {"error": "Scenario not found"}

    def test_run_simulation_disabled_scenario(self):
        svc = AdversarySimService()
        sc = svc.create_scenario(TENANT, "disabled")
        svc._scenarios[sc["id"]].enabled = False
        result = svc.run_simulation(sc["id"])
        assert result == {"error": "Scenario is disabled"}

    def test_run_simulation_no_techniques(self):
        svc = AdversarySimService()
        sc = svc.create_scenario(TENANT, "empty-tech")
        result = svc.run_simulation(sc["id"])
        assert result["status"] == "completed"
        assert any("No techniques to test" in str(f) for f in result["findings"])

    def test_run_simulation_increments_counter(self):
        svc = AdversarySimService()
        sc = svc.create_scenario(TENANT, "counter", mitre_techniques=["T1059"])
        svc.run_simulation(sc["id"])
        svc.run_simulation(sc["id"])
        updated = svc.list_scenarios(TENANT)
        assert updated[0]["simulations_run"] == 2

    def test_run_simulation_detection_rate(self):
        svc = AdversarySimService()
        sc = svc.create_scenario(
            TENANT,
            "rates",
            mitre_techniques=["T1566.001", "T1059", "T1078"],
        )
        result = svc.run_simulation(sc["id"])
        assert 0.0 <= result["detection_rate"] <= 100.0
        assert 0.0 <= result["block_rate"] <= 100.0

    def test_run_simulation_techniques_accounted(self):
        svc = AdversarySimService()
        techs = ["T1566.001", "T1059", "T1078", "T1021"]
        sc = svc.create_scenario(TENANT, "full", mitre_techniques=techs)
        result = svc.run_simulation(sc["id"])
        total_categorized = len(result["techniques_detected"]) + len(result["techniques_missed"])
        # Every technique should be either detected or missed
        # (blocked is a subset of detected)
        assert total_categorized == len(techs)

    def test_run_simulation_updates_last_run(self):
        svc = AdversarySimService()
        sc = svc.create_scenario(TENANT, "ts", mitre_techniques=["T1059"])
        svc.run_simulation(sc["id"])
        updated = svc.list_scenarios(TENANT)
        assert updated[0]["last_run_at"] is not None


class TestAdversarySimGetResults:
    """Retrieving simulation results."""

    def test_get_results_empty(self):
        svc = AdversarySimService()
        sc = svc.create_scenario(TENANT, "no-runs")
        assert svc.get_simulation_results(sc["id"]) == []

    def test_get_results_after_run(self):
        svc = AdversarySimService()
        sc = svc.create_scenario(TENANT, "one-run", mitre_techniques=["T1059"])
        svc.run_simulation(sc["id"])
        results = svc.get_simulation_results(sc["id"])
        assert len(results) == 1
        assert results[0]["scenario_id"] == sc["id"]

    def test_get_results_multiple_runs(self):
        svc = AdversarySimService()
        sc = svc.create_scenario(TENANT, "multi", mitre_techniques=["T1059"])
        svc.run_simulation(sc["id"])
        svc.run_simulation(sc["id"])
        results = svc.get_simulation_results(sc["id"])
        assert len(results) == 2


class TestAdversarySimValidateDefense:
    """Defense validation against techniques."""

    def test_validate_defense_blocked(self):
        svc = AdversarySimService()
        # T1059 starts with T1 and len("T1059") == 5 -> blocked
        val = svc.validate_defense(TENANT, "T1059")
        assert val["defense_status"] == "blocked"
        assert val["confidence"] == 95.0

    def test_validate_defense_detected(self):
        svc = AdversarySimService()
        # T1566.001 starts with T1 but len > 5 -> detected (not blocked)
        val = svc.validate_defense(TENANT, "T1566.001")
        assert val["defense_status"] == "detected"
        assert val["confidence"] == 75.0

    def test_validate_defense_missed(self):
        svc = AdversarySimService()
        # Does not start with T1 -> missed
        val = svc.validate_defense(TENANT, "M0001")
        assert val["defense_status"] == "missed"
        assert val["confidence"] == 30.0

    def test_validate_defense_details(self):
        svc = AdversarySimService()
        val = svc.validate_defense(TENANT, "T1059")
        assert val["details"]["technique_id"] == "T1059"
        assert val["details"]["detection_source"] == "edr"
        assert val["details"]["block_mechanism"] == "policy"

    def test_validate_defense_missed_details(self):
        svc = AdversarySimService()
        val = svc.validate_defense(TENANT, "X9999")
        assert val["details"]["detection_source"] == "none"
        assert val["details"]["block_mechanism"] == "none"

    @pytest.mark.parametrize(
        "tech_id,expected_status",
        [
            ("T1059", "blocked"),
            ("T1566.001", "detected"),
            ("T1021.002", "detected"),
            ("X0001", "missed"),
            ("CUSTOM", "missed"),
        ],
    )
    def test_validate_defense_parametrized(self, tech_id, expected_status):
        svc = AdversarySimService()
        val = svc.validate_defense(TENANT, tech_id)
        assert val["defense_status"] == expected_status


class TestAdversarySimStats:
    """Adversary simulation statistics."""

    def test_stats_empty(self):
        svc = AdversarySimService()
        stats = svc.get_stats(TENANT)
        assert stats["total_scenarios"] == 0
        assert stats["total_simulations"] == 0
        assert stats["completed_simulations"] == 0
        assert stats["total_validations"] == 0
        assert stats["avg_detection_rate"] == 0.0
        assert stats["avg_block_rate"] == 0.0

    def test_stats_after_activity(self):
        svc = AdversarySimService()
        sc = svc.create_scenario(
            TENANT,
            "stat-test",
            attack_type="ransomware",
            mitre_techniques=["T1566.001", "T1059"],
        )
        svc.run_simulation(sc["id"])
        svc.validate_defense(TENANT, "T1059")
        stats = svc.get_stats(TENANT)
        assert stats["total_scenarios"] == 1
        assert stats["by_attack_type"]["ransomware"] == 1
        assert stats["total_simulations"] == 1
        assert stats["completed_simulations"] == 1
        assert stats["total_validations"] == 1

    def test_stats_failed_simulations(self):
        svc = AdversarySimService()
        sc = svc.create_scenario(TENANT, "fail-test", mitre_techniques=["T1059"])
        # Inject a failure scenario by monkeypatching _execute_simulation
        original = svc._execute_simulation

        def _fail(scenario, result):
            raise RuntimeError("boom")

        svc._execute_simulation = _fail
        svc.run_simulation(sc["id"])
        svc._execute_simulation = original
        stats = svc.get_stats(TENANT)
        assert stats["failed_simulations"] == 1


# ===========================================================================
# IntelCorrelationService
# ===========================================================================


class TestIntelCorrelateEvents:
    """Event correlation."""

    def test_correlate_events_basic(self):
        svc = IntelCorrelationService()
        corr = svc.correlate_events(TENANT, ["evt-1", "evt-2"])
        assert corr["correlation_type"] == "event"
        assert corr["tenant_id"] == TENANT
        assert len(corr["event_ids"]) == 2
        assert corr["confidence"] > 0

    def test_correlate_events_confidence_scaling(self):
        svc = IntelCorrelationService()
        c1 = svc.correlate_events(TENANT, ["e1"])
        c2 = svc.correlate_events(TENANT, ["e1", "e2", "e3", "e4"])
        assert c2["confidence"] > c1["confidence"]

    def test_correlate_events_confidence_cap(self):
        svc = IntelCorrelationService()
        many = [f"evt-{i}" for i in range(100)]
        corr = svc.correlate_events(TENANT, many)
        assert corr["confidence"] <= 95.0

    @pytest.mark.parametrize(
        "ctype",
        [
            "event",
            "ioc",
            "behavioral",
            "temporal",
            "network",
            "identity",
        ],
    )
    def test_correlate_events_valid_types(self, ctype):
        svc = IntelCorrelationService()
        corr = svc.correlate_events(TENANT, ["e1"], correlation_type=ctype)
        assert corr["correlation_type"] == ctype

    def test_correlate_events_invalid_type_defaults(self):
        svc = IntelCorrelationService()
        corr = svc.correlate_events(TENANT, ["e1"], correlation_type="bogus")
        assert corr["correlation_type"] == "event"

    def test_correlate_events_ioc_confidence_boost(self):
        svc = IntelCorrelationService()
        c_event = svc.correlate_events(TENANT, ["e1", "e2"], correlation_type="event")
        svc2 = IntelCorrelationService()
        c_ioc = svc2.correlate_events(TENANT, ["e1", "e2"], correlation_type="ioc")
        assert c_ioc["confidence"] >= c_event["confidence"]

    def test_correlate_events_behavioral_confidence_boost(self):
        svc = IntelCorrelationService()
        c_event = svc.correlate_events(TENANT, ["e1", "e2"], correlation_type="event")
        svc2 = IntelCorrelationService()
        c_beh = svc2.correlate_events(TENANT, ["e1", "e2"], correlation_type="behavioral")
        assert c_beh["confidence"] >= c_event["confidence"]

    @pytest.mark.parametrize(
        "count,expected_severity",
        [
            (1, "low"),
            (3, "medium"),
            (5, "high"),
            (6, "critical"),
        ],
    )
    def test_correlate_events_severity(self, count, expected_severity):
        svc = IntelCorrelationService()
        events = [f"e{i}" for i in range(count)]
        corr = svc.correlate_events(TENANT, events)
        assert corr["severity"] == expected_severity

    def test_correlate_events_description(self):
        svc = IntelCorrelationService()
        corr = svc.correlate_events(TENANT, ["e1", "e2", "e3"])
        assert "3 events" in corr["description"]

    def test_correlate_events_indicators_extracted(self):
        svc = IntelCorrelationService()
        corr = svc.correlate_events(TENANT, ["e1", "e2"])
        assert len(corr["indicators"]) == 2
        assert corr["indicators"][0]["event_id"] == "e1"


class TestIntelGetCorrelations:
    """Correlation retrieval and filtering."""

    def test_get_correlations_empty(self):
        svc = IntelCorrelationService()
        assert svc.get_correlations(TENANT) == []

    def test_get_correlations_returns_all(self):
        svc = IntelCorrelationService()
        svc.correlate_events(TENANT, ["e1"])
        svc.correlate_events(TENANT, ["e2"])
        corrs = svc.get_correlations(TENANT)
        assert len(corrs) == 2

    def test_get_correlations_min_confidence_filter(self):
        svc = IntelCorrelationService()
        svc.correlate_events(TENANT, ["e1"])  # 1*15=15 confidence
        svc.correlate_events(TENANT, ["e1", "e2", "e3", "e4", "e5"])  # 5*15=75
        corrs = svc.get_correlations(TENANT, min_confidence=50.0)
        assert len(corrs) == 1
        assert corrs[0]["confidence"] >= 50.0

    def test_get_correlations_limit(self):
        svc = IntelCorrelationService()
        for i in range(10):
            svc.correlate_events(TENANT, [f"e{i}"])
        corrs = svc.get_correlations(TENANT, limit=3)
        assert len(corrs) == 3

    def test_get_correlations_sorted_by_confidence(self):
        svc = IntelCorrelationService()
        svc.correlate_events(TENANT, ["e1"])
        svc.correlate_events(TENANT, ["e1", "e2", "e3", "e4"])
        corrs = svc.get_correlations(TENANT)
        if len(corrs) >= 2:
            assert corrs[0]["confidence"] >= corrs[1]["confidence"]

    def test_get_correlations_tenant_isolation(self):
        svc = IntelCorrelationService()
        svc.correlate_events(TENANT, ["e1"])
        svc.correlate_events("other", ["e2"])
        assert len(svc.get_correlations(TENANT)) == 1
        assert len(svc.get_correlations("other")) == 1


class TestIntelDiscoverPatterns:
    """Pattern discovery across correlated events."""

    def test_discover_patterns_no_correlations(self):
        svc = IntelCorrelationService()
        result = svc.discover_patterns(TENANT)
        assert result["patterns_discovered"] == 0
        assert "No correlations available" in result["message"]

    def test_discover_patterns_frequency(self):
        svc = IntelCorrelationService()
        svc.correlate_events(TENANT, ["e1", "e2"])
        svc.correlate_events(TENANT, ["e3", "e4"])
        result = svc.discover_patterns(TENANT)
        assert result["patterns_discovered"] >= 1
        types = [p["pattern_type"] for p in result["patterns"]]
        assert "frequency" in types

    def test_discover_patterns_severity_escalation(self):
        svc = IntelCorrelationService()
        # Create 3+ high/critical correlations (need 6+ events each for critical)
        for i in range(3):
            events = [f"e{i}-{j}" for j in range(6)]
            svc.correlate_events(TENANT, events)
        result = svc.discover_patterns(TENANT)
        types = [p["pattern_type"] for p in result["patterns"]]
        assert "sequence" in types

    def test_discover_patterns_time_window(self):
        svc = IntelCorrelationService()
        svc.correlate_events(TENANT, ["e1", "e2"])
        svc.correlate_events(TENANT, ["e3", "e4"])
        result = svc.discover_patterns(TENANT, time_window_hours=48)
        assert result["time_window_hours"] == 48
        if result["patterns"]:
            assert result["patterns"][0]["time_window_hours"] == 48

    def test_discover_patterns_confidence_scaling(self):
        svc = IntelCorrelationService()
        # Create many correlations of same type to drive up confidence
        for i in range(5):
            svc.correlate_events(TENANT, [f"e{i}"])
        result = svc.discover_patterns(TENANT)
        for p in result["patterns"]:
            assert p["confidence"] <= 90.0


class TestIntelAttributeCampaign:
    """Campaign attribution from indicators."""

    def test_attribute_campaign_basic(self):
        svc = IntelCorrelationService()
        campaign = svc.attribute_campaign(TENANT, ["ioc-1", "ioc-2"])
        assert campaign["tenant_id"] == TENANT
        assert campaign["campaign_name"].startswith("CAMPAIGN-")
        assert len(campaign["indicator_ids"]) == 2
        assert campaign["confidence"] > 0

    def test_attribute_campaign_confidence_scaling(self):
        svc = IntelCorrelationService()
        c1 = svc.attribute_campaign(TENANT, ["ioc-1"])
        c2 = svc.attribute_campaign(TENANT, ["ioc-1", "ioc-2", "ioc-3", "ioc-4"])
        assert c2["confidence"] > c1["confidence"]

    def test_attribute_campaign_confidence_cap(self):
        svc = IntelCorrelationService()
        many = [f"ioc-{i}" for i in range(100)]
        campaign = svc.attribute_campaign(TENANT, many)
        assert campaign["confidence"] <= 90.0

    def test_attribute_campaign_details(self):
        svc = IntelCorrelationService()
        campaign = svc.attribute_campaign(TENANT, ["ioc-1", "ioc-2"])
        assert campaign["details"]["indicator_count"] == 2
        assert campaign["details"]["analysis_method"] == "indicator_clustering"

    def test_attribute_campaign_unique_names(self):
        svc = IntelCorrelationService()
        c1 = svc.attribute_campaign(TENANT, ["ioc-1"])
        c2 = svc.attribute_campaign(TENANT, ["ioc-2"])
        assert c1["campaign_name"] != c2["campaign_name"]

    def test_attribute_campaign_unique_ids(self):
        svc = IntelCorrelationService()
        c1 = svc.attribute_campaign(TENANT, ["ioc-1"])
        c2 = svc.attribute_campaign(TENANT, ["ioc-2"])
        assert c1["id"] != c2["id"]


class TestIntelStats:
    """Intelligence correlation statistics."""

    def test_stats_empty(self):
        svc = IntelCorrelationService()
        stats = svc.get_stats(TENANT)
        assert stats["total_correlations"] == 0
        assert stats["total_patterns"] == 0
        assert stats["total_campaigns"] == 0
        assert stats["avg_confidence"] == 0.0

    def test_stats_after_correlations(self):
        svc = IntelCorrelationService()
        svc.correlate_events(TENANT, ["e1", "e2"])
        svc.correlate_events(TENANT, ["e3", "e4"], correlation_type="ioc")
        stats = svc.get_stats(TENANT)
        assert stats["total_correlations"] == 2
        assert stats["by_type"]["event"] == 1
        assert stats["by_type"]["ioc"] == 1
        assert stats["avg_confidence"] > 0

    def test_stats_after_patterns(self):
        svc = IntelCorrelationService()
        svc.correlate_events(TENANT, ["e1", "e2"])
        svc.correlate_events(TENANT, ["e3", "e4"])
        svc.discover_patterns(TENANT)
        stats = svc.get_stats(TENANT)
        assert stats["total_patterns"] >= 1

    def test_stats_after_campaigns(self):
        svc = IntelCorrelationService()
        svc.attribute_campaign(TENANT, ["ioc-1"])
        svc.attribute_campaign(TENANT, ["ioc-2"])
        stats = svc.get_stats(TENANT)
        assert stats["total_campaigns"] == 2

    def test_stats_by_severity(self):
        svc = IntelCorrelationService()
        svc.correlate_events(TENANT, ["e1"])  # low confidence -> low severity
        svc.correlate_events(TENANT, [f"e{i}" for i in range(6)])  # high sev
        stats = svc.get_stats(TENANT)
        assert "low" in stats["by_severity"]
        assert sum(stats["by_severity"].values()) == 2

    def test_stats_tenant_isolation(self):
        svc = IntelCorrelationService()
        svc.correlate_events(TENANT, ["e1"])
        svc.correlate_events("other", ["e2", "e3", "e4"])
        stats_mine = svc.get_stats(TENANT)
        stats_other = svc.get_stats("other")
        assert stats_mine["total_correlations"] == 1
        assert stats_other["total_correlations"] == 1
