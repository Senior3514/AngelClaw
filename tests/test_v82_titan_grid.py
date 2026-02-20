"""Tests for V8.2.0 Titan Grid: Exposure Validation, Identity Governance, SecOps Workflow."""

from __future__ import annotations

import pytest

from cloud.services.exposure_validation import ExposureValidationService
from cloud.services.identity_governance import IdentityGovernanceService
from cloud.services.secops_workflow import SecOpsWorkflowService


TENANT = "test-tenant"


# ===========================================================================
# ExposureValidationService
# ===========================================================================

class TestExposureValidationService:
    """ExposureValidationService tests."""

    def test_run_simulation_full_spectrum(self):
        svc = ExposureValidationService()
        result = svc.run_simulation(TENANT, "full_spectrum")
        assert result["tenant_id"] == TENANT
        assert result["scenario"] == "full_spectrum"
        assert result["controls_tested"] == 25
        assert result["attacks_simulated"] == 40
        assert result["controls_passed"] + result["controls_failed"] == 25
        assert result["status"] == "completed"
        assert "exposure_score" in result
        assert "effectiveness_pct" in result

    def test_run_simulation_ransomware(self):
        svc = ExposureValidationService()
        result = svc.run_simulation(TENANT, "ransomware")
        assert result["scenario"] == "ransomware"
        assert result["controls_tested"] == 12

    def test_run_simulation_data_exfil(self):
        svc = ExposureValidationService()
        result = svc.run_simulation(TENANT, "data_exfil")
        assert result["scenario"] == "data_exfil"
        assert result["controls_tested"] == 10

    def test_run_simulation_lateral_movement(self):
        svc = ExposureValidationService()
        result = svc.run_simulation(TENANT, "lateral_movement")
        assert result["controls_tested"] == 8

    def test_run_simulation_phishing(self):
        svc = ExposureValidationService()
        result = svc.run_simulation(TENANT, "phishing")
        assert result["controls_tested"] == 6

    def test_run_simulation_unknown_scenario(self):
        svc = ExposureValidationService()
        result = svc.run_simulation(TENANT, "unknown_scenario")
        assert result["controls_tested"] == 25  # defaults to full_spectrum

    def test_run_simulation_unique_ids(self):
        svc = ExposureValidationService()
        r1 = svc.run_simulation(TENANT)
        r2 = svc.run_simulation(TENANT)
        assert r1["id"] != r2["id"]

    def test_run_simulation_gaps(self):
        svc = ExposureValidationService()
        result = svc.run_simulation(TENANT)
        assert len(result["gaps"]) == result["controls_failed"]

    def test_test_control(self):
        svc = ExposureValidationService()
        result = svc.test_control(TENANT, "firewall-rule-01", "ransomware")
        assert result["tenant_id"] == TENANT
        assert result["control_id"] == "firewall-rule-01"
        assert result["attack_type"] == "ransomware"
        assert isinstance(result["effective"], bool)
        assert "response_time_ms" in result

    def test_test_control_default_attack(self):
        svc = ExposureValidationService()
        result = svc.test_control(TENANT, "waf-rule-01")
        assert result["attack_type"] == "generic"

    def test_get_exposure_trend_empty(self):
        svc = ExposureValidationService()
        result = svc.get_exposure_trend("empty-tenant")
        assert result["total_runs"] == 0
        assert result["current_exposure"] == 0.0
        assert result["trend"] == "stable"

    def test_get_exposure_trend_with_data(self):
        svc = ExposureValidationService()
        svc.run_simulation(TENANT)
        svc.run_simulation(TENANT)
        result = svc.get_exposure_trend(TENANT)
        assert result["total_runs"] >= 2
        assert result["avg_exposure"] > 0

    def test_get_runs(self):
        svc = ExposureValidationService()
        svc.run_simulation(TENANT, "ransomware")
        svc.run_simulation(TENANT, "phishing")
        runs = svc.get_runs(TENANT)
        assert len(runs) >= 2

    def test_get_runs_limit(self):
        svc = ExposureValidationService()
        for _ in range(5):
            svc.run_simulation(TENANT)
        runs = svc.get_runs(TENANT, limit=2)
        assert len(runs) <= 2

    def test_status(self):
        svc = ExposureValidationService()
        result = svc.status(TENANT)
        assert result["service"] == "ExposureValidationService"
        assert result["version"] == "8.2.0"
        assert result["tenant_id"] == TENANT


# ===========================================================================
# IdentityGovernanceService
# ===========================================================================

class TestIdentityGovernanceService:
    """IdentityGovernanceService tests."""

    def test_onboard_identity(self):
        svc = IdentityGovernanceService()
        result = svc.onboard_identity(TENANT, {
            "username": "jdoe",
            "email": "jdoe@example.com",
            "department": "engineering",
            "roles": ["developer", "viewer"],
        })
        assert "id" in result
        assert result["tenant_id"] == TENANT
        assert result["lifecycle_state"] == "active"
        assert "developer" in result["roles"]

    def test_onboard_default_roles(self):
        svc = IdentityGovernanceService()
        result = svc.onboard_identity(TENANT, {"username": "newuser"})
        assert result["roles"] == ["viewer"]

    def test_onboard_unique_ids(self):
        svc = IdentityGovernanceService()
        r1 = svc.onboard_identity(TENANT, {"username": "user1"})
        r2 = svc.onboard_identity(TENANT, {"username": "user2"})
        assert r1["id"] != r2["id"]

    def test_offboard_identity(self):
        svc = IdentityGovernanceService()
        created = svc.onboard_identity(TENANT, {
            "username": "departing",
            "roles": ["admin", "developer"],
        })
        result = svc.offboard_identity(TENANT, created["id"])
        assert result["lifecycle_state"] == "deprovisioned"
        assert result["roles"] == []
        assert result["entitlements"] == []

    def test_offboard_not_found(self):
        svc = IdentityGovernanceService()
        result = svc.offboard_identity(TENANT, "nonexistent-id")
        assert "error" in result

    def test_start_certification(self):
        svc = IdentityGovernanceService()
        svc.onboard_identity(TENANT, {"username": "user-cert"})
        result = svc.start_certification(TENANT, {"name": "Q1 Review"})
        assert "id" in result
        assert result["name"] == "Q1 Review"
        assert result["status"] == "in_progress"

    def test_start_certification_default_name(self):
        svc = IdentityGovernanceService()
        result = svc.start_certification(TENANT, {})
        assert result["name"] == "Quarterly Review"

    def test_mine_roles(self):
        svc = IdentityGovernanceService()
        svc.onboard_identity(TENANT, {"username": "u1", "roles": ["admin", "dev", "viewer", "deployer"]})
        svc.onboard_identity(TENANT, {"username": "u2", "roles": ["viewer"]})
        result = svc.mine_roles(TENANT)
        assert result["identities_analyzed"] >= 2
        assert result["unique_roles"] >= 1
        assert result["over_privileged_users"] >= 1

    def test_mine_roles_empty_tenant(self):
        svc = IdentityGovernanceService()
        result = svc.mine_roles("empty-tenant")
        assert result["identities_analyzed"] == 0
        assert result["unique_roles"] == 0

    def test_check_sod_compliant(self):
        svc = IdentityGovernanceService()
        created = svc.onboard_identity(TENANT, {"username": "clean", "roles": ["viewer"]})
        result = svc.check_sod(TENANT, created["id"])
        assert result["compliant"] is True
        assert result["violation_count"] == 0

    def test_check_sod_violations(self):
        svc = IdentityGovernanceService()
        created = svc.onboard_identity(TENANT, {
            "username": "risky",
            "roles": ["admin", "auditor", "developer", "deployer"],
        })
        result = svc.check_sod(TENANT, created["id"])
        assert result["compliant"] is False
        assert result["violation_count"] >= 2

    def test_check_sod_not_found(self):
        svc = IdentityGovernanceService()
        result = svc.check_sod(TENANT, "missing-id")
        assert result["compliant"] is True  # no roles = no violations

    def test_get_identities(self):
        svc = IdentityGovernanceService()
        svc.onboard_identity(TENANT, {"username": "list-user"})
        identities = svc.get_identities(TENANT)
        assert len(identities) >= 1

    def test_get_identities_limit(self):
        svc = IdentityGovernanceService()
        for i in range(5):
            svc.onboard_identity(TENANT, {"username": f"limit-user-{i}"})
        identities = svc.get_identities(TENANT, limit=2)
        assert len(identities) <= 2

    def test_get_campaigns(self):
        svc = IdentityGovernanceService()
        svc.start_certification(TENANT, {"name": "Campaign A"})
        campaigns = svc.get_campaigns(TENANT)
        assert len(campaigns) >= 1

    def test_status(self):
        svc = IdentityGovernanceService()
        result = svc.status(TENANT)
        assert result["service"] == "IdentityGovernanceService"
        assert result["version"] == "8.2.0"
        assert result["tenant_id"] == TENANT


# ===========================================================================
# SecOpsWorkflowService
# ===========================================================================

class TestSecOpsWorkflowService:
    """SecOpsWorkflowService tests."""

    def test_create_workflow(self):
        svc = SecOpsWorkflowService()
        result = svc.create_workflow(TENANT, {"name": "IR Playbook", "trigger": "alert"})
        assert "id" in result
        assert result["name"] == "IR Playbook"
        assert result["trigger"] == "alert"
        assert result["status"] == "active"
        assert result["step_count"] >= 1

    def test_create_workflow_defaults(self):
        svc = SecOpsWorkflowService()
        result = svc.create_workflow(TENANT, {})
        assert result["name"] == "Incident Response"
        assert result["trigger"] == "alert"
        assert result["step_count"] == 4

    def test_create_workflow_custom_steps(self):
        svc = SecOpsWorkflowService()
        steps = [
            {"name": "Detect", "type": "auto"},
            {"name": "Contain", "type": "manual"},
        ]
        result = svc.create_workflow(TENANT, {"steps": steps})
        assert result["step_count"] == 2

    def test_create_workflow_unique_ids(self):
        svc = SecOpsWorkflowService()
        r1 = svc.create_workflow(TENANT, {"name": "wf1"})
        r2 = svc.create_workflow(TENANT, {"name": "wf2"})
        assert r1["id"] != r2["id"]

    def test_execute_workflow(self):
        svc = SecOpsWorkflowService()
        wf = svc.create_workflow(TENANT, {"name": "Exec Test"})
        result = svc.execute_workflow(TENANT, wf["id"], {"severity": "high"})
        assert result["workflow_id"] == wf["id"]
        assert result["status"] == "running"
        assert result["current_step"] == 0

    def test_execute_workflow_not_found(self):
        svc = SecOpsWorkflowService()
        result = svc.execute_workflow(TENANT, "nonexistent-wf")
        assert "error" in result

    def test_execute_increments_count(self):
        svc = SecOpsWorkflowService()
        wf = svc.create_workflow(TENANT, {"name": "Count Test"})
        svc.execute_workflow(TENANT, wf["id"])
        svc.execute_workflow(TENANT, wf["id"])
        workflows = svc.get_workflows(TENANT)
        target = [w for w in workflows if w["id"] == wf["id"]][0]
        assert target["executions"] == 2

    def test_advance_step(self):
        svc = SecOpsWorkflowService()
        wf = svc.create_workflow(TENANT, {})
        execution = svc.execute_workflow(TENANT, wf["id"])
        result = svc.advance_step(TENANT, execution["id"])
        assert result["current_step"] == 1
        assert result["status"] == "running"

    def test_advance_to_completion(self):
        svc = SecOpsWorkflowService()
        wf = svc.create_workflow(TENANT, {"steps": [{"name": "A"}, {"name": "B"}]})
        execution = svc.execute_workflow(TENANT, wf["id"])
        svc.advance_step(TENANT, execution["id"])
        result = svc.advance_step(TENANT, execution["id"])
        assert result["status"] == "completed"
        assert "completed_at" in result

    def test_advance_not_found(self):
        svc = SecOpsWorkflowService()
        result = svc.advance_step(TENANT, "nonexistent-exec")
        assert "error" in result

    def test_get_workflows(self):
        svc = SecOpsWorkflowService()
        svc.create_workflow(TENANT, {"name": "List WF"})
        workflows = svc.get_workflows(TENANT)
        assert len(workflows) >= 1

    def test_get_executions(self):
        svc = SecOpsWorkflowService()
        wf = svc.create_workflow(TENANT, {})
        svc.execute_workflow(TENANT, wf["id"])
        executions = svc.get_executions(TENANT)
        assert len(executions) >= 1

    def test_get_executions_limit(self):
        svc = SecOpsWorkflowService()
        wf = svc.create_workflow(TENANT, {})
        for _ in range(5):
            svc.execute_workflow(TENANT, wf["id"])
        executions = svc.get_executions(TENANT, limit=2)
        assert len(executions) <= 2

    def test_get_templates(self):
        svc = SecOpsWorkflowService()
        templates = svc.get_templates(TENANT)
        assert len(templates) == 5
        names = [t["name"] for t in templates]
        assert "Incident Response" in names
        assert "Vulnerability Triage" in names
        assert "Threat Hunt" in names

    def test_status(self):
        svc = SecOpsWorkflowService()
        result = svc.status(TENANT)
        assert result["service"] == "SecOpsWorkflowService"
        assert result["version"] == "8.2.0"
        assert result["tenant_id"] == TENANT


# ===========================================================================
# API Route Integration Tests
# ===========================================================================

class TestTitanGridRoutes:
    """Titan Grid API route integration tests."""

    def test_exposure_simulate(self, client):
        resp = client.post("/api/v1/titan-grid/exposure/simulate?scenario=ransomware")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scenario"] == "ransomware"
        assert data["status"] == "completed"

    def test_exposure_test_control(self, client):
        resp = client.post("/api/v1/titan-grid/exposure/test-control?control_id=fw-01")
        assert resp.status_code == 200
        assert resp.json()["control_id"] == "fw-01"

    def test_exposure_trend(self, client):
        resp = client.get("/api/v1/titan-grid/exposure/trend")
        assert resp.status_code == 200
        assert "trend" in resp.json()

    def test_exposure_runs(self, client):
        resp = client.get("/api/v1/titan-grid/exposure/runs")
        assert resp.status_code == 200

    def test_exposure_status(self, client):
        resp = client.get("/api/v1/titan-grid/exposure/status")
        assert resp.status_code == 200
        assert resp.json()["service"] == "ExposureValidationService"

    def test_identity_onboard(self, client):
        resp = client.post("/api/v1/titan-grid/identity/onboard", json={"username": "api-user"})
        assert resp.status_code == 200
        assert resp.json()["lifecycle_state"] == "active"

    def test_identity_offboard(self, client):
        create = client.post("/api/v1/titan-grid/identity/onboard", json={"username": "offboard-api"})
        identity_id = create.json()["id"]
        resp = client.post(f"/api/v1/titan-grid/identity/offboard/{identity_id}")
        assert resp.status_code == 200
        assert resp.json()["lifecycle_state"] == "deprovisioned"

    def test_identity_certification(self, client):
        resp = client.post("/api/v1/titan-grid/identity/certification", json={"name": "API Review"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "in_progress"

    def test_identity_mine_roles(self, client):
        resp = client.get("/api/v1/titan-grid/identity/mine-roles")
        assert resp.status_code == 200

    def test_identity_sod(self, client):
        create = client.post("/api/v1/titan-grid/identity/onboard", json={
            "username": "sod-test",
            "roles": ["admin", "auditor"],
        })
        identity_id = create.json()["id"]
        resp = client.get(f"/api/v1/titan-grid/identity/sod/{identity_id}")
        assert resp.status_code == 200

    def test_identity_list(self, client):
        resp = client.get("/api/v1/titan-grid/identity/list")
        assert resp.status_code == 200

    def test_identity_campaigns(self, client):
        resp = client.get("/api/v1/titan-grid/identity/campaigns")
        assert resp.status_code == 200

    def test_identity_status(self, client):
        resp = client.get("/api/v1/titan-grid/identity/status")
        assert resp.status_code == 200
        assert resp.json()["service"] == "IdentityGovernanceService"

    def test_workflow_create(self, client):
        resp = client.post("/api/v1/titan-grid/workflow/create", json={"name": "API WF"})
        assert resp.status_code == 200
        assert resp.json()["name"] == "API WF"

    def test_workflow_execute(self, client):
        create = client.post("/api/v1/titan-grid/workflow/create", json={"name": "Exec WF"})
        wf_id = create.json()["id"]
        resp = client.post(f"/api/v1/titan-grid/workflow/execute/{wf_id}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "running"

    def test_workflow_advance(self, client):
        create = client.post("/api/v1/titan-grid/workflow/create", json={})
        wf_id = create.json()["id"]
        execute = client.post(f"/api/v1/titan-grid/workflow/execute/{wf_id}")
        exec_id = execute.json()["id"]
        resp = client.post(f"/api/v1/titan-grid/workflow/advance/{exec_id}")
        assert resp.status_code == 200

    def test_workflow_list(self, client):
        resp = client.get("/api/v1/titan-grid/workflow/list")
        assert resp.status_code == 200

    def test_workflow_executions(self, client):
        resp = client.get("/api/v1/titan-grid/workflow/executions")
        assert resp.status_code == 200

    def test_workflow_templates(self, client):
        resp = client.get("/api/v1/titan-grid/workflow/templates")
        assert resp.status_code == 200
        templates = resp.json()
        assert len(templates) == 5

    def test_workflow_status(self, client):
        resp = client.get("/api/v1/titan-grid/workflow/status")
        assert resp.status_code == 200
        assert resp.json()["service"] == "SecOpsWorkflowService"

    def test_combined_status(self, client):
        resp = client.get("/api/v1/titan-grid/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["version"] == "8.2.0"
        assert data["codename"] == "Titan Grid"
        assert "exposure_validation" in data
        assert "identity_governance" in data
        assert "secops_workflow" in data
