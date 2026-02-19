"""Tests for V3.0 Remediation Workflows."""

from __future__ import annotations

import uuid

from cloud.db.models import RemediationWorkflowRow


class TestRemediationRoutes:
    def test_create_workflow(self, client):
        resp = client.post(
            "/api/v1/remediation/workflows",
            json={
                "name": "test-workflow",
                "description": "Test remediation",
                "steps": [
                    {"action": "quarantine_agent", "params": {"timeout": 300}},
                    {"action": "notify_admin", "params": {"channel": "slack"}},
                ],
                "trigger_conditions": {"severity": "critical"},
            },
            headers={"X-TENANT-ID": "dev-tenant"},
        )
        assert resp.status_code in (200, 201)
        data = resp.json()
        assert "id" in data

    def test_list_workflows(self, client):
        resp = client.get(
            "/api/v1/remediation/workflows",
            headers={"X-TENANT-ID": "dev-tenant"},
        )
        assert resp.status_code == 200

    def test_get_workflow(self, client, db):
        wf_id = str(uuid.uuid4())
        row = RemediationWorkflowRow(
            id=wf_id,
            tenant_id="dev-tenant",
            name="get-test",
            steps=[{"action": "notify"}],
        )
        db.add(row)
        db.commit()
        resp = client.get(
            f"/api/v1/remediation/workflows/{wf_id}",
            headers={"X-TENANT-ID": "dev-tenant"},
        )
        assert resp.status_code == 200

    def test_execute_workflow(self, client, db):
        wf_id = str(uuid.uuid4())
        row = RemediationWorkflowRow(
            id=wf_id,
            tenant_id="dev-tenant",
            name="exec-test",
            steps=[{"action": "quarantine"}],
            enabled="true",
        )
        db.add(row)
        db.commit()
        resp = client.post(
            f"/api/v1/remediation/workflows/{wf_id}/execute",
            headers={"X-TENANT-ID": "dev-tenant"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("executed") is True

    def test_toggle_workflow(self, client, db):
        wf_id = str(uuid.uuid4())
        row = RemediationWorkflowRow(
            id=wf_id,
            tenant_id="dev-tenant",
            name="toggle-test",
            steps=[],
            enabled="true",
        )
        db.add(row)
        db.commit()
        resp = client.put(
            f"/api/v1/remediation/workflows/{wf_id}/toggle",
            headers={"X-TENANT-ID": "dev-tenant"},
        )
        assert resp.status_code == 200

    def test_workflow_not_found(self, client):
        resp = client.get(
            "/api/v1/remediation/workflows/fake-id",
            headers={"X-TENANT-ID": "dev-tenant"},
        )
        assert resp.status_code == 404

    def test_execute_disabled_workflow(self, client, db):
        wf_id = str(uuid.uuid4())
        row = RemediationWorkflowRow(
            id=wf_id,
            tenant_id="dev-tenant",
            name="disabled-test",
            steps=[],
            enabled="false",
        )
        db.add(row)
        db.commit()
        resp = client.post(
            f"/api/v1/remediation/workflows/{wf_id}/execute",
            headers={"X-TENANT-ID": "dev-tenant"},
        )
        assert resp.status_code == 400


class TestRemediationDB:
    def test_workflow_record(self, db):
        wf = RemediationWorkflowRow(
            id=str(uuid.uuid4()),
            tenant_id="dev-tenant",
            name="db-test",
            steps=[{"action": "quarantine"}, {"action": "notify"}],
            rollback_steps=[{"action": "release"}],
        )
        db.add(wf)
        db.commit()
        loaded = db.query(RemediationWorkflowRow).filter_by(name="db-test").first()
        assert loaded is not None
        assert len(loaded.steps) == 2
        assert len(loaded.rollback_steps) == 1
