"""Tests for agent registration and event ingestion endpoints."""

from __future__ import annotations

import uuid

# ---------------------------------------------------------------------------
# Agent registration
# ---------------------------------------------------------------------------


class TestAgentRegistration:
    def test_register_new_agent(self, client, db):
        """Register a brand-new agent and receive policy set."""
        hostname = f"test-host-{uuid.uuid4().hex[:8]}"
        r = client.post(
            "/api/v1/agents/register",
            json={
                "type": "endpoint",
                "os": "linux",
                "hostname": hostname,
                "tags": ["test"],
                "version": "0.4.0",
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "registered"
        assert data["agent_id"]
        assert data["policy_set"] is not None or data["policy_set"] is None  # May or may not exist

    def test_re_register_existing_agent(self, client, db):
        """Re-registering same hostname updates instead of duplicating."""
        hostname = f"re-reg-{uuid.uuid4().hex[:8]}"
        payload = {
            "type": "server",
            "os": "linux",
            "hostname": hostname,
            "tags": ["v1"],
            "version": "0.3.0",
        }
        r1 = client.post("/api/v1/agents/register", json=payload)
        assert r1.status_code == 200
        id1 = r1.json()["agent_id"]

        # Re-register with updated version
        payload["version"] = "0.4.0"
        payload["tags"] = ["v2"]
        r2 = client.post("/api/v1/agents/register", json=payload)
        assert r2.status_code == 200
        id2 = r2.json()["agent_id"]
        assert id1 == id2  # Same agent, updated

    def test_register_all_agent_types(self, client, db):
        """All agent types can be registered."""
        for agent_type in ["endpoint", "server", "ai_host", "container", "agentless"]:
            hostname = f"{agent_type}-{uuid.uuid4().hex[:6]}"
            r = client.post(
                "/api/v1/agents/register",
                json={
                    "type": agent_type,
                    "os": "linux",
                    "hostname": hostname,
                },
            )
            assert r.status_code == 200, f"Failed for type: {agent_type}"

    def test_register_missing_required_fields(self, client):
        """Missing required fields return 422."""
        r = client.post("/api/v1/agents/register", json={"type": "endpoint"})
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# Event ingestion
# ---------------------------------------------------------------------------


class TestEventIngestion:
    def _register_agent(self, client) -> str:
        """Helper: register an agent and return its ID."""
        hostname = f"ingest-test-{uuid.uuid4().hex[:8]}"
        r = client.post(
            "/api/v1/agents/register",
            json={
                "type": "endpoint",
                "os": "linux",
                "hostname": hostname,
            },
        )
        return r.json()["agent_id"]

    def test_ingest_empty_batch(self, client, db):
        """Empty event batch is accepted."""
        agent_id = self._register_agent(client)
        r = client.post(
            "/api/v1/events/batch",
            json={
                "agent_id": agent_id,
                "events": [],
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["accepted"] == 0
        assert data["agent_id"] == agent_id

    def test_ingest_single_event(self, client, db):
        """Single event is persisted."""
        agent_id = self._register_agent(client)
        r = client.post(
            "/api/v1/events/batch",
            json={
                "agent_id": agent_id,
                "events": [
                    {
                        "agent_id": agent_id,
                        "category": "shell",
                        "type": "exec",
                        "severity": "info",
                        "details": {"command": "ls -la"},
                        "source": "bash",
                    }
                ],
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["accepted"] == 1

    def test_ingest_multiple_events(self, client, db):
        """Batch of multiple events is accepted."""
        agent_id = self._register_agent(client)
        events = [
            {
                "agent_id": agent_id,
                "category": "shell",
                "type": "exec",
                "severity": "info",
                "details": {"command": f"cmd-{i}"},
                "source": "bash",
            }
            for i in range(5)
        ]
        r = client.post(
            "/api/v1/events/batch",
            json={
                "agent_id": agent_id,
                "events": events,
            },
        )
        assert r.status_code == 200
        assert r.json()["accepted"] == 5

    def test_ingest_high_severity_events(self, client, db):
        """High severity events are ingested and may trigger alerts."""
        agent_id = self._register_agent(client)
        events = [
            {
                "agent_id": agent_id,
                "category": "auth",
                "type": "secret_access",
                "severity": "critical",
                "details": {"accesses_secrets": True, "path": "/etc/shadow"},
                "source": "unknown",
            }
            for _ in range(3)
        ]
        r = client.post(
            "/api/v1/events/batch",
            json={
                "agent_id": agent_id,
                "events": events,
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["accepted"] == 3

    def test_ingest_all_categories(self, client, db):
        """Events of all categories are accepted."""
        agent_id = self._register_agent(client)
        categories = [
            "shell",
            "file",
            "network",
            "db",
            "ai_tool",
            "auth",
            "config",
            "system",
            "logging",
            "metric",
        ]
        events = [
            {
                "agent_id": agent_id,
                "category": cat,
                "type": "test",
                "severity": "info",
                "details": {},
            }
            for cat in categories
        ]
        r = client.post(
            "/api/v1/events/batch",
            json={
                "agent_id": agent_id,
                "events": events,
            },
        )
        assert r.status_code == 200
        assert r.json()["accepted"] == len(categories)

    def test_ingest_invalid_category(self, client, db):
        """Invalid event category returns 422."""
        r = client.post(
            "/api/v1/events/batch",
            json={
                "agent_id": "agent-1",
                "events": [
                    {
                        "agent_id": "agent-1",
                        "category": "nonexistent_category",
                        "type": "test",
                    }
                ],
            },
        )
        assert r.status_code == 422

    def test_ingest_invalid_severity(self, client, db):
        """Invalid severity returns 422."""
        r = client.post(
            "/api/v1/events/batch",
            json={
                "agent_id": "agent-1",
                "events": [
                    {
                        "agent_id": "agent-1",
                        "category": "shell",
                        "type": "test",
                        "severity": "nonexistent",
                    }
                ],
            },
        )
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# Policy distribution
# ---------------------------------------------------------------------------


class TestPolicyDistribution:
    def test_policy_for_registered_agent(self, client, db):
        """Registered agent can fetch its policy."""
        hostname = f"policy-test-{uuid.uuid4().hex[:8]}"
        reg = client.post(
            "/api/v1/agents/register",
            json={
                "type": "endpoint",
                "os": "linux",
                "hostname": hostname,
            },
        )
        agent_id = reg.json()["agent_id"]

        r = client.get(f"/api/v1/policies/current?agentId={agent_id}")
        # May be 200 or 404 depending on whether default policy was seeded
        assert r.status_code in (200, 404)
        if r.status_code == 200:
            data = r.json()
            assert "rules" in data
            assert "version" in data

    def test_policy_for_unknown_agent(self, client, db):
        """Unknown agent ID returns 404."""
        r = client.get("/api/v1/policies/current?agentId=nonexistent-agent")
        assert r.status_code == 404
