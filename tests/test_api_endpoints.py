"""Tests for core API endpoints."""


def test_health_endpoint(client):
    r = client.get("/health")
    assert r.status_code == 200


def test_ready_endpoint(client):
    r = client.get("/ready")
    assert r.status_code == 200


def test_metrics_endpoint(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")


def test_orchestrator_status(client):
    r = client.get("/api/v1/orchestrator/status")
    assert r.status_code == 200
    data = r.json()
    assert "running" in data
    assert "agents" in data


def test_orchestrator_incidents(client):
    r = client.get("/api/v1/orchestrator/incidents")
    assert r.status_code == 200
    data = r.json()
    assert "incidents" in data


def test_orchestrator_agents(client):
    r = client.get("/api/v1/orchestrator/agents")
    assert r.status_code == 200
    data = r.json()
    assert "agents" in data
    assert len(data["agents"]) >= 4  # V2: 10 agents (Angel Legion)


def test_orchestrator_playbooks(client):
    r = client.get("/api/v1/orchestrator/playbooks")
    assert r.status_code == 200
    data = r.json()
    assert "playbooks" in data
    assert len(data["playbooks"]) >= 4


def test_self_audit(client):
    r = client.get("/api/v1/orchestrator/self-audit")
    assert r.status_code == 200
    data = r.json()
    assert "findings" in data
    assert "checks_run" in data


def test_learning_summary(client):
    r = client.get("/api/v1/orchestrator/learning/summary")
    assert r.status_code == 200
    data = r.json()
    assert "total_reflections" in data
    assert "playbook_ranking" in data


def test_learning_reflections(client):
    r = client.get("/api/v1/orchestrator/learning/reflections")
    assert r.status_code == 200
    data = r.json()
    assert "reflections" in data


def test_playbook_dry_run(client):
    r = client.post("/api/v1/orchestrator/playbooks/quarantine_agent/dry-run")
    assert r.status_code == 200
    data = r.json()
    assert data["dry_run"] is True
    assert data["success"] is True


def test_unknown_playbook_dry_run(client):
    r = client.post("/api/v1/orchestrator/playbooks/nonexistent/dry-run")
    assert r.status_code == 200
    data = r.json()
    assert data["success"] is False
