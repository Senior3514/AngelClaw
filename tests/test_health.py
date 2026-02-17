"""Tests for health, readiness, and metrics endpoints."""


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["version"] == "1.2.0"
    assert "orchestrator" in data
    assert "agents" in data


def test_ready(client):
    r = client.get("/ready")
    assert r.status_code == 200
    data = r.json()
    assert "checks" in data
    assert "timestamp" in data


def test_metrics(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "angelclaw_uptime_seconds" in r.text
    assert "angelclaw_orchestrator_running" in r.text
    assert "angelclaw_playbooks_loaded" in r.text
