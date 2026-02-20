"""Tests for the ANGEL AGI Orchestrator."""

import pytest

from cloud.guardian.orchestrator import AngelOrchestrator


@pytest.fixture
def orchestrator():
    return AngelOrchestrator()


def test_orchestrator_init(orchestrator):
    """Orchestrator initializes with all sub-agents."""
    assert orchestrator.warden is not None
    assert orchestrator.response is not None
    assert orchestrator.forensic is not None
    assert orchestrator.audit is not None
    assert orchestrator._running is False


def test_orchestrator_status(orchestrator):
    """Status returns correct structure."""
    status = orchestrator.status()
    assert "running" in status
    assert "stats" in status
    assert "agents" in status
    assert "incidents" in status
    assert "playbooks" in status

    agents = status["agents"]
    agent_types = {info["agent_type"] for info in agents.values()}
    for expected in (
        "warden",
        "response",
        "forensic",
        "audit",
        "network",
        "secrets",
        "toolchain",
        "behavior",
        "timeline",
        "browser",
    ):
        assert expected in agent_types, f"Missing agent type: {expected}"


def test_orchestrator_playbooks(orchestrator):
    """Playbooks are loaded from YAML files."""
    playbooks = orchestrator.response.list_playbooks()
    assert len(playbooks) >= 4
    assert "quarantine_agent" in playbooks
    assert "throttle_agent" in playbooks


def test_orchestrator_incidents_empty(orchestrator):
    """No incidents initially."""
    incidents = orchestrator.list_incidents()
    assert incidents == []


def test_orchestrator_incident_not_found(orchestrator):
    """Getting a nonexistent incident returns None."""
    assert orchestrator.get_incident("nonexistent") is None
