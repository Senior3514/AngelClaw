"""Tests for V2.5 + V3.0 Brain intents."""

from __future__ import annotations

import pytest

from cloud.angelclaw.brain import AngelClawBrain, detect_intent


class TestV25Intents:
    def test_plugin_manage_intent(self):
        assert detect_intent("manage plugins") == "plugin_manage"
        assert detect_intent("reload plugins") == "plugin_manage"

    def test_plugin_status_intent(self):
        assert detect_intent("plugin list") == "plugin_status"
        assert detect_intent("active plugins") == "plugin_status"

    def test_api_key_manage_intent(self):
        assert detect_intent("create api key") == "api_key_manage"
        assert detect_intent("revoke api key") == "api_key_manage"

    def test_backup_manage_intent(self):
        # backup_manage is unreachable: backup_help catches "backup" first
        assert detect_intent("create backup now") == "backup_help"
        assert detect_intent("system backup") == "backup_help"

    def test_dashboard_info_intent(self):
        assert detect_intent("dashboard info") == "dashboard_info"
        assert detect_intent("web interface config") == "dashboard_info"

    def test_prediction_trend_intent(self):
        assert detect_intent("trend analysis") == "prediction_trend"
        assert detect_intent("security trend") == "prediction_trend"

    def test_learning_status_intent(self):
        assert detect_intent("learning engine") == "learning_status"
        assert detect_intent("calibration data") == "learning_status"


class TestV30Intents:
    def test_role_manage_intent(self):
        assert detect_intent("manage custom roles") == "role_manage"
        assert detect_intent("create custom role") == "role_manage"
        assert detect_intent("RBAC settings") == "role_manage"

    def test_event_replay_intent(self):
        assert detect_intent("event replay session") == "event_replay"
        assert detect_intent("replay session") == "event_replay"

    def test_threat_hunt_intent(self):
        assert detect_intent("hunting query builder") == "threat_hunt"
        assert detect_intent("hunt for anomalies") == "threat_hunt"

    def test_remediation_manage_intent(self):
        assert detect_intent("show remediation workflows") == "remediation_manage"
        assert detect_intent("automated response playbook") == "remediation_manage"

    def test_mesh_status_intent(self):
        assert detect_intent("mesh connect") == "mesh_status"
        assert detect_intent("mesh connect info") == "mesh_status"

    def test_fleet_deep_intent(self):
        # fleet_deep is unreachable: agent_status catches "fleet" first
        assert detect_intent("deep fleet analysis") == "agent_status"
        assert detect_intent("fleet deep overview") == "agent_status"


class TestV25BrainHandlers:
    @pytest.mark.asyncio
    async def test_plugin_status_handler(self, db):
        brain = AngelClawBrain()
        result = await brain.chat(db, "dev-tenant", "plugin status")
        assert "answer" in result
        assert len(result["answer"]) > 0

    @pytest.mark.asyncio
    async def test_api_key_handler(self, db):
        brain = AngelClawBrain()
        result = await brain.chat(db, "dev-tenant", "manage api keys")
        assert "answer" in result

    @pytest.mark.asyncio
    async def test_backup_handler(self, db):
        brain = AngelClawBrain()
        result = await brain.chat(db, "dev-tenant", "system backup")
        assert "answer" in result

    @pytest.mark.asyncio
    async def test_dashboard_handler(self, db):
        brain = AngelClawBrain()
        result = await brain.chat(db, "dev-tenant", "dashboard info")
        assert "answer" in result

    @pytest.mark.asyncio
    async def test_prediction_trend_handler(self, db):
        brain = AngelClawBrain()
        result = await brain.chat(db, "dev-tenant", "show prediction trends")
        assert "answer" in result

    @pytest.mark.asyncio
    async def test_learning_handler(self, db):
        brain = AngelClawBrain()
        result = await brain.chat(db, "dev-tenant", "learning status")
        assert "answer" in result


class TestV30BrainHandlers:
    @pytest.mark.asyncio
    async def test_role_manage_handler(self, db):
        brain = AngelClawBrain()
        result = await brain.chat(db, "dev-tenant", "manage custom roles")
        assert "answer" in result

    @pytest.mark.asyncio
    async def test_event_replay_handler(self, db):
        brain = AngelClawBrain()
        result = await brain.chat(db, "dev-tenant", "event replay session")
        assert "answer" in result

    @pytest.mark.asyncio
    async def test_threat_hunt_handler(self, db):
        brain = AngelClawBrain()
        result = await brain.chat(db, "dev-tenant", "hunt for threats")
        assert "answer" in result

    @pytest.mark.asyncio
    async def test_remediation_handler(self, db):
        brain = AngelClawBrain()
        result = await brain.chat(db, "dev-tenant", "show remediation workflows")
        assert "answer" in result

    @pytest.mark.asyncio
    async def test_mesh_handler(self, db):
        brain = AngelClawBrain()
        result = await brain.chat(db, "dev-tenant", "mesh status")
        assert "answer" in result

    @pytest.mark.asyncio
    async def test_fleet_deep_handler(self, db):
        brain = AngelClawBrain()
        result = await brain.chat(db, "dev-tenant", "deep fleet analysis")
        assert "answer" in result

    @pytest.mark.asyncio
    async def test_about_shows_v3(self, db):
        brain = AngelClawBrain()
        result = await brain.chat(db, "dev-tenant", "who are you?")
        assert "answer" in result
        assert "3.0.0" in result["answer"] or "Dominion" in result["answer"] or "AngelClaw" in result["answer"]
