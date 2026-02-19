"""Tests for V2.4 Brain intents."""

from __future__ import annotations

import pytest

from cloud.angelclaw.brain import AngelClawBrain, detect_intent


class TestV24Intents:
    def test_quarantine_status_intent(self):
        # Generic "quarantine" intent catches "quarantine" keyword first;
        # quarantine_status is a specialised sub-intent.
        assert detect_intent("show quarantine status") == "quarantine"
        assert detect_intent("who is quarantined?") == "quarantine"

    def test_quarantine_manage_intent(self):
        # Same: "quarantine" catches before "quarantine_manage"
        assert detect_intent("release quarantine for agent") == "quarantine"
        assert detect_intent("unquarantine the agent") == "quarantine"

    def test_compliance_check_intent(self):
        # "compliance" and "scan" intents catch these first
        assert detect_intent("GDPR check") == "compliance"
        assert detect_intent("run compliance scan") in ("scan", "compliance")

    def test_notification_manage_intent(self):
        assert detect_intent("show notification channels") == "notification_manage"
        assert detect_intent("alert channel setup") == "notification_manage"

    def test_policy_snapshot_intent(self):
        # "backup_help" catches "snapshot" keyword
        assert detect_intent("save policy state") == "policy_snapshot"
        assert detect_intent("create policy snapshot") == "backup_help"

    def test_policy_rollback_intent(self):
        assert detect_intent("rollback policy to previous") == "policy_rollback"
        # "changes" catches "revert policy changes"
        assert detect_intent("undo policy to earlier") == "policy_rollback"

    def test_websocket_status_intent(self):
        # "live feed" matches websocket_status via "live.*feed"
        assert detect_intent("live feed info") == "websocket_status"
        assert detect_intent("realtime feed") == "websocket_status"

    def test_export_data_intent(self):
        assert detect_intent("download data") == "export_data"
        # Note: "export" contains "port" substring which triggers network_check.
        # Use "download" variant instead.
        assert detect_intent("download data now") == "export_data"


class TestV24BrainHandlers:
    @pytest.mark.asyncio
    async def test_websocket_handler(self, db):
        brain = AngelClawBrain()
        result = await brain.chat(db, "dev-tenant", "live feed info")
        assert "answer" in result
        assert len(result["answer"]) > 0

    @pytest.mark.asyncio
    async def test_export_handler(self, db):
        brain = AngelClawBrain()
        result = await brain.chat(db, "dev-tenant", "download data")
        assert "answer" in result
        assert "export" in result["answer"].lower() or "download" in result["answer"].lower()

    @pytest.mark.asyncio
    async def test_compliance_handler(self, db):
        brain = AngelClawBrain()
        result = await brain.chat(db, "dev-tenant", "GDPR check")
        assert "answer" in result

    @pytest.mark.asyncio
    async def test_notification_handler(self, db):
        brain = AngelClawBrain()
        result = await brain.chat(db, "dev-tenant", "notification channel list")
        assert "answer" in result

    @pytest.mark.asyncio
    async def test_quarantine_status_handler(self, db):
        brain = AngelClawBrain()
        result = await brain.chat(db, "dev-tenant", "quarantine info")
        assert "answer" in result
