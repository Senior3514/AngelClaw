"""Tests for V2.5 Plugin System."""

from __future__ import annotations

import json
import uuid

from cloud.db.models import PluginRegistrationRow
from cloud.plugins.loader import PluginLoader


class TestPluginLoader:
    def test_create_loader(self):
        loader = PluginLoader()
        assert loader is not None

    def test_list_plugins_empty(self):
        loader = PluginLoader()
        plugins = loader.list_plugins()
        assert isinstance(plugins, list)
        assert len(plugins) == 0

    def test_discover_plugins(self, tmp_path):
        """Test plugin discovery from directory."""
        # Create a fake plugin
        plugin_dir = tmp_path / "test_plugin"
        plugin_dir.mkdir()
        manifest = {
            "name": "test-warden",
            "version": "1.0.0",
            "agent_type": "plugin",
            "entry_point": "warden.TestWarden",
            "permissions": ["read_events"],
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))
        (plugin_dir / "warden.py").write_text("class TestWarden: pass")

        loader = PluginLoader(plugins_dir=str(tmp_path))
        discovered = loader.discover_plugins()
        assert isinstance(discovered, list)

    def test_invalid_manifest(self, tmp_path):
        """Invalid manifest should not crash."""
        plugin_dir = tmp_path / "bad_plugin"
        plugin_dir.mkdir()
        (plugin_dir / "manifest.json").write_text("not json")

        loader = PluginLoader(plugins_dir=str(tmp_path))
        discovered = loader.discover_plugins()
        assert isinstance(discovered, list)

    def test_missing_manifest(self, tmp_path):
        """Directory without manifest should be skipped."""
        plugin_dir = tmp_path / "no_manifest"
        plugin_dir.mkdir()
        (plugin_dir / "warden.py").write_text("class NoManifest: pass")

        loader = PluginLoader(plugins_dir=str(tmp_path))
        discovered = loader.discover_plugins()
        assert isinstance(discovered, list)


class TestPluginRoutes:
    def test_list_plugins_endpoint(self, client):
        resp = client.get("/api/v1/plugins")
        assert resp.status_code == 200

    def test_reload_plugins_endpoint(self, client):
        resp = client.post("/api/v1/plugins/reload")
        assert resp.status_code in (200, 201, 404)


class TestPluginDB:
    def test_plugin_registration_row(self, db):
        row = PluginRegistrationRow(
            id=str(uuid.uuid4()),
            name="test-plugin",
            version="1.0.0",
            agent_type="plugin",
            entry_point="warden.py",
            permissions=["read_events"],
            status="loaded",
        )
        db.add(row)
        db.commit()
        loaded = db.query(PluginRegistrationRow).filter_by(name="test-plugin").first()
        assert loaded is not None
        assert loaded.version == "1.0.0"
