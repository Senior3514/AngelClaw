"""AngelClaw V2.5 — Plugin Loader.

Dynamically discovers and loads warden plugins from the plugins directory.
Each plugin lives in its own subdirectory with a ``manifest.json`` that
declares metadata, entry point, and required permissions.

Usage::

    from cloud.plugins.loader import plugin_loader

    plugin_loader.discover_plugins(registry=my_registry)
    for info in plugin_loader.list_plugins():
        print(info.name, info.status)
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from cloud.guardian.base_agent import SubAgent
from cloud.guardian.models import AgentType, Permission

logger = logging.getLogger("angelgrid.cloud.plugins.loader")

_DEFAULT_PLUGINS_DIR = "/root/AngelClaw/plugins"


# ---------------------------------------------------------------------------
# Manifest & info models
# ---------------------------------------------------------------------------


class PluginManifest(BaseModel):
    """Schema for a plugin's ``manifest.json``."""

    name: str
    version: str
    description: str = ""
    author: str = ""
    agent_type: str = "plugin"
    entry_point: str  # e.g. "warden.ExampleWarden"
    permissions: list[str] = Field(default_factory=list)
    min_angelclaw_version: str = "2.5.0"


class PluginInfo(BaseModel):
    """Public-facing metadata for a loaded (or failed) plugin."""

    name: str
    version: str
    description: str = ""
    author: str = ""
    agent_type: str = "plugin"
    status: str = "loaded"  # loaded | error | disabled
    loaded_at: datetime | None = None
    error: str = ""


# ---------------------------------------------------------------------------
# PluginLoader
# ---------------------------------------------------------------------------


class PluginLoader:
    """Discover, load, unload, and reload warden plugins at runtime."""

    def __init__(self, plugins_dir: str | None = None) -> None:
        self.plugins_dir = Path(plugins_dir or _DEFAULT_PLUGINS_DIR)
        # name -> {"manifest": PluginManifest, "agent": SubAgent,
        #          "info": PluginInfo, "module": module}
        self._plugins: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover_plugins(self, registry: Any = None) -> list[PluginInfo]:
        """Scan *plugins_dir* for subdirectories containing a ``manifest.json``.

        Each valid plugin is loaded via :meth:`load_plugin`.  Returns a
        list of :class:`PluginInfo` for every plugin found (including
        those that failed to load).
        """
        results: list[PluginInfo] = []
        if not self.plugins_dir.is_dir():
            logger.warning("Plugins directory does not exist: %s", self.plugins_dir)
            return results

        for child in sorted(self.plugins_dir.iterdir()):
            if not child.is_dir():
                continue
            manifest_path = child / "manifest.json"
            if not manifest_path.exists():
                continue
            info = self.load_plugin(child, registry=registry)
            results.append(info)

        logger.info(
            "Plugin discovery complete — %d plugin(s) found, %d loaded",
            len(results),
            sum(1 for r in results if r.status == "loaded"),
        )
        return results

    # ------------------------------------------------------------------
    # Load / unload / reload
    # ------------------------------------------------------------------

    def load_plugin(self, plugin_dir: Path, registry: Any = None) -> PluginInfo:
        """Load a single plugin from *plugin_dir*.

        Steps:
        1. Read and validate ``manifest.json``.
        2. Import the module specified by *entry_point*.
        3. Instantiate the warden class.
        4. Optionally register the agent with an :class:`AgentRegistry`.

        Returns :class:`PluginInfo` reflecting success or failure.
        """
        manifest_path = plugin_dir / "manifest.json"

        # -- Parse manifest --------------------------------------------------
        try:
            raw = manifest_path.read_text(encoding="utf-8")
            manifest = PluginManifest(**json.loads(raw))
        except Exception as exc:
            error_msg = f"Invalid manifest in {plugin_dir.name}: {exc}"
            logger.error(error_msg)
            info = PluginInfo(
                name=plugin_dir.name,
                version="0.0.0",
                status="error",
                error=error_msg,
            )
            self._plugins[plugin_dir.name] = {
                "manifest": None,
                "agent": None,
                "info": info,
                "module": None,
            }
            return info

        # -- Resolve entry point (e.g. "warden.ExampleWarden") ---------------
        try:
            module_rel, class_name = manifest.entry_point.rsplit(".", 1)
            module_file = plugin_dir / (module_rel.replace(".", "/") + ".py")

            spec = importlib.util.spec_from_file_location(
                f"angelclaw_plugin_{manifest.name}.{module_rel}",
                str(module_file),
            )
            if spec is None or spec.loader is None:
                raise ImportError(f"Cannot create module spec for {module_file}")

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # type: ignore[union-attr]

            warden_cls = getattr(module, class_name)
        except Exception as exc:
            error_msg = (
                f"Failed to import entry point '{manifest.entry_point}' "
                f"for plugin '{manifest.name}': {exc}"
            )
            logger.error(error_msg)
            info = PluginInfo(
                name=manifest.name,
                version=manifest.version,
                description=manifest.description,
                author=manifest.author,
                agent_type=manifest.agent_type,
                status="error",
                error=error_msg,
            )
            self._plugins[manifest.name] = {
                "manifest": manifest,
                "agent": None,
                "info": info,
                "module": None,
            }
            return info

        # -- Instantiate warden -----------------------------------------------
        try:
            # Resolve agent_type and permissions from manifest strings
            agent_type = AgentType(manifest.agent_type)
            permissions: set[Permission] = set()
            for perm_str in manifest.permissions:
                try:
                    permissions.add(Permission(perm_str))
                except ValueError:
                    logger.warning(
                        "Plugin '%s' declares unknown permission '%s' — skipped",
                        manifest.name,
                        perm_str,
                    )

            agent: SubAgent = warden_cls(
                agent_type=agent_type,
                permissions=permissions,
            )
        except Exception as exc:
            error_msg = f"Failed to instantiate warden for plugin '{manifest.name}': {exc}"
            logger.error(error_msg)
            info = PluginInfo(
                name=manifest.name,
                version=manifest.version,
                description=manifest.description,
                author=manifest.author,
                agent_type=manifest.agent_type,
                status="error",
                error=error_msg,
            )
            self._plugins[manifest.name] = {
                "manifest": manifest,
                "agent": None,
                "info": info,
                "module": module,
            }
            return info

        # -- Register with AgentRegistry (optional) --------------------------
        if registry is not None:
            try:
                registry.register(agent)
            except Exception as exc:
                logger.warning(
                    "Plugin '%s' loaded but registry registration failed: %s",
                    manifest.name,
                    exc,
                )

        now = datetime.now(timezone.utc)
        info = PluginInfo(
            name=manifest.name,
            version=manifest.version,
            description=manifest.description,
            author=manifest.author,
            agent_type=manifest.agent_type,
            status="loaded",
            loaded_at=now,
        )
        self._plugins[manifest.name] = {
            "manifest": manifest,
            "agent": agent,
            "info": info,
            "module": module,
        }
        logger.info(
            "Plugin '%s' v%s loaded (agent_id=%s)",
            manifest.name,
            manifest.version,
            agent.agent_id,
        )
        return info

    def unload_plugin(self, name: str, registry: Any = None) -> bool:
        """Unload a plugin by name.

        If a *registry* is provided the plugin's agent is deregistered.
        Returns ``True`` if the plugin was found and removed.
        """
        entry = self._plugins.pop(name, None)
        if entry is None:
            logger.warning("Cannot unload unknown plugin '%s'", name)
            return False

        agent: SubAgent | None = entry.get("agent")
        if agent is not None and registry is not None:
            try:
                registry.deregister(agent.agent_id)
            except Exception as exc:
                logger.warning(
                    "Failed to deregister agent for plugin '%s': %s",
                    name,
                    exc,
                )

        logger.info("Plugin '%s' unloaded", name)
        return True

    def reload_plugin(self, name: str, registry: Any = None) -> PluginInfo | None:
        """Unload then re-load a single plugin by name.

        Returns the new :class:`PluginInfo`, or ``None`` if the plugin
        directory cannot be located.
        """
        self.unload_plugin(name, registry=registry)

        # Locate plugin directory
        plugin_dir = self.plugins_dir / name
        if not plugin_dir.is_dir():
            logger.error("Plugin directory not found for reload: %s", plugin_dir)
            return None

        return self.load_plugin(plugin_dir, registry=registry)

    def reload_all(self, registry: Any = None) -> list[PluginInfo]:
        """Reload every currently-known plugin.

        Returns updated :class:`PluginInfo` for each.
        """
        names = list(self._plugins.keys())
        results: list[PluginInfo] = []
        for name in names:
            info = self.reload_plugin(name, registry=registry)
            if info is not None:
                results.append(info)
        logger.info("Reloaded %d plugin(s)", len(results))
        return results

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_plugin(self, name: str) -> PluginInfo | None:
        """Return :class:`PluginInfo` for a plugin, or ``None``."""
        entry = self._plugins.get(name)
        if entry is None:
            return None
        return entry["info"]

    def list_plugins(self) -> list[PluginInfo]:
        """Return :class:`PluginInfo` for every known plugin."""
        return [entry["info"] for entry in self._plugins.values()]

    def get_plugin_health(self, name: str) -> dict[str, Any]:
        """Return the agent's health/info dict for a loaded plugin.

        Returns an error dict if the plugin is not loaded or has no agent.
        """
        entry = self._plugins.get(name)
        if entry is None:
            return {"error": f"Plugin '{name}' not found"}

        agent: SubAgent | None = entry.get("agent")
        if agent is None:
            return {
                "plugin": name,
                "status": entry["info"].status,
                "error": entry["info"].error or "No agent instance",
            }

        health = agent.info()
        health["plugin"] = name
        health["plugin_version"] = entry["info"].version
        return health


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

plugin_loader = PluginLoader()
