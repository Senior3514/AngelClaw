"""AngelClaw V2.5 — Plugin Management API Routes.

Endpoints for listing, reloading, enabling, and disabling warden plugins
at runtime.

Endpoints:
  GET   /api/v1/plugins              — List all plugins
  POST  /api/v1/plugins/reload       — Hot-reload all plugins
  POST  /api/v1/plugins/{name}/enable  — Enable a plugin
  POST  /api/v1/plugins/{name}/disable — Disable a plugin
  GET   /api/v1/plugins/{name}/health  — Plugin health info
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException

from cloud.plugins.loader import PluginInfo, plugin_loader

logger = logging.getLogger("angelgrid.cloud.plugins.routes")

router = APIRouter(prefix="/api/v1/plugins", tags=["Plugins"])


# ---------------------------------------------------------------------------
# GET /api/v1/plugins
# ---------------------------------------------------------------------------


@router.get("", response_model=list[PluginInfo], summary="List all plugins")
async def list_plugins() -> list[PluginInfo]:
    """Return metadata for every discovered plugin."""
    return plugin_loader.list_plugins()


# ---------------------------------------------------------------------------
# POST /api/v1/plugins/reload
# ---------------------------------------------------------------------------


@router.post("/reload", response_model=list[PluginInfo], summary="Hot-reload all plugins")
async def reload_all_plugins() -> list[PluginInfo]:
    """Unload and re-load every plugin from disk.

    Useful for picking up new plugins or updated code without restarting
    the entire AngelClaw service.
    """
    results = plugin_loader.reload_all()
    logger.info("Hot-reloaded %d plugin(s) via API", len(results))
    return results


# ---------------------------------------------------------------------------
# POST /api/v1/plugins/{name}/enable
# ---------------------------------------------------------------------------


@router.post("/{name}/enable", response_model=PluginInfo, summary="Enable a plugin")
async def enable_plugin(name: str) -> PluginInfo:
    """Re-load a previously disabled or errored plugin."""
    info = plugin_loader.get_plugin(name)

    if info is None:
        # Attempt to discover and load from the plugins directory

        plugin_dir = plugin_loader.plugins_dir / name
        if not plugin_dir.is_dir():
            raise HTTPException(status_code=404, detail=f"Plugin '{name}' not found")
        new_info = plugin_loader.load_plugin(plugin_dir)
        logger.info("Plugin '%s' enabled via API", name)
        return new_info

    if info.status == "loaded":
        return info  # already enabled

    # Reload to clear error / disabled state
    reloaded = plugin_loader.reload_plugin(name)
    if reloaded is None:
        raise HTTPException(status_code=500, detail=f"Failed to enable plugin '{name}'")
    logger.info("Plugin '%s' enabled via API", name)
    return reloaded


# ---------------------------------------------------------------------------
# POST /api/v1/plugins/{name}/disable
# ---------------------------------------------------------------------------


@router.post("/{name}/disable", response_model=PluginInfo, summary="Disable a plugin")
async def disable_plugin(name: str) -> PluginInfo:
    """Disable a running plugin without removing it from discovery."""
    info = plugin_loader.get_plugin(name)
    if info is None:
        raise HTTPException(status_code=404, detail=f"Plugin '{name}' not found")

    if info.status == "disabled":
        return info  # already disabled

    # Unload the agent but keep a disabled record
    plugin_loader.unload_plugin(name)

    disabled_info = PluginInfo(
        name=info.name,
        version=info.version,
        description=info.description,
        author=info.author,
        agent_type=info.agent_type,
        status="disabled",
    )

    # Re-insert as a disabled stub so it still shows up in list_plugins
    plugin_loader._plugins[name] = {
        "manifest": None,
        "agent": None,
        "info": disabled_info,
        "module": None,
    }

    logger.info("Plugin '%s' disabled via API", name)
    return disabled_info


# ---------------------------------------------------------------------------
# GET /api/v1/plugins/{name}/health
# ---------------------------------------------------------------------------


@router.get("/{name}/health", summary="Get plugin health")
async def plugin_health(name: str) -> dict[str, Any]:
    """Return detailed health and performance metrics for a plugin's agent."""
    health = plugin_loader.get_plugin_health(name)
    if "error" in health and health["error"].endswith("not found"):
        raise HTTPException(status_code=404, detail=health["error"])
    return health
