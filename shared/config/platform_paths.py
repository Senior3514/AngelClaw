"""AngelClaw – Cross-platform path defaults.

Returns the right default directories for data, logs, and backups
depending on the host operating system (Linux, macOS, Windows).
"""

from __future__ import annotations

import os
import platform
from pathlib import Path

_SYS = platform.system()  # "Linux", "Windows", "Darwin"


def data_dir() -> Path:
    """Default data directory for AngelClaw state files."""
    if _SYS == "Windows":
        return Path(os.environ.get("APPDATA", "~")) / "AngelClaw"
    elif _SYS == "Darwin":
        return Path.home() / "Library" / "Application Support" / "AngelClaw"
    return Path("/var/lib/angelclaw")


def log_dir() -> Path:
    """Default log directory for AngelClaw decision logs."""
    if _SYS == "Windows":
        return data_dir() / "logs"
    elif _SYS == "Darwin":
        return Path.home() / "Library" / "Logs" / "AngelClaw"
    return Path("/var/log/angelgrid")


def backup_dir() -> Path:
    """Default backup directory for AngelClaw skill snapshots."""
    if _SYS == "Windows":
        return data_dir() / "backups"
    elif _SYS == "Darwin":
        return Path.home() / "Library" / "Backups" / "AngelClaw"
    return Path("/var/backups/angelclaw")


def is_windows() -> bool:
    """Return True when running on Windows."""
    return _SYS == "Windows"
