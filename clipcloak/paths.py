"""Per-user config/data locations (no Qt dependency)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .meta import APP_NAME


def config_dir() -> Path:
    override = os.environ.get(APP_NAME.upper().replace("-", "_") + "_CONFIG_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / APP_NAME


def data_dir() -> Path:
    override = os.environ.get(APP_NAME.upper().replace("-", "_") + "_DATA_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / APP_NAME


def config_file() -> Path:
    return config_dir() / "config.yaml"


def projects_dir() -> Path:
    return data_dir() / "projects"


def resource_path(*parts: str) -> Path:
    """Locate bundled resources both from source and from a PyInstaller build."""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / __package__ / "resources" / Path(*parts)
    return Path(__file__).resolve().parent / "resources" / Path(*parts)
