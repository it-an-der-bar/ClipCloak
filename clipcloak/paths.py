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


def private_dir(d: Path) -> Path:
    """Create ``d`` (and parents) readable for the owner only (0700 on POSIX)."""
    d = Path(d)
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
    return d


def write_private(path: Path, data: str | bytes) -> None:
    """Write atomically; the file is created with mode 0600 from the start (no readable window)."""
    path = Path(path)
    private_dir(path.parent)
    tmp = path.with_name(path.name + ".tmp")
    raw = data.encode("utf-8") if isinstance(data, str) else data
    try:
        tmp.unlink()
    except OSError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    os.replace(tmp, path)
