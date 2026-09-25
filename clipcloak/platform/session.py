"""Detect the desktop session (Windows / X11 / Wayland)."""

from __future__ import annotations

import os
import shutil
import sys


def os_name() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "mac"
    return "linux"


def display_server(qt_platform: str | None = None) -> str:
    """windows | x11 | wayland | mac | offscreen | unknown"""
    osn = os_name()
    if osn in ("windows", "mac"):
        return osn
    if qt_platform:
        qp = qt_platform.lower()
        if qp.startswith("wayland"):
            return "wayland"
        if qp == "xcb":
            # XWayland: Qt runs on X11 but global grabs only see X clients
            return "xwayland" if os.environ.get("WAYLAND_DISPLAY") else "x11"
        if qp in ("offscreen", "minimal"):
            return "offscreen"
    if os.environ.get("WAYLAND_DISPLAY") or os.environ.get("XDG_SESSION_TYPE") == "wayland":
        return "wayland"
    if os.environ.get("DISPLAY"):
        return "x11"
    return "unknown"


def desktop() -> str:
    return (os.environ.get("XDG_CURRENT_DESKTOP") or os.environ.get("DESKTOP_SESSION") or "").lower()


def has_wl_clipboard() -> bool:
    return bool(shutil.which("wl-paste") and shutil.which("wl-copy"))


def info(qt_platform: str | None = None) -> dict:
    return {"os": os_name(), "display": display_server(qt_platform), "desktop": desktop(),
            "qt_platform": qt_platform or "", "wl_clipboard": has_wl_clipboard()}
