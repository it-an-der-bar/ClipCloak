"""Remembers window size/position, splitter positions, column widths and the last tab.

Stored in ``ui.ini`` next to ``config.yaml`` (Qt's own binary states, not part of the
settings, so policies and the settings dialog are not affected).
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QByteArray, QSettings
from PySide6.QtWidgets import QHeaderView, QSplitter, QWidget


class UiState:
    def __init__(self, path: Path | None):
        self._s = QSettings(str(path), QSettings.IniFormat) if path else None
        self._items: dict[str, object] = {}

    def track(self, key: str, obj, default_sizes: list[int] | None = None) -> bool:
        """Register a splitter, header view or top-level widget and restore its state.
        Returns True if a saved state was restored."""
        self._items[key] = obj
        data = self._s.value(key) if self._s is not None else None
        ok = False
        if isinstance(data, QByteArray) and not data.isEmpty():
            if isinstance(obj, (QSplitter, QHeaderView)):
                ok = bool(obj.restoreState(data))
            elif isinstance(obj, QWidget):
                ok = bool(obj.restoreGeometry(data))
        if not ok and default_sizes and isinstance(obj, QSplitter):
            obj.setSizes(default_sizes)
        return ok

    def value(self, key: str, default=None):
        if self._s is None:
            return default
        v = self._s.value(key)
        return default if v is None else v

    def set_value(self, key: str, value) -> None:
        if self._s is not None:
            self._s.setValue(key, value)

    def save(self) -> None:
        if self._s is None:
            return
        for key, obj in list(self._items.items()):
            try:
                if isinstance(obj, (QSplitter, QHeaderView)):
                    self._s.setValue(key, obj.saveState())
                elif isinstance(obj, QWidget):
                    self._s.setValue(key, obj.saveGeometry())
            except RuntimeError:        # widget already deleted
                self._items.pop(key, None)
        self._s.sync()
