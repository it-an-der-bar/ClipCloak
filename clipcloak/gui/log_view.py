"""Log tab: what the program is doing (actions, watcher, LLM, NER)."""

from __future__ import annotations

import logging
import time
from collections import deque

from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QGuiApplication, QTextCursor
from PySide6.QtWidgets import (QComboBox, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton,
                               QVBoxLayout, QWidget)

from ..i18n import t
from .widgets import mono_font

PKG = (__package__ or "clipcloak").split(".")[0]


class LogBridge(QObject):
    line = Signal(int, str)       # level, formatted line


class UiLogHandler(logging.Handler):
    """Keeps the last lines in RAM and forwards new ones to the Log tab (thread safe)."""

    def __init__(self, maxlen: int = 3000):
        super().__init__(logging.INFO)
        self.bridge = LogBridge()
        self.buffer: deque[tuple[int, str]] = deque(maxlen=maxlen)

    def emit(self, record: logging.LogRecord) -> None:
        if not (record.name.startswith(PKG) or record.levelno >= logging.WARNING):
            return
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return
        level = {logging.WARNING: "WARN", logging.ERROR: "ERROR", logging.CRITICAL: "ERROR"}.get(record.levelno, "INFO")
        stamp = time.strftime("%H:%M:%S", time.localtime(record.created))
        line = f"{stamp}  {level:<5}  {msg}"
        self.buffer.append((record.levelno, line))
        try:
            self.bridge.line.emit(record.levelno, line)
        except RuntimeError:   # bridge deleted during shutdown
            pass


class LogView(QWidget):
    def __init__(self, handler: UiLogHandler, parent=None):
        super().__init__(parent)
        self.handler = handler
        self.text = QPlainTextEdit(readOnly=True)
        self.text.setFont(mono_font())
        self.text.setMaximumBlockCount(5000)
        self.level = QComboBox()
        self.level.addItem(t("logtab.all"), logging.INFO)
        self.level.addItem(t("logtab.warnings"), logging.WARNING)
        clear = QPushButton(t("logtab.clear"))
        copy = QPushButton(t("logtab.copy"))
        note = QLabel(t("logtab.note"))
        note.setWordWrap(True)
        top = QHBoxLayout()
        top.addWidget(self.level)
        top.addStretch(1)
        top.addWidget(copy)
        top.addWidget(clear)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(self.text, 1)
        lay.addWidget(note)
        self.level.currentIndexChanged.connect(self.reload)
        clear.clicked.connect(self._clear)
        copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(self.text.toPlainText()))
        handler.bridge.line.connect(self._append)
        self.reload()

    def _min(self) -> int:
        return int(self.level.currentData() or logging.INFO)

    def reload(self):
        m = self._min()
        self.text.setPlainText("\n".join(line for lvl, line in self.handler.buffer if lvl >= m))
        self.text.moveCursor(QTextCursor.End)

    def _append(self, level: int, line: str):
        if level >= self._min():
            self.text.appendPlainText(line)

    def _clear(self):
        self.handler.buffer.clear()
        self.text.clear()
