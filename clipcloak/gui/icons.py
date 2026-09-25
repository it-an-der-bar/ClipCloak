"""Programmatically drawn application/tray icons (no image assets needed)."""

from __future__ import annotations

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QBrush, QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap

BASE = QColor("#1f5f73")
STATE_COLORS = {
    "idle": None,
    "watch": QColor("#2fb56a"),      # watcher active
    "critical": QColor("#f0a020"),   # watcher critical-only
    "paused": QColor("#9aa0a6"),
    "busy": QColor("#3d8bfd"),
}


def draw(size: int, state: str = "idle", base: QColor | None = None) -> QPixmap:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    s = size / 64.0
    p.scale(s, s)
    # rounded background
    p.setPen(Qt.NoPen)
    p.setBrush(QBrush(base or BASE))
    p.drawRoundedRect(QRectF(2, 2, 60, 60), 13, 13)
    # clipboard board
    p.setBrush(QBrush(QColor("#ffffff")))
    p.drawRoundedRect(QRectF(15, 13, 34, 42), 5, 5)
    # clip
    p.setBrush(QBrush(QColor("#d7e3e8")))
    p.setPen(QPen(QColor("#ffffff"), 2.5))
    p.drawRoundedRect(QRectF(24, 8, 16, 10), 3, 3)
    # text line + redaction bars
    p.setPen(Qt.NoPen)
    p.setBrush(QBrush(QColor("#9fb4bd")))
    p.drawRoundedRect(QRectF(20, 24, 24, 3.5), 1.5, 1.5)
    p.setBrush(QBrush(QColor("#10262e")))
    p.drawRoundedRect(QRectF(20, 31, 18, 5), 1.5, 1.5)
    p.drawRoundedRect(QRectF(20, 40, 24, 5), 1.5, 1.5)
    # mask/cloak arc
    path = QPainterPath()
    path.moveTo(15, 50)
    path.cubicTo(24, 44, 40, 44, 49, 50)
    path.lineTo(49, 55)
    path.lineTo(15, 55)
    path.closeSubpath()
    p.setBrush(QBrush(base or BASE))
    p.drawPath(path)
    dot = STATE_COLORS.get(state)
    if dot is not None:
        p.setPen(QPen(QColor("#ffffff"), 3))
        p.setBrush(QBrush(dot))
        p.drawEllipse(QRectF(40, 40, 22, 22))
    p.end()
    return pm


def icon(state: str = "idle") -> QIcon:
    ic = QIcon()
    for sz in (16, 20, 22, 24, 32, 48, 64, 128, 256):
        ic.addPixmap(draw(sz, state))
    return ic
