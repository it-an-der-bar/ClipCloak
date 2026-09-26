"""Black bars, mosaic and blur for image regions (Qt only, no plugin needed)."""

from __future__ import annotations

from PySide6.QtCore import QPoint, QRect, Qt
from PySide6.QtGui import QColor, QImage, QPainter


def clip_rect(img: QImage, x: int, y: int, w: int, h: int) -> QRect:
    return QRect(int(x), int(y), int(w), int(h)).intersected(QRect(0, 0, img.width(), img.height()))


def patch(src: QImage, rect: QRect, effect: str) -> QImage:
    """The replacement pixels for ``rect`` of ``src``."""
    w, h = rect.width(), rect.height()
    if w <= 0 or h <= 0:
        return QImage()
    if effect == "mosaic":
        # about 8 blocks across the shorter side: coarse enough that faces cannot be
        # recognised (for TEXT use black – pixelated text can be recovered)
        block = max(6, min(w, h) // 8)
        small = src.copy(rect).scaled(max(1, w // block), max(1, h // block),
                                      Qt.IgnoreAspectRatio, Qt.SmoothTransformation)
        return small.scaled(w, h, Qt.IgnoreAspectRatio, Qt.FastTransformation)
    if effect == "blur":
        f = max(6, min(w, h) // 5)
        small = src.copy(rect).scaled(max(1, w // f), max(1, h // f), Qt.IgnoreAspectRatio, Qt.SmoothTransformation)
        mid = small.scaled(max(1, w // 3), max(1, h // 3), Qt.IgnoreAspectRatio, Qt.SmoothTransformation)
        return mid.scaled(w, h, Qt.IgnoreAspectRatio, Qt.SmoothTransformation)
    img = QImage(w, h, QImage.Format_ARGB32)
    img.fill(QColor(0, 0, 0))
    return img


def render(src: QImage, regions) -> QImage:
    """A new, flat image: the source with all regions replaced. It is painted into a
    fresh QImage, so no metadata (text chunks, EXIF, colour-space tags) of the source
    is carried over."""
    base = src.convertToFormat(QImage.Format_ARGB32)
    out = QImage(base.width(), base.height(), QImage.Format_ARGB32)
    out.fill(Qt.transparent)
    p = QPainter(out)
    p.drawImage(QPoint(0, 0), base)
    for r in regions:
        rect = clip_rect(base, r.x, r.y, r.w, r.h)
        if rect.isEmpty():
            continue
        p.drawImage(rect.topLeft(), patch(base, rect, r.effect))
    p.end()
    return out
