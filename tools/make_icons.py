"""Render the application icon to clipcloak/resources (PNG, ICO, SVG-free).

Run once after changing ``clipcloak/gui/icons.py``:
    QT_QPA_PLATFORM=offscreen python tools/make_icons.py
"""

import os
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

from clipcloak.gui.icons import draw  # noqa: E402
from clipcloak.meta import APP_NAME  # noqa: E402

app = QApplication([])
res = ROOT / APP_NAME / "resources"
res.mkdir(parents=True, exist_ok=True)
draw(256).save(str(res / "icon.png"), "PNG")


def png_bytes(size: int) -> bytes:
    from PySide6.QtCore import QBuffer, QByteArray, QIODevice
    ba = QByteArray()
    buf = QBuffer(ba)
    buf.open(QIODevice.WriteOnly)
    draw(size).save(buf, "PNG")
    buf.close()
    return bytes(ba.data())


# multi-resolution ICO with PNG-compressed entries (supported since Windows Vista)
sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]
images = [png_bytes(s) for s in sizes]
header = struct.pack("<HHH", 0, 1, len(sizes))
offset = 6 + 16 * len(sizes)
entries = b""
for s, data in zip(sizes, images, strict=True):
    entries += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(data), offset)
    offset += len(data)
(res / "icon.ico").write_bytes(header + entries + b"".join(images))
print("written", res / "icon.png", res / "icon.ico")
