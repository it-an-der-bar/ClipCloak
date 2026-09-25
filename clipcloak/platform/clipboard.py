"""Clipboard backends: Qt (Windows/X11/focused Wayland) and wl-clipboard (Wayland)."""

from __future__ import annotations

import hashlib
import logging
import shutil
import subprocess
from dataclasses import dataclass, field

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QMimeData, QObject, QProcess, Signal
from PySide6.QtGui import QGuiApplication, QImage

log = logging.getLogger(__name__)


@dataclass
class ClipContent:
    text: str | None = None
    html: str | None = None
    image_png: bytes | None = None
    formats: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        h = hashlib.sha256()
        h.update((self.text or "").encode("utf-8", "surrogatepass"))
        h.update(b"\0")
        h.update((self.html or "").encode("utf-8", "surrogatepass"))
        if self.image_png:
            h.update(self.image_png[:4096])
        return h.hexdigest()


def text_fingerprint(text: str | None, html: str | None = None) -> str:
    return ClipContent(text, html).fingerprint


class ClipboardBackend(QObject):
    changed = Signal()
    name = "base"

    def read(self) -> ClipContent:  # pragma: no cover
        raise NotImplementedError

    def write(self, text: str, html: str | None = None) -> None:  # pragma: no cover
        raise NotImplementedError

    def can_watch(self) -> bool:
        return True

    def start_watch(self) -> bool:
        return True

    def stop_watch(self) -> None:
        pass

    def release(self) -> None:
        pass


def _png_bytes(img: QImage) -> bytes | None:
    if img is None or img.isNull():
        return None
    ba = QByteArray()
    buf = QBuffer(ba)
    buf.open(QIODevice.WriteOnly)
    img.save(buf, "PNG")
    buf.close()
    return bytes(ba.data())


class QtClipboard(ClipboardBackend):
    name = "qt"

    def __init__(self, parent=None):
        super().__init__(parent)
        self.cb = QGuiApplication.clipboard()
        self._watching = False
        self._last_text = None
        self.cb.dataChanged.connect(self._on_change)

    def _on_change(self):
        if self._watching:
            self.changed.emit()

    def start_watch(self) -> bool:
        self._watching = True
        return True

    def stop_watch(self) -> None:
        self._watching = False

    def read(self) -> ClipContent:
        md = self.cb.mimeData()
        c = ClipContent()
        if md is None:
            return c
        c.formats = list(md.formats())
        if md.hasText():
            c.text = md.text()
        if md.hasHtml():
            c.html = md.html()
        if md.hasImage():
            c.image_png = _png_bytes(self.cb.image())
        return c

    def write(self, text: str, html: str | None = None) -> None:
        if not html:
            self.cb.setText(text)          # QMimeData created on the C++ side
            self._last_text = None
            return
        md = QMimeData()
        md.setText(text)
        md.setHtml(html)
        self.cb.setMimeData(md)
        self._last_text = text

    def release(self) -> None:
        """Replace a Python-created QMimeData before the interpreter shuts down.

        Qt deletes clipboard data in a static destructor after Python has been
        finalised; a Python-owned QMimeData wrapper would crash there. The text
        stays in the clipboard (formatting is dropped at exit).
        """
        if getattr(self, "_last_text", None) is not None:
            md = self.cb.mimeData()
            if md is not None and md.hasHtml() and md.text() == self._last_text:
                self.cb.setText(self._last_text)
            self._last_text = None


class WlClipboard(ClipboardBackend):
    """Uses ``wl-paste``/``wl-copy`` (package *wl-clipboard*).

    Reading and writing work on all Wayland compositors (wl-clipboard falls
    back to a short-lived focused surface where needed). Watching requires the
    data-control protocol (KDE Plasma, wlroots compositors such as Sway/Hyprland);
    GNOME does not offer it.
    """

    name = "wl-clipboard"

    def __init__(self, parent=None):
        super().__init__(parent)
        self._proc: QProcess | None = None
        self.watch_error = ""

    @staticmethod
    def available() -> bool:
        return bool(shutil.which("wl-paste") and shutil.which("wl-copy"))

    @staticmethod
    def _run(args: list[str], timeout: float = 3.0) -> bytes | None:
        try:
            r = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               stdin=subprocess.DEVNULL, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return r.stdout if r.returncode == 0 else None

    def read(self) -> ClipContent:
        c = ClipContent()
        types_raw = self._run(["wl-paste", "--list-types"])
        if types_raw is None:
            return c
        types = [t.strip() for t in types_raw.decode("utf-8", "replace").splitlines() if t.strip()]
        c.formats = types
        text_type = next((t for t in types if t.lower().startswith("text/plain;charset=utf-8")), None) \
            or next((t for t in types if t in ("UTF8_STRING", "text/plain", "STRING", "TEXT")), None)
        if text_type:
            data = self._run(["wl-paste", "--no-newline", "--type", text_type])
            if data is not None:
                c.text = data.decode("utf-8", "replace")
        if "text/html" in types:
            data = self._run(["wl-paste", "--no-newline", "--type", "text/html"])
            if data is not None:
                c.html = data.decode("utf-8", "replace")
        if c.text is None and "image/png" in types:
            c.image_png = self._run(["wl-paste", "--type", "image/png"], timeout=5)
        return c

    def write(self, text: str, html: str | None = None) -> None:
        # wl-copy offers exactly one MIME type per call; plain text is what every
        # target accepts, so formatted HTML is not offered on this backend.
        try:
            subprocess.run(["wl-copy", "--type", "text/plain;charset=utf-8"], input=text.encode("utf-8"),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.error("wl-copy failed: %s", exc)

    def start_watch(self) -> bool:
        if self._proc is not None:
            return True
        p = QProcess(self)
        p.setProgram("wl-paste")
        p.setArguments(["--watch", "echo", "changed"])
        p.readyReadStandardOutput.connect(self._on_output)
        p.finished.connect(self._on_finished)
        p.start()
        if not p.waitForStarted(2000):
            self.watch_error = "wl-paste could not be started"
            return False
        self._proc = p
        return True

    def _on_output(self):
        if self._proc is None:
            return
        data = bytes(self._proc.readAllStandardOutput().data())
        if data.strip():
            self.changed.emit()

    def _on_finished(self, code, _status):
        if self._proc is not None:
            err = bytes(self._proc.readAllStandardError().data()).decode("utf-8", "replace").strip()
            self.watch_error = err or f"wl-paste --watch exited ({code})"
            log.warning("clipboard watch stopped: %s", self.watch_error)
        self._proc = None

    def stop_watch(self) -> None:
        if self._proc is not None:
            p, self._proc = self._proc, None
            p.kill()
            p.waitForFinished(1000)


def make_backend(preference: str, display: str, parent=None) -> ClipboardBackend:
    if preference == "wl-clipboard" or (preference == "auto" and display == "wayland" and WlClipboard.available()):
        if WlClipboard.available():
            return WlClipboard(parent)
        log.warning("wl-clipboard requested but not installed, using Qt clipboard")
    return QtClipboard(parent)
