"""Small non-focus-stealing notification window with action buttons."""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from ..i18n import t
from ..meta import APP_DISPLAY_NAME


class Popup(QWidget):
    chosen = Signal(str)     # action name or "" for dismissed

    def __init__(self, title: str, text: str, actions: list[tuple], timeout_s: int = 12,
                 parent=None):
        super().__init__(parent, Qt.Tool | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint
                         | Qt.WindowDoesNotAcceptFocus)
        self.setAttribute(Qt.WA_ShowWithoutActivating)
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.setWindowTitle(APP_DISPLAY_NAME)
        frame = QFrame(self)
        frame.setObjectName("popup")
        frame.setStyleSheet("#popup{border:1px solid palette(mid); border-radius:6px; background:palette(window);}")
        head = QLabel(f"<b>{title}</b>")
        body = QLabel(text)
        body.setWordWrap(True)
        body.setTextFormat(Qt.PlainText)
        body.setMaximumWidth(380)
        btns = QHBoxLayout()
        self.buttons: dict[str, QPushButton] = {}
        for key, label, *rest in actions:
            shortcut = rest[0] if rest else ""
            # the global shortcut is shown right on the button, so it is learnt by use
            b = QPushButton(f"{label}\n{shortcut}" if shortcut else label)
            if shortcut:
                b.setToolTip(f"{label} ({shortcut})")
            self.buttons[key] = b
            b.setFocusPolicy(Qt.NoFocus)
            b.clicked.connect(lambda _=False, k=key: self._choose(k))
            btns.addWidget(b)
        close = QPushButton(t("popup.ignore"))
        close.setFocusPolicy(Qt.NoFocus)
        close.clicked.connect(lambda: self._choose(""))
        btns.addStretch(1)
        btns.addWidget(close)
        fl = QVBoxLayout(frame)
        fl.addWidget(head)
        fl.addWidget(body)
        fl.addLayout(btns)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(frame)
        self._done = False
        if timeout_s > 0:
            QTimer.singleShot(timeout_s * 1000, lambda: self._choose(""))

    def _choose(self, key: str):
        if self._done:
            return
        self._done = True
        self.chosen.emit(key)
        self.close()

    def show_near_tray(self):
        self.adjustSize()
        screen = QGuiApplication.primaryScreen()
        if screen is not None:
            geo = screen.availableGeometry()
            self.move(geo.right() - self.width() - 16, geo.bottom() - self.height() - 16)
        self.show()
