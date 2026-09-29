"""Single-instance guard and command channel (``<app> --action revert``)."""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import sys

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtNetwork import QLocalServer, QLocalSocket

from ..meta import APP_ID


def server_name() -> str:
    try:
        user = getpass.getuser()
    except Exception:  # pragma: no cover
        user = "user"
    name = APP_ID + "-" + hashlib.sha1(user.encode(), usedforsecurity=False).hexdigest()[:10]
    # Linux: the socket goes into the per-user runtime folder (0700) instead of /tmp, so no
    # other account can take the name first
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if sys.platform.startswith("linux") and runtime and os.path.isdir(runtime):
        return os.path.join(runtime, name)
    return name


def send_command(command: dict, timeout_ms: int = 1500) -> bool:
    """Send a command to a running instance. Returns False if none is running."""
    sock = QLocalSocket()
    sock.connectToServer(server_name())
    if not sock.waitForConnected(timeout_ms):
        return False
    sock.write((json.dumps(command) + "\n").encode("utf-8"))
    sock.flush()
    sock.waitForBytesWritten(timeout_ms)
    sock.waitForReadyRead(timeout_ms)
    sock.disconnectFromServer()
    return True


class InstanceServer(QObject):
    command = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.server = QLocalServer(self)
        self.server.setSocketOptions(QLocalServer.UserAccessOption)
        self.server.newConnection.connect(self._on_connection)

    def listen(self) -> bool:
        name = server_name()
        if self.server.listen(name):
            return True
        # stale socket from a crashed instance?
        probe = QLocalSocket()
        probe.connectToServer(name)
        if probe.waitForConnected(300):
            probe.disconnectFromServer()
            return False
        QLocalServer.removeServer(name)
        return self.server.listen(name)

    def _on_connection(self):
        while self.server.hasPendingConnections():
            sock = self.server.nextPendingConnection()
            sock.readyRead.connect(lambda s=sock: self._read(s))
            sock.disconnected.connect(sock.deleteLater)

    def _read(self, sock: QLocalSocket):
        commands = []
        try:
            while sock.canReadLine():
                line = bytes(sock.readLine().data()).decode("utf-8", "replace").strip()
                if not line:
                    continue
                try:
                    cmd = json.loads(line)
                except ValueError:
                    continue
                if isinstance(cmd, dict):
                    sock.write(b"ok\n")
                    sock.flush()
                    commands.append(cmd)
        except RuntimeError:   # socket already deleted
            return
        # run actions from the main loop, never inside the socket slot: an action
        # may open a modal dialog while the socket gets deleted underneath
        for cmd in commands:
            QTimer.singleShot(0, lambda c=cmd: self.command.emit(c))

    def close(self):
        self.server.close()
