"""Regression: the application must exit cleanly (no crash in Qt/PySide teardown)."""

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from clipcloak.meta import APP_NAME

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = textwrap.dedent("""
    import sys
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication
    app = QApplication([])
    app.setQuitOnLastWindowClosed(False)
    from {pkg}.config import Config
    from {pkg} import paths
    from {pkg}.gui.app import Controller
    from {pkg}.gui.settings_dialog import SettingsDialog
    cfg = Config.load(paths.config_file())
    cfg.set("hotkeys", {{k: "" for k in cfg.get("hotkeys")}})
    c = Controller(app, cfg)
    c.start(show_window=True)
    def step():
        c.clip.write("x 10.1.2.3", "<b>x 10.1.2.3</b>")
        c.run_action("pseudonymize", "test")
        d = SettingsDialog(c)
        QTimer.singleShot(200, d.reject)
        d.exec()
        c.show_main("history")
        QTimer.singleShot(200, c.show_settings)     # quit while a modal dialog is open
        QTimer.singleShot(900, c.quit)
    QTimer.singleShot(200, step)
    sys.exit(app.exec())
""")


class ExitTest(unittest.TestCase):
    def test_clean_exit(self):
        tmp = tempfile.mkdtemp()
        pre = APP_NAME.upper().replace("-", "_")
        env = dict(os.environ, PYTHONPATH=str(ROOT), **{pre + "_CONFIG_DIR": tmp + "/c", pre + "_DATA_DIR": tmp + "/d"})
        env.setdefault("QT_QPA_PLATFORM", "offscreen")
        r = subprocess.run([sys.executable, "-c", SCRIPT.format(pkg=APP_NAME)], env=env, cwd=str(ROOT),
                           capture_output=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr.decode(errors="replace")[-2000:])


if __name__ == "__main__":
    unittest.main()
