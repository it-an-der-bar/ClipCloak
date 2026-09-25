"""Main window: workbench, history and mapping overview in tabs."""

from __future__ import annotations

from PySide6.QtWidgets import QMainWindow, QTabWidget

from .. import __version__
from ..i18n import LANGUAGES, t
from ..meta import APP_DISPLAY_NAME
from . import icons
from .language_menu import add_language_menu
from .history_view import HistoryView
from .mapping_view import MappingView
from .workbench import Workbench

TABS = ["workbench", "history", "mappings"]


class MainWindow(QMainWindow):
    def __init__(self, controller):
        super().__init__()
        self.c = controller
        self.setWindowTitle(f"{APP_DISPLAY_NAME} {__version__}")
        self.setWindowIcon(icons.icon())
        self.resize(1180, 760)
        self.tabs = QTabWidget()
        self.workbench = Workbench(controller)
        self.history = HistoryView(controller)
        self.mappings = MappingView(controller)
        self.tabs.addTab(self.workbench, t("tab.workbench"))
        self.tabs.addTab(self.history, t("tab.history"))
        self.tabs.addTab(self.mappings, t("tab.mappings"))
        self.setCentralWidget(self.tabs)
        m = self.menuBar()
        f = m.addMenu(t("menu.file"))
        f.addAction(t("tray.settings")).triggered.connect(controller.show_settings)
        f.addSeparator()
        f.addAction(t("menu.close")).triggered.connect(self.close)
        f.addAction(t("tray.quit")).triggered.connect(controller.quit)
        self.lang_menu = add_language_menu(m, controller)
        self.lang_menu.aboutToShow.connect(self._sync_language_checks)
        h = m.addMenu(t("menu.help"))
        h.addAction(t("tray.about")).triggered.connect(controller.show_about)
        self.update_status()

    def _sync_language_checks(self):
        cur = self.c.cfg.get("general.language", "auto")
        codes = ["auto"] + list(LANGUAGES)
        for a, code in zip(self.lang_menu.actions(), codes):
            a.setChecked(code == cur)

    def select(self, tab: str):
        if tab in TABS:
            self.tabs.setCurrentIndex(TABS.index(tab))

    def update_status(self):
        wm = t("watch." + (self.c.cfg.get("watcher.mode") or "off"))
        self.statusBar().showMessage(t("tray.tooltip", project=self.c.project_label(), watch=wm))

    def closeEvent(self, ev):
        if self.c.tray_available():
            ev.ignore()
            self.hide()
        else:
            ev.accept()
            self.c.quit()
