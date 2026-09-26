"""Main window: workbench, history and mapping overview in tabs."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel, QMainWindow, QProgressBar, QTabWidget, QVBoxLayout, QWidget

from .. import __version__
from ..i18n import t
from ..meta import APP_DISPLAY_NAME
from . import icons
from .project_bar import ProjectBar, fill_project_menu
from .history_view import HistoryView
from .image_view import ImageView
from .log_view import LogView
from .mapping_view import MappingView
from .workbench import Workbench

TABS = ["workbench", "image", "history", "mappings", "log"]


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
        self.image = ImageView(controller)
        self.tabs.addTab(self.workbench, t("tab.workbench"))
        self.tabs.addTab(self.image, t("tab.image"))
        self.tabs.addTab(self.history, t("tab.history"))
        self.tabs.addTab(self.mappings, t("tab.mappings"))
        self.log = LogView(controller.log_handler)
        self.tabs.addTab(self.log, t("tab.log"))
        # activity indicator (right side of the status bar)
        self.busy_label = QLabel("")
        self.busy_bar = QProgressBar()
        self.busy_bar.setRange(0, 0)          # indeterminate animation
        self.busy_bar.setMaximumWidth(120)
        self.busy_bar.setMaximumHeight(14)
        self.busy_bar.setTextVisible(False)
        self.statusBar().addPermanentWidget(self.busy_label)
        self.statusBar().addPermanentWidget(self.busy_bar)
        self.project_bar = ProjectBar(controller)
        central = QWidget()
        cl = QVBoxLayout(central)
        cl.setContentsMargins(6, 6, 6, 0)
        cl.addWidget(self.project_bar)
        cl.addWidget(self.tabs, 1)
        self.setCentralWidget(central)
        m = self.menuBar()
        f = m.addMenu(t("menu.file"))
        f.addAction(t("file.menu")).triggered.connect(lambda: controller.process_file())
        f.addSeparator()
        f.addAction(t("tray.settings")).triggered.connect(controller.show_settings)
        f.addSeparator()
        f.addAction(t("menu.close")).triggered.connect(self.close)
        f.addAction(t("tray.quit")).triggered.connect(controller.quit)
        self.project_menu = m.addMenu(t("tray.project"))
        self.project_menu.aboutToShow.connect(lambda: fill_project_menu(self.project_menu, controller))
        fill_project_menu(self.project_menu, controller)
        h = m.addMenu(t("menu.help"))
        h.addAction(t("tray.about")).triggered.connect(controller.show_about)
        self.update_status()
        self.update_activity()
        st = controller.ui_state
        st.track("main/geometry", self)
        tab = str(st.value("main/tab", "workbench"))
        if tab in TABS:
            self.select(tab)

    def save_state(self):
        st = self.c.ui_state
        st.set_value("main/tab", TABS[self.tabs.currentIndex()])
        st.save()

    def select(self, tab: str):
        if tab in TABS:
            self.tabs.setCurrentIndex(TABS.index(tab))

    def update_activity(self):
        jobs = self.c.active_jobs()
        self.busy_label.setText(t("status.busy", what=", ".join(jobs)) if jobs else t("status.idle"))
        self.busy_bar.setVisible(bool(jobs))

    def update_status(self):
        self.project_bar.refresh()
        wm = t("watch." + (self.c.cfg.get("watcher.mode") or "off"))
        self.statusBar().showMessage(t("tray.tooltip", project=self.c.project_label(), watch=wm))

    def closeEvent(self, ev):
        self.save_state()
        if self.c.tray_available():
            ev.ignore()
            self.hide()
        else:
            ev.accept()
            self.c.quit()
