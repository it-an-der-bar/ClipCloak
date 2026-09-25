"""System tray icon and menu."""

from __future__ import annotations

from PySide6.QtGui import QAction, QActionGroup
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from ..i18n import t
from ..meta import APP_DISPLAY_NAME
from . import icons
from .language_menu import add_language_menu

WATCH_MODES = ["off", "notify", "critical", "always"]


class Tray(QSystemTrayIcon):
    def __init__(self, controller):
        super().__init__(icons.icon("idle"))
        self.c = controller
        self.menu = QMenu()
        self.menu.aboutToShow.connect(self.rebuild)
        self.setContextMenu(self.menu)
        self.activated.connect(self._activated)
        self.rebuild()
        self.update_state()

    def _activated(self, reason):
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.c.show_main()

    def _hk(self, action):
        seq = self.c.cfg.get("hotkeys." + action) or ""
        return f"\t{seq}" if seq and action not in self.c.hotkey_errors else ""

    def rebuild(self):
        m = self.menu
        m.clear()
        head = m.addAction(f"{APP_DISPLAY_NAME} – {self.c.project_label()}")
        head.setEnabled(False)
        m.addSeparator()
        for action in ("pseudonymize", "anonymize", "redact", "revert"):
            a = m.addAction(t("action." + action) + self._hk(action))
            a.triggered.connect(lambda _=False, x=action: self.c.run_action(x, "tray"))
        if self.c.cfg.get("llm.enabled"):
            a = m.addAction(t("action.screenshot") + self._hk("screenshot"))
            a.triggered.connect(lambda: self.c.run_action("screenshot", "tray"))
        m.addSeparator()

        mode_menu = m.addMenu(t("tray.default_mode"))
        grp = QActionGroup(mode_menu)
        cur = self.c.cfg.get("general.mode")
        for mode in ("pseudonymize", "anonymize", "redact"):
            a = QAction(t("mode." + mode), mode_menu, checkable=True)
            a.setChecked(mode == cur)
            a.triggered.connect(lambda _=False, x=mode: self.c.set_default_mode(x))
            grp.addAction(a)
            mode_menu.addAction(a)

        watch_menu = m.addMenu(t("tray.watcher"))
        grp2 = QActionGroup(watch_menu)
        wm = self.c.cfg.get("watcher.mode")
        for mode in WATCH_MODES:
            a = QAction(t("watch." + mode), watch_menu, checkable=True)
            a.setChecked(mode == wm)
            a.setEnabled(mode == "off" or self.c.clip_can_watch())
            a.triggered.connect(lambda _=False, x=mode: self.c.set_watch_mode(x))
            grp2.addAction(a)
            watch_menu.addAction(a)
        watch_menu.addSeparator()
        if self.c.is_paused():
            a = watch_menu.addAction(t("tray.resume"))
            a.triggered.connect(lambda: self.c.pause(0))
        else:
            for minutes in (5, 15, 60):
                a = watch_menu.addAction(t("tray.pause", n=minutes))
                a.triggered.connect(lambda _=False, n=minutes: self.c.pause(n))

        prj_menu = m.addMenu(t("tray.project"))
        grp3 = QActionGroup(prj_menu)
        a = QAction(t("project.session"), prj_menu, checkable=True)
        a.setChecked(self.c.project is None)
        a.triggered.connect(lambda: self.c.open_project(None))
        grp3.addAction(a)
        prj_menu.addAction(a)
        for info in self.c.store.list():
            label = info.name + ("  🔒" if info.encrypted else "")
            a = QAction(label, prj_menu, checkable=True)
            a.setChecked(self.c.project is not None and self.c.project.name == info.name)
            a.triggered.connect(lambda _=False, n=info.name: self.c.open_project(n))
            grp3.addAction(a)
            prj_menu.addAction(a)
        prj_menu.addSeparator()
        prj_menu.addAction(t("project.new")).triggered.connect(self.c.new_project)
        if self.c.project is not None:
            prj_menu.addAction(t("project.delete")).triggered.connect(self.c.delete_project)
        else:
            prj_menu.addAction(t("project.clear_session")).triggered.connect(self.c.clear_mappings_confirm)

        m.addSeparator()
        m.addAction(t("tray.workbench") + self._hk("workbench")).triggered.connect(lambda: self.c.show_main("workbench"))
        m.addAction(t("tray.history")).triggered.connect(lambda: self.c.show_main("history"))
        m.addAction(t("tray.mappings")).triggered.connect(lambda: self.c.show_main("mappings"))
        m.addAction(t("tray.settings")).triggered.connect(self.c.show_settings)
        add_language_menu(m, self.c)
        m.addAction(t("tray.about")).triggered.connect(self.c.show_about)
        m.addSeparator()
        m.addAction(t("tray.quit")).triggered.connect(self.c.quit)

    def update_state(self, busy: bool = False):
        if busy:
            state = "busy"
        elif self.c.is_paused():
            state = "paused"
        else:
            wm = self.c.cfg.get("watcher.mode")
            state = {"off": "idle", "notify": "watch", "critical": "critical", "always": "watch"}.get(wm, "idle")
        self.setIcon(icons.icon(state))
        wm = t("watch." + (self.c.cfg.get("watcher.mode") or "off"))
        self.setToolTip(f"{APP_DISPLAY_NAME}\n{t('tray.tooltip', project=self.c.project_label(), watch=wm)}")
