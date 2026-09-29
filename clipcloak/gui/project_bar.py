"""Project management in the main window (selector bar + menu), shared with the tray."""

from __future__ import annotations

from PySide6.QtGui import QAction, QActionGroup
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QPushButton, QWidget

from ..i18n import t

RAM = "\x00ram"   # combo item data for "RAM only"


def protection_label(protection: str) -> str:
    return t({"passphrase": "project.enc_passphrase", "dpapi": "project.enc_dpapi",
              "secret-service": "project.enc_keyring"}.get(protection,
                                                                                     "project.not_encrypted"))


def fill_project_menu(menu, controller) -> None:
    """(Re)build a project menu: RAM only, all projects, new / settings / delete."""
    menu.clear()
    grp = QActionGroup(menu)
    a = QAction(t("project.session"), menu, checkable=True)
    a.setChecked(controller.project is None)
    a.triggered.connect(lambda: controller.open_project(None))
    grp.addAction(a)
    menu.addAction(a)
    for info in controller.store.list():
        label = info.name + ("  🔒" if info.encrypted else "")
        a = QAction(label, menu, checkable=True)
        a.setChecked(controller.project is not None and controller.project.name == info.name)
        a.triggered.connect(lambda _=False, n=info.name: controller.open_project(n))
        grp.addAction(a)
        menu.addAction(a)
    menu.addSeparator()
    menu.addAction(t("project.new")).triggered.connect(controller.new_project)
    if controller.project is not None:
        menu.addAction(t("project.settings")).triggered.connect(lambda: controller.show_settings("project"))
        menu.addAction(t("project.delete")).triggered.connect(controller.delete_project)
    else:
        menu.addAction(t("project.clear_session")).triggered.connect(controller.clear_mappings_confirm)


class ProjectBar(QWidget):
    """Always visible: which project is active, switch, create, configure, delete."""

    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.c = controller
        self.combo = QComboBox()
        self.combo.setMinimumWidth(220)
        self.info = QLabel("")
        self.btn_new = QPushButton(t("project.new"))
        self.btn_settings = QPushButton(t("project.settings"))
        self.btn_delete = QPushButton(t("project.delete"))
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(QLabel("<b>" + t("tray.project") + ":</b>"))
        lay.addWidget(self.combo)
        lay.addWidget(self.info)
        lay.addStretch(1)
        for b in (self.btn_new, self.btn_settings, self.btn_delete):
            lay.addWidget(b)
        self.combo.activated.connect(self._chosen)
        self.btn_new.clicked.connect(self.c.new_project)
        self.btn_settings.clicked.connect(lambda: self.c.show_settings("project"))
        self.btn_delete.clicked.connect(self.c.delete_project)
        self.refresh()

    def refresh(self):
        self.combo.blockSignals(True)
        self.combo.clear()
        self.combo.addItem(t("project.session"), RAM)
        current = 0
        for info in self.c.store.list():
            self.combo.addItem(info.name + ("  🔒" if info.encrypted else ""), info.name)
            if self.c.project is not None and self.c.project.name == info.name:
                current = self.combo.count() - 1
        self.combo.setCurrentIndex(current)
        self.combo.blockSignals(False)
        prj = self.c.project
        if prj is None:
            self.info.setText(t("project.info_ram"))
            self.info.setStyleSheet("color:#c0392b")
        else:
            self.info.setText(t("project.info_saved", n=len(prj.vault.entries), enc=protection_label(prj.protection)))
            self.info.setStyleSheet("" if prj.encrypted else "color:#c0392b")
            self.info.setToolTip(t("project.protection_tip." + (prj.protection if prj.protection in
                                                                 ("passphrase", "dpapi", "secret-service")
                                                                 else "none").replace("secret-service", "keyring")))
        self.btn_settings.setEnabled(prj is not None)
        self.btn_delete.setEnabled(prj is not None)

    def _chosen(self, index: int):
        data = self.combo.itemData(index)
        ok = self.c.open_project(None if data == RAM else data, self.window())
        if not ok:
            self.refresh()
