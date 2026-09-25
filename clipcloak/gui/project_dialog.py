"""Dialogs for creating and opening projects."""

from __future__ import annotations

from PySide6.QtWidgets import (QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QInputDialog,
                               QLabel, QLineEdit, QVBoxLayout)

from ..i18n import t


class NewProjectDialog(QDialog):
    def __init__(self, existing: set[str], parent=None):
        super().__init__(parent)
        self.existing = {e.lower() for e in existing}
        self.setWindowTitle(t("project.new_title"))
        self.name = QLineEdit()
        self.pw1 = QLineEdit(echoMode=QLineEdit.Password)
        self.pw2 = QLineEdit(echoMode=QLineEdit.Password)
        self.history = QCheckBox(t("settings.project_store_history"))
        self.history.setChecked(True)
        self.err = QLabel("")
        self.err.setStyleSheet("color:#c0392b")
        hint = QLabel(t("project.passphrase_hint"))
        hint.setWordWrap(True)
        f = QFormLayout()
        f.addRow(t("project.name"), self.name)
        f.addRow(t("project.passphrase"), self.pw1)
        f.addRow(t("project.passphrase2"), self.pw2)
        f.addRow("", self.history)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._ok)
        bb.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addLayout(f)
        lay.addWidget(hint)
        lay.addWidget(self.err)
        lay.addWidget(bb)

    def _ok(self):
        name = self.name.text().strip()
        if not name:
            self.err.setText(t("project.err_name"))
            return
        if name.lower() in self.existing:
            self.err.setText(t("project.err_exists"))
            return
        if self.pw1.text() != self.pw2.text():
            self.err.setText(t("project.err_mismatch"))
            return
        self.accept()

    def values(self) -> tuple[str, str | None, bool]:
        return self.name.text().strip(), (self.pw1.text() or None), self.history.isChecked()


def ask_passphrase(parent, name: str) -> str | None:
    pw, ok = QInputDialog.getText(parent, t("project.open_title"), t("project.enter_passphrase", name=name),
                                  QLineEdit.Password)
    return pw if ok else None
