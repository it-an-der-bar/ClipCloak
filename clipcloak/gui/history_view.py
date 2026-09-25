"""History list with side-by-side diff of every processed clipboard content."""

from __future__ import annotations

import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QMessageBox, QPushButton, QSplitter,
                               QVBoxLayout, QWidget)

from ..i18n import t
from .widgets import DiffView, fill_replacements, is_dark, item, make_table, replacements_table


def fmt_time(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


class HistoryView(QWidget):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.c = controller
        self.table = make_table([t("col.time"), t("col.action"), t("col.source"), t("col.project"),
                                 t("col.changes"), t("col.preview")])
        self.table.itemSelectionChanged.connect(self._selected)
        self.diff = DiffView()
        self.reps = replacements_table()
        self.warn = QLabel("")
        self.warn.setWordWrap(True)
        self.warn.setStyleSheet("color:#c0392b")
        self.btn_copy_out = QPushButton(t("hist.copy_output"))
        self.btn_copy_in = QPushButton(t("hist.copy_input"))
        self.btn_workbench = QPushButton(t("hist.to_workbench"))
        self.btn_delete = QPushButton(t("hist.delete"))
        self.btn_clear = QPushButton(t("hist.clear"))
        for b in (self.btn_copy_out, self.btn_copy_in, self.btn_workbench, self.btn_delete):
            b.setEnabled(False)
        self.btn_copy_out.clicked.connect(lambda: self._copy(False))
        self.btn_copy_in.clicked.connect(lambda: self._copy(True))
        self.btn_workbench.clicked.connect(self._to_workbench)
        self.btn_delete.clicked.connect(self._delete)
        self.btn_clear.clicked.connect(self._clear)

        detail = QWidget()
        dl = QVBoxLayout(detail)
        dl.setContentsMargins(0, 0, 0, 0)
        dl.addWidget(self.diff, 3)
        dl.addWidget(self.warn)
        dl.addWidget(self.reps, 1)
        split = QSplitter(Qt.Vertical)
        split.addWidget(self.table)
        split.addWidget(detail)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 3)
        btns = QHBoxLayout()
        for b in (self.btn_copy_out, self.btn_copy_in, self.btn_workbench, self.btn_delete):
            btns.addWidget(b)
        btns.addStretch(1)
        btns.addWidget(self.btn_clear)
        lay = QVBoxLayout(self)
        lay.addWidget(split, 1)
        lay.addLayout(btns)
        self.c.history_changed.connect(self.refresh)
        self.refresh()

    def refresh(self):
        entries = list(self.c.history.entries)
        sel = self._current_id()
        self.table.setRowCount(len(entries))
        for i, e in enumerate(entries):
            preview = e.output.replace("\n", " ⏎ ")[:120]
            self.table.setItem(i, 0, item(fmt_time(e.timestamp), data=e.id))
            self.table.setItem(i, 1, item(t("mode." + e.action) if e.action else ""))
            self.table.setItem(i, 2, item(t("source." + e.source) if e.source else ""))
            self.table.setItem(i, 3, item(e.project or t("project.session")))
            self.table.setItem(i, 4, item(len(e.replacements)))
            self.table.setItem(i, 5, item(preview))
        self.table.resizeColumnsToContents()
        if sel is not None:
            for i, e in enumerate(entries):
                if e.id == sel:
                    self.table.selectRow(i)
                    break
        if not entries:
            self.diff.clear()
            self.reps.setRowCount(0)
            self.warn.clear()

    def _current_id(self):
        rows = {i.row() for i in self.table.selectedItems()}
        if len(rows) != 1:
            return None
        it = self.table.item(rows.pop(), 0)
        return it.data(Qt.UserRole) if it else None

    def _selected(self):
        eid = self._current_id()
        e = self.c.history.get(eid) if eid is not None else None
        for b in (self.btn_copy_out, self.btn_copy_in, self.btn_workbench, self.btn_delete):
            b.setEnabled(e is not None)
        if e is None:
            return
        if e.action == "revert":
            self.diff.left_label.setText(t("diff.pseudonymised"))
            self.diff.right_label.setText(t("diff.restored"))
        else:
            self.diff.left_label.setText(t("diff.before"))
            self.diff.right_label.setText(t("diff.after"))
        self.diff.show_diff(e.input, e.output, e.replacements)
        fill_replacements(self.reps, e.replacements, is_dark(self))
        self.warn.setText("\n".join(e.warnings))

    def _copy(self, original: bool):
        e = self.c.history.get(self._current_id())
        if e:
            self.c.write_clipboard(e.input if original else e.output, None)

    def _to_workbench(self):
        e = self.c.history.get(self._current_id())
        if e:
            self.c.show_workbench(e.input)

    def _delete(self):
        eid = self._current_id()
        if eid is not None:
            self.c.history.remove(eid)

    def _clear(self):
        if QMessageBox.question(self, t("hist.clear"), t("hist.clear_confirm")) == QMessageBox.Yes:
            self.c.history.clear()
