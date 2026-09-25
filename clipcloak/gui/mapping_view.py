"""Overview of all original <-> surrogate mappings of the active session/project."""

from __future__ import annotations

import csv

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
                               QMessageBox, QPushButton, QVBoxLayout, QWidget)

from ..i18n import t
from .history_view import fmt_time
from .widgets import is_dark, item, make_table, type_color


class MappingView(QWidget):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.c = controller
        self.title = QLabel("")
        self.filter = QLineEdit()
        self.filter.setPlaceholderText(t("map.filter"))
        self.type = QComboBox()
        self.hide = QCheckBox(t("map.hide_originals"))
        self.table = make_table([t("col.type"), t("col.original"), t("col.surrogate"), t("col.count"),
                                 t("col.first_seen"), t("col.last_seen")])
        self.table.setSortingEnabled(True)
        self.btn_remove = QPushButton(t("map.remove"))
        self.btn_export = QPushButton(t("map.export"))
        self.btn_clear = QPushButton(t("map.clear"))
        top = QHBoxLayout()
        top.addWidget(self.title, 1)
        top.addWidget(self.filter, 1)
        top.addWidget(self.type)
        top.addWidget(self.hide)
        btns = QHBoxLayout()
        btns.addWidget(self.btn_remove)
        btns.addWidget(self.btn_export)
        btns.addStretch(1)
        btns.addWidget(self.btn_clear)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(self.table, 1)
        lay.addLayout(btns)
        self.filter.textChanged.connect(self.refresh)
        self.type.currentIndexChanged.connect(self.refresh)
        self.hide.toggled.connect(self.refresh)
        self.btn_remove.clicked.connect(self._remove)
        self.btn_export.clicked.connect(self._export)
        self.btn_clear.clicked.connect(self._clear)
        self.c.mappings_changed.connect(self.refresh)
        self.refresh()

    def _rows(self):
        return sorted(self.c.engine.vault.rows(), key=lambda e: (e.type, e.original.lower()))

    def refresh(self):
        v = self.c.engine.vault
        self.title.setText(t("map.title", name=self.c.project_label()))
        rows = self._rows()
        types = sorted({r.type for r in rows})
        cur = self.type.currentData()
        self.type.blockSignals(True)
        self.type.clear()
        self.type.addItem(t("map.all_types"), "")
        for ty in types:
            self.type.addItem(ty, ty)
        idx = self.type.findData(cur) if cur else 0
        self.type.setCurrentIndex(max(idx, 0))
        self.type.blockSignals(False)
        flt = self.filter.text().lower()
        want = self.type.currentData()
        rows = [r for r in rows if (not want or r.type == want)
                and (not flt or flt in r.original.lower() or flt in r.surrogate.lower())]
        dark = is_dark(self)
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            orig = "•" * min(len(r.original), 12) if self.hide.isChecked() else r.original
            self.table.setItem(i, 0, item(r.type, data=(r.type, r.original), color=type_color(r.type, dark)))
            self.table.setItem(i, 1, item(orig))
            self.table.setItem(i, 2, item(r.surrogate))
            self.table.setItem(i, 3, item(r.count if r.count else ""))
            self.table.setItem(i, 4, item(fmt_time(r.first_seen)))
            self.table.setItem(i, 5, item(fmt_time(r.last_seen)))
        self.table.setSortingEnabled(True)
        self.table.resizeColumnsToContents()
        _ = v

    def _selected_keys(self):
        keys = []
        for r in sorted({i.row() for i in self.table.selectedItems()}):
            it = self.table.item(r, 0)
            if it:
                keys.append(it.data(Qt.UserRole))
        return keys

    def _remove(self):
        keys = self._selected_keys()
        if not keys:
            return
        self.c.remove_mappings(keys)

    def _export(self):
        path, _ = QFileDialog.getSaveFileName(self, t("map.export"), "mappings.csv", "CSV (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh, delimiter=";")
            w.writerow(["type", "original", "surrogate", "count", "first_seen", "last_seen"])
            for r in self._rows():
                w.writerow([r.type, r.original, r.surrogate, r.count, fmt_time(r.first_seen), fmt_time(r.last_seen)])

    def _clear(self):
        if QMessageBox.question(self, t("map.clear"), t("map.clear_confirm")) == QMessageBox.Yes:
            self.c.clear_mappings()
