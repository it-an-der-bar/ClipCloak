"""Reusable widgets: side-by-side diff with highlighted replacements, tables."""

from __future__ import annotations

import hashlib
import html

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QFontDatabase
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView, QLabel, QTableWidget,
                               QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget)

from ..core.entities import Replacement
from ..i18n import t

PALETTE = ["#ffd8a8", "#c3fae8", "#d0ebff", "#e5dbff", "#ffc9c9", "#d3f9d8", "#fff3bf",
           "#ffdeeb", "#dbe4ff", "#c5f6fa", "#e9fac8", "#f3d9fa"]
PALETTE_DARK = ["#7a4a12", "#0b5345", "#16456e", "#4a3780", "#7d2626", "#1f5d2c", "#6b5a00",
                "#6d2146", "#2c3f7a", "#0d5460", "#46600f", "#5e2a6e"]


def type_color(typ: str, dark: bool = False) -> str:
    idx = int(hashlib.md5(typ.encode()).hexdigest(), 16) % len(PALETTE)
    return (PALETTE_DARK if dark else PALETTE)[idx]


def is_dark(widget: QWidget) -> bool:
    return widget.palette().color(widget.backgroundRole()).lightness() < 128


def mono_font() -> QFont:
    f = QFontDatabase.systemFont(QFontDatabase.FixedFont)
    return f


def highlighted_html(text: str, spans: list[tuple[int, int, str]], dark: bool) -> str:
    out, pos = [], 0
    for s, e, typ in sorted(spans):
        if s < pos:
            continue
        out.append(html.escape(text[pos:s]))
        out.append(f'<span style="background-color:{type_color(typ, dark)}">{html.escape(text[s:e])}</span>')
        pos = e
    out.append(html.escape(text[pos:]))
    body = "".join(out).replace("\n", "<br>")
    return f'<div style="white-space:pre-wrap">{body}</div>'


class DiffView(QWidget):
    """Input and output side by side, replacements highlighted in both."""

    def __init__(self, parent=None, left_title: str | None = None, right_title: str | None = None):
        super().__init__(parent)
        self.left = QTextEdit(readOnly=True)
        self.right = QTextEdit(readOnly=True)
        for ed in (self.left, self.right):
            ed.setFont(mono_font())
            ed.setLineWrapMode(QTextEdit.WidgetWidth)
        self.left_label = QLabel(left_title or t("diff.before"))
        self.right_label = QLabel(right_title or t("diff.after"))
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        for lab, ed in ((self.left_label, self.left), (self.right_label, self.right)):
            col = QVBoxLayout()
            col.addWidget(lab)
            col.addWidget(ed)
            lay.addLayout(col)
        self._sync = False
        self.left.verticalScrollBar().valueChanged.connect(lambda v: self._mirror(self.left, self.right))
        self.right.verticalScrollBar().valueChanged.connect(lambda v: self._mirror(self.right, self.left))

    def _mirror(self, src: QTextEdit, dst: QTextEdit):
        if self._sync:
            return
        self._sync = True
        sb, db = src.verticalScrollBar(), dst.verticalScrollBar()
        if sb.maximum() > 0:
            db.setValue(int(sb.value() / sb.maximum() * db.maximum()))
        self._sync = False

    def show_diff(self, before: str, after: str, reps: list[Replacement]):
        dark = is_dark(self)
        self.left.setHtml(highlighted_html(before, [(r.in_start, r.in_end, r.type) for r in reps], dark))
        self.right.setHtml(highlighted_html(after, [(r.out_start, r.out_end, r.type) for r in reps], dark))

    def clear(self):
        self.left.clear()
        self.right.clear()


def make_table(headers: list[str]) -> QTableWidget:
    tbl = QTableWidget(0, len(headers))
    tbl.setHorizontalHeaderLabels(headers)
    tbl.setSelectionBehavior(QAbstractItemView.SelectRows)
    tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)
    tbl.verticalHeader().setVisible(False)
    tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
    tbl.horizontalHeader().setStretchLastSection(True)
    tbl.setAlternatingRowColors(True)
    tbl.setWordWrap(False)
    return tbl


def item(text, data=None, color: str | None = None) -> QTableWidgetItem:
    it = QTableWidgetItem("" if text is None else str(text))
    if data is not None:
        it.setData(Qt.UserRole, data)
    if color:
        it.setBackground(QColor(color))
    return it


def replacements_table() -> QTableWidget:
    return make_table([t("col.type"), t("col.original"), t("col.replacement"), t("col.detector")])


def fill_replacements(tbl: QTableWidget, reps: list[Replacement], dark: bool = False):
    tbl.setRowCount(0)
    tbl.setRowCount(len(reps))
    for i, r in enumerate(reps):
        tbl.setItem(i, 0, item(r.type, color=type_color(r.type, dark)))
        tbl.setItem(i, 1, item(r.original))
        tbl.setItem(i, 2, item(r.replacement))
        tbl.setItem(i, 3, item(r.detector))
    tbl.resizeColumnsToContents()
