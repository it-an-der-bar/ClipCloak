"""Workbench: paste text, see findings live, process/revert manually."""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (QCheckBox, QFileDialog, QHBoxLayout, QLabel, QMenu, QPlainTextEdit, QPushButton,
                               QSplitter, QTextEdit, QVBoxLayout, QWidget)

from ..core.entities import Result
from ..core.files import read_text_file, suggest_output_path, write_text_file
from ..i18n import t
from .widgets import (autosize, fill_replacements, group_by, highlighted_html, is_dark, item, make_table,
                      mono_font, replacements_table, track_table, type_color)

MODES = ["pseudonymize", "anonymize", "redact", "revert"]
LARGE_TEXT = 200_000   # above this, no colour highlighting (keeps the UI responsive)


def u16(text: str, index: int) -> int:
    """Python code point index -> Qt (UTF-16) position."""
    return len(text[:index].encode("utf-16-le")) // 2


class Workbench(QWidget):
    add_term = Signal(str, str)        # text, type
    add_allow = Signal(str)

    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.c = controller
        self.input = QPlainTextEdit()
        self.input.setFont(mono_font())
        self.input.setPlaceholderText(t("wb.input_placeholder"))
        self.output = QTextEdit(readOnly=True)
        self.output.setFont(mono_font())
        # one button per action; the configured default mode is the default button
        self.action_buttons: dict[str, QPushButton] = {}
        default_mode = controller.cfg.get("general.mode", "pseudonymize")
        for m in MODES:
            b = QPushButton(t("mode." + m) + "  →")
            seq = controller.cfg.get("hotkeys." + m) or ""
            b.setToolTip(t("wb.btn_tip." + m) + (f"  ({seq})" if seq else ""))
            b.clicked.connect(lambda _=False, x=m: self.run(x))
            if m == default_mode:
                b.setDefault(True)
            self.action_buttons[m] = b
        self.auto_copy = QCheckBox(t("wb.auto_copy"))
        self.auto_copy.setChecked(bool(controller.cfg.get("general.workbench_auto_copy", True)))
        if controller.cfg.is_locked("general.workbench_auto_copy"):
            self.auto_copy.setEnabled(False)
            self.auto_copy.setToolTip(t("settings.locked"))
        self.auto_copy.toggled.connect(self._auto_copy_toggled)
        self.btn_from = QPushButton(t("wb.from_clipboard"))
        self.btn_open = QPushButton(t("wb.open_file"))
        self.btn_save = QPushButton(t("wb.save_file"))
        self.btn_to = QPushButton(t("wb.to_clipboard"))
        self.btn_shot = QPushButton(t("wb.screenshot"))
        self.btn_check = QPushButton(t("wb.llm_check"))
        self.status = QLabel("")
        self.findings = make_table([t("col.type"), t("col.text"), t("col.times"), t("col.detector")])
        self.findings.setContextMenuPolicy(Qt.CustomContextMenu)
        self.findings.customContextMenuRequested.connect(self._findings_menu)
        self.input.setContextMenuPolicy(Qt.CustomContextMenu)
        self.input.customContextMenuRequested.connect(self._input_menu)
        self.findings.itemSelectionChanged.connect(self._select_finding)
        self.findings.cellDoubleClicked.connect(self._next_occurrence)
        self.findings.setToolTip(t("wb.findings_tip"))
        self.reps = replacements_table()

        # workflow left -> right: 1. input  |  2. action  |  3. result
        in_bar = QHBoxLayout()
        in_bar.addWidget(QLabel("<b>1. " + t("wb.input") + "</b>"))
        in_bar.addStretch(1)
        for b in (self.btn_open, self.btn_from, self.btn_shot):
            in_bar.addWidget(b)
        in_box, find_box = QWidget(), QWidget()
        ib = QVBoxLayout(in_box)
        ib.setContentsMargins(0, 0, 0, 0)
        ib.addLayout(in_bar)
        ib.addWidget(self.input, 1)
        fb = QVBoxLayout(find_box)
        fb.setContentsMargins(0, 0, 0, 0)
        fb.addWidget(QLabel(t("wb.findings")))
        fb.addWidget(self.findings, 1)
        self.left_split = QSplitter(Qt.Vertical)
        self.left_split.addWidget(in_box)
        self.left_split.addWidget(find_box)
        self.left_split.setChildrenCollapsible(False)
        left = self.left_split

        middle = QWidget()
        ml = QVBoxLayout(middle)
        ml.setContentsMargins(6, 0, 6, 0)
        ml.addWidget(QLabel("<b>2. " + t("wb.action") + "</b>"))
        for b in self.action_buttons.values():
            b.setMinimumHeight(34)
            ml.addWidget(b)
        ml.addStretch(1)
        middle.setMaximumWidth(max(b.sizeHint().width() for b in self.action_buttons.values()) + 24)

        out_bar = QHBoxLayout()
        out_bar.addWidget(QLabel("<b>3. " + t("wb.output") + "</b>"))
        out_bar.addStretch(1)
        for b in (self.btn_to, self.btn_save, self.btn_check):
            out_bar.addWidget(b)
        out_box, rep_box = QWidget(), QWidget()
        ob = QVBoxLayout(out_box)
        ob.setContentsMargins(0, 0, 0, 0)
        ob.addLayout(out_bar)
        ob.addWidget(self.auto_copy)
        ob.addWidget(self.output, 1)
        rb = QVBoxLayout(rep_box)
        rb.setContentsMargins(0, 0, 0, 0)
        rb.addWidget(QLabel(t("wb.replacements")))
        rb.addWidget(self.reps, 1)
        self.right_split = QSplitter(Qt.Vertical)
        self.right_split.addWidget(out_box)
        self.right_split.addWidget(rep_box)
        self.right_split.setChildrenCollapsible(False)
        right = self.right_split

        split = QSplitter(Qt.Horizontal)
        split.addWidget(left)
        split.addWidget(middle)
        split.addWidget(right)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 0)
        split.setStretchFactor(2, 1)
        split.setCollapsible(1, False)
        self.split = split
        st = getattr(controller, "ui_state", None)
        if st is not None:
            st.track("workbench/split", split)
            st.track("workbench/left", self.left_split, [360, 220])
            st.track("workbench/right", self.right_split, [360, 220])
        track_table(st, "workbench/findings", self.findings)
        track_table(st, "workbench/replacements", self.reps)

        lay = QVBoxLayout(self)
        lay.addWidget(split, 1)
        lay.addWidget(self.status)

        self._timer = QTimer(self, singleShot=True, interval=350)
        self._timer.timeout.connect(self.analyze)
        self.input.textChanged.connect(self._timer.start)
        self.btn_from.clicked.connect(self.from_clipboard)
        self.btn_open.clicked.connect(self.open_file)
        self.btn_save.clicked.connect(self.save_file)
        self.btn_to.clicked.connect(self.to_clipboard)
        self.btn_shot.clicked.connect(lambda: self.c.screenshot_to_text(target=self))
        self.btn_check.clicked.connect(self.llm_check)
        self._findings = []
        self.pseudonymised = 0
        self._occurrences: dict = {}
        self._next_occ: dict = {}
        self._last: Result | None = None
        self.refresh_llm_buttons()

    def refresh_llm_buttons(self):
        on = bool(self.c.cfg.get("llm.enabled"))
        self.btn_shot.setEnabled(on)
        self.btn_check.setEnabled(on)
        tip = "" if on else t("wb.llm_disabled")
        self.btn_shot.setToolTip(tip)
        self.btn_check.setToolTip(tip)

    # ---------------------------------------------------------------- actions
    def set_text(self, text: str):
        self.input.setPlainText(text)
        self.analyze()

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, t("wb.open_file"))
        if not path:
            return
        try:
            text, enc = read_text_file(path)
        except OSError as exc:
            self.status.setText(t("msg.error", err=str(exc)))
            return
        self._file = (path, enc, "\r\n" in text)
        self.set_text(text)
        self.status.setText(t("wb.file_loaded", path=path, n=len(text)))

    def save_file(self):
        text = self._last.output if self._last is not None else ""
        if not text:
            self.status.setText(t("wb.nothing_to_save"))
            return
        src, enc, crlf = getattr(self, "_file", (None, "utf-8", False))
        if crlf:
            text = text.replace("\r\n", "\n").replace("\n", "\r\n")
        suggestion = suggest_output_path(src, self._last.mode) if src else ""
        path, _ = QFileDialog.getSaveFileName(self, t("wb.save_file"), suggestion)
        if not path:
            return
        try:
            write_text_file(path, text, enc)
        except OSError as exc:
            self.status.setText(t("msg.error", err=str(exc)))
            return
        self.status.setText(t("wb.file_saved", path=path))

    def from_clipboard(self):
        content = self.c.clip.read()
        if content.text is not None:
            self.set_text(content.text)
        else:
            self.status.setText(t("msg.no_text"))

    def to_clipboard(self):
        text = self.output.toPlainText()
        if text:
            self.c.write_clipboard(text, None, sensitive=getattr(self, "_last_mode", "") == "revert")
            self.status.setText(t("wb.copied"))

    def analyze(self):
        text = self.input.toPlainText()
        engine = self.c.engine

        def job():
            findings = engine.analyze(text)
            looks, reverted, _real = engine.surrogate_hint(text, findings)
            return findings, (len(reverted.replacements) if looks else 0)

        self.c.submit(job, self._show_findings, label=t("job.analyze"), quiet=len(text) < 200_000)

    def _mark_pseudonymised(self, n: int):
        """A pseudonymised result in the input: Revert becomes the default button."""
        self.pseudonymised = n
        default_mode = self.c.cfg.get("general.mode", "pseudonymize")
        for m, b in self.action_buttons.items():
            b.setDefault(m == ("revert" if n else default_mode))
        rb = self.action_buttons.get("revert")
        if rb is not None:
            rb.setStyleSheet("font-weight:bold;" if n else "")

    def _show_findings(self, result):
        findings, pseudo = result if isinstance(result, tuple) else (result, 0)
        self._mark_pseudonymised(pseudo)
        # one row per distinct value; all occurrences are highlighted in the text
        groups = group_by(findings, lambda f: (f.type, f.text.lower()))
        self._findings = [f for f, _n in groups]
        self._occurrences = {(f.type, f.text.lower()): [] for f in self._findings}
        for f in findings:
            self._occurrences[(f.type, f.text.lower())].append(f)
        self._next_occ: dict = {}
        dark = is_dark(self)
        self.findings.setRowCount(len(groups))
        for i, (f, n) in enumerate(groups):
            self.findings.setItem(i, 0, item(f.type, data=i, color=type_color(f.type, dark)))
            self.findings.setItem(i, 1, item(f.text))
            self.findings.setItem(i, 2, item(n))
            self.findings.setItem(i, 3, item(f.detector))
        autosize(self.findings)
        sels = []
        text = self.input.toPlainText()
        if len(text) > LARGE_TEXT:
            findings = []            # plain view for big files (table is still filled)
        for f in findings:
            sel = QTextEdit.ExtraSelection()
            fmt = QTextCharFormat()
            fmt.setBackground(QColor(type_color(f.type, dark)))
            sel.format = fmt
            cur = QTextCursor(self.input.document())
            cur.setPosition(u16(text, f.start))
            cur.setPosition(u16(text, f.end), QTextCursor.KeepAnchor)
            sel.cursor = cur
            sels.append(sel)
        self.input.setExtraSelections(sels)
        self.status.setText(t("wb.n_findings_grouped", n=len(findings), d=len(groups))
                            if len(groups) != len(findings) else t("wb.n_findings", n=len(findings)))
        if pseudo:
            self.status.setText(self.status.text() + " · " + t("wb.pseudonymised", n=pseudo))

    def _select_finding(self):
        rows = {i.row() for i in self.findings.selectedItems()}
        if len(rows) == 1:
            first = self._findings[rows.pop()]
            key = (first.type, first.text.lower())
            occ = self._occurrences.get(key) or [first]
            f = occ[self._next_occ.get(key, 0) % len(occ)]
            text = self.input.toPlainText()
            cur = self.input.textCursor()
            cur.setPosition(u16(text, f.start))
            cur.setPosition(u16(text, f.end), QTextCursor.KeepAnchor)
            self.input.setTextCursor(cur)

    def _next_occurrence(self, row: int, _col: int = 0):
        """Double click: jump to the next place where this value occurs."""
        if 0 <= row < len(self._findings):
            f = self._findings[row]
            key = (f.type, f.text.lower())
            self._next_occ[key] = self._next_occ.get(key, 0) + 1
            self._select_finding()

    def _auto_copy_toggled(self, on: bool):
        self.c.cfg.set("general.workbench_auto_copy", bool(on))
        self.c.cfg.save()

    def run(self, mode: str | None = None):
        text = self.input.toPlainText()
        mode = mode or self.c.cfg.get("general.mode", "pseudonymize")
        if not text:
            self.status.setText(t("wb.empty"))
            return
        self.status.setText(t("status.busy", what=t("mode." + mode)))
        self.c.submit(lambda: self.c.engine.process(text, mode), self._show_result,
                      label=t("job.workbench", mode=t("mode." + mode)))

    def _show_result(self, res: Result):
        self._last = res
        dark = is_dark(self)
        if len(res.output) > LARGE_TEXT:
            self.output.setPlainText(res.output)
        else:
            self.output.setHtml(highlighted_html(res.output, [(r.out_start, r.out_end, r.type)
                                                              for r in res.replacements], dark))
        fill_replacements(self.reps, res.replacements, dark)
        self.c.record(res, "workbench")
        self._last_mode = res.mode
        msg = t("wb.n_replaced", n=len(res.replacements))
        if self.auto_copy.isChecked() and res.output:
            self.c.write_clipboard(res.output, None, sensitive=res.mode == "revert")
            msg += " – " + t("wb.copied")
        self.status.setText(msg)

    def llm_check(self):
        # only the processed result goes to the LLM – never the unprocessed input
        text = self.output.toPlainText()
        if not text:
            self.status.setText(t("wb.llm_check_first"))
            return
        self.c.llm_verify(text, show=True)

    def _findings_menu(self, pos):
        rows = sorted({i.row() for i in self.findings.selectedItems()})
        if not rows:
            return
        m = QMenu(self)
        a_allow = m.addAction(t("wb.add_allow"))
        a_term = m.addAction(t("wb.add_term"))
        custom = [self._findings[r] for r in rows if self._findings[r].type == "CUSTOM"]
        a_edit = m.addAction(t("wb.edit_term")) if custom else None
        chosen = m.exec(self.findings.viewport().mapToGlobal(pos))
        if chosen is not None and chosen is a_edit:
            self.c.show_settings("terms:" + custom[0].text)
            self.analyze()
            return
        for r in rows:
            f = self._findings[r]
            if chosen is a_allow:
                self.c.add_allow_term(f.text)
            elif chosen is a_term:
                self.c.add_custom_term(f.text, f.type)
        if chosen:
            self.analyze()

    def _input_menu(self, pos):
        """Standard edit menu plus: mark any text and have it always / never replaced."""
        m = self.input.createStandardContextMenu()
        sel = self.input.textCursor().selectedText().replace("\u2029", " ").strip()
        a_term = a_allow = None
        if sel and len(sel) <= 200:
            short = sel if len(sel) <= 40 else sel[:37] + "…"
            m.addSeparator()
            a_term = m.addAction(t("wb.sel_term", text=short))
            a_allow = m.addAction(t("wb.sel_allow", text=short))
        chosen = m.exec(self.input.viewport().mapToGlobal(pos))
        if chosen is not None and chosen is a_term:
            self.c.add_custom_term(sel, "")
            self.c.notify(t("wb.sel_term_done", text=sel, where=self.c.project_label()), force=True)
            self.analyze()
        elif chosen is not None and chosen is a_allow:
            self.c.add_allow_term(sel)
            self.analyze()

    def add_text_as_term(self, text: str, typ: str = "CUSTOM"):
        self.c.add_custom_term(text, typ)
        self.analyze()
