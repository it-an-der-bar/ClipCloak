"""Settings dialog (all options of config.yaml)."""

from __future__ import annotations

import copy
import sys
import threading
from pathlib import Path

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox, QDoubleSpinBox,
                               QFileDialog, QFormLayout, QGridLayout, QGroupBox, QHBoxLayout,
                               QKeySequenceEdit, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton,
                               QScrollArea, QSpinBox, QTableWidget, QTableWidgetItem, QTabWidget,
                               QVBoxLayout, QWidget)

from ..config import ACTIONS, DEFAULTS
from ..core.detectors import BUILTIN_DETECTORS
from ..core.entities import ALL_TYPES
from ..i18n import LANGUAGES, t
from .. import __version__
from ..meta import APP_NAME, NER_HELPER_NAME, RELEASES_URL

MODE_CHOICES = ["pseudonymize", "anonymize", "redact"]
TYPE_MODE_CHOICES = ["", "pseudonymize", "anonymize", "redact", "keep"]


def _scroll(widget: QWidget) -> QScrollArea:
    sa = QScrollArea()
    sa.setWidgetResizable(True)
    sa.setWidget(widget)
    return sa


class ListEdit(QPlainTextEdit):
    """One entry per line."""

    def set_items(self, items):
        self.setPlainText("\n".join(str(i) for i in items or []))

    def items(self) -> list[str]:
        return [ln.strip() for ln in self.toPlainText().splitlines() if ln.strip()]


class TermsTable(QWidget):
    """Custom terms: term, type, replacement, regex, case sensitive."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels([t("terms.term"), t("terms.type"), t("terms.replacement"),
                                              t("terms.regex"), t("terms.case")])
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.setColumnWidth(0, 220)
        self.table.setColumnWidth(2, 180)
        add = QPushButton(t("terms.add"))
        rem = QPushButton(t("terms.remove"))
        add.clicked.connect(lambda: self.add_row({}))
        rem.clicked.connect(self.remove_selected)
        btns = QHBoxLayout()
        btns.addWidget(add)
        btns.addWidget(rem)
        btns.addStretch(1)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.table)
        lay.addLayout(btns)

    def add_row(self, term: dict):
        r = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setItem(r, 0, QTableWidgetItem(term.get("term", "")))
        combo = QComboBox()
        combo.addItem(t("terms.type_auto"), "")
        for ty in ALL_TYPES:
            combo.addItem(ty, ty)
        combo.setCurrentIndex(max(0, combo.findData((term.get("type") or "").upper())))
        self.table.setCellWidget(r, 1, combo)
        self.table.setItem(r, 2, QTableWidgetItem(term.get("replacement", "")))
        for col, key in ((3, "regex"), (4, "case_sensitive")):
            it = QTableWidgetItem()
            it.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            it.setCheckState(Qt.Checked if term.get(key) else Qt.Unchecked)
            self.table.setItem(r, col, it)

    def remove_selected(self):
        for r in sorted({i.row() for i in self.table.selectedIndexes()}, reverse=True):
            self.table.removeRow(r)

    def set_terms(self, terms):
        self.table.setRowCount(0)
        for term in terms or []:
            self.add_row(term)

    def terms(self) -> list[dict]:
        out = []
        for r in range(self.table.rowCount()):
            term = (self.table.item(r, 0).text() if self.table.item(r, 0) else "").strip()
            if not term:
                continue
            out.append({
                "term": term,
                "type": self.table.cellWidget(r, 1).currentData() or "",
                "replacement": (self.table.item(r, 2).text() if self.table.item(r, 2) else "").strip(),
                "regex": self.table.item(r, 3).checkState() == Qt.Checked,
                "case_sensitive": self.table.item(r, 4).checkState() == Qt.Checked,
            })
        return out


class SettingsDialog(QDialog):
    _test_done = Signal(str, str)      # target, message
    _models_done = Signal(object, str, str)   # models or None, message, working URL

    def __init__(self, controller, parent=None, initial_tab: str | None = None):
        super().__init__(parent)
        self.c = controller
        self.data = copy.deepcopy(controller.cfg.data)
        self.setWindowTitle(t("settings.title"))
        self.resize(820, 640)
        self.w: dict[str, QWidget] = {}
        tabs = QTabWidget()
        tabs.addTab(_scroll(self._general()), t("settings.tab.general"))
        tabs.addTab(_scroll(self._hotkeys()), t("settings.tab.hotkeys"))
        tabs.addTab(_scroll(self._watcher()), t("settings.tab.watcher"))
        tabs.addTab(_scroll(self._detectors()), t("settings.tab.detectors"))
        tabs.addTab(self._lists(), t("settings.tab.lists"))
        tabs.addTab(_scroll(self._llm()), t("settings.tab.llm"))
        tabs.addTab(_scroll(self._ner()), t("settings.tab.ner"))
        if controller.project is not None:
            tabs.addTab(self._project(), t("settings.tab.project"))
            if initial_tab == "project":
                tabs.setCurrentIndex(tabs.count() - 1)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel | QDialogButtonBox.RestoreDefaults)
        bb.accepted.connect(self._accept)
        bb.rejected.connect(self.reject)
        bb.button(QDialogButtonBox.RestoreDefaults).clicked.connect(self._defaults)
        lay = QVBoxLayout(self)
        lay.addWidget(tabs)
        lay.addWidget(bb)
        self._test_done.connect(self._show_test)
        self._load()
        self._baseline = self._collect()

    # ------------------------------------------------------------- builders
    def _combo(self, key, choices, label_prefix=None):
        cb = QComboBox()
        for c in choices:
            cb.addItem(t(label_prefix + c) if label_prefix else c, c)
        self.w[key] = cb
        return cb

    def _check(self, key, text):
        cb = QCheckBox(text)
        self.w[key] = cb
        return cb

    def _line(self, key, password=False):
        le = QLineEdit()
        if password:
            le.setEchoMode(QLineEdit.Password)
        self.w[key] = le
        return le

    def _spin(self, key, lo, hi):
        sb = QSpinBox()
        sb.setRange(lo, hi)
        self.w[key] = sb
        return sb

    def _general(self):
        w = QWidget()
        f = QFormLayout(w)
        lang = QComboBox()
        lang.addItem(t("settings.lang_auto"), "auto")
        for code, name in LANGUAGES.items():
            lang.addItem(name, code)
        self.w["general.language"] = lang
        f.addRow(t("settings.language"), lang)
        f.addRow(t("settings.default_mode"), self._combo("general.mode", MODE_CHOICES, "mode."))
        f.addRow("", self._check("general.notify", t("settings.notify")))
        f.addRow("", self._check("general.workbench_auto_copy", t("wb.auto_copy")))
        f.addRow("", self._check("general.start_minimized", t("settings.start_minimized")))
        f.addRow("", self._check("general.autostart", t("settings.autostart")))
        f.addRow(t("settings.history_size"), self._spin("general.history_size", 1, 10000))
        f.addRow("", self._check("general.history_store_originals", t("settings.history_originals")))
        f.addRow(QLabel("<b>" + t("settings.processing") + "</b>"))
        f.addRow(t("settings.anon_style"), self._combo("processing.anonymize_style", ["realistic", "placeholder"], "anonstyle."))
        f.addRow(t("settings.placeholder_template"), self._line("processing.placeholder_template"))
        f.addRow(t("settings.redact_template"), self._line("processing.redact_template"))
        f.addRow("", self._check("processing.skip_known_surrogates", t("settings.skip_known")))
        f.addRow(QLabel("<b>" + t("settings.clipboard") + "</b>"))
        f.addRow(t("settings.clip_backend"), self._combo("clipboard.backend", ["auto", "qt", "wl-clipboard"]))
        f.addRow("", self._check("clipboard.process_html", t("settings.process_html")))
        info = self.c.session
        f.addRow(t("settings.session"), QLabel(f"{info['os']} / {info['display']} / {info['desktop'] or '-'}"
                                                f" / Qt: {info['qt_platform']}"))
        return w

    def _hotkeys(self):
        w = QWidget()
        v = QVBoxLayout(w)
        grid = QGridLayout()
        self.hk_edits = {}
        for row, action in enumerate(ACTIONS):
            ed = QKeySequenceEdit()
            clear = QPushButton("✕")
            clear.setFixedWidth(28)
            clear.clicked.connect(ed.clear)
            err = QLabel(self.c.hotkey_errors.get(action, ""))
            err.setStyleSheet("color:#c0392b")
            grid.addWidget(QLabel(t("action." + action)), row, 0)
            grid.addWidget(ed, row, 1)
            grid.addWidget(clear, row, 2)
            grid.addWidget(err, row, 3)
            self.hk_edits[action] = ed
        v.addLayout(grid)
        box = QGroupBox(t("settings.hotkeys_wayland_title"))
        bl = QVBoxLayout(box)
        lab = QLabel(t("settings.hotkeys_wayland_text"))
        lab.setWordWrap(True)
        bl.addWidget(lab)
        exe = self.c.launch_command_str()
        cmds = QPlainTextEdit("\n".join(f"{exe} --action {a}" for a in ACTIONS))
        cmds.setReadOnly(True)
        cmds.setMaximumHeight(170)
        bl.addWidget(cmds)
        copy_btn = QPushButton(t("settings.copy"))
        copy_btn.clicked.connect(lambda: QGuiApplication.clipboard().setText(cmds.toPlainText()))
        bl.addWidget(copy_btn, 0, Qt.AlignLeft)
        v.addWidget(box)
        backend = self.c.hotkeys.backend
        v.addWidget(QLabel(t("settings.hotkey_backend", backend=backend)))
        v.addStretch(1)
        return w

    def _watcher(self):
        w = QWidget()
        f = QFormLayout(w)
        f.addRow(t("settings.watch_mode"), self._combo("watcher.mode", ["off", "notify", "critical", "always"], "watch."))
        f.addRow(t("settings.watch_action"), self._combo("watcher.action", MODE_CHOICES, "mode."))
        f.addRow(t("settings.critical_action"), self._combo("watcher.critical_action", MODE_CHOICES, "mode."))
        f.addRow("", self._check("watcher.notify_noncritical", t("settings.notify_noncritical")))
        f.addRow(t("settings.popup_timeout"), self._spin("watcher.popup_timeout", 0, 600))
        f.addRow(t("settings.max_chars"), self._spin("watcher.max_chars", 1000, 50_000_000))
        box = QGroupBox(t("settings.critical_types"))
        grid = QGridLayout(box)
        self.crit = {}
        for i, ty in enumerate(ALL_TYPES):
            cb = QCheckBox(ty)
            self.crit[ty] = cb
            grid.addWidget(cb, i // 3, i % 3)
        f.addRow(box)
        expl = QLabel(t("settings.watch_explain"))
        expl.setWordWrap(True)
        f.addRow(expl)
        if not self.c.clip_can_watch():
            warn = QLabel(t("settings.watch_unavailable", reason=self.c.watch_error or "-"))
            warn.setWordWrap(True)
            warn.setStyleSheet("color:#c0392b")
            f.addRow(warn)
        return w

    def _detectors(self):
        w = QWidget()
        v = QVBoxLayout(w)
        box = QGroupBox(t("settings.detectors"))
        grid = QGridLayout(box)
        self.det = {}
        ids = [cls.id for cls in BUILTIN_DETECTORS] + ["learned-names"]
        for i, did in enumerate(ids):
            cb = QCheckBox(t("det." + did))
            cb.setToolTip(did)
            self.det[did] = cb
            grid.addWidget(cb, i // 2, i % 2)
        v.addWidget(box)
        f = QFormLayout()
        f.addRow("", self._check("detectors.keep_special_hosts", t("settings.keep_special_hosts")))
        f.addRow("", self._check("detectors.mac_keep_oui", t("settings.mac_keep_oui")))
        f.addRow(t("settings.tld_strategy"), self._combo("detectors.tld_strategy", ["keep", "example"], "tld."))
        ent = QDoubleSpinBox()
        ent.setRange(2.0, 6.0)
        ent.setSingleStep(0.1)
        self.w["detectors.entropy_threshold"] = ent
        f.addRow(t("settings.entropy_threshold"), ent)
        v.addLayout(f)
        box2 = QGroupBox(t("settings.type_modes"))
        g2 = QGridLayout(box2)
        self.type_modes = {}
        for i, ty in enumerate(ALL_TYPES):
            cb = QComboBox()
            for m in TYPE_MODE_CHOICES:
                cb.addItem(t("typemode." + (m or "default")), m)
            self.type_modes[ty] = cb
            g2.addWidget(QLabel(ty), i // 2, (i % 2) * 2)
            g2.addWidget(cb, i // 2, (i % 2) * 2 + 1)
        v.addWidget(box2)
        v.addStretch(1)
        return w

    def _lists(self):
        tabs = QTabWidget()
        self.terms = TermsTable()
        tabs.addTab(self._with_help(self.terms, "lists.terms_help"), t("lists.terms"))
        self.lists = {}
        for key in ("known_domains", "allow_terms", "allow_domains", "allow_ip_ranges",
                    "generic_labels_extra", "extra_tlds"):
            ed = ListEdit()
            self.lists[key] = ed
            tabs.addTab(self._with_help(ed, "lists." + key + "_help"), t("lists." + key))
        return tabs

    @staticmethod
    def _with_help(widget, help_key):
        w = QWidget()
        v = QVBoxLayout(w)
        lab = QLabel(t(help_key))
        lab.setWordWrap(True)
        v.addWidget(lab)
        v.addWidget(widget, 1)
        return w

    def _llm(self):
        w = QWidget()
        v = QVBoxLayout(w)
        intro = QLabel(t("llm.note"))
        intro.setWordWrap(True)
        v.addWidget(intro)

        # 1. connection -------------------------------------------------------
        box1 = QGroupBox(t("llm.step_connection"))
        f1 = QFormLayout(box1)
        url = self._line("llm.base_url")
        url.setPlaceholderText("http://server:11434/v1")
        f1.addRow(t("llm.base_url"), url)
        key = self._line("llm.api_key", password=True)
        key.setPlaceholderText(t("llm.api_key_optional"))
        f1.addRow(t("llm.api_key"), key)
        f1.addRow("", self._check("llm.verify_tls", t("llm.verify_tls")))
        f1.addRow(t("llm.ca_bundle"), self._file_row(self._line("llm.ca_bundle")))
        f1.addRow(t("llm.timeout"), self._spin("llm.timeout", 5, 600))
        self.llm_test_btn = QPushButton(t("llm.test"))
        self.llm_test_btn.clicked.connect(self._test_llm)
        self.llm_result = QLabel(t("llm.test_hint"))
        self.llm_result.setWordWrap(True)
        f1.addRow(self.llm_test_btn, self.llm_result)
        v.addWidget(box1)

        # 2. models -------------------------------------------------------------
        box2 = QGroupBox(t("llm.step_models"))
        f2 = QFormLayout(box2)
        self.llm_model = QComboBox(editable=True)
        self.llm_vision = QComboBox(editable=True)
        self.llm_model.lineEdit().setPlaceholderText(t("llm.model_placeholder"))
        self.llm_vision.lineEdit().setPlaceholderText(t("llm.vision_same"))
        f2.addRow(t("llm.model"), self.llm_model)
        f2.addRow(t("llm.vision_model"), self.llm_vision)
        v.addWidget(box2)

        # 3. features -----------------------------------------------------------
        box3 = QGroupBox(t("llm.step_features"))
        f3 = QFormLayout(box3)
        f3.addRow("", self._check("llm.enabled", t("llm.enabled")))
        f3.addRow(t("llm.verify_output"), self._combo("llm.verify_output", ["off", "warn"], "llmverify."))
        f3.addRow("", self._check("llm.detect", t("llm.detect")))
        v.addWidget(box3)
        v.addStretch(1)
        self._models_done.connect(self._on_models)
        return w

    def _ner(self):
        w = QWidget()
        f = QFormLayout(w)
        f.addRow(self._ner_setup_box())
        f.addRow("", self._check("ner.enabled", t("ner.enabled")))
        path = self._line("ner.helper_path")
        path.setPlaceholderText(t("ner.path_auto"))
        path.textChanged.connect(lambda _=None: self._update_ner_status())
        f.addRow(t("ner.helper_path"), self._file_row(path))
        f.addRow(t("ner.language"), self._combo("ner.language", ["auto", "de", "en", "both"], "nerlang."))
        box = QGroupBox(t("ner.types"))
        hl = QHBoxLayout(box)
        self.ner_types = {}
        for ty in ("PERSON", "ORG", "LOCATION"):
            cb = QCheckBox(ty)
            self.ner_types[ty] = cb
            hl.addWidget(cb)
        f.addRow(box)
        f.addRow(t("ner.model_de"), self._line("ner.model_de"))
        f.addRow(t("ner.model_en"), self._line("ner.model_en"))
        test = QPushButton(t("ner.test"))
        self.ner_result = QLabel("")
        self.ner_result.setWordWrap(True)
        test.clicked.connect(self._test_ner)
        f.addRow(test, self.ner_result)
        return w

    @staticmethod
    def _program_dir() -> Path:
        if getattr(sys, "frozen", False):
            return Path(sys.executable).resolve().parent
        return Path(sys.argv[0]).resolve().parent

    def _ner_setup_box(self) -> QGroupBox:
        box = QGroupBox(t("ner.setup_title"))
        v = QVBoxLayout(box)
        self.ner_status = QLabel("")
        self.ner_status.setWordWrap(True)
        self.ner_status.setTextInteractionFlags(Qt.TextSelectableByMouse)
        v.addWidget(self.ner_status)
        folder = str(self._program_dir())
        if getattr(sys, "frozen", False):
            steps = t("ner.setup_steps",
                      win=f"{NER_HELPER_NAME}-v{__version__}-windows-x86_64.exe",
                      linux=f"{NER_HELPER_NAME}-v{__version__}-linux-x86_64",
                      folder=folder)
        else:
            steps = t("ner.setup_source", folder=folder)
        lab = QLabel(steps)
        lab.setWordWrap(True)
        lab.setTextInteractionFlags(Qt.TextSelectableByMouse)
        v.addWidget(lab)
        row = QHBoxLayout()
        if RELEASES_URL:
            b = QPushButton(t("ner.open_releases"))
            b.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(RELEASES_URL)))
            row.addWidget(b)
        b2 = QPushButton(t("ner.open_folder"))
        b2.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(folder)))
        row.addWidget(b2)
        row.addStretch(1)
        v.addLayout(row)
        return box

    def _update_ner_status(self):
        from ..core.detectors.external import find_ner_helper
        wdg = self.w.get("ner.helper_path")
        cmd = find_ner_helper(wdg.text().strip() if wdg else "")
        if cmd:
            self.ner_status.setText(t("ner.status_found", path=" ".join(cmd)))
            self.ner_status.setStyleSheet("color:#2e7d32")
        else:
            self.ner_status.setText(t("ner.status_missing"))
            self.ner_status.setStyleSheet("color:#c0392b")

    def _project(self):
        w = QWidget()
        v = QVBoxLayout(w)
        prj = self.c.project
        v.addWidget(QLabel(t("settings.project_info", name=prj.name,
                             enc=t("yes") if prj.encrypted else t("no"))))
        self.prj_store_history = QCheckBox(t("settings.project_store_history"))
        self.prj_store_history.setChecked(prj.store_history)
        v.addWidget(self.prj_store_history)
        v.addWidget(QLabel(t("settings.project_terms")))
        self.prj_terms = TermsTable()
        self.prj_terms.set_terms(prj.terms)
        v.addWidget(self.prj_terms, 2)
        v.addWidget(QLabel(t("lists.known_domains")))
        self.prj_domains = ListEdit()
        self.prj_domains.set_items(prj.known_domains)
        v.addWidget(self.prj_domains, 1)
        return w

    def _file_row(self, line: QLineEdit) -> QWidget:
        # a container widget instead of QFormLayout.addRow(label, QLayout):
        # PySide6 keeps Python ownership of such a layout and double-frees it at exit
        box = QWidget()
        hl = QHBoxLayout(box)
        hl.setContentsMargins(0, 0, 0, 0)
        pick = QPushButton("…")
        pick.clicked.connect(lambda: self._pick_file(line))
        hl.addWidget(line)
        hl.addWidget(pick)
        return box

    def _pick_file(self, line: QLineEdit):
        path, _ = QFileDialog.getOpenFileName(self, t("settings.choose_file"))
        if path:
            line.setText(path)

    # ------------------------------------------------------------- load/save
    def _get(self, dotted, data=None):
        cur = data or self.data
        for p in dotted.split("."):
            cur = cur.get(p, {}) if isinstance(cur, dict) else {}
        return cur

    def _load(self, data=None):
        data = data or self.data
        for key, wdg in self.w.items():
            val = self._get(key, data)
            if isinstance(wdg, QComboBox):
                idx = wdg.findData(val)
                wdg.setCurrentIndex(max(idx, 0))
            elif isinstance(wdg, QCheckBox):
                wdg.setChecked(bool(val))
            elif isinstance(wdg, QLineEdit):
                wdg.setText("" if val in (None, {}) else str(val))
            elif isinstance(wdg, QDoubleSpinBox):
                wdg.setValue(float(val or 0))
            elif isinstance(wdg, QSpinBox):
                wdg.setValue(int(val or 0))
        for action, ed in self.hk_edits.items():
            ed.setKeySequence(QKeySequence(data["hotkeys"].get(action) or ""))
        crit = set(data["watcher"].get("critical_types") or [])
        for ty, cb in self.crit.items():
            cb.setChecked(ty in crit)
        enabled = data["detectors"].get("enabled") or {}
        for did, cb in self.det.items():
            cb.setChecked(bool(enabled.get(did, False)))
        tm = data["processing"].get("type_modes") or {}
        for ty, cb in self.type_modes.items():
            cb.setCurrentIndex(max(0, cb.findData(tm.get(ty, ""))))
        self.terms.set_terms(data["lists"].get("custom_terms"))
        for key, ed in self.lists.items():
            ed.set_items(data["lists"].get(key))
        self._update_ner_status()
        for combo, key in ((self.llm_model, "model"), (self.llm_vision, "vision_model")):
            val = data["llm"].get(key) or ""
            if val and combo.findText(val) < 0:
                combo.addItem(val)
            combo.setCurrentText(val)
        types = set(data["ner"].get("types") or [])
        for ty, cb in self.ner_types.items():
            cb.setChecked(ty in types)

    def _collect(self) -> dict:
        d = copy.deepcopy(self.data)

        def put(dotted, val):
            cur = d
            parts = dotted.split(".")
            for p in parts[:-1]:
                cur = cur.setdefault(p, {})
            cur[parts[-1]] = val

        for key, wdg in self.w.items():
            if isinstance(wdg, QComboBox):
                put(key, wdg.currentData())
            elif isinstance(wdg, QCheckBox):
                put(key, wdg.isChecked())
            elif isinstance(wdg, QLineEdit):
                put(key, wdg.text().strip())
            elif isinstance(wdg, QDoubleSpinBox):
                put(key, float(wdg.value()))
            elif isinstance(wdg, QSpinBox):
                put(key, int(wdg.value()))
        for action, ed in self.hk_edits.items():
            d["hotkeys"][action] = ed.keySequence().toString(QKeySequence.PortableText)
        d["watcher"]["critical_types"] = [ty for ty, cb in self.crit.items() if cb.isChecked()]
        d["detectors"]["enabled"] = {did: cb.isChecked() for did, cb in self.det.items()}
        d["processing"]["type_modes"] = {ty: cb.currentData() for ty, cb in self.type_modes.items() if cb.currentData()}
        d["lists"]["custom_terms"] = self.terms.terms()
        for key, ed in self.lists.items():
            d["lists"][key] = ed.items()
        d["ner"]["types"] = [ty for ty, cb in self.ner_types.items() if cb.isChecked()]
        d["llm"]["model"] = self.llm_model.currentText().strip()
        d["llm"]["vision_model"] = self.llm_vision.currentText().strip()
        return d

    def reject(self):
        """Closing without OK: ask before dropping changes (URL, token, …)."""
        if not getattr(self.c, "_quitting", False) and self._collect() != self._baseline:
            ans = QMessageBox.question(self, t("settings.title"), t("settings.unsaved"),
                                       QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel,
                                       QMessageBox.Save)
            if ans == QMessageBox.Cancel:
                return
            if ans == QMessageBox.Save:
                self._accept()
                return
        super().reject()

    def _defaults(self):
        self._load(copy.deepcopy(DEFAULTS))

    def _accept(self):
        data = self._collect()
        project_update = None
        if self.c.project is not None and hasattr(self, "prj_terms"):
            project_update = {"terms": self.prj_terms.terms(), "known_domains": self.prj_domains.items(),
                              "store_history": self.prj_store_history.isChecked()}
        self.c.apply_settings(data, project_update)
        self.accept()

    # ------------------------------------------------------------- tests
    def _test_llm(self):
        from ..llm.client import LLMClient, LLMSettings
        d = self._collect()["llm"]
        if not d.get("base_url"):
            self.llm_result.setText(t("llm.url_missing"))
            return
        self.llm_result.setText(t("llm.testing"))
        self.llm_test_btn.setEnabled(False)

        def run():
            base = d["base_url"].rstrip("/")
            candidates = [base] if base.endswith("/v1") else [base, base + "/v1"]
            err = None
            for url in candidates:
                try:
                    models = LLMClient(LLMSettings.from_config(dict(d, base_url=url))).list_models()
                except Exception as exc:
                    err = exc
                    continue
                self._models_done.emit(models, t("llm.test_ok", n=len(models)), url)
                return
            self._models_done.emit(None, t("llm.test_fail", err=str(err)), "")

        threading.Thread(target=run, daemon=True).start()

    def _on_models(self, models, msg, url):
        self.llm_test_btn.setEnabled(True)
        self.llm_result.setText(msg)
        if models is None:
            return
        if url and url != self.w["llm.base_url"].text().strip().rstrip("/"):
            self.w["llm.base_url"].setText(url)          # e.g. "/v1" was missing
        self._fill_models(models)
        if not self.llm_model.currentText() and models:
            self.llm_model.setCurrentIndex(1)
        self.w["llm.enabled"].setChecked(True)

    def _fill_models(self, models):
        for combo in (self.llm_model, self.llm_vision):
            cur = combo.currentText()
            combo.blockSignals(True)
            combo.clear()
            combo.addItem("")
            for m in models:
                combo.addItem(m)
            combo.setCurrentText(cur)
            combo.blockSignals(False)

    def _test_ner(self):
        from ..core.detectors.external import NerClient, find_ner_helper
        d = self._collect()["ner"]
        cmd = find_ner_helper(d.get("helper_path", ""))
        if not cmd:
            self.ner_result.setText(t("ner.not_found", helper=APP_NAME + "-ner"))
            return
        self.ner_result.setText(t("ner.testing"))

        def run():
            client = NerClient(cmd, timeout=120)
            try:
                sample = "Jonas Hartmann arbeitet bei der Siemens AG in München."
                res = client.request({"text": sample, "lang": "de",
                                      "models": {"de": d.get("model_de"), "en": d.get("model_en")}})
                ents = [sample[e["start"]:e["end"]] + f" ({e['label']})" for e in res.get("entities", [])]
                msg = t("ner.test_ok") + " " + ", ".join(ents)
            except Exception as exc:
                msg = t("ner.test_fail", err=str(exc))
            finally:
                client.close()
            self._test_done.emit("ner", msg)

        threading.Thread(target=run, daemon=True).start()

    def _show_test(self, target, msg):
        (self.llm_result if target == "llm" else self.ner_result).setText(msg)
