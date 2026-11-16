"""PDF tab: redact a PDF file for real.

1. open a PDF (button, drag & drop, "Process file", action "redact_pdf") → 2. detect: the text
detectors on the text layer, and the plugin on images (scans, screenshots) → check the boxes on
every page, delete or draw boxes by hand → 3. save: the text, image pixels and graphics under the
boxes are removed, the rest of the file is cleaned (metadata, annotations, forms, attachments,
JavaScript), and the result is read again to check that nothing redacted is left.

Pages are shown at ZOOM × 72 dpi; the boxes are kept in those pixels and converted to PDF points
when saving.
"""

from __future__ import annotations

import base64
import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QImage, QKeySequence, QShortcut
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QInputDialog, QLabel, QLineEdit,
                               QMenu, QMessageBox, QPushButton, QSplitter, QVBoxLayout, QWidget)

from shiboken6 import isValid

from ..core import pdfredact as pr
from ..core.imageredact import Region
from ..i18n import t
from .image_view import ImageCanvas
from .widgets import item, make_table, track_table

ZOOM = 2.0
SOURCE = {"FACE": "face", "NUDITY": "nudity", "QR_CODE": "code", "BARCODE": "code"}


def to_region(r: pr.PdfRegion) -> Region:
    src = "manual" if r.source == "manual" else SOURCE.get(r.kind, "text")
    x, y = int(r.x0 * ZOOM), int(r.y0 * ZOOM)
    w = max(2, int(round((r.x1 - r.x0) * ZOOM)) + 1)
    h = max(2, int(round((r.y1 - r.y0) * ZOOM)) + 1)
    return Region(x, y, w, h, r.kind, "black", r.label, src)


def to_pdf(page: int, reg: Region, meta) -> pr.PdfRegion:
    start, end, first, source = meta if meta else (-1, -1, True, "manual")
    return pr.PdfRegion(page, reg.x / ZOOM, reg.y / ZOOM, (reg.x + reg.w) / ZOOM, (reg.y + reg.h) / ZOOM,
                        reg.kind, reg.label, source, start, end, first)


def page_image(doc, pno: int) -> QImage:
    m = pr._fitz()
    pix = doc[pno].get_pixmap(matrix=m.Matrix(ZOOM, ZOOM), alpha=False)
    return QImage(pix.samples, pix.width, pix.height, pix.stride, QImage.Format_RGB888).copy()


class PdfView(QWidget):
    status = Signal(str)

    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.c = controller
        cfg = getattr(controller, "cfg", None)
        self.canvas = ImageCanvas()
        self.canvas.menu_callback = self._menu
        self.btn_open = QPushButton(t("pdf.open"))
        self.btn_detect = QPushButton(t("img.detect"))
        self.mode = QComboBox()
        for m in pr.MODES:
            self.mode.addItem(t("pdf.mode." + m), m)
        self.rasterize = QCheckBox(t("pdf.rasterize"))
        self.rasterize.setToolTip(t("pdf.rasterize_tip"))
        if cfg is not None:
            self.mode.setCurrentIndex(max(0, self.mode.findData(cfg.get("pdf.mode", "redact"))))
            self.mode.setEnabled(not cfg.is_locked("pdf.mode"))
            self.rasterize.setChecked(bool(cfg.get("pdf.rasterize", False)))
            self.rasterize.setEnabled(not cfg.is_locked("pdf.rasterize"))
        self.btn_save = QPushButton(t("pdf.save"))
        self.btn_prev = QPushButton("◀")
        self.btn_next = QPushButton("▶")
        self.page_label = QLabel("")
        self.btn_fit = QPushButton(t("img.fit"))
        self.btn_delete = QPushButton(t("img.delete"))
        self.btn_clear = QPushButton(t("pdf.clear_page"))
        self.table = make_table([t("pdf.col_page"), t("col.type"), t("col.text")])
        track_table(getattr(controller, "ui_state", None), "pdf/columns", self.table)
        self.info = QLabel(t("pdf.hint"))
        self.info.setWordWrap(True)

        bar = QHBoxLayout()
        bar.addWidget(QLabel("<b>1. " + t("pdf.step_file") + "</b>"))
        bar.addWidget(self.btn_open)
        bar.addSpacing(16)
        bar.addWidget(QLabel("<b>2. " + t("img.step_detect") + "</b>"))
        bar.addWidget(self.btn_detect)
        bar.addSpacing(16)
        bar.addWidget(QLabel("<b>3. " + t("img.step_result") + "</b>"))
        bar.addWidget(self.mode)
        bar.addWidget(self.rasterize)
        bar.addWidget(self.btn_save)
        bar.addStretch(1)
        bar.addWidget(self.btn_prev)
        bar.addWidget(self.page_label)
        bar.addWidget(self.btn_next)
        bar.addWidget(self.btn_fit)

        side = QWidget()
        sl = QVBoxLayout(side)
        sl.setContentsMargins(0, 0, 0, 0)
        sl.addWidget(QLabel(t("img.regions")))
        sl.addWidget(self.table, 1)
        row = QHBoxLayout()
        row.addWidget(self.btn_delete)
        row.addWidget(self.btn_clear)
        sl.addLayout(row)
        sl.addWidget(self.info)

        self.split = QSplitter(Qt.Horizontal)
        self.split.addWidget(self.canvas)
        self.split.addWidget(side)
        self.split.setStretchFactor(0, 1)
        self.split.setChildrenCollapsible(False)
        st = getattr(controller, "ui_state", None)
        if st is not None:
            st.track("pdf/split", self.split, [800, 320])
        lay = QVBoxLayout(self)
        lay.addLayout(bar)
        lay.addWidget(self.split, 1)

        self.btn_open.clicked.connect(lambda: self.open_file())
        self.btn_detect.clicked.connect(self.detect)
        self.btn_save.clicked.connect(lambda: self.save())
        self.btn_prev.clicked.connect(lambda: self.show_page(self.page - 1))
        self.btn_next.clicked.connect(lambda: self.show_page(self.page + 1))
        self.btn_fit.clicked.connect(self.canvas.fit)
        self.btn_delete.clicked.connect(self.delete_selected)
        self.btn_clear.clicked.connect(lambda: self.canvas.clear_regions())
        self.mode.activated.connect(self._store_mode)
        self.canvas.region_changed.connect(self.refresh_table)
        self.canvas.selection_changed.connect(self._update_buttons)
        self.table.itemSelectionChanged.connect(self._table_selection)
        QShortcut(QKeySequence.Delete, self.canvas, activated=self.delete_selected)
        QShortcut(QKeySequence(Qt.Key_PageDown), self, activated=lambda: self.show_page(self.page + 1))
        QShortcut(QKeySequence(Qt.Key_PageUp), self, activated=lambda: self.show_page(self.page - 1))
        if hasattr(controller, "image_progress"):
            controller.image_progress.connect(self._progress)
        self.setAcceptDrops(True)

        self.path: str | None = None
        self.password: str | None = None
        self.doc = None                       # for rendering only; jobs open their own copy
        self.page = 0
        self.pages: dict[int, list[Region]] = {}
        self.meta: dict[int, tuple] = {}      # id(Region) -> (start, end, first, source)
        self.text = ""                        # text layer and findings of the last detection
        self.offpage: list = []               # findings outside the visible page: always removed, not shown
        self.findings: list = []
        self._busy = False
        self._syncing = False
        self._update_buttons()

    # ------------------------------------------------------------------ file
    def open_file(self, path: str | None = None, detect: bool = True) -> bool:
        if not pr.available():
            QMessageBox.warning(self, "PDF", t("pdf.no_pymupdf"))
            return False
        if path is None:
            path, _ = QFileDialog.getOpenFileName(self, t("pdf.open"), "", "PDF (*.pdf)")
            if not path:
                return False
        password = None
        while True:
            try:
                doc = pr.open_pdf(path, password)
                break
            except pr.PdfPasswordError:
                password, ok = QInputDialog.getText(self, "PDF", t("pdf.password", name=os.path.basename(path)),
                                                    QLineEdit.Password)
                if not ok:
                    return False
            except pr.PdfError as exc:
                self.c.notify(t("pdf.cannot_open", err=str(exc)), error=True)
                return False
        if self.doc is not None:
            self.doc.close()
        self.doc, self.path, self.password = doc, path, password
        self.pages, self.meta, self.text, self.findings, self.offpage = {}, {}, "", [], []
        self.page = -1
        self.show_page(0)
        self.info.setText(t("pdf.opened", name=os.path.basename(path), n=doc.page_count))
        if detect:
            self.detect()
        return True

    def dragEnterEvent(self, ev):
        if any(u.toLocalFile().lower().endswith(".pdf") for u in ev.mimeData().urls()):
            ev.acceptProposedAction()

    def dropEvent(self, ev):
        for u in ev.mimeData().urls():
            if u.toLocalFile().lower().endswith(".pdf"):
                self.open_file(u.toLocalFile())
                return

    # ------------------------------------------------------------------ pages
    def _sync_page(self):
        if self.doc is not None and self.page >= 0:
            self.pages[self.page] = list(self.canvas.regions())

    def show_page(self, pno: int, select: Region | None = None):
        if self.doc is None or not 0 <= pno < self.doc.page_count:
            return
        if pno != self.page:
            self._sync_page()
            self.page = pno
            self._syncing = True
            self.canvas.set_image(page_image(self.doc, pno))
            for r in self.pages.get(pno, []):
                self.canvas.add_region(r)
            self._syncing = False
        if select is not None:
            for it in self.canvas.items_list():
                it.setSelected(it.region is select)
                if it.region is select:
                    self.canvas.ensureVisible(it.sceneBoundingRect())
        self.page_label.setText(t("pdf.page", i=pno + 1, n=self.doc.page_count))
        self.refresh_table()

    def all_regions(self) -> list[tuple[int, Region]]:
        self._sync_page()
        return [(p, r) for p in sorted(self.pages) for r in self.pages[p]]

    # ------------------------------------------------------------------ detection
    def detect(self):
        if self.path is None or self._busy:
            return
        cfg = self.c.cfg
        path, password = self.path, self.password
        engine = self.c.engine
        images = bool(cfg.get("pdf.images", True))
        dpi = int(cfg.get("pdf.dpi", 150) or 150)
        client = self.c.plugin_client() if images else None
        from ..core.imageredact import ImageSettings
        settings = ImageSettings.from_config(cfg.get("image") or {})
        progress = self.c.image_progress.emit
        from .app import analyse_image

        def analyser(png: bytes, w: int, h: int):
            try:
                regs, _counts = analyse_image(client, base64.b64encode(png).decode(), w, h, settings, engine.analyze)
            except (RuntimeError, TimeoutError, OSError, ValueError):
                return None
            return [(r.x, r.y, r.w, r.h, r.kind, r.label) for r in regs]

        def job():
            try:
                return work()
            except Exception as exc:                   # noqa: BLE001 – shown in the tab, the busy state ends
                return exc

        def work():
            doc = pr.open_pdf(path, password)
            try:
                progress(t("pdf.step_text"))
                ptext, findings = pr.analyze_text(doc, engine.analyze)
                regions = pr.text_regions(ptext, findings)
                total = len(pr.image_areas(doc))
                done = 0
                if client is not None and total:
                    img, total, done = pr.image_regions(
                        doc, analyser, dpi, lambda i, n, p: progress(t("pdf.step_image", i=i, n=n, p=p)))
                    regions += img
                return ptext.text, findings, regions, total, done, None
            finally:
                doc.close()

        def done(res):
            if not isValid(self.btn_detect):
                return
            self._set_busy(False)
            if isinstance(res, Exception):
                self.info.setText(t("pdf.detect_failed", err=str(res)))
                return
            text, findings, regions, total, analysed, _ = res
            self.text, self.findings = text, findings
            # boxes found by hand stay; detected ones are replaced
            self._sync_page()
            for p in list(self.pages):
                self.pages[p] = [r for r in self.pages[p] if r.source == "manual"]
            self.meta = {k: v for k, v in self.meta.items() if v[3] == "manual"}
            self.offpage = []
            for r in regions:
                pw, ph = self.doc[r.page].rect.width, self.doc[r.page].rect.height
                if r.x0 < -1 or r.y0 < -1 or r.x1 > pw + 1 or r.y1 > ph + 1:
                    self.offpage.append(r)          # cannot be shown (the canvas keeps boxes on the page)
                    continue
                reg = to_region(r)
                self.meta[id(reg)] = (r.start, r.end, r.first, r.source)
                self.pages.setdefault(r.page, []).append(reg)
            cur = self.page
            self.page = -1
            self.show_page(cur)
            msg = t("pdf.detected", n=len(regions), pages=len({r.page for r in regions}))
            if self.offpage:
                msg += "\n" + t("pdf.offpage", n=len(self.offpage))
            if total and client is None:
                msg += "\n" + (t("pdf.images_off", n=total) if not images else
                               t("pdf.images_no_plugin", n=total))
            elif total:
                msg += "\n" + t("pdf.images_done", n=analysed, total=total)
            self.info.setText(msg)
            self.status.emit(msg.split("\n")[0])

        self._set_busy(True, t("pdf.busy_detect"))
        self.c.submit(job, done, executor=self.c.llm_executor, label=t("job.pdf_detect"))

    def _progress(self, text: str):
        if self._busy:
            self.canvas.busy.set_step(text)

    def _set_busy(self, on: bool, text: str = ""):
        self._busy = on
        if on:
            self.canvas.busy.start(text)
        else:
            self.canvas.busy.stop()
        self._update_buttons()

    # ------------------------------------------------------------------ save
    def save(self, out_path: str | None = None):
        if self.path is None or self._busy:
            return
        if out_path is None:
            base, _ext = os.path.splitext(self.path)
            out_path, _ = QFileDialog.getSaveFileName(self, t("pdf.save"), base + ".redacted.pdf", "PDF (*.pdf)")
            if not out_path:
                return
        if os.path.abspath(out_path) == os.path.abspath(self.path):
            self.c.notify(t("pdf.same_file"), error=True)
            return
        regions = [to_pdf(p, r, self.meta.get(id(r))) for p, r in self.all_regions()] + list(self.offpage)
        mode = self.mode.currentData()
        rasterize = self.rasterize.isChecked()
        dpi = int(self.c.cfg.get("pdf.dpi", 150) or 150)
        engine = self.c.engine
        path, password, text = self.path, self.password, self.text
        spans = {(r.start, r.end) for r in regions if r.source == "text"}
        findings = [f for f in self.findings if (f.start, f.end) in spans]

        def job():
            try:
                return work()
            except Exception as exc:                   # noqa: BLE001
                return exc

        def work():
            res = engine.process(text, mode, findings) if text else None
            reps = pr.replacements_for(res) if (res is not None and mode != "redact") else None
            doc = pr.open_pdf(path, password)
            try:
                titles = pr.clean_titles(engine, mode, text, [e[1] for e in doc.get_toc()])
                warnings = pr.redact(doc, regions, reps, lambda s: titles.get(s, s))
                pr.save(doc, out_path, rasterize, dpi)
            finally:
                doc.close()
            left = pr.verify(out_path, [r.label for r in regions if r.source == "text" and r.label])
            return res, warnings, left

        def done(r):
            if not isValid(self.btn_save):
                return
            self._set_busy(False)
            if isinstance(r, Exception):
                self.c.notify(t("pdf.save_failed", err=str(r)), error=True)
                return
            res, warnings, left = r
            if res is not None and res.replacements:
                res.warnings.append(t("file.history_note", src=path, dst=out_path))
                self.c.history.add(res, "pdf", self.c.project.name if self.c.project else "")
                self.c.history_changed.emit()
                self.c.mappings_changed.emit()
            self.info.setText(t("pdf.saved", n=len(regions), path=out_path) +
                              ("\n" + "\n".join(warnings) if warnings else ""))
            if left:
                QMessageBox.warning(self, "PDF", t("pdf.leftovers", n=len(left), path=out_path))
            else:
                self.c.notify(t("pdf.saved", n=len(regions), path=out_path), force=True)

        self._set_busy(True, t("pdf.busy_save"))
        self.c.submit(job, done, executor=self.c.llm_executor, label=t("job.pdf_save"))

    def _store_mode(self, _idx=None):
        cfg = self.c.cfg
        if not cfg.is_locked("pdf.mode"):
            cfg.set("pdf.mode", self.mode.currentData())

    # ------------------------------------------------------------------ regions
    def _selected_items(self):
        return [i for i in self.canvas.items_list() if i.isSelected()]

    def delete_selected(self):
        self.canvas.remove(self._selected_items())

    def _menu(self, screen_pos):
        m = QMenu(self)
        m.addAction(t("img.delete")).triggered.connect(self.delete_selected)
        m.exec(screen_pos)

    def refresh_table(self):
        if self._syncing:
            return
        rows = self.all_regions()
        selected = {id(i.region) for i in self._selected_items()}
        self._syncing = True
        self.table.setRowCount(len(rows))
        for n, (p, r) in enumerate(rows):
            kind = t("img.kind." + r.kind) if r.kind in ("FACE", "NUDITY", "QR_CODE", "BARCODE", "MANUAL") else r.kind
            self.table.setItem(n, 0, item(str(p + 1), data=n))
            self.table.setItem(n, 1, item(kind))
            self.table.setItem(n, 2, item(r.label))
            if id(r) in selected:
                self.table.selectRow(n)
        self._syncing = False
        self._update_buttons()

    def _table_selection(self):
        if self._syncing:
            return
        rows = sorted({i.row() for i in self.table.selectedItems()})
        if not rows:
            return
        all_r = self.all_regions()
        if rows[0] < len(all_r):
            p, r = all_r[rows[0]]
            self._syncing = True
            self.show_page(p, select=r)
            self._syncing = False
        self._update_buttons()

    def _update_buttons(self):
        has = self.doc is not None
        for b in (self.btn_detect, self.btn_save):
            b.setEnabled(has and not self._busy)
        self.btn_open.setEnabled(not self._busy)
        self.btn_fit.setEnabled(has)
        self.btn_clear.setEnabled(has and not self._busy)
        self.btn_prev.setEnabled(has and self.page > 0)
        self.btn_next.setEnabled(has and self.page < (self.doc.page_count - 1 if has else 0))
        self.btn_delete.setEnabled(bool(self._selected_items()))

    def showEvent(self, ev):
        super().showEvent(ev)
        self.canvas.fit()
