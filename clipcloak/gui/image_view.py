"""Image tab: hide faces, text and codes in an image with black bars, mosaic or blur.

Left to right: 1. image (clipboard / file) → 2. detect automatically (plugin) or draw
boxes by hand → 3. result to the clipboard or into a file. Boxes can be moved,
resized (lower right corner), deleted (Del) and switched between the effects.
The margin around detected faces can be widened in the tab; boxes edited by hand
keep their size.
"""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QBrush, QColor, QImage, QKeySequence, QPainter, QPen, QPixmap, QShortcut
from PySide6.QtWidgets import (QComboBox, QFileDialog, QGraphicsItem, QGraphicsPixmapItem, QGraphicsRectItem,
                               QGraphicsScene, QGraphicsView, QHBoxLayout, QLabel, QMenu, QPushButton,
                               QSpinBox, QSplitter, QVBoxLayout, QWidget)

from ..core.imageredact import EFFECTS, Region, with_margin
from ..i18n import t
from . import image_effects
from .widgets import item, make_table, track_table

HANDLE = 12      # size of the resize corner in screen pixels
COLORS = {"face": "#e67e22", "nudity": "#d81b60", "text": "#c0392b", "code": "#8e44ad", "manual": "#2980b9"}


class RegionItem(QGraphicsRectItem):
    """One box. Shows a live preview of its effect; the outline is not part of the result."""

    def __init__(self, view: "ImageCanvas", region: Region):
        super().__init__(0, 0, region.w, region.h)
        self.view = view
        self.region = region
        self.setPos(region.x, region.y)
        self.setFlags(QGraphicsItem.ItemIsMovable | QGraphicsItem.ItemIsSelectable |
                      QGraphicsItem.ItemSendsGeometryChanges)
        self.setAcceptHoverEvents(True)
        self._resizing = False
        self._press_geo = None
        self._cache_key = None
        self._cache: QPixmap | None = None

    # geometry ----------------------------------------------------------------
    def set_geometry(self, x: int, y: int, w: int, h: int):
        """Programmatic resize (margin changed); keeps ``region.base``."""
        self.prepareGeometryChange()
        self.setRect(0, 0, w, h)
        self.setPos(x, y)
        self.sync()
        self.update()

    def _geo(self):
        return (self.pos().x(), self.pos().y(), self.rect().width(), self.rect().height())

    def sync(self):
        r = self.rect()
        self.region.x, self.region.y = int(round(self.pos().x())), int(round(self.pos().y()))
        self.region.w, self.region.h = max(1, int(round(r.width()))), max(1, int(round(r.height())))

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionChange and self.view.image is not None:
            img = self.view.image
            r = self.rect()
            x = min(max(0.0, value.x()), max(0.0, img.width() - r.width()))
            y = min(max(0.0, value.y()), max(0.0, img.height() - r.height()))
            return QPointF(round(x), round(y))
        if change == QGraphicsItem.ItemPositionHasChanged:
            self.sync()
            self.view.region_changed.emit()
        return super().itemChange(change, value)

    def _handle_size(self) -> float:
        scale = self.view.transform().m11() or 1.0
        return HANDLE / scale

    def _in_handle(self, pos: QPointF) -> bool:
        r = self.rect()
        s = self._handle_size()
        return pos.x() >= r.right() - s and pos.y() >= r.bottom() - s

    def hoverMoveEvent(self, ev):
        self.setCursor(Qt.SizeFDiagCursor if self._in_handle(ev.pos()) else Qt.SizeAllCursor)
        super().hoverMoveEvent(ev)

    def mousePressEvent(self, ev):
        self._press_geo = self._geo()
        if ev.button() == Qt.LeftButton and self._in_handle(ev.pos()):
            self._resizing = True
            self.setSelected(True)
            ev.accept()
            return
        super().mousePressEvent(ev)

    def mouseMoveEvent(self, ev):
        if self._resizing:
            img = self.view.image
            w = max(4.0, ev.pos().x())
            h = max(4.0, ev.pos().y())
            if img is not None:
                w = min(w, img.width() - self.pos().x())
                h = min(h, img.height() - self.pos().y())
            self.prepareGeometryChange()
            self.setRect(0, 0, round(w), round(h))
            self.sync()
            self.view.region_changed.emit()
            return
        super().mouseMoveEvent(ev)

    def mouseReleaseEvent(self, ev):
        self._resizing = False
        super().mouseReleaseEvent(ev)
        if self._press_geo is not None and self._press_geo != self._geo():
            self.region.base = None            # edited by hand: the margin setting no longer applies
        self._press_geo = None

    def contextMenuEvent(self, ev):
        self.view.scene().clearSelection()
        self.setSelected(True)
        self.view.show_menu(ev.screenPos())

    # painting ----------------------------------------------------------------
    def set_effect(self, effect: str):
        self.region.effect = effect
        self._cache_key = None
        self.update()

    def paint(self, painter, option, widget=None):
        img = self.view.image
        r = self.region
        if img is not None:
            key = (r.x, r.y, r.w, r.h, r.effect)
            if key != self._cache_key:
                rect = image_effects.clip_rect(img, r.x, r.y, r.w, r.h)
                pt = image_effects.patch(img, rect, r.effect)
                self._cache = QPixmap.fromImage(pt) if not pt.isNull() else None
                self._cache_key = key
            if self._cache is not None:
                painter.drawPixmap(0, 0, self._cache)
        color = QColor(COLORS.get(r.source, "#2980b9"))
        pen = QPen(color, 0)
        pen.setCosmetic(True)
        pen.setWidth(3 if self.isSelected() else 2)
        if self.isSelected():
            pen.setStyle(Qt.DashLine)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawRect(self.rect())
        s = self._handle_size()
        rr = self.rect()
        painter.fillRect(QRectF(rr.right() - s, rr.bottom() - s, s, s), QBrush(color))


class ImageCanvas(QGraphicsView):
    region_changed = Signal()
    selection_changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setScene(QGraphicsScene(self))
        self.setRenderHint(QPainter.SmoothPixmapTransform)
        self.setDragMode(QGraphicsView.NoDrag)
        self.setBackgroundBrush(QColor("#6d6d6d"))
        self.image: QImage | None = None
        self._pix: QGraphicsPixmapItem | None = None
        self._drawing: RegionItem | None = None
        self._origin = QPointF()
        self.default_effect = "black"
        self.menu_callback = None
        self.scene().selectionChanged.connect(self.selection_changed.emit)

    def set_image(self, img: QImage | None):
        self.scene().clear()
        self._pix = None
        self.image = img
        if img is None or img.isNull():
            self.image = None
            self.region_changed.emit()
            return
        self._pix = self.scene().addPixmap(QPixmap.fromImage(img))
        self._pix.setZValue(-1)
        self.scene().setSceneRect(QRectF(0, 0, img.width(), img.height()))
        self.fit()
        self.region_changed.emit()

    def fit(self):
        if self.image is not None:
            self.fitInView(self.scene().sceneRect(), Qt.KeepAspectRatio)

    def items_list(self) -> list[RegionItem]:
        return [i for i in self.scene().items() if isinstance(i, RegionItem)][::-1]

    def regions(self) -> list[Region]:
        return [i.region for i in self.items_list()]

    def add_region(self, region: Region) -> RegionItem:
        it = RegionItem(self, region)
        self.scene().addItem(it)
        self.region_changed.emit()
        return it

    def remove(self, items):
        for it in items:
            self.scene().removeItem(it)
        self.region_changed.emit()

    def clear_regions(self, source: str | None = None):
        self.remove([i for i in self.items_list() if source is None or i.region.source == source])

    def show_menu(self, screen_pos):
        if self.menu_callback:
            self.menu_callback(screen_pos)

    # drawing new boxes ----------------------------------------------------------
    def mousePressEvent(self, ev):
        if self.image is not None and ev.button() == Qt.LeftButton:
            hit = self.itemAt(ev.position().toPoint())
            if hit is None or hit is self._pix:
                p = self.mapToScene(ev.position().toPoint())
                p = QPointF(min(max(0, p.x()), self.image.width()), min(max(0, p.y()), self.image.height()))
                self.scene().clearSelection()
                self._origin = p
                self._drawing = self.add_region(Region(int(p.x()), int(p.y()), 1, 1, "MANUAL",
                                                       self.default_effect, "", "manual"))
                ev.accept()
                return
        super().mousePressEvent(ev)

    def mouseMoveEvent(self, ev):
        if self._drawing is not None:
            p = self.mapToScene(ev.position().toPoint())
            p = QPointF(min(max(0, p.x()), self.image.width()), min(max(0, p.y()), self.image.height()))
            x0, y0 = min(p.x(), self._origin.x()), min(p.y(), self._origin.y())
            w, h = abs(p.x() - self._origin.x()), abs(p.y() - self._origin.y())
            it = self._drawing
            it.setFlag(QGraphicsItem.ItemSendsGeometryChanges, False)
            it.setPos(round(x0), round(y0))
            it.setFlag(QGraphicsItem.ItemSendsGeometryChanges, True)
            it.prepareGeometryChange()
            it.setRect(0, 0, max(1, round(w)), max(1, round(h)))
            it.sync()
            it.update()
            return
        super().mouseMoveEvent(ev)

    def mouseReleaseEvent(self, ev):
        if self._drawing is not None:
            it, self._drawing = self._drawing, None
            if it.region.w < 4 or it.region.h < 4:
                self.remove([it])
            else:
                it.setSelected(True)
                self.region_changed.emit()
            return
        super().mouseReleaseEvent(ev)

    def wheelEvent(self, ev):
        if ev.modifiers() & Qt.ControlModifier:
            f = 1.15 if ev.angleDelta().y() > 0 else 1 / 1.15
            self.scale(f, f)
            return
        super().wheelEvent(ev)


class ImageView(QWidget):
    status = Signal(str)

    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.c = controller
        self.canvas = ImageCanvas()
        self.canvas.menu_callback = self._menu
        self.btn_from = QPushButton(t("img.from_clipboard"))
        self.btn_open = QPushButton(t("img.open_file"))
        self.btn_detect = QPushButton(t("img.detect"))
        self.btn_to = QPushButton(t("img.to_clipboard"))
        self.btn_save = QPushButton(t("img.save"))
        self.btn_fit = QPushButton(t("img.fit"))
        self.effect = QComboBox()
        for e in EFFECTS:
            self.effect.addItem(t("effect." + e), e)
        self.btn_delete = QPushButton(t("img.delete"))
        self.btn_clear = QPushButton(t("img.clear"))
        self.table = make_table([t("col.type"), t("col.text"), t("img.col_effect")])
        track_table(getattr(controller, "ui_state", None), "image/columns", self.table)
        self.face_margin = QSpinBox()
        self.face_margin.setRange(0, 200)
        self.face_margin.setSingleStep(5)
        self.face_margin.setSuffix(" %")
        self.face_margin.setToolTip(t("img.face_margin_tip"))
        cfg = getattr(controller, "cfg", None)
        if cfg is not None:
            self.face_margin.setValue(int(cfg.get("image.face_margin", 15) or 0))
            self.face_margin.setEnabled(not cfg.is_locked("image.face_margin"))
        else:
            self.face_margin.setValue(15)
        self._save_margin = QTimer(self)
        self._save_margin.setSingleShot(True)
        self._save_margin.setInterval(600)
        self._save_margin.timeout.connect(self._store_margin)
        self.info = QLabel(t("img.hint"))
        self.info.setWordWrap(True)

        bar = QHBoxLayout()
        bar.addWidget(QLabel("<b>1. " + t("img.step_image") + "</b>"))
        bar.addWidget(self.btn_from)
        bar.addWidget(self.btn_open)
        bar.addSpacing(16)
        bar.addWidget(QLabel("<b>2. " + t("img.step_detect") + "</b>"))
        bar.addWidget(self.btn_detect)
        bar.addSpacing(16)
        bar.addWidget(QLabel("<b>3. " + t("img.step_result") + "</b>"))
        bar.addWidget(self.btn_to)
        bar.addWidget(self.btn_save)
        bar.addStretch(1)
        bar.addWidget(self.btn_fit)

        side = QWidget()
        sl = QVBoxLayout(side)
        sl.setContentsMargins(0, 0, 0, 0)
        sl.addWidget(QLabel(t("img.regions")))
        sl.addWidget(self.table, 1)
        row = QHBoxLayout()
        row.addWidget(QLabel(t("img.col_effect") + ":"))
        row.addWidget(self.effect, 1)
        sl.addLayout(row)
        row_m = QHBoxLayout()
        row_m.addWidget(QLabel(t("img.face_margin") + ":"))
        row_m.addWidget(self.face_margin, 1)
        sl.addLayout(row_m)
        row2 = QHBoxLayout()
        row2.addWidget(self.btn_delete)
        row2.addWidget(self.btn_clear)
        sl.addLayout(row2)
        sl.addWidget(self.info)

        self.split = QSplitter(Qt.Horizontal)
        self.split.addWidget(self.canvas)
        self.split.addWidget(side)
        self.split.setStretchFactor(0, 1)
        self.split.setChildrenCollapsible(False)
        st = getattr(controller, "ui_state", None)
        if st is not None:
            st.track("image/split", self.split, [800, 300])

        lay = QVBoxLayout(self)
        lay.addLayout(bar)
        lay.addWidget(self.split, 1)

        self.btn_from.clicked.connect(self.load_clipboard)
        self.btn_open.clicked.connect(self.open_file)
        self.btn_detect.clicked.connect(self.detect)
        self.btn_to.clicked.connect(self.to_clipboard)
        self.btn_save.clicked.connect(self.save_file)
        self.btn_fit.clicked.connect(self.canvas.fit)
        self.btn_delete.clicked.connect(self.delete_selected)
        self.btn_clear.clicked.connect(lambda: self.canvas.clear_regions())
        self.effect.activated.connect(self._effect_chosen)
        self.face_margin.valueChanged.connect(self._margin_changed)
        self.canvas.region_changed.connect(self.refresh_table)
        self.canvas.selection_changed.connect(self._scene_selection)
        self.table.itemSelectionChanged.connect(self._table_selection)
        QShortcut(QKeySequence.Delete, self.canvas, activated=self.delete_selected)
        self._syncing = False
        self._update_buttons()

    # ------------------------------------------------------------------ image in
    def set_image(self, img: QImage | None, detect: bool = False):
        self.canvas.set_image(img)
        self._update_buttons()
        if img is not None and detect:
            self.detect()

    def load_clipboard(self, detect: bool = True):
        img = self.c.read_clipboard_image()
        if img is None:
            self.status.emit(t("msg.no_image"))
            self.c.notify(t("msg.no_image"), force=True)
            return
        self.set_image(img, detect=detect)

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, t("img.open_file"), "",
                                              t("img.filter") + " (*.png *.jpg *.jpeg *.bmp *.gif *.webp *.tif *.tiff)")
        if not path:
            return
        img = QImage(path)
        if img.isNull():
            self.c.notify(t("img.cannot_open"), error=True)
            return
        self.set_image(img, detect=True)

    # ------------------------------------------------------------------ detection
    def detect(self):
        if self.canvas.image is None:
            return
        self.btn_detect.setEnabled(False)
        self.info.setText(t("img.detecting"))
        self.c.detect_image_regions(self.canvas.image, self._detected)

    def _detected(self, result):
        self.btn_detect.setEnabled(self.canvas.image is not None)
        regions, message = result
        if regions is not None:
            for src in ("face", "nudity", "text", "code"):
                self.canvas.clear_regions(src)
            for r in regions:
                self.canvas.add_region(r)
        self.info.setText(message)

    def _margin_changed(self, pct: int):
        """Grow/shrink the detected faces around their detected box (hand-edited boxes stay)."""
        img = self.canvas.image
        if img is not None:
            cfg = getattr(self.c, "cfg", None)
            pad = int((cfg.get("image.padding", 3) if cfg is not None else 3) or 0)
            for it in self.canvas.items_list():
                r = it.region
                if r.source == "face" and r.base is not None:
                    it.set_geometry(*with_margin(r.base, pct, pad, img.width(), img.height()))
        self._save_margin.start()

    def _store_margin(self):
        cfg = getattr(self.c, "cfg", None)
        if cfg is not None and not cfg.is_locked("image.face_margin"):
            cfg.set("image.face_margin", int(self.face_margin.value()))

    # ------------------------------------------------------------------ result
    def result_image(self) -> QImage | None:
        if self.canvas.image is None:
            return None
        return image_effects.render(self.canvas.image, self.canvas.regions())

    def to_clipboard(self):
        img = self.result_image()
        if img is not None:
            self.c.write_clipboard_image(img, len(self.canvas.regions()))

    def save_file(self):
        img = self.result_image()
        if img is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, t("img.save"), "redacted.png", "PNG (*.png);;JPEG (*.jpg)")
        if not path:
            return
        fmt = "JPG" if path.lower().endswith((".jpg", ".jpeg")) else "PNG"
        out = img.convertToFormat(QImage.Format_RGB32) if fmt == "JPG" else img
        if out.save(path, fmt, 92 if fmt == "JPG" else -1):
            self.c.notify(t("img.saved", path=path), force=True)
        else:
            self.c.notify(t("img.save_failed", path=path), error=True)

    # ------------------------------------------------------------------ regions
    def delete_selected(self):
        self.canvas.remove([i for i in self.canvas.items_list() if i.isSelected()])

    def _selected_items(self):
        return [i for i in self.canvas.items_list() if i.isSelected()]

    def _effect_chosen(self, _idx=None):
        eff = self.effect.currentData()
        items = self._selected_items()
        if items:
            for it in items:
                it.set_effect(eff)
            self.refresh_table()
        else:
            self.canvas.default_effect = eff

    def _menu(self, screen_pos):
        m = QMenu(self)
        for e in EFFECTS:
            a = m.addAction(t("effect." + e))
            a.triggered.connect(lambda _=False, x=e: self._set_effect_selected(x))
        m.addSeparator()
        m.addAction(t("img.delete")).triggered.connect(self.delete_selected)
        m.exec(screen_pos)

    def _set_effect_selected(self, eff):
        for it in self._selected_items():
            it.set_effect(eff)
        self.refresh_table()

    def refresh_table(self):
        items = self.canvas.items_list()
        self._syncing = True
        self.table.setRowCount(len(items))
        for row, it in enumerate(items):
            r = it.region
            kind = t("img.kind." + r.kind) if r.kind in ("FACE", "NUDITY", "QR_CODE", "BARCODE", "MANUAL") else r.kind
            self.table.setItem(row, 0, item(kind, data=row))
            self.table.setItem(row, 1, item(r.label))
            self.table.setItem(row, 2, item(t("effect." + r.effect)))
            if it.isSelected():
                self.table.selectRow(row)
        self._syncing = False
        self._update_buttons()

    def _scene_selection(self):
        if self._syncing:
            return
        self._syncing = True
        self.table.clearSelection()
        items = self.canvas.items_list()
        for row, it in enumerate(items):
            if it.isSelected():
                self.table.selectRow(row)
        sel = self._selected_items()
        if sel:
            self.effect.setCurrentIndex(max(0, self.effect.findData(sel[0].region.effect)))
        self._syncing = False
        self._update_buttons()

    def _table_selection(self):
        if self._syncing:
            return
        rows = {i.row() for i in self.table.selectedItems()}
        items = self.canvas.items_list()
        self._syncing = True
        for row, it in enumerate(items):
            it.setSelected(row in rows)
        if rows:
            it = items[min(rows)]
            self.canvas.ensureVisible(it.sceneBoundingRect())
        self._syncing = False
        self._update_buttons()

    def _update_buttons(self):
        has = self.canvas.image is not None
        for b in (self.btn_detect, self.btn_to, self.btn_save, self.btn_fit, self.btn_clear):
            b.setEnabled(has)
        self.btn_delete.setEnabled(bool(self._selected_items()))

    def showEvent(self, ev):
        super().showEvent(ev)
        cfg = getattr(self.c, "cfg", None)
        if cfg is not None and not self._save_margin.isActive():      # changed in the settings meanwhile
            self.face_margin.blockSignals(True)
            self.face_margin.setValue(int(cfg.get("image.face_margin", 15) or 0))
            self.face_margin.blockSignals(False)
            self.face_margin.setEnabled(not cfg.is_locked("image.face_margin"))
        self.canvas.fit()
