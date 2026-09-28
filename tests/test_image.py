"""Image redaction: OCR -> regions, effects, image tab, watcher."""

import os
import tempfile
import unittest

from tests import helpers  # noqa: F401

from PySide6.QtCore import QEventLoop, QTimer  # noqa: E402
from PySide6.QtGui import QColor, QImage, QPainter  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from clipcloak.config import Config, engine_settings  # noqa: E402
from clipcloak.core.engine import Engine  # noqa: E402
from clipcloak.core.imageredact import ImageSettings, Region, face_regions, span_box, text_regions  # noqa: E402
from clipcloak.core.projects import ProjectStore  # noqa: E402
from clipcloak.core.vault import Vault  # noqa: E402

app = QApplication.instance() or QApplication([])


def spin(ms=100):
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def wait_for(cond, timeout=5000):
    waited = 0
    while waited < timeout:
        if cond():
            return True
        spin(50)
        waited += 50
    return cond()


def ocr_line(text, x, y, char_w=10, h=20):
    """A fake OCR line with one box per character (like the plugin returns)."""
    words = [{"text": ch, "s": i, "e": i + 1, "x": x + i * char_w, "y": y, "w": char_w, "h": h}
             for i, ch in enumerate(text) if ch != " "]
    return {"text": text, "x": x, "y": y, "w": len(text) * char_w, "h": h, "score": 0.9, "words": words}


def picture(w=400, h=300) -> QImage:
    img = QImage(w, h, QImage.Format_ARGB32)
    img.fill(QColor("white"))
    p = QPainter(img)
    for i in range(0, w, 8):                        # stripes, so a mosaic visibly changes pixels
        p.fillRect(i, 0, 4, h, QColor("#3366cc"))
    p.end()
    return img


class RegionMappingTest(unittest.TestCase):
    def setUp(self):
        self.engine = Engine(engine_settings(Config()), Vault("t"))

    def test_findings_become_boxes_over_their_characters(self):
        lines = [ocr_line("Server srv01 IP 10.88.10.10", 20, 10),
                 ocr_line("Mail: jonas.hartmann@contoso.com", 20, 50),
                 ocr_line("nothing here", 20, 90)]
        regs = text_regions(lines, self.engine.analyze, ImageSettings(padding=0), 800, 200)
        kinds = {r.kind for r in regs}
        self.assertIn("IPV4", kinds)
        self.assertIn("EMAIL", kinds)
        ip = next(r for r in regs if r.kind == "IPV4")
        start = "Server srv01 IP ".__len__()
        self.assertEqual(ip.x, 20 + start * 10)
        self.assertEqual(ip.w, len("10.88.10.10") * 10)
        self.assertEqual((ip.y, ip.h), (10, 20))
        self.assertEqual(ip.effect, "black")
        self.assertFalse(any(r.y >= 90 for r in regs))

    def test_key_value_context_across_the_line(self):
        lines = [ocr_line("password: S3cr3t!Pass2024", 0, 0)]
        regs = text_regions(lines, self.engine.analyze, ImageSettings(padding=2), 500, 100)
        self.assertTrue(regs)
        r = regs[0]
        self.assertGreaterEqual(r.x, len("password: ") * 10 - 2 - 1)

    def test_proportional_fallback_without_word_boxes(self):
        line = {"text": "abcdefghij", "x": 100, "y": 5, "w": 200, "h": 10, "words": []}
        self.assertEqual(span_box(line, 5, 10), {"x": 200, "y": 5, "w": 100, "h": 10})

    def test_face_margin_configurable(self):
        box = [{"x": 100, "y": 100, "w": 50, "h": 60}]
        r0 = face_regions(box, ImageSettings(face_margin=0, padding=0), 400, 400)[0]
        self.assertEqual(r0.as_tuple(), (100, 100, 50, 60))
        r50 = face_regions(box, ImageSettings(face_margin=50, padding=0), 400, 400)[0]
        self.assertEqual(r50.as_tuple(), (70, 70, 110, 120))          # 50 % of 60 = 30 px on every side
        self.assertEqual(r50.base, (100, 100, 50, 60))
        s = ImageSettings.from_config({"face_margin": 80, "nudity_margin": "x"})
        self.assertEqual((s.face_margin, s.nudity_margin), (80, 0))
        self.assertEqual(ImageSettings.from_config({}).face_margin, 20)
        self.assertEqual(ImageSettings.from_config({"face_margin": 999}).face_margin, 200)

    def test_face_margin_and_clamping(self):
        regs = face_regions([{"x": 5, "y": 5, "w": 100, "h": 100}], ImageSettings(), 110, 110)
        r = regs[0]
        self.assertEqual((r.x, r.y), (0, 0))
        self.assertLessEqual(r.x + r.w, 110)
        self.assertEqual(r.effect, "mosaic")


class EffectsTest(unittest.TestCase):
    def test_render(self):
        from clipcloak.gui.image_effects import render
        src = picture()
        src.setText("Author", "Jonas")                  # metadata must not survive
        out = render(src, [Region(10, 10, 50, 40, effect="black"),
                           Region(200, 100, 120, 120, effect="mosaic"),
                           Region(100, 200, 60, 60, effect="blur")])
        self.assertEqual(out.size(), src.size())
        self.assertEqual(out.textKeys(), [])
        self.assertEqual(QColor(out.pixel(30, 30)).name(), "#000000")
        self.assertEqual(out.pixel(300, 20), src.pixel(300, 20))      # outside unchanged
        # mosaic: blocks of equal colour, different from the stripes
        block = [out.pixel(200 + dx, 100) for dx in range(0, 12)]
        self.assertEqual(len(set(block)), 1)
        self.assertNotEqual([out.pixel(200 + dx, 150) for dx in range(8)],
                            [src.pixel(200 + dx, 150) for dx in range(8)])


class FakePlugin:
    def __init__(self):
        self.ops = []

    def request(self, payload, timeout=None):
        op = payload.get("op")
        self.ops.append(op)
        if op == "faces":
            return {"boxes": [{"x": 250, "y": 60, "w": 60, "h": 70, "score": 0.9, "kind": "FACE"}]}
        if op == "codes":
            return {"boxes": []}
        if op == "nudity":
            return {"boxes": [{"x": 40, "y": 100, "w": 50, "h": 40, "score": 0.8, "kind": "NUDITY",
                               "part": "BUTTOCKS_EXPOSED"}]}
        if op == "ocr":
            return {"boxes": [ocr_line("host 10.88.10.10", 10, 200)]}
        raise RuntimeError("unknown op")


class ImageTabTest(unittest.TestCase):
    def setUp(self):
        from clipcloak.gui.app import Controller
        self.tmp = tempfile.mkdtemp()
        cfg = Config(os.path.join(self.tmp, "config.yaml"))
        cfg.set("hotkeys", {k: "" for k in cfg.get("hotkeys")})
        self.c = Controller(app, cfg)
        self.c.store = ProjectStore(os.path.join(self.tmp, "projects"))
        self.plugin = FakePlugin()
        self.c.plugin_client = lambda: self.plugin

    def tearDown(self):
        self.c.shutdown()
        if self.c.main is not None:
            self.c.main.deleteLater()
        spin(50)

    def test_redact_clipboard_image(self):
        c = self.c
        c.clip.cb.setImage(picture())
        c.redact_image()
        view = c.main.image
        self.assertIs(c.main.tabs.currentWidget(), view)
        self.assertTrue(wait_for(lambda: len(view.canvas.regions()) == 3))
        kinds = sorted(r.kind for r in view.canvas.regions())
        self.assertEqual(kinds, ["FACE", "IPV4", "NUDITY"])
        nude = next(r for r in view.canvas.regions() if r.kind == "NUDITY")
        self.assertEqual(nude.effect, "black")
        self.assertEqual(view.table.rowCount(), 3)
        # a box drawn by hand is kept when detecting again
        view.canvas.add_region(Region(0, 0, 20, 20))
        view.detect()
        self.assertTrue(wait_for(lambda: len(view.canvas.regions()) == 4))
        view.to_clipboard()
        img = c.clip.cb.image()
        self.assertFalse(img.isNull())
        self.assertEqual(QColor(img.pixel(5, 5)).name(), "#000000")

    def test_face_margin_in_tab(self):
        c = self.c
        c.cfg.set("image.face_margin", 0)
        c.cfg.set("image.padding", 0)
        c.clip.cb.setImage(picture())
        c.redact_image()
        view = c.main.image
        self.assertEqual(view.face_margin.value(), 0)
        self.assertTrue(wait_for(lambda: len(view.canvas.regions()) == 3))
        face = next(i for i in view.canvas.items_list() if i.region.source == "face")
        self.assertEqual(face.region.as_tuple(), (250, 60, 60, 70))
        view.face_margin.setValue(20)                                  # 20 % of 70 = 14 px
        self.assertEqual(face.region.as_tuple(), (236, 46, 88, 98))
        self.assertEqual((face.pos().x(), face.rect().width()), (236, 88))
        # a box edited by hand keeps its size
        face.region.base = None
        view.face_margin.setValue(60)
        self.assertEqual(face.region.as_tuple(), (236, 46, 88, 98))
        self.assertTrue(wait_for(lambda: c.cfg.get("image.face_margin") == 60, 2000))

    def test_progress_shown_while_detecting(self):
        import threading
        c = self.c
        gate = threading.Event()
        slow = FakePlugin()
        orig = slow.request

        def request(payload, timeout=None):
            if payload.get("op") == "codes":
                gate.wait(5)
            return orig(payload, timeout)
        slow.request = request
        c.plugin_client = lambda: slow
        c.clip.cb.setImage(picture())
        c.redact_image()
        view = c.main.image
        busy = view.canvas.busy
        self.assertTrue(busy.isVisible())
        self.assertFalse(view.btn_detect.isEnabled())
        self.assertFalse(view.btn_to.isEnabled())              # no half-redacted result
        self.assertTrue(wait_for(lambda: "3/4" in busy.step.text()))
        gate.set()
        self.assertTrue(wait_for(lambda: not busy.isVisible()))
        self.assertTrue(view.btn_to.isEnabled())
        self.assertEqual(view.btn_detect.text(), view.btn_detect.text().strip())
        self.assertEqual(len(view.canvas.regions()), 3)

    def test_without_plugin_manual_only(self):
        c = self.c
        c.plugin_client = lambda: None
        c.show_main("image")
        view = c.main.image
        view.set_image(picture(), detect=True)
        self.assertTrue(wait_for(lambda: "plugin" in view.info.text().lower() or "Plugin" in view.info.text()))
        self.assertEqual(view.canvas.regions(), [])

    def test_hotkey_action_on_image_opens_tab(self):
        c = self.c
        c.clip.cb.setImage(picture())
        c.process_clipboard("pseudonymize", "hotkey")
        self.assertIsNotNone(c.main)
        self.assertIs(c.main.tabs.currentWidget(), c.main.image)

    def test_watcher_offers_image_redaction(self):
        c = self.c
        c.set_watch_mode("notify")
        c.clip.cb.setImage(picture())
        c._watch_check()
        self.assertIsNotNone(c._popup)
        self.assertIn("image", c._popup.buttons)
        c._popup._choose("")
        c._popup = None
        c._watch_check()                       # same image: no second popup
        self.assertIsNone(c._popup)
        c.set_watch_mode("off")


if __name__ == "__main__":
    unittest.main()
