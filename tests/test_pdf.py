"""PDF redaction: the text under a box is gone from the file, not just painted over."""

import os
import tempfile
import unittest

from tests import helpers  # noqa: F401

from clipcloak.core import pdfredact as pr
from clipcloak.core.engine import Engine

try:
    import pymupdf as m
except ImportError:                                # pragma: no cover
    try:
        import fitz as m
    except ImportError:
        m = None

EMAIL = "jonas.hartmann@contoso.com"
IP = "10.88.10.10"
PW = "S3cr3t!Xy9q"


def make_pdf(path, rotate=0, extra=None):
    d = m.open()
    p = d.new_page()
    p.insert_text((72, 72), f"Kontakt: {EMAIL}, Server {IP}", fontsize=11)
    p.insert_text((72, 100), f"password: {PW} und Kölpertechnis GmbH", fontsize=11)
    p.insert_text((72, 130), "unsichtbar: 10.1.2.3", fontsize=11, render_mode=3)
    p.insert_text((72, 800), "ausserhalb: 10.9.9.9", fontsize=11)
    p.set_cropbox(m.Rect(0, 0, 595, 700))                                  # the last line is not visible
    p.add_text_annot((300, 300), "Kommentar von Jonas Hartmann")
    if rotate:
        p.set_rotation(rotate)
    p2 = d.new_page()
    p2.insert_text((72, 72), "Seite zwei ohne Daten", fontsize=11)
    if extra:
        extra(d)
    d.set_metadata({"author": "Jonas Hartmann", "title": "Intern", "subject": IP})
    d.set_toc([[1, "Kapitel Jonas Hartmann " + IP, 1]])
    d.embfile_add("notes.txt", f"secret {PW}".encode())
    d.save(path)
    d.close()


def all_text(path) -> str:
    d = m.open(path)
    try:
        return "\n".join(pg.get_text("text", flags=0, clip=m.INFINITE_RECT()) for pg in d) + str(d.metadata) + \
            str(d.get_toc())
    finally:
        d.close()


@unittest.skipIf(m is None, "PyMuPDF not installed")
class PdfRedactTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.src = os.path.join(self.tmp, "in.pdf")
        self.dst = os.path.join(self.tmp, "out.pdf")
        self.e = Engine()

    def test_redact_removes_the_text_and_the_rest(self):
        make_pdf(self.src)
        rep = pr.redact_pdf(self.src, self.dst, self.e, "redact")
        self.assertEqual(rep.leftovers, [])
        self.assertGreaterEqual(rep.counts.get("IPV4", 0), 3)       # visible, invisible, outside the page
        text = all_text(self.dst)
        for s in (EMAIL, IP, PW, "10.1.2.3", "Kölpertechnis", "Jonas", "Hartmann"):
            self.assertNotIn(s, text)
        self.assertIn("Kontakt:", text)                              # the rest stays
        self.assertIn("Seite zwei ohne Daten", text)
        d = m.open(self.dst)
        try:
            self.assertEqual(d.embfile_count(), 0)
            self.assertEqual(list(d[0].annots()), [])
            self.assertFalse(d.metadata.get("author"))
            for x in range(1, d.xref_length()):          # every object and (decompressed) stream
                data = (d.xref_object(x) or "").encode() + (d.xref_stream(x) or b"" if d.xref_is_stream(x) else b"")
                for s in (PW, IP, "Jonas", "10.9.9.9"):
                    self.assertNotIn(s.encode(), data)
        finally:
            d.close()

    def test_pseudonymize_writes_the_replacement(self):
        make_pdf(self.src)
        rep = pr.redact_pdf(self.src, self.dst, self.e, "pseudonymize")
        self.assertEqual(rep.leftovers, [])
        text = all_text(self.dst)
        self.assertNotIn(EMAIL, text)
        self.assertNotIn(IP, text)
        surrogate = next(r.replacement for r in rep.result.replacements if r.original == EMAIL)
        self.assertIn(surrogate, text.replace("\n", ""))
        self.assertEqual(self.e.revert(surrogate).output, EMAIL)             # in the mappings like any text

    def test_rotated_page(self):
        make_pdf(self.src, rotate=90)
        rep = pr.redact_pdf(self.src, self.dst, self.e, "redact")
        self.assertEqual(rep.leftovers, [])
        self.assertNotIn(IP, all_text(self.dst))

    def test_images_and_rasterize(self):
        def add_image(d):
            pix = m.Pixmap(m.csRGB, m.IRect(0, 0, 400, 300), False)
            pix.set_rect(pix.irect, (200, 50, 50))
            d[1].insert_image(m.Rect(72, 200, 472, 500), pixmap=pix)
        make_pdf(self.src, extra=add_image)
        seen = []

        def analyser(png, w, h):
            seen.append((w, h))
            return [(10, 10, 100, 50, "FACE", "")]            # pixels of the rendered image

        rep = pr.redact_pdf(self.src, self.dst, self.e, "redact", analyser=analyser)
        self.assertEqual((rep.images_total, rep.images_analysed), (1, 1))
        self.assertEqual(rep.counts.get("FACE"), 1)
        d = m.open(self.dst)
        pix = d[1].get_pixmap(dpi=72)
        self.assertEqual(pix.pixel(72 + 12, 200 + 12), (0, 0, 0))            # the face is black
        self.assertEqual(pix.pixel(300, 400), (200, 50, 50))                  # the rest of the image stays
        d.close()
        rep = pr.redact_pdf(self.src, self.dst, self.e, "redact", rasterize=True, dpi=72)
        d = m.open(self.dst)
        self.assertEqual("".join(pg.get_text() for pg in d).strip(), "")      # no text at all
        self.assertEqual(d.page_count, 2)
        d.close()

    def test_password(self):
        make_pdf(self.src)
        enc = os.path.join(self.tmp, "enc.pdf")
        d = m.open(self.src)
        d.save(enc, encryption=m.PDF_ENCRYPT_AES_256, user_pw="geheim", owner_pw="geheim2")
        d.close()
        with self.assertRaises(pr.PdfPasswordError):
            pr.redact_pdf(enc, self.dst, self.e)
        rep = pr.redact_pdf(enc, self.dst, self.e, password="geheim")
        self.assertEqual(rep.leftovers, [])
        self.assertFalse(m.open(self.dst).needs_pass)                           # result without password
        self.assertNotIn(IP, all_text(self.dst))

    def test_verify_finds_leftovers(self):
        make_pdf(self.src)
        self.assertEqual(pr.verify(self.src, [IP, "Maximum"]), [IP])
        self.assertEqual(pr.verify(self.src, ["Kont"]), [])                   # whole words only

    def test_not_a_pdf(self):
        bad = os.path.join(self.tmp, "x.pdf")
        with open(bad, "w") as fh:
            fh.write("kein pdf")
        with self.assertRaises(pr.PdfError):
            pr.redact_pdf(bad, self.dst, self.e)

    def test_cli(self):
        from clipcloak.cli import main
        make_pdf(self.src)
        rc = main(["--config", os.path.join(self.tmp, "c.yaml"), "pdf", self.src, "-o", self.dst])
        self.assertEqual(rc, 0)
        self.assertNotIn(IP, all_text(self.dst))
        self.assertEqual(main(["--config", os.path.join(self.tmp, "c.yaml"), "pdf", self.src, "-o", self.src]), 2)


@unittest.skipIf(m is None, "PyMuPDF not installed")
class PdfTabTest(unittest.TestCase):
    def setUp(self):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication

        from clipcloak.config import Config
        from clipcloak.gui.app import Controller
        from clipcloak.core.projects import ProjectStore
        self.app = QApplication.instance() or QApplication([])
        self.tmp = tempfile.mkdtemp()
        cfg = Config(os.path.join(self.tmp, "config.yaml"))
        cfg.set("hotkeys", {k: "" for k in cfg.get("hotkeys")})
        cfg.set("ner.helper_path", os.path.join(self.tmp, "missing-helper"))
        self.c = Controller(self.app, cfg)
        self.c.store = ProjectStore(os.path.join(self.tmp, "projects"))

    def tearDown(self):
        from tests.test_gui import spin
        self.c.shutdown()
        if self.c.main is not None:
            self.c.main.deleteLater()
        spin(50)

    def test_detect_edit_save(self):
        from PySide6.QtCore import Qt
        from PySide6.QtTest import QTest

        from tests.test_gui import spin, wait_for
        src = os.path.join(self.tmp, "in.pdf")
        dst = os.path.join(self.tmp, "out.pdf")
        make_pdf(src)
        self.c.process_file(src)                                    # "Process file" with a PDF -> PDF tab
        v = self.c.main.pdf
        self.assertEqual(self.c.main.tabs.currentWidget(), v)
        self.assertTrue(wait_for(lambda: v.findings and not v._busy, 10000))
        self.assertEqual(len(v.offpage), 1)                         # the line outside the crop box
        labels = [r.label for _p, r in v.all_regions()]
        self.assertIn(IP, labels)
        self.assertIn(EMAIL, labels)
        # the user keeps the company name: delete its box
        org = [it for it in v.canvas.items_list() if "Kölpertechnis" in it.region.label]
        self.assertTrue(org)
        v.canvas.remove(org)
        # and draws a box by hand on page 2 over "zwei"
        v.show_page(1)
        v.canvas.show()
        v.canvas.resize(800, 1000)
        v.canvas.fit()
        spin(50)
        word = m.open(src)[1].search_for("zwei")[0]
        tl = v.canvas.mapFromScene((word.x0 - 1) * 2, (word.y0 - 1) * 2)
        br = v.canvas.mapFromScene((word.x1 + 1) * 2, (word.y1 + 1) * 2)
        QTest.mousePress(v.canvas.viewport(), Qt.LeftButton, pos=tl)
        QTest.mouseMove(v.canvas.viewport(), br)
        QTest.mouseRelease(v.canvas.viewport(), Qt.LeftButton, pos=br)
        self.assertEqual(len([r for p, r in v.all_regions() if p == 1]), 1)
        self.assertEqual(v.table.rowCount(), len(v.all_regions()))
        v.save(dst)
        self.assertTrue(wait_for(lambda: not v._busy and os.path.exists(dst), 10000))
        spin(100)
        text = all_text(dst)
        self.assertNotIn(IP, text)
        self.assertNotIn(EMAIL, text)
        self.assertNotIn("10.9.9.9", text)
        self.assertIn("Kölpertechnis", text)                      # deleted box: stays
        self.assertNotIn("zwei", text)                             # the box drawn by hand
        self.assertIn("Seite", text)
        self.assertTrue(any(e.source == "pdf" for e in self.c.history.entries))



@unittest.skipIf(m is None, "PyMuPDF not installed")
class PdfScanTest(PdfTabTest):
    def test_detect_edit_save(self):                     # inherited test: run once, in PdfTabTest
        pass

    def test_scanned_page_via_plugin(self):
        from tests.test_gui import wait_for
        from tests.test_image import FakePlugin
        plugin = FakePlugin()
        self.c.plugin_client = lambda: plugin
        self.c.cfg.set("pdf.dpi", 72)                     # 1 image pixel = 1 point at 72 dpi
        src = os.path.join(self.tmp, "scan.pdf")
        dst = os.path.join(self.tmp, "scan-out.pdf")
        d = m.open()
        page = d.new_page()
        pix = m.Pixmap(m.csRGB, m.IRect(0, 0, 595, 842), False)
        pix.set_rect(pix.irect, (230, 230, 230))
        page.insert_image(page.rect, pixmap=pix)          # a scan: one image over the whole page, no text
        d.save(src)
        d.close()
        self.c.redact_pdf(src)
        v = self.c.main.pdf
        self.assertTrue(wait_for(lambda: not v._busy and v.all_regions(), 10000))
        kinds = sorted(r.kind for _p, r in v.all_regions())
        self.assertEqual(kinds, ["FACE", "IPV4", "NUDITY"])
        self.assertIn("ocr", plugin.ops)
        v.save(dst)
        self.assertTrue(wait_for(lambda: not v._busy and os.path.exists(dst), 10000))
        out = m.open(dst)
        p = out[0].get_pixmap(dpi=72)
        self.assertEqual(p.pixel(250 + 30, 60 + 35), (0, 0, 0))     # the face (FakePlugin: 250, 60, 60x70)
        self.assertEqual(p.pixel(500, 700), (230, 230, 230))        # the rest of the scan
        out.close()


if __name__ == "__main__":
    unittest.main()
