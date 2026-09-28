"""GUI smoke tests (run with QT_QPA_PLATFORM=offscreen)."""

import os
import tempfile
import unittest

from tests import helpers  # noqa: F401

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from clipcloak.config import Config  # noqa: E402
from clipcloak.core.projects import ProjectStore  # noqa: E402

app = QApplication.instance() or QApplication([])


def spin(ms=300):
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def wait_for(cond, timeout_ms=5000):
    waited = 0
    while not cond() and waited < timeout_ms:
        spin(50)
        waited += 50
    return cond()


class GuiTest(unittest.TestCase):
    def setUp(self):
        from clipcloak.gui.app import Controller
        self.tmp = tempfile.mkdtemp()
        cfg = Config(os.path.join(self.tmp, "config.yaml"))
        cfg.set("hotkeys", {k: "" for k in cfg.get("hotkeys")})   # no global grabs in tests
        self.c = Controller(app, cfg)
        self.c.store = ProjectStore(os.path.join(self.tmp, "projects"))

    def tearDown(self):
        self.c.shutdown()
        if self.c.main is not None:
            self.c.main.deleteLater()
        spin(50)

    def test_process_and_revert_clipboard(self):
        c = self.c
        original = "Mail jonas.hartmann@contoso.com Server 10.88.10.10 password: Geheim123"
        c.clip.write(original, "<p>Mail <b>jonas.hartmann@contoso.com</b></p>")
        c.run_action("pseudonymize", "hotkey")
        self.assertTrue(wait_for(lambda: len(c.history.entries) == 1))
        pseudo = c.clip.read()
        self.assertNotIn("hartmann", pseudo.text)
        self.assertNotIn("Geheim123", pseudo.text)
        if pseudo.html:
            self.assertNotIn("hartmann", pseudo.html)
        c.run_action("revert", "hotkey")
        self.assertTrue(wait_for(lambda: len(c.history.entries) == 2))
        self.assertEqual(c.clip.read().text, original)

    def test_windows_and_views(self):
        c = self.c
        c.engine.process("10.1.2.3 m.muster@kunde.de", "pseudonymize")
        c.show_main("mappings")
        self.assertGreater(c.main.mappings.table.rowCount(), 0)
        wb = c.main.workbench
        wb.set_text("Server 10.1.2.3 password: abc123xyz")
        self.assertTrue(wait_for(lambda: wb.findings.rowCount() == 2))
        wb.run()
        self.assertTrue(wait_for(lambda: bool(wb.output.toPlainText())))
        self.assertNotIn("abc123xyz", wb.output.toPlainText())
        c.show_main("history")
        c.main.history.refresh()
        c.main.history.table.selectRow(0)
        self.assertIn("Server", c.main.history.diff.left.toPlainText())

    def test_workbench_buttons_and_auto_copy(self):
        c = self.c
        c.show_main("workbench")
        wb = c.main.workbench
        self.assertEqual(set(wb.action_buttons), {"pseudonymize", "anonymize", "redact", "revert"})
        c.clip.write("unverändert", None)
        wb.auto_copy.setChecked(True)
        wb.set_text("Server 10.1.2.3 password: abc123xyz")
        wb.action_buttons["redact"].click()
        self.assertTrue(wait_for(lambda: bool(wb.output.toPlainText())))
        self.assertEqual(wb.output.toPlainText(), "Server [REDACTED] password: [REDACTED]")
        self.assertEqual(c.clip.read().text, wb.output.toPlainText())
        wb.auto_copy.setChecked(False)
        self.assertFalse(c.cfg.get("general.workbench_auto_copy"))
        c.clip.write("unverändert", None)
        wb.action_buttons["anonymize"].click()
        self.assertTrue(wait_for(lambda: "REDACTED" not in wb.output.toPlainText()))
        self.assertEqual(c.clip.read().text, "unverändert")

    def test_language_switch_requests_restart(self):
        from unittest import mock
        from PySide6.QtWidgets import QMessageBox
        c = self.c
        with mock.patch.object(QMessageBox, "question", return_value=QMessageBox.Yes):
            c.set_language("de")
        self.assertEqual(c.cfg.get("general.language"), "de")
        self.assertTrue(c.restart_requested)
        c.tray.rebuild()
        titles = [a.text() for a in c.tray.menu.actions()]
        self.assertNotIn("Sprache / Language", titles)      # language lives in the settings only
        from clipcloak import i18n
        i18n.init("en")

    def test_busy_indicator_and_log(self):
        import threading
        c = self.c
        c.show_main("log")
        gate = threading.Event()
        c.submit(lambda: gate.wait(5), label="Testjob")
        self.assertTrue(wait_for(lambda: c.active_jobs() == ["Testjob"]))
        self.assertTrue(wait_for(lambda: c.main.busy_bar.isVisible()))
        self.assertIn("Testjob", c.main.busy_label.text())
        gate.set()
        self.assertTrue(wait_for(lambda: not c.active_jobs()))
        self.assertTrue(wait_for(lambda: not c.main.busy_bar.isVisible()))
        c.clip.write("Server 10.1.2.3 password: Geheim99", None)
        c.run_action("pseudonymize", "hotkey")
        self.assertTrue(wait_for(lambda: len(c.history.entries) == 1))
        spin(100)
        log_text = c.main.log.text.toPlainText()
        self.assertIn("Testjob", log_text)
        self.assertIn("IPV4", log_text)
        self.assertNotIn("Geheim99", log_text)          # no clipboard contents in the log

    def test_watcher_critical(self):
        c = self.c
        c.set_watch_mode("critical")
        c.cfg.set("watcher.categories.secrets", "auto")
        c.clip.write("token glpat_abcdefghijklmnopqrst1234", None)
        c._on_clip_changed()
        self.assertTrue(wait_for(lambda: "abcdefghijklmnopqrst1234" not in (c.clip.read().text or "")))
        self.assertTrue(c.clip.read().text.startswith("token glpat-"))
        c.set_watch_mode("off")

    def test_watcher_rules_per_category(self):
        c = self.c
        c.cfg.set("lists.allow_domains", ["example.com"])
        c.apply_config()
        c.set_watch_mode("critical")
        # tracking: auto, persons (e-mail): ask -> link cleaned at once, popup for the address
        c.clip.write("Link https://example.com/p?id=5&utm_source=nl von max.muster@firma.de", None)
        c._watch_check()
        self.assertTrue(wait_for(lambda: "utm_source" not in (c.clip.read().text or "")))
        self.assertIn("max.muster@firma.de", c.clip.read().text)
        self.assertTrue(wait_for(lambda: c._popup is not None))
        from PySide6.QtWidgets import QLabel
        texts = " ".join(lab.text() for lab in c._popup.findChildren(QLabel))
        self.assertIn("EMAIL", texts)
        self.assertIn("1", texts)                      # "Already done: tracking removed: 1"
        self.assertNotIn("TRACKING", texts)
        c._popup._choose("")
        c._popup = None
        # persons: nothing -> no popup, tracking still removed
        c.cfg.set("watcher.categories.persons", "ignore")
        c.clip.write("wieder https://example.com/?fbclid=x2 an max.muster@firma.de", None)
        c._watch_check()
        self.assertTrue(wait_for(lambda: "fbclid" not in (c.clip.read().text or "")))
        spin(200)
        self.assertIsNone(c._popup)
        # notify: auto categories ask instead
        rules = c.watch_rules("notify")
        self.assertEqual(rules["TRACKING"], "ask")
        self.assertEqual(rules["EMAIL"], "ignore")
        self.assertEqual(c.watch_rules("always")["IPV4"], "auto")
        c.set_watch_mode("off")

    def test_watcher_offers_revert_for_pseudonymised_result(self):
        c = self.c
        original = "Bitte an jonas.hartmann@contoso.com, Server 10.88.10.10, password: Geheim123"
        pseudo = c.engine.process(original, "pseudonymize").output
        c.set_watch_mode("always")                   # would change everything at once
        # the LLM answers with the replacement values -> copied from the browser
        answer = "Klar, ich schreibe " + pseudo.split(" Server")[0].split("an ")[1] + " an. " + pseudo
        c.clip.write(answer, None)
        c._watch_check()
        self.assertTrue(wait_for(lambda: c._popup is not None))
        self.assertIn("revert", c._popup.buttons)
        self.assertNotIn("redact", c._popup.buttons)
        self.assertEqual(c.clip.read().text, answer)     # nothing changed automatically
        c._popup._choose("revert")
        self.assertTrue(wait_for(lambda: "jonas.hartmann@contoso.com" in (c.clip.read().text or "")))
        self.assertIn("Geheim123", c.clip.read().text)
        c.set_watch_mode("off")

    def test_real_data_is_not_mistaken_for_a_result(self):
        c = self.c
        c.engine.process("Mail an jonas.hartmann@contoso.com", "pseudonymize")
        c.set_watch_mode("notify")
        c.clip.write("Neue Daten: max.muster@firma.de, 10.1.1.1, kunde@beispiel-gmbh.de", None)
        c._watch_check()
        self.assertTrue(wait_for(lambda: c._popup is not None))
        self.assertNotIn("revert", c._popup.buttons)
        self.assertIn("redact", c._popup.buttons)
        c._popup._choose("")
        c.set_watch_mode("off")

    def test_workbench_marks_pseudonymised_input(self):
        c = self.c
        pseudo = c.engine.process("Mail an jonas.hartmann@contoso.com", "pseudonymize").output
        c.show_workbench(pseudo)
        wb = c.main.workbench
        self.assertTrue(wait_for(lambda: wb.pseudonymised > 0))
        self.assertTrue(wb.action_buttons["revert"].isDefault())
        c.show_workbench("nur max.muster@firma.de")
        self.assertTrue(wait_for(lambda: wb.pseudonymised == 0))
        self.assertFalse(wb.action_buttons["revert"].isDefault())

    def test_findings_grouped(self):
        c = self.c
        c.show_main("workbench")
        wb = c.main.workbench
        wb.input.setPlainText("a 10.0.0.1 b 10.0.0.1 c 10.0.0.1 d 10.0.0.2")
        wb.analyze()
        self.assertTrue(wait_for(lambda: wb.findings.rowCount() == 2))
        self.assertEqual(wb.findings.item(0, 2).text(), "3")
        wb.findings.selectRow(0)
        first = wb.input.textCursor().selectionStart()
        wb._next_occurrence(0)
        self.assertGreater(wb.input.textCursor().selectionStart(), first)

    def test_result_text_names_tracking_separately(self):
        from clipcloak.core.entities import Replacement, Result
        reps = [Replacement(0, 1, 0, 0, "TRACKING", "?utm=1", ""), Replacement(2, 3, 2, 3, "EMAIL", "a@b.de", "x@y.de")]
        text = self.c._result_text(Result("pseudonymize", "i", "o", reps, []))
        self.assertIn("EMAIL ×1", text)
        self.assertNotIn("TRACKING", text)
        only = self.c._result_text(Result("pseudonymize", "i", "o", reps[:1], []))
        self.assertNotIn("replacement", only.lower().replace("tracking removed", ""))

    def test_popup_shows_shortcuts(self):
        c = self.c
        c.cfg.set("hotkeys.pseudonymize", "Ctrl+Alt+P")
        c.hotkeys.backend = "x11"           # pretend the shortcut is registered
        c.hotkey_errors = {}
        c.clip.write("mail jonas.hartmann@contoso.com", None)
        c._findings_popup(c.engine.analyze("mail jonas.hartmann@contoso.com"), None, None)
        pop = c._popup
        self.assertIn("Ctrl+Alt+P", pop.buttons["pseudonymize"].text())
        self.assertNotIn("\n", pop.buttons["anonymize"].text())   # no shortcut configured
        c.hotkey_errors = {"pseudonymize": "taken"}
        self.assertEqual(c.hotkey_text("pseudonymize"), "")
        c.hotkeys.backend = "none"
        pop._choose("")
        spin(50)

    def test_layout_is_remembered(self):
        from clipcloak.gui.app import Controller
        c = self.c
        c.show_main("history")
        w = c.main
        w.resize(900, 700)
        spin(50)
        w.history.split.setSizes([300, 350])
        before = w.history.split.sizes()
        w.history.table.setColumnWidth(0, 222)
        w.save_state()
        self.assertTrue((self.tmp and os.path.exists(os.path.join(self.tmp, "ui.ini"))))
        c2 = Controller(app, Config(os.path.join(self.tmp, "config.yaml")))
        try:
            c2.show_main()
            spin(50)
            self.assertEqual(c2.main.tabs.currentWidget(), c2.main.history)   # history tab again
            self.assertEqual(c2.main.history.table.columnWidth(0), 222)
            self.assertEqual(c2.main.history.split.sizes(), before)
        finally:
            c2.shutdown()
            c2.main.deleteLater()
            spin(50)

    def test_policy_locks_settings(self):
        from clipcloak.gui.settings_dialog import SettingsDialog
        from clipcloak.policy import SystemConfig
        c = self.c
        c.cfg.system = SystemConfig(policy={"watcher.mode": "critical", "hotkeys.revert": "Ctrl+Alt+U",
                                            "detectors.enabled.kv-secrets": True,
                                            "lists.known_domains": ["corp.local"]})
        c.cfg.replace(c.cfg.data)
        self.assertEqual(c.cfg.get("watcher.mode"), "critical")
        c.set_watch_mode("off")
        self.assertEqual(c.cfg.get("watcher.mode"), "critical")
        dlg = SettingsDialog(c)
        self.assertFalse(dlg.w["watcher.mode"].isEnabled())
        self.assertTrue(dlg.w["watcher.action"].isEnabled())
        self.assertFalse(dlg.hk_edits["revert"].isEnabled())
        self.assertTrue(dlg.hk_edits["anonymize"].isEnabled())
        self.assertFalse(dlg.det["kv-secrets"].isEnabled())
        self.assertIn("corp.local", dlg.lists["known_domains"].items())
        dlg.w["watcher.action"].setCurrentIndex(dlg.w["watcher.action"].findData("redact"))
        dlg._accept()
        self.assertEqual(c.cfg.get("watcher.action"), "redact")
        self.assertEqual(c.cfg.get("watcher.mode"), "critical")
        self.assertIn("corp.local", c.cfg.get("lists.known_domains"))
        c.set_watch_mode("off")
        c.cfg.set("watcher.mode", "critical")
        dlg.deleteLater()
        spin(50)

    def test_settings_dialog_roundtrip(self):
        from clipcloak.gui.settings_dialog import SettingsDialog
        d = SettingsDialog(self.c)
        data = d._collect()
        self.assertEqual(set(data), set(self.c.cfg.data))
        self.assertEqual(data["detectors"]["enabled"], self.c.cfg.data["detectors"]["enabled"])
        self.assertEqual(data["lists"]["allow_domains"], self.c.cfg.data["lists"]["allow_domains"])
        d.terms.add_row({"term": "Adler", "type": "ORG"})
        d.w["watcher.mode"].setCurrentIndex(d.w["watcher.mode"].findData("notify"))
        d._accept()
        self.assertEqual(self.c.cfg.get("watcher.mode"), "notify")
        self.assertEqual(self.c.cfg.get("lists.custom_terms")[0]["term"], "Adler")
        self.assertIn(("ORG", "Adler"), [(f.type, f.text) for f in self.c.engine.analyze("Firma Adler")])

    def test_llm_settings_load_models(self):
        import threading
        from http.server import HTTPServer
        from tests.test_llm_ner import _Handler
        from clipcloak.gui.settings_dialog import SettingsDialog
        srv = HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            d = SettingsDialog(self.c)
            d.w["llm.base_url"].setText(f"http://127.0.0.1:{srv.server_port}")   # without /v1
            d._test_llm()
            self.assertTrue(wait_for(lambda: d.llm_model.count() == 3))
            self.assertEqual(d.w["llm.base_url"].text(), f"http://127.0.0.1:{srv.server_port}/v1")
            self.assertEqual(d.llm_model.currentText(), "qwen")
            d.llm_vision.setCurrentText("llava")
            data = d._collect()
            self.assertEqual((data["llm"]["model"], data["llm"]["vision_model"]), ("qwen", "llava"))
            self.assertTrue(data["llm"]["enabled"])
            d.deleteLater()
        finally:
            srv.shutdown()
            srv.server_close()

    def test_settings_cancel_asks_when_changed(self):
        from unittest import mock
        from PySide6.QtWidgets import QMessageBox
        from clipcloak.gui.settings_dialog import SettingsDialog
        d = SettingsDialog(self.c)
        with mock.patch.object(QMessageBox, "question") as q:
            d.reject()                       # unchanged: no question
            q.assert_not_called()
        d = SettingsDialog(self.c)
        d.w["llm.base_url"].setText("http://llm.lab:8000/v1")
        d.w["llm.api_key"].setText("tok")
        with mock.patch.object(QMessageBox, "question", return_value=QMessageBox.Save):
            d.reject()
        self.assertEqual(self.c.cfg.get("llm.api_key"), "tok")
        self.assertEqual(self.c.cfg.get("llm.base_url"), "http://llm.lab:8000/v1")

    def test_no_layouts_in_form_rows(self):
        # PySide6 double-frees layouts passed to QFormLayout.addRow(label, layout)
        # at interpreter exit; rows must use container widgets instead.
        from PySide6.QtWidgets import QFormLayout
        from clipcloak.gui.settings_dialog import SettingsDialog
        d = SettingsDialog(self.c)
        for form in d.findChildren(QFormLayout):
            for row in range(form.rowCount()):
                for role in (QFormLayout.LabelRole, QFormLayout.FieldRole, QFormLayout.SpanningRole):
                    it = form.itemAt(row, role)
                    self.assertTrue(it is None or it.layout() is None, f"layout in form row {row}")
        d.deleteLater()

    def test_pseudonyms_persist_by_default(self):
        from clipcloak.gui.app import DEFAULT_PROJECT, RAM_ONLY
        c = self.c
        c.open_default_project()
        self.assertEqual(c.project.name, DEFAULT_PROJECT)
        r = c.engine.process("Server 10.20.30.40", "pseudonymize")
        c.record(r, "test")
        c._save_project_now()
        store = c.store
        c.shutdown()
        from clipcloak.gui.app import Controller
        self.c = Controller(app, c.cfg)
        self.c.store = store
        self.c.open_default_project()
        self.assertEqual(self.c.engine.revert(r.output).output, "Server 10.20.30.40")
        self.c._switch(None)
        self.assertEqual(self.c.cfg.get("project.last"), RAM_ONLY)
        self.c.open_default_project()
        self.assertIsNone(self.c.project)

    def test_process_large_file_roundtrip(self):
        import time
        from tests.helpers import SAMPLE
        c = self.c
        filler = "# Kapitel\r\n\r\nNormaler Text ohne sensible Daten.\r\n- Punkt\r\n\r\n"
        block = filler * 6 + SAMPLE.replace("\n", "\r\n")
        text = block * (1_000_000 // len(block))
        src = os.path.join(self.tmp, "notes.md")
        with open(src, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        out, back = os.path.join(self.tmp, "notes.pseudo.md"), os.path.join(self.tmp, "notes.restored.md")
        t0 = time.time()
        c.process_file(src, "pseudonymize", out)
        self.assertTrue(wait_for(lambda: len(c.history.entries) == 1, 60000))
        self.assertLess(time.time() - t0, 30)
        pseudo = open(out, encoding="utf-8", newline="").read()
        self.assertNotIn("hartmann", pseudo)
        self.assertIn("\r\n", pseudo)
        c.process_file(out, "revert", back)
        self.assertTrue(wait_for(lambda: len(c.history.entries) == 2, 60000))
        self.assertEqual(open(back, encoding="utf-8", newline="").read(), text)

    def test_project_bar_in_main_window(self):
        c = self.c
        c.store.create("Kunde A")
        c.show_main()
        bar = c.main.project_bar
        bar.refresh()
        names = [bar.combo.itemData(i) for i in range(bar.combo.count())]
        self.assertIn("Kunde A", names)
        bar._chosen(names.index("Kunde A"))
        self.assertEqual(c.project.name, "Kunde A")
        self.assertEqual(bar.combo.currentData(), "Kunde A")
        self.assertTrue(bar.btn_delete.isEnabled())
        menu_texts = [a.text() for a in c.main.project_menu.actions()]
        self.assertTrue(any("Kunde A" in x for x in menu_texts))
        bar._chosen(0)
        self.assertIsNone(c.project)
        self.assertFalse(bar.btn_delete.isEnabled())

    def test_projects_switch(self):
        c = self.c
        prj = c.store.create("Kunde")
        c._switch(prj)
        r = c.engine.process("10.5.5.5", "pseudonymize")
        c.record(r, "test")
        c._save_project_now()
        c._switch(None)
        self.assertEqual(len(c.engine.vault.entries), 0)
        self.assertTrue(c.open_project("Kunde"))
        self.assertEqual(c.engine.revert(r.output).output, "10.5.5.5")
        self.assertEqual(len(c.history.entries), 1)
        c.tray.rebuild()
        c._switch(None, save_current=True)


if __name__ == "__main__":
    unittest.main()
