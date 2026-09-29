"""Application controller: glues clipboard, engine, hotkeys, watcher, projects and UI."""

from __future__ import annotations

import hashlib
import itertools
import logging
import os
import threading
import shlex
import subprocess
import sys
import time
from pathlib import Path
from collections import deque
from concurrent.futures import ThreadPoolExecutor

from PySide6.QtCore import QLibraryInfo, QObject, QTimer, QTranslator, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication, QMessageBox, QSystemTrayIcon

from .. import __version__, i18n, paths
from ..config import Config, engine_settings
from ..core.detectors.external import LlmDetector, NerDetector, find_ner_helper
from ..core.engine import Engine
from ..core.entities import ALL_TYPES, Result
from ..core.formats import process_html, strip_cf_html
from ..core.history import History
from ..core.projects import Project, ProjectError, ProjectStore, WrongPassphrase
from ..core.vault import Vault
from ..activity import event, ui_only
from ..i18n import t
from ..llm.client import LLMClient, LLMSettings
from ..meta import APP_DISPLAY_NAME, APP_LICENSE, APP_NAME, APP_URL
from ..platform import autostart, session
from ..platform.clipboard import ClipContent, WlClipboard, make_backend
from ..platform.hotkeys import HotkeyManager
from . import icons
from .log_view import UiLogHandler

log = logging.getLogger(__name__)
PROCESS_ACTIONS = ("pseudonymize", "anonymize", "redact", "revert")
DEFAULT_PROJECT = "Standard"
RAM_ONLY = "@ram"          # config value for "keep mappings in memory only"
TOKEN_ROWS = {"WORD": "words", "FIRST_NAME": "first", "LAST_NAME": "last", "USER_TOKEN": "users"}


def _summary(findings) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.type] = counts.get(f.type, 0) + 1
    return ", ".join(f"{k} ×{v}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1]))


def _counts(counts: dict) -> str:
    return ", ".join(f"{k} ×{v}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1]))


def text_hash(text: str | None) -> str:
    return hashlib.sha256((text or "").encode("utf-8", "surrogatepass")).hexdigest()


class Controller(QObject):
    history_changed = Signal()
    mappings_changed = Signal()
    activity_changed = Signal()
    image_progress = Signal(str)       # current step of the image detection (shown in the image tab)
    _hotkey = Signal(str)
    _job_done = Signal(object, object)

    def __init__(self, app: QApplication, cfg: Config):
        super().__init__()
        self.app = app
        self.cfg = cfg
        from .uistate import UiState
        self.ui_state = UiState(Path(cfg.path).parent / "ui.ini" if cfg.path else None)
        lang = i18n.init(cfg.get("general.language", "auto"))
        self._qt_translator = QTranslator(self)
        if self._qt_translator.load(f"qtbase_{lang}", QLibraryInfo.path(QLibraryInfo.TranslationsPath)):
            app.installTranslator(self._qt_translator)
        self.session = session.info(QGuiApplication.platformName())
        self.display = self.session["display"]
        self.store = ProjectStore(paths.projects_dir(), protector=self._protector())
        self.project: Project | None = None
        self.session_vault = Vault("session")
        self._session_history: list = []
        self.history = History(int(cfg.get("general.history_size", 200)),
                               bool(cfg.get("general.history_store_originals", True)))
        self.engine = Engine(engine_settings(cfg), self.session_vault)
        self._active: dict[int, str] = {}
        self._active_lock = threading.Lock()
        self._job_ids = itertools.count(1)
        self.log_handler = UiLogHandler()
        root = logging.getLogger()
        if root.level > logging.INFO or root.level == logging.NOTSET:
            root.setLevel(logging.INFO)
        root.addHandler(self.log_handler)
        ui_only.addHandler(self.log_handler)
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="engine")
        self.llm_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="llm")
        self._job_done.connect(self._run_callback)
        self._hotkey.connect(lambda a: self.run_action(a, "hotkey"))
        self.hotkeys = HotkeyManager(self._hotkey.emit, HotkeyManager.backend_for(self.display))
        self.hotkey_errors: dict[str, str] = {}
        self.clip = None
        self.watch_error = ""
        self._clip_pref = None
        self._own: deque[str] = deque(maxlen=8)
        self._paused_until = 0.0
        self._last_watch_mode = "notify"
        self._ner_key = None
        self._ner_det = None
        self._img_client = None
        self._own_image_until = 0.0
        self._last_image_fp = ""
        self._popup = None
        self.main = None
        self._watch_timer = QTimer(self, singleShot=True, interval=200)
        self._watch_timer.timeout.connect(self._watch_check)
        self._save_timer = QTimer(self, singleShot=True, interval=1500)
        self._save_timer.timeout.connect(self._save_project_now)
        self._pause_timer = QTimer(self, singleShot=True)
        self._pause_timer.timeout.connect(self._pause_ended)
        self.restart_requested = False
        self.tray = None
        from .tray import Tray
        self.tray = Tray(self)
        self.activity_changed.connect(self._on_activity)
        self.mappings_changed.connect(self._on_mappings)
        self.apply_config(initial=True)

    # ================================================================= infra
    def submit(self, fn, callback=None, executor=None, label: str | None = None, quiet: bool = False):
        """Run ``fn`` in a worker thread; ``label`` makes the job visible (status bar, tray, log)."""
        job_id = next(self._job_ids)
        started = time.monotonic()
        if label:
            with self._active_lock:
                self._active[job_id] = label
            self.activity_changed.emit()
            if not quiet:
                event("log.job_start", label=label)
        fut = (executor or self.executor).submit(fn)

        def finished():
            if label:
                with self._active_lock:
                    self._active.pop(job_id, None)
                self.activity_changed.emit()

        def done(f):
            ms = int((time.monotonic() - started) * 1000)
            if f.cancelled():          # shutting down
                finished()
                return
            try:
                res = f.result()
            except Exception as exc:  # noqa: BLE001
                log.error("background job failed: %s", exc, exc_info=exc)
                if label:
                    event("log.job_fail", logging.WARNING, label=label, err=str(exc))
                finished()
                self._job_done.emit(self._on_job_error, exc)
                return
            if label and not quiet:
                event("log.job_done", label=label, ms=ms)
            finished()
            if callback is not None:
                self._job_done.emit(callback, res)

        fut.add_done_callback(done)
        return fut

    @staticmethod
    def _run_callback(cb, res):
        cb(res)

    def active_jobs(self) -> list[str]:
        with self._active_lock:
            return list(self._active.values())

    def _on_mappings(self):
        if self.main is not None:
            self.main.project_bar.refresh()

    def _on_activity(self):
        if self.tray is not None:
            self.tray.update_state()
        if self.main is not None:
            self.main.update_activity()

    def _on_job_error(self, exc):
        self.tray.update_state()
        self.notify(t("msg.error", err=str(exc)), error=True)

    def tray_available(self) -> bool:
        return QSystemTrayIcon.isSystemTrayAvailable()

    def notify(self, msg: str, error: bool = False, force: bool = False):
        event("log.notice", logging.WARNING if error else logging.INFO, msg=msg)
        if not (force or error or self.cfg.get("general.notify", True)):
            return
        if self.tray_available() and self.tray.isVisible():
            self.tray.showMessage(APP_DISPLAY_NAME, msg,
                                  QSystemTrayIcon.Warning if error else QSystemTrayIcon.Information, 4000)
        elif self.main is not None and self.main.isVisible():
            self.main.statusBar().showMessage(msg, 8000)

    def project_label(self) -> str:
        return self.project.name if self.project else t("project.session")

    def launch_command_str(self) -> str:
        cmd = autostart.launch_command()
        if sys.platform == "win32":
            return subprocess.list2cmdline(cmd)
        return " ".join(shlex.quote(c) for c in cmd)

    # ================================================================= config
    def apply_config(self, initial: bool = False):
        cfg = self.cfg
        keep = bool(cfg.get("general.history_store_originals", True))
        was = self.history.store_originals
        self.history.set_store_originals(keep)
        if was and not keep and getattr(self, "project", None) is not None:
            self._save_project_now()            # the project file must not keep the originals either
        self.history.set_maxlen(int(cfg.get("general.history_size", 200)))
        self._apply_engine_settings()
        # clipboard backend
        pref = cfg.get("clipboard.backend", "auto")
        if self.clip is None or pref != self._clip_pref:
            if self.clip is not None:
                self.clip.stop_watch()
                self.clip.changed.disconnect(self._on_clip_changed)
                self.clip.deleteLater()
            self.clip = make_backend(pref, self.display, self)
            self.clip.changed.connect(self._on_clip_changed)
            self._clip_pref = pref
        self._apply_watcher()
        # hotkeys
        bindings = {a: s for a, s in (cfg.get("hotkeys") or {}).items() if s}
        self.hotkey_errors = self.hotkeys.register(bindings)
        ok = [f"{a}={seq}" for a, seq in bindings.items() if a not in self.hotkey_errors]
        event("log.hotkeys", backend=self.hotkeys.backend, ok=", ".join(ok) or "-",
              err="; ".join(f"{a}: {e}" for a, e in self.hotkey_errors.items()) or "-")
        if self.hotkey_errors and not initial and self.hotkeys.backend != "none":
            self.notify(t("msg.hotkey_errors", n=len(self.hotkey_errors)), error=True)
        if self.tray:
            self.tray.update_state()
        if self.main is not None:
            self.main.update_status()
            self.main.workbench.refresh_llm_buttons()

    def _apply_engine_settings(self):
        terms = self.project.terms if self.project else None
        domains = self.project.known_domains if self.project else None
        self.engine.configure(engine_settings(self.cfg, terms, domains))
        # optional detectors
        ner_cfg = self.cfg.get("ner") or {}
        key = (bool(ner_cfg.get("enabled")), ner_cfg.get("helper_path"), ner_cfg.get("language"),
               tuple(ner_cfg.get("types") or []), ner_cfg.get("model_de"), ner_cfg.get("model_en"))
        if key != self._ner_key:
            if self._ner_det is not None and self._ner_det.client:
                self._ner_det.client.close()
            self._ner_det = None
            if ner_cfg.get("enabled"):
                cmd = find_ner_helper(ner_cfg.get("helper_path", ""))
                self._ner_det = NerDetector(cmd, ner_cfg.get("language", "auto"), ner_cfg.get("types") or [],
                                            {"de": ner_cfg.get("model_de"), "en": ner_cfg.get("model_en")})
                if cmd is None:
                    self.notify(t("ner.not_found", helper=APP_NAME + "-ner"), error=True)
                else:
                    self.submit(self._ner_det.warm_up, label=t("job.ner_load"))
            self._ner_key = key
        self.engine.detectors = [d for d in self.engine.detectors if d.id not in ("ner", "llm")]
        if self._ner_det is not None:
            self.engine.add_detector(self._ner_det)
        if self.cfg.get("llm.enabled") and self.cfg.get("llm.detect"):
            types = self.cfg.get("llm.detect_types") or ["PERSON", "ORG"]
            self.engine.add_detector(LlmDetector(self._llm_client(), types))

    def apply_settings(self, data: dict, project_update: dict | None = None):
        old_lang = self.cfg.get("general.language")
        old_autostart = self.cfg.get("general.autostart")
        old_os_enc = self.cfg.get("project.os_encryption", True)
        self.cfg.replace(data)
        data = self.cfg.data            # policy applied
        self.cfg.save()
        if bool(data["project"].get("os_encryption", True)) != bool(old_os_enc):
            self.store.protector = self._protector()
            if self.project is not None:
                self._save_project_now()
                if self.main is not None:
                    self.main.project_bar.refresh()
        if bool(data["general"].get("autostart")) != bool(old_autostart):
            try:
                autostart.set_enabled(bool(data["general"].get("autostart")))
            except OSError as exc:
                self.notify(t("msg.error", err=str(exc)), error=True)
        if project_update and self.project is not None:
            self.project.terms = project_update["terms"]
            self.project.known_domains = project_update["known_domains"]
            self.project.store_history = project_update["store_history"]
            self._save_project_now()
        self.apply_config()
        if data["general"].get("language") != old_lang:
            self._ask_restart_for_language(data["general"].get("language", "auto"))

    def _llm_client(self) -> LLMClient:
        return LLMClient(LLMSettings.from_config(self.cfg.get("llm") or {}))

    # ================================================================= actions
    def run_action(self, action: str, source: str = "tray"):
        if action in PROCESS_ACTIONS:
            self.process_clipboard(action, source)
        elif action == "process":
            self.process_clipboard(self.cfg.get("general.mode", "pseudonymize"), source)
        elif action == "workbench":
            content = self.clip.read()
            self.show_workbench(content.text if content.text else None)
        elif action == "process_file":
            self.process_file()
        elif action == "screenshot":
            self.screenshot_to_text()
        elif action == "redact_image":
            self.redact_image()
        elif action == "toggle_watcher":
            cur = self.cfg.get("watcher.mode")
            self.set_watch_mode("off" if cur != "off" else self._last_watch_mode)
            self.notify(t("msg.watch_mode", mode=t("watch." + self.cfg.get("watcher.mode"))), force=True)
        elif action in ("show", "history", "mappings"):
            self.show_main(None if action == "show" else action)
        elif action == "settings":
            self.show_settings()
        elif action == "quit":
            self.quit()
        elif action == "restart":
            self.restart()
        else:
            log.warning("unknown action %s", action)

    def process_clipboard(self, mode: str, source: str, content: ClipContent | None = None,
                          expect_hash: str | None = None, types: set | None = None, after=None):
        """``types``: only change findings of these types (watcher rules); ``after`` runs when done."""
        content = content if content is not None else self.clip.read()
        text = content.text
        if not text:
            if content.image_png and mode in ("pseudonymize", "anonymize", "redact"):
                self.redact_image(content)
            elif self.display == "wayland" and not WlClipboard.available():
                self.notify(t("msg.wayland_no_wlclip"), error=True)
            else:
                self.notify(t("msg.no_text"), force=True)
            return
        html = None
        if content.html and self.cfg.get("clipboard.process_html", True) and self.clip.name == "qt":
            html = strip_cf_html(content.html)
        engine = self.engine

        skip = {"llm"} if source == "watcher" else set()     # automatic runs never go to the LLM

        def run(s):
            if mode == "revert":
                return engine.revert(s)
            if types is None and not skip:
                return engine.process(s, mode)
            found = engine.analyze(s, skip=skip)
            return engine.process(s, mode, findings=[f for f in found if types is None or f.type in types])

        def job():
            res = run(text)
            html_out = None
            if html:
                html_out = process_html(html, engine.revert if mode == "revert" else run)
            return res, html_out

        def done(r):
            res, html_out = r
            self.tray.update_state()
            if expect_hash is not None and text_hash(self.clip.read().text) != expect_hash:
                self.notify(t("msg.clip_changed"), error=True)
                return
            if res.changed:
                self.write_clipboard(res.output, html_out, sensitive=res.mode == "revert")
            self.record(res, source)
            if after is not None:
                after(res)                # it reports the result itself (one popup, no extra toast)
            else:
                self._notify_result(res)
            if res.changed and mode != "revert" and self.cfg.get("llm.enabled") \
                    and self.cfg.get("llm.verify_output") == "warn":
                self.llm_verify(res.output, show=False, result=res)

        self.submit(job, done, label=t("job.clipboard", mode=t("mode." + mode)))

    def process_file(self, path: str | None = None, mode: str | None = None, out_path: str | None = None):
        """Process a whole text file (any size up to the engine limit) into a new file."""
        from PySide6.QtWidgets import QFileDialog
        from ..core.files import read_text_file, suggest_output_path, write_text_file
        parent = self.main
        if path is None:
            path, _ = QFileDialog.getOpenFileName(parent, t("file.choose"))
            if not path:
                return
        if mode is None:
            box = QMessageBox(parent)
            box.setWindowTitle(APP_DISPLAY_NAME)
            box.setText(t("file.choose_action", name=path))
            buttons = {box.addButton(t("mode." + m), QMessageBox.AcceptRole): m for m in PROCESS_ACTIONS}
            box.addButton(QMessageBox.Cancel)
            box.exec()
            mode = buttons.get(box.clickedButton())
            if mode is None:
                return
        if out_path is None:
            out_path, _ = QFileDialog.getSaveFileName(parent, t("file.save_as"), suggest_output_path(path, mode))
            if not out_path:
                return
        engine = self.engine

        def job():
            text, enc = read_text_file(path)
            res = engine.revert(text) if mode == "revert" else engine.process(text, mode)
            write_text_file(out_path, res.output, enc)
            return res

        def done(res):
            self.tray.update_state()
            res.warnings.append(t("file.history_note", src=path, dst=out_path))
            self.history.add(res, "file", self.project.name if self.project else "")
            self.history_changed.emit()
            self.mappings_changed.emit()
            if self.project is not None:
                self._save_timer.start()
            self.notify(t("file.done", n=len(res.replacements), dst=out_path), force=True)

        self.submit(job, done, label=t("job.file", mode=t("mode." + mode), name=os.path.basename(path)))

    def write_clipboard(self, text: str, html: str | None, sensitive: bool = False):
        self._own.append(text_hash(text))
        self.clip.write(text, html, sensitive=sensitive)

    def record(self, res: Result, source: str):
        if not res.changed:
            return
        self.history.add(res, source, self.project.name if self.project else "")
        self.history_changed.emit()
        self.mappings_changed.emit()
        if self.project is not None:
            self._save_timer.start()

    def _notify_result(self, res: Result):
        if res.changed:
            event("log.process_result", mode=t("mode." + res.mode), n=len(res.replacements),
                  details=", ".join(f"{k} ×{v}" for k, v in sorted(res.counts().items(), key=lambda kv: -kv[1])),
                  chars=len(res.input))
        else:
            event("log.nothing", mode=t("mode." + res.mode), chars=len(res.input))
        for w in res.warnings:
            event("log.warning", logging.WARNING, msg=w)
        if not res.changed:
            self.notify(t("msg.nothing_reverted" if res.mode == "revert" else "msg.nothing_found"), force=True)
            return
        self.notify(self._result_text(res))

    @staticmethod
    def _result_text(res: Result) -> str:
        """"Pseudonymise: 2 replacement(s) – EMAIL ×2 · tracking removed: 3" – removed tracking
        is not a pseudonymisation, so it is named separately."""
        counts = res.counts()
        tracking = counts.pop("TRACKING", 0)
        parts = []
        if counts:
            details = ", ".join(f"{k} ×{v}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1]))
            parts.append(t("msg.done", mode=t("mode." + res.mode), n=sum(counts.values()), details=details))
        if tracking:
            parts.append(t("msg.tracking_removed", n=tracking))
        return " · ".join(parts)

    # ================================================================= watcher
    def clip_can_watch(self) -> bool:
        if self.clip is None:
            return False
        if isinstance(self.clip, WlClipboard):
            return not self.watch_error
        return self.display != "wayland"

    def _apply_watcher(self):
        mode = self.cfg.get("watcher.mode", "off")
        if mode != "off":
            self._last_watch_mode = mode
            ok = self.clip.start_watch()
            self.watch_error = "" if ok else getattr(self.clip, "watch_error", "") or "unavailable"
        else:
            self.clip.stop_watch()

    def set_watch_mode(self, mode: str):
        if not self.cfg.set("watcher.mode", mode):
            self.notify(t("msg.locked"), force=True)
        self.cfg.save()
        self._apply_watcher()
        self.tray.update_state()
        if self.main is not None:
            self.main.update_status()

    def set_default_mode(self, mode: str):
        if not self.cfg.set("general.mode", mode):
            self.notify(t("msg.locked"), force=True)
        self.cfg.save()

    def is_paused(self) -> bool:
        return time.time() < self._paused_until

    def pause(self, minutes: int):
        self._paused_until = time.time() + minutes * 60 if minutes else 0.0
        if minutes:
            self._pause_timer.start(minutes * 60 * 1000)
        else:
            self._pause_timer.stop()
        self.tray.update_state()

    def _pause_ended(self):
        self._paused_until = 0.0
        self.tray.update_state()

    def _on_clip_changed(self):
        self._watch_timer.start()

    def _watch_check(self):
        mode = self.cfg.get("watcher.mode", "off")
        if mode == "off" or self.is_paused():
            return
        content = self.clip.read()
        text = content.text
        if not text:
            if content.image_png:
                self._watch_image(content)
            return
        h = text_hash(text)
        if h in self._own:
            return
        if len(text) > int(self.cfg.get("watcher.max_chars", 500_000)):
            return
        engine = self.engine

        offer_revert = bool(self.cfg.get("watcher.offer_revert", True))

        def job():
            # every copy passes here: never send it to an LLM (that runs only on explicit actions)
            findings = engine.analyze(text, skip={"llm"})
            if offer_revert:
                looks, reverted, real = engine.surrogate_hint(text, findings)
                if looks:
                    return findings, (reverted, real)
            return findings, None

        def done(r):
            findings, hint = r
            if hint is not None:
                # a pseudonymised result (e.g. the LLM's answer): offer revert, change nothing automatically
                reverted, real = hint
                event("log.watch_pseudonymised", n=len(reverted.replacements), summary=_counts(reverted.counts()))
                self._revert_popup(reverted, real, content, h)
                return
            if not findings:
                event("log.watch_none")
                return
            rules = self.watch_rules(mode)
            auto = [f for f in findings if rules.get(f.type) == "auto"]
            ask = [f for f in findings if rules.get(f.type) == "ask"]
            summary = _summary(findings)
            if not auto and not ask:
                event("log.watch_findings", summary=summary, decision=t("log.decision_ignore"))
                return
            if auto:
                act = self.cfg.get("watcher.action", "pseudonymize")
                event("log.watch_findings", summary=_summary(auto), decision=t("mode." + act))
                if ask:
                    event("log.watch_findings", summary=_summary(ask), decision=t("log.decision_popup"))
                self.process_clipboard(act, "watcher", content, h, types={f.type for f in auto},
                                       after=(lambda res: self._after_auto(res, ask)) if ask else None)
            else:
                event("log.watch_findings", summary=summary, decision=t("log.decision_popup"))
                self._findings_popup(ask, content, h)

        event("log.watch_change", chars=len(text))
        self.submit(job, done, label=t("job.watch"), quiet=True)

    def watch_rules(self, mode: str | None = None) -> dict[str, str]:
        """Finding type -> auto | ask | ignore for the current watcher mode.
        notify: every category that is not ignored asks; always: they are all changed;
        critical ("by category"): as set per category."""
        from ..core.entities import CATEGORY_OF, DEFAULT_CATEGORY_RULES
        mode = mode or self.cfg.get("watcher.mode", "off")
        cats = dict(DEFAULT_CATEGORY_RULES, **(self.cfg.get("watcher.categories") or {}))
        out = {}
        for typ, cat in CATEGORY_OF.items():
            rule = cats.get(cat, "ask")
            if rule not in ("auto", "ask", "ignore"):
                rule = "ask"
            if mode == "notify" and rule == "auto":
                rule = "ask"
            elif mode == "always" and rule == "ask":
                rule = "auto"
            out[typ] = rule
        return out

    def hotkey_text(self, action: str) -> str:
        """Configured global shortcut of an action, or "" if none or it could not be registered."""
        seq = self.cfg.get("hotkeys." + action) or ""
        if not seq or action in self.hotkey_errors or self.hotkeys.backend == "none":
            return ""
        return seq

    def _watch_image(self, content: ClipContent):
        if not self.cfg.get("image.watch", True) or time.monotonic() < self._own_image_until:
            return
        fp = content.fingerprint
        if fp == self._last_image_fp:
            return
        self._last_image_fp = fp
        from .popup import Popup
        event("log.watch_image")
        actions = [("image", t("popup.redact_image"), self.hotkey_text("redact_image"))]
        self._show_popup(Popup(t("popup.image_title"), t("popup.image_text"), actions,
                               int(self.cfg.get("watcher.popup_timeout", 12))),
                         lambda key: self.redact_image(content) if key == "image" else None)

    def _after_auto(self, res: Result, ask):
        """Automatic part done, the rest asks: one popup that says both."""
        if res.changed:
            event("log.process_result", mode=t("mode." + res.mode), n=len(res.replacements),
                  details=", ".join(f"{k} ×{v}" for k, v in sorted(res.counts().items(), key=lambda kv: -kv[1])),
                  chars=len(res.input))
        self._findings_popup(ask, None, None, auto_res=res)

    def _findings_popup(self, findings, content, h, auto_res: Result | None = None):
        from .popup import Popup
        summary = _summary(findings)
        text = t("popup.found_text", summary=summary)
        if auto_res is not None and auto_res.changed:
            text = t("popup.auto_done", what=self._result_text(auto_res)) + "\n" + text
        actions = [(m, t("mode." + m), self.hotkey_text(m)) for m in ("pseudonymize", "anonymize", "redact")]
        actions.append(("details", t("popup.details"), ""))
        self._show_popup(Popup(t("popup.found_title"), text, actions,
                               int(self.cfg.get("watcher.popup_timeout", 12))),
                         lambda key: self._popup_choice(key, content, h))

    def _revert_popup(self, reverted: Result, real, content, h):
        from .popup import Popup
        text = t("popup.pseudo_text", n=len(reverted.replacements), summary=_counts(reverted.counts()))
        actions = [("revert", t("mode.revert"), self.hotkey_text("revert"))]
        if real:
            text += "\n" + t("popup.pseudo_also", summary=_summary(real))
            actions.append(("pseudonymize", t("mode.pseudonymize"), self.hotkey_text("pseudonymize")))
        actions.append(("details", t("popup.details"), ""))
        self._show_popup(Popup(t("popup.pseudo_title"), text, actions,
                               int(self.cfg.get("watcher.popup_timeout", 12))),
                         lambda key: self._popup_choice(key, content, h))

    def _show_popup(self, popup, handler):
        if self._popup is not None:
            try:
                self._popup.close()
            except RuntimeError:
                pass
        self._popup = popup
        popup.chosen.connect(handler)
        popup.show_near_tray()

    def _popup_choice(self, key, content, h):
        self._popup = None
        if key in ("pseudonymize", "anonymize", "redact", "revert"):
            self.process_clipboard(key, "popup", content, h)
        elif key == "details":
            self.show_workbench((content.text if content is not None else self.clip.read().text) or "")

    # ================================================================= LLM
    def llm_verify(self, text: str, show: bool = False, result: Result | None = None):
        if not self.cfg.get("llm.enabled"):
            return
        client = self._llm_client()
        safe = [r.replacement for r in result.replacements] if result else \
            [s for s in list(self.engine.vault.by_surrogate)[:5000] if s in text]

        def done(items):
            if not items:
                if show:
                    self.notify(t("llm.verify_clean"), force=True)
                return
            lines = [f"• {it['text']} ({it['type']})" for it in items[:15]]
            if self.history.entries and result is not None:
                self.history.add_warning(self.history.entries[0],
                                         t("llm.verify_warning", items=", ".join(i["text"] for i in items)),
                                         sensitive=True)
                self.history_changed.emit()
            from .popup import Popup
            actions = [("add", t("llm.add_terms")), ("details", t("popup.details"))]
            self._show_popup(Popup(t("llm.verify_title"), "\n".join(lines), actions, 30),
                             lambda key: self._verify_choice(key, items, text if result is None else result.input))

        self.submit(lambda: client.verify(text, safe), done, executor=self.llm_executor, label=t("job.llm_verify"))

    def _verify_choice(self, key, items, original_text):
        self._popup = None
        if key == "add":
            for it in items:
                typ = it["type"] if it["type"] in ALL_TYPES else ""
                self.add_custom_term(it["text"], typ, apply=False)
            self._apply_engine_settings()
            self.notify(t("llm.terms_added", n=len(items)), force=True)
        elif key == "details":
            self.show_workbench(original_text)

    def screenshot_to_text(self, target=None):
        if not self.cfg.get("llm.enabled"):
            self.notify(t("wb.llm_disabled"), error=True)
            return
        content = self.clip.read()
        if not content.image_png:
            self.notify(t("msg.no_image"), force=True)
            return
        client = self._llm_client()
        mode = self.cfg.get("general.mode", "pseudonymize")
        engine = self.engine

        def job():
            text = client.transcribe_image(content.image_png)
            return text, (None if target is not None else engine.process(text, mode))

        def done(r):
            text, res = r
            self.tray.update_state()
            if target is not None:
                target.set_text(text)
                return
            self.write_clipboard(res.output, None)
            res.warnings.append(t("msg.from_screenshot"))
            self.history.add(res, "screenshot", self.project.name if self.project else "")
            self.history_changed.emit()
            self.mappings_changed.emit()
            self._notify_result(res) if res.changed else self.notify(t("msg.screenshot_text"), force=True)

        self.notify(t("msg.screenshot_running"), force=True)
        self.submit(job, done, executor=self.llm_executor, label=t("job.screenshot"))

    # ================================================================= images
    def plugin_client(self):
        """The plugin process (names + images). Shared with the NER detector if it runs."""
        if self._ner_det is not None and self._ner_det.client is not None:
            return self._ner_det.client
        if self._img_client is None:
            from ..core.detectors.external import NerClient
            cmd = find_ner_helper(self.cfg.get("ner.helper_path", "") or "")
            if cmd is None:
                return None
            self._img_client = NerClient(cmd, timeout=180)
        return self._img_client

    def read_clipboard_image(self):
        from PySide6.QtGui import QImage
        content = self.clip.read()
        if not content.image_png:
            return None
        img = QImage.fromData(content.image_png, "PNG")
        return None if img.isNull() else img

    def write_clipboard_image(self, img, n_regions: int = 0):
        self._own_image_until = time.monotonic() + 2.0
        self.clip.write_image(img)
        event("log.image_copied", n=n_regions)
        self.notify(t("img.copied", n=n_regions), force=True)

    def redact_image(self, content: ClipContent | None = None):
        """Open the image tab with the clipboard image and detect regions."""
        from PySide6.QtGui import QImage
        content = content if content is not None else self.clip.read()
        if not content.image_png:
            self.notify(t("msg.no_image"), force=True)
            return
        img = QImage.fromData(content.image_png, "PNG")
        if img.isNull():
            self.notify(t("msg.no_image"), force=True)
            return
        self.show_main("image")
        self.main.image.set_image(img, detect=True)

    def detect_image_regions(self, qimage, callback):
        """Faces, codes and sensitive text in ``qimage`` via the plugin -> callback((regions, message))."""
        import base64

        from PySide6.QtCore import QBuffer, QByteArray, QIODevice

        from ..core.imageredact import ImageSettings, code_regions, face_regions, nudity_regions, text_regions
        ba = QByteArray()
        buf = QBuffer(ba)
        buf.open(QIODevice.WriteOnly)
        qimage.save(buf, "PNG")
        buf.close()
        b64 = base64.b64encode(bytes(ba.data())).decode()
        w, h = qimage.width(), qimage.height()
        settings = ImageSettings.from_config(self.cfg.get("image") or {})
        client = self.plugin_client()
        engine = self.engine
        if client is None:
            callback((None, t("img.no_plugin", helper=APP_NAME + "-ner")))
            return

        steps = [k for k, on in (("faces", settings.faces), ("nudity", settings.nudity),
                                 ("codes", settings.codes), ("text", settings.text)) if on]

        def step(key):
            self.image_progress.emit(t("img.step." + key, i=steps.index(key) + 1, n=len(steps)))

        def job():
            regions, counts = [], {}
            try:
                if settings.faces:
                    step("faces")
                    boxes = client.request({"op": "faces", "image": b64}, timeout=180).get("boxes", [])
                    regions += face_regions(boxes, settings, w, h)
                    counts["faces"] = len(boxes)
                if settings.nudity:
                    step("nudity")
                    try:
                        boxes = client.request({"op": "nudity", "image": b64}, timeout=180).get("boxes", [])
                    except RuntimeError as exc:           # plugin of 0.1.11 has no nudity model
                        if "unknown op" not in str(exc):
                            raise
                        boxes = []
                        counts["nudity_missing"] = True
                    regions += nudity_regions(boxes, settings, w, h)
                    counts["nudity"] = len(boxes)
                if settings.codes:
                    step("codes")
                    boxes = client.request({"op": "codes", "image": b64}, timeout=180).get("boxes", [])
                    regions += code_regions(boxes, settings, w, h)
                    counts["codes"] = len(boxes)
                if settings.text:
                    step("text")
                    lines = client.request({"op": "ocr", "image": b64}, timeout=300).get("boxes", [])
                    found = text_regions(lines, engine.analyze, settings, w, h)
                    regions += found
                    counts["lines"] = len(lines)
                    counts["text"] = len(found)
            except (RuntimeError, TimeoutError, OSError, ValueError) as exc:
                msg = str(exc)
                if "unknown op" in msg:
                    return None, t("img.plugin_old")
                return None, t("img.detect_failed", err=msg)
            event("log.image_detect", faces=counts.get("faces", "-"), codes=counts.get("codes", "-"),
                  text=counts.get("text", "-"), lines=counts.get("lines", "-"), nudity=counts.get("nudity", "-"))
            msg = t("img.detected", n=len(regions), faces=counts.get("faces", 0), nudity=counts.get("nudity", 0),
                    text=counts.get("text", 0), codes=counts.get("codes", 0))
            if counts.get("nudity_missing"):
                msg += "\n" + t("img.plugin_old")
            return regions, msg

        self.submit(job, callback, executor=self.llm_executor, label=t("job.image_detect"))

    # ================================================================= lists
    def add_custom_term(self, text: str, typ: str = "", apply: bool = True):
        typ = "" if typ in ("CUSTOM", None) else typ
        term = {"term": text, "type": typ, "replacement": "", "regex": False, "case_sensitive": False}
        if self.project is not None:
            if not any(x.get("term") == text for x in self.project.terms):
                self.project.terms.append(term)
                self._save_timer.start()
        else:
            terms = self.cfg.get("lists.custom_terms") or []
            if not any(x.get("term") == text for x in terms):
                terms.append(term)
                self.cfg.set("lists.custom_terms", terms)
                self.cfg.save()
        if apply:
            self._apply_engine_settings()

    def add_allow_term(self, text: str):
        allow = self.cfg.get("lists.allow_terms") or []
        if text not in allow:
            allow.append(text)
            self.cfg.set("lists.allow_terms", allow)
            self.cfg.save()
        self._apply_engine_settings()

    def remove_mappings(self, keys):
        v = self.engine.vault
        for typ, orig in keys:
            if typ in TOKEN_ROWS:
                v.maps[TOKEN_ROWS[typ]].remove(orig)
                v.revision += 1
            else:
                v.remove(typ, orig)
        self.engine._revert_cache = None
        self.mappings_changed.emit()
        if self.project is not None:
            self._save_timer.start()

    def clear_mappings(self):
        self.engine.vault.clear()
        self.engine._revert_cache = None
        self.mappings_changed.emit()
        if self.project is not None:
            self._save_project_now()

    def clear_mappings_confirm(self):
        if QMessageBox.question(None, APP_DISPLAY_NAME, t("map.clear_confirm")) == QMessageBox.Yes:
            self.clear_mappings()

    # ================================================================= projects
    def _save_project_now(self):
        self._save_timer.stop()
        if self.project is None:
            return
        if self.project.store_history:
            self.project.history = self.history.to_list()
        if self.store.protector is None and not self.project.passphrase:
            self.store.protector = self._protector()     # keyring started after us (login autostart)
        try:
            self.store.save(self.project)
        except OSError as exc:
            self.notify(t("msg.error", err=str(exc)), error=True)

    def _switch(self, prj: Project | None, save_current: bool = True):
        if self.project is None:
            self._session_history = self.history.to_list()
        elif save_current:
            self._save_project_now()
        self._save_timer.stop()
        self.project = prj
        if prj is None:
            self.engine.set_vault(self.session_vault)
            self.history.load_list(self._session_history)
        else:
            self.engine.set_vault(prj.vault)
            self.history.load_list(prj.history if prj.store_history else [])
        self.cfg.set("project.last", prj.name if prj else RAM_ONLY)
        event("log.project", name=self.project_label())
        self.cfg.save()
        self._apply_engine_settings()
        self.history_changed.emit()
        self.mappings_changed.emit()
        self.tray.update_state()
        if self.main is not None:
            self.main.update_status()

    def open_default_project(self):
        """Pseudonyms are persisted by default: open the last project or "Standard".

        Only an explicit choice of "RAM only" keeps the mappings in memory.
        """
        last = self.cfg.get("project.last") or ""
        if last == RAM_ONLY:
            return
        name = last if last and self.store.exists(last) else DEFAULT_PROJECT
        if not self.store.exists(name):
            try:
                self.store.create(name)
            except (ProjectError, OSError) as exc:
                self.notify(t("msg.error", err=str(exc)), error=True)
                return
        if not self.open_project(name):
            self._switch(None)

    def _protector(self):
        """Account-bound encryption for projects without passphrase (Windows DPAPI)."""
        if not self.cfg.get("project.os_encryption", True):
            return None
        from ..core.osprotect import protector
        return protector()

    def open_project(self, name: str | None, parent=None) -> bool:
        if name is None:
            self._switch(None)
            return True
        if self.project is not None and self.project.name == name:
            return True
        from .project_dialog import ask_passphrase
        try:
            pw = None
            if self.store.needs_passphrase(name):
                pw = ask_passphrase(parent, name)
                if pw is None:
                    self.tray.rebuild()
                    return False
            prj = self.store.load(name, pw, upgrade=True)
        except WrongPassphrase:
            QMessageBox.warning(parent, APP_DISPLAY_NAME, t("project.wrong_passphrase"))
            return False
        except (ProjectError, OSError, ValueError, KeyError) as exc:
            QMessageBox.warning(parent, APP_DISPLAY_NAME, t("msg.error", err=str(exc)))
            return False
        self._switch(prj)
        self.notify(t("project.opened", name=name), force=True)
        return True

    def new_project(self):
        from .project_dialog import NewProjectDialog
        dlg = NewProjectDialog({p.name for p in self.store.list()}, self.main)
        if dlg.exec() != NewProjectDialog.Accepted:
            return
        name, pw, store_history = dlg.values()
        try:
            prj = self.store.create(name, pw)
        except (ProjectError, OSError) as exc:
            QMessageBox.warning(self.main, APP_DISPLAY_NAME, t("msg.error", err=str(exc)))
            return
        prj.store_history = store_history
        self._switch(prj)
        self._save_project_now()

    def delete_project(self):
        if self.project is None:
            return
        name = self.project.name
        if QMessageBox.question(self.main, APP_DISPLAY_NAME, t("project.delete_confirm", name=name)) != QMessageBox.Yes:
            return
        self._switch(None, save_current=False)
        self.store.delete(name)

    # ================================================================= windows
    def ensure_main(self):
        if self.main is None:
            from .main_window import MainWindow
            self.main = MainWindow(self)
        return self.main

    def show_main(self, tab: str | None = None):
        w = self.ensure_main()
        if tab:
            w.select(tab)
        w.show()
        w.raise_()
        w.activateWindow()

    def show_workbench(self, text: str | None = None):
        w = self.ensure_main()
        if text is not None:
            w.workbench.set_text(text)
        self.show_main("workbench")

    def show_settings(self, tab: str | None = None):
        from .settings_dialog import SettingsDialog
        dlg = SettingsDialog(self, self.main, tab if isinstance(tab, str) else None)
        dlg.setWindowIcon(icons.icon())
        dlg.exec()

    def show_about(self):
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QDialog, QDialogButtonBox, QLabel, QVBoxLayout
        dlg = QDialog(self.main)
        dlg.setWindowTitle(t("tray.about"))
        dlg.setWindowIcon(icons.icon())
        url = f'<a href="{APP_URL}">{APP_URL}</a>' if APP_URL else "-"
        lab = QLabel(t("about.text", name=APP_DISPLAY_NAME, version=__version__, license=APP_LICENSE, url=url,
                       config=str(paths.config_file()), data=str(paths.data_dir())))
        lab.setTextFormat(Qt.RichText)
        lab.setOpenExternalLinks(True)
        lab.setTextInteractionFlags(Qt.TextBrowserInteraction)
        lab.setWordWrap(True)
        icon = QLabel()
        icon.setPixmap(icons.draw(64))
        bb = QDialogButtonBox(QDialogButtonBox.Ok)
        bb.accepted.connect(dlg.accept)
        lay = QVBoxLayout(dlg)
        lay.addWidget(icon, 0, Qt.AlignHCenter)
        lay.addWidget(lab)
        lay.addWidget(bb)
        dlg.resize(460, 280)
        dlg.exec()

    # ================================================================= lifecycle
    def start(self, show_window: bool = False):
        if self.cfg.load_error:
            QMessageBox.warning(None, APP_DISPLAY_NAME, t("msg.config_broken", err=self.cfg.load_error))
        self._apply_system_config()
        if self.tray_available():
            self.tray.show()
        else:
            show_window = True
        self.open_default_project()
        if show_window or not self.cfg.get("general.start_minimized", True):
            self.show_main()
        if self.display == "wayland" and not WlClipboard.available():
            self.notify(t("msg.wayland_no_wlclip"), error=True)
        elif self.hotkeys.backend == "none" and self.display not in ("offscreen",):
            self.notify(t("msg.no_global_hotkeys"), force=True)
        elif self.hotkey_errors:
            self.notify(t("msg.hotkey_errors", n=len(self.hotkey_errors)), error=True)

    def _apply_system_config(self):
        """Log central settings and enforce a managed autostart."""
        sc = self.cfg.system
        if sc.sources:
            event("log.policy", sources=", ".join(sc.sources), n=len(sc.policy), d=len(sc.defaults))
        for err in sc.errors:
            event("log.policy_error", logging.WARNING, err=err)
        if self.cfg.is_locked("general.autostart") or autostart.machine_enabled():
            want = bool(self.cfg.get("general.autostart")) and not autostart.machine_enabled()
            try:
                if autostart.is_enabled() != want:
                    autostart.set_enabled(want)   # the installer's machine-wide entry replaces the user's
            except OSError as exc:
                log.warning("autostart: %s", exc)

    def handle_command(self, cmd: dict):
        action = cmd.get("action")
        if action:
            self.run_action(action, "cli")

    def shutdown(self):
        if self.main is not None:
            self.main.save_state()
        logging.getLogger().removeHandler(self.log_handler)
        ui_only.removeHandler(self.log_handler)
        self._save_project_now()
        self.hotkeys.unregister()
        if self.clip is not None:
            self.clip.stop_watch()
            self.clip.release()
        if self._ner_det is not None and self._ner_det.client:
            self._ner_det.client.close()
        if self._img_client is not None:
            self._img_client.close()
        self.executor.shutdown(wait=False, cancel_futures=True)
        self.llm_executor.shutdown(wait=False, cancel_futures=True)
        self.tray.hide()

    # ------------------------------------------------------------------ language
    def set_language(self, lang: str):
        if lang == self.cfg.get("general.language", "auto"):
            return
        if not self.cfg.set("general.language", lang):
            self.notify(t("msg.locked"), force=True)
            return
        self.cfg.save()
        self._ask_restart_for_language(lang)

    def _ask_restart_for_language(self, lang: str):
        i18n.init(lang)   # ask in the newly chosen language
        answer = QMessageBox.question(self.main, APP_DISPLAY_NAME, t("msg.restart_language_now"),
                                      QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if answer == QMessageBox.Yes:
            self.restart()

    def restart(self):
        """Quit and start again (the entry point relaunches after the event loop ends)."""
        self.restart_requested = True
        self.quit()

    def quit(self):
        if getattr(self, "_quitting", False):
            return
        self._quitting = True
        if self._popup is not None:
            try:
                self._popup.close()
            except RuntimeError:
                pass
        QApplication.closeAllWindows()
        self.shutdown()
        QTimer.singleShot(0, self.app.quit)
