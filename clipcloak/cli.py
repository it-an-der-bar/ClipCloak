"""Command line entry point: GUI (tray), remote actions and headless processing."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import logging.handlers
import os
import sys

from . import __version__, paths
from .meta import APP_DISPLAY_NAME, APP_NAME, APP_ORG

ACTION_CHOICES = ["pseudonymize", "anonymize", "redact", "revert", "process", "workbench", "process_file", "redact_image", "screenshot",
                  "toggle_watcher", "show", "history", "mappings", "settings", "restart", "quit"]
HEADLESS = ("process", "revert", "analyze", "projects")


def _fix_std_streams(headless: bool) -> None:
    """PyInstaller --windowed builds have no stdout/stderr on Windows."""
    if sys.stdout is not None and sys.stderr is not None:
        return
    if headless and sys.platform == "win32":
        import ctypes
        if ctypes.windll.kernel32.AttachConsole(-1):
            sys.stdout = open("CONOUT$", "w", encoding="utf-8")
            sys.stderr = open("CONOUT$", "w", encoding="utf-8")
            return
    devnull = open(os.devnull, "w", encoding="utf-8")
    if sys.stdout is None:
        sys.stdout = devnull
    if sys.stderr is None:
        sys.stderr = devnull


def setup_logging(verbose: bool) -> None:
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        d = paths.data_dir()
        d.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(d / f"{APP_NAME}.log", maxBytes=1_000_000,
                                                  backupCount=2, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError:
        pass
    if verbose and sys.stderr is not None:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(fmt)
        root.addHandler(sh)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=APP_NAME, description=f"{APP_DISPLAY_NAME}: redact, anonymise or "
                                "pseudonymise clipboard contents.")
    p.add_argument("--version", action="store_true", help="print version and exit")
    p.add_argument("--action", choices=ACTION_CHOICES,
                   help="send an action to the running instance (starts it if needed)")
    p.add_argument("--show", action="store_true", help="open the main window on start")
    p.add_argument("--config", help="path to config.yaml")
    p.add_argument("-v", "--verbose", action="store_true", help="verbose logging")
    sub = p.add_subparsers(dest="command")

    def io(sp):
        sp.add_argument("--in", dest="infile", help="input file (default: stdin)")
        sp.add_argument("--out", dest="outfile", help="output file (default: stdout)")
        sp.add_argument("--project", help="use the mappings of this project")
        sp.add_argument("--passphrase-env", help="environment variable holding the project passphrase")

    sp = sub.add_parser("process", help="process text without GUI")
    sp.add_argument("--mode", choices=["pseudonymize", "anonymize", "redact"], help="default: config")
    io(sp)
    sp = sub.add_parser("revert", help="restore original values (needs --project)")
    io(sp)
    sp = sub.add_parser("analyze", help="list findings as JSON")
    io(sp)
    sub.add_parser("projects", help="list projects")
    return p


def _read_input(args) -> str:
    if args.infile:
        with open(args.infile, encoding="utf-8") as fh:
            return fh.read()
    if sys.stdin is None:
        raise SystemExit("error: no standard input available (Windows GUI build) – use --in FILE")
    return sys.stdin.buffer.read().decode("utf-8", "replace")


def _write_output(args, text: str) -> None:
    if args.outfile:
        with open(args.outfile, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
        sys.stdout.flush()


def headless(args) -> int:
    from .config import Config, engine_settings
    from .core.engine import Engine
    from .core.history import History
    from .core.projects import ProjectError, ProjectStore, WrongPassphrase
    from .core.vault import Vault

    cfg = Config.load(args.config or paths.config_file())
    from .core.osprotect import protector
    store = ProjectStore(paths.projects_dir(),
                         protector=protector() if cfg.get("project.os_encryption", True) else None)
    if args.command == "projects":
        for info in store.list():
            print(f"{info.name}\t{info.protection}\t{info.path}")
        return 0
    prj = None
    if args.project:
        try:
            pw = os.environ.get(args.passphrase_env) if args.passphrase_env else None
            if store.exists(args.project) and store.needs_passphrase(args.project) and not pw:
                if sys.stdin is not None and sys.stdin.isatty():
                    pw = getpass.getpass(f"Passphrase for {args.project}: ")
                else:
                    print("error: project is encrypted, use --passphrase-env", file=sys.stderr)
                    return 2
            prj = store.load(args.project, pw)
        except WrongPassphrase:
            print("error: wrong passphrase", file=sys.stderr)
            return 2
        except ProjectError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    elif args.command == "revert":
        print("error: revert needs --project (session mappings exist only inside the running app)",
              file=sys.stderr)
        return 2
    vault = prj.vault if prj else Vault("cli")
    engine = Engine(engine_settings(cfg, prj.terms if prj else None, prj.known_domains if prj else None), vault)
    if cfg.get("ner.enabled"):
        from .core.detectors.external import NerDetector, find_ner_helper
        cmd = find_ner_helper(cfg.get("ner.helper_path", ""))
        if cmd:
            engine.add_detector(NerDetector(cmd, cfg.get("ner.language", "auto"), cfg.get("ner.types") or [],
                                            {"de": cfg.get("ner.model_de"), "en": cfg.get("ner.model_en")}))
    if cfg.get("llm.enabled") and cfg.get("llm.detect"):
        from .core.detectors.external import LlmDetector
        from .llm.client import LLMClient, LLMSettings
        engine.add_detector(LlmDetector(LLMClient(LLMSettings.from_config(cfg.get("llm"))),
                                        cfg.get("llm.detect_types") or ["PERSON", "ORG"]))
    text = _read_input(args)
    if args.command == "analyze":
        warnings: list[str] = []
        findings = engine.analyze(text, warnings)
        _write_output(args, json.dumps([{"start": f.start, "end": f.end, "type": f.type, "text": f.text,
                                         "detector": f.detector} for f in findings],
                                       ensure_ascii=False, indent=2) + "\n")
        for w in warnings:
            print("warning:", w, file=sys.stderr)
        return 0
    if args.command == "revert":
        res = engine.revert(text)
    else:
        res = engine.process(text, args.mode or cfg.get("general.mode", "pseudonymize"))
    _write_output(args, res.output)
    for w in res.warnings:
        print("warning:", w, file=sys.stderr)
    if prj is not None:
        if prj.store_history and res.changed:
            h = History(int(cfg.get("general.history_size", 200)), bool(cfg.get("general.history_store_originals", True)))
            h.load_list(prj.history)
            h.add(res, "cli", prj.name)
            prj.history = h.to_list()
        store.save(prj)
    return 0


def gui(args) -> int:
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication

    from .config import Config
    from .platform.ipc import InstanceServer, send_command

    QApplication.setApplicationName(APP_NAME)
    QApplication.setOrganizationName(APP_ORG)
    QApplication.setApplicationDisplayName(APP_DISPLAY_NAME)
    QApplication.setApplicationVersion(__version__)
    QApplication.setDesktopFileName(APP_NAME)
    app = QApplication(sys.argv[:1])
    app.setQuitOnLastWindowClosed(False)

    if send_command({"action": args.action or "show"}):
        return 0
    server = InstanceServer()
    if not server.listen():
        send_command({"action": args.action or "show"})
        return 0

    from .gui import icons
    from .gui.app import Controller
    app.setWindowIcon(icons.icon())
    cfg = Config.load(args.config or paths.config_file())
    ctrl = Controller(app, cfg)
    server.command.connect(ctrl.handle_command)
    ctrl.start(show_window=args.show)
    if args.action and args.action != "show":
        QTimer.singleShot(400, lambda: ctrl.run_action(args.action, "cli"))

    import signal
    signal.signal(signal.SIGINT, lambda *_: ctrl.quit())
    keepalive = QTimer()
    keepalive.start(500)
    keepalive.timeout.connect(lambda: None)   # let Python handle SIGINT
    rc = app.exec()
    server.close()
    if ctrl.restart_requested:
        from PySide6.QtCore import QProcess, QProcessEnvironment
        from .platform.autostart import launch_command
        cmd = launch_command()
        proc = QProcess()
        proc.setProgram(cmd[0])
        proc.setArguments(cmd[1:] + (["--show"] if args.show else []))
        proc.setWorkingDirectory(os.getcwd())
        env = QProcessEnvironment.systemEnvironment()
        # a PyInstaller onefile build must not reuse our temporary extraction
        # directory – it is deleted as soon as this process exits
        env.insert("PYINSTALLER_RESET_ENVIRONMENT", "1")
        proc.setProcessEnvironment(env)
        proc.startDetached()
    return rc


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    headless_cmd = bool(argv) and argv[0] in HEADLESS
    _fix_std_streams(headless_cmd or "--version" in argv or "-h" in argv or "--help" in argv)
    args = build_parser().parse_args(argv)
    if args.version:
        print(f"{APP_NAME} {__version__}")
        return 0
    setup_logging(args.verbose)
    if args.command in HEADLESS:
        return headless(args)
    return gui(args)
