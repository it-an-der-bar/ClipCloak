"""Tiny JSON based translation layer (English + German)."""

from __future__ import annotations

import json
import locale
import logging
import os

from .paths import resource_path

log = logging.getLogger(__name__)

LANGUAGES = {"en": "English", "de": "Deutsch"}
_strings: dict[str, str] = {}
_fallback: dict[str, str] = {}
_lang = "en"


def _load(lang: str) -> dict[str, str]:
    p = resource_path("i18n", f"{lang}.json")
    try:
        return json.loads(p.read_text("utf-8"))
    except (OSError, ValueError) as exc:
        log.error("cannot load translations %s: %s", p, exc)
        return {}


def system_language() -> str:
    for var in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
        v = os.environ.get(var)
        if v:
            return "de" if v.lower().startswith("de") else "en"
    try:
        loc = locale.getlocale()[0] or ""
    except ValueError:
        loc = ""
    if not loc:
        try:
            from PySide6.QtCore import QLocale
            loc = QLocale.system().name()
        except Exception:  # pragma: no cover
            loc = ""
    return "de" if loc.lower().startswith("de") or loc.lower().startswith("german") else "en"


def init(setting: str = "auto") -> str:
    global _strings, _fallback, _lang
    lang = setting if setting in LANGUAGES else system_language()
    _fallback = _load("en")
    _strings = _fallback if lang == "en" else _load(lang)
    _lang = lang
    return lang


def current() -> str:
    return _lang


def t(key: str, **kw) -> str:
    if not _fallback:           # used before init() (CLI, tests): English
        init("en")
    s = _strings.get(key) or _fallback.get(key) or key
    if kw:
        try:
            return s.format(**kw)
        except (KeyError, IndexError, ValueError):
            return s
    return s
