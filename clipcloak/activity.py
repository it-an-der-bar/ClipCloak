"""User-visible activity log (shown in the "Log" tab).

Two loggers:
* ``<pkg>.activity`` – what the program does (actions, durations, LLM/NER calls).
  Goes to the log file and to the Log tab. Never contains clipboard contents.
* ``<pkg>.ui``       – details that may contain data (e.g. leftovers reported by the
  LLM check). Only shown in the Log tab (RAM), never written to the log file.
"""

from __future__ import annotations

import logging

from .i18n import t

_PKG = __package__ or "clipcloak"
activity = logging.getLogger(_PKG + ".activity")
ui_only = logging.getLogger(_PKG + ".ui")
ui_only.propagate = False
ui_only.setLevel(logging.INFO)


def event(key: str, level: int = logging.INFO, **kw) -> None:
    activity.log(level, t(key, **kw))


def detail(key: str, **kw) -> None:
    ui_only.info(t(key, **kw))
