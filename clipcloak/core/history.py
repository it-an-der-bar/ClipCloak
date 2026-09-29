"""History of processed clipboard contents (for diff view and traceability)."""

from __future__ import annotations

import itertools
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from .entities import Replacement, Result

_ids = itertools.count(1)


@dataclass
class HistoryEntry:
    id: int
    timestamp: float
    action: str
    source: str
    input: str
    output: str
    replacements: list[Replacement] = field(default_factory=list)
    project: str = ""
    warnings: list[str] = field(default_factory=list)
    sensitive_warnings: list[str] = field(default_factory=list)   # name original values (LLM check)

    def all_warnings(self) -> list[str]:
        return self.warnings + self.sensitive_warnings

    def counts(self) -> dict[str, int]:
        c: dict[str, int] = {}
        for r in self.replacements:
            c[r.type] = c.get(r.type, 0) + 1
        return c

    def to_dict(self) -> dict:
        return {"id": self.id, "timestamp": self.timestamp, "action": self.action,
                "source": self.source, "input": self.input, "output": self.output,
                "replacements": [r.to_dict() for r in self.replacements],
                "project": self.project, "warnings": self.warnings,
                "sensitive_warnings": self.sensitive_warnings}

    @classmethod
    def from_dict(cls, d: dict) -> "HistoryEntry":
        return cls(next(_ids), d.get("timestamp", time.time()), d.get("action", ""),
                   d.get("source", ""), d.get("input", ""), d.get("output", ""),
                   [Replacement.from_dict(r) for r in d.get("replacements", [])],
                   d.get("project", ""), d.get("warnings", []), d.get("sensitive_warnings", []))


class History:
    def __init__(self, maxlen: int = 200, store_originals: bool = True):
        self.entries: deque[HistoryEntry] = deque(maxlen=max(1, maxlen))
        self.store_originals = store_originals
        self.lock = threading.RLock()
        self.listeners: list = []

    def set_maxlen(self, n: int) -> None:
        with self.lock:
            self.entries = deque(self.entries, maxlen=max(1, n))

    def add(self, result: Result, source: str, project: str = "") -> HistoryEntry:
        with self.lock:
            e = HistoryEntry(next(_ids), time.time(), result.mode, source, result.input, result.output,
                             list(result.replacements), project, list(result.warnings))
            if not self.store_originals:
                _mask_entry(e)
            self.entries.appendleft(e)
        for cb in list(self.listeners):
            cb(e)
        return e

    def set_store_originals(self, on: bool) -> None:
        """Switching it off also blanks the originals in the entries kept so far."""
        with self.lock:
            self.store_originals = on
            if not on:
                for e in self.entries:
                    _mask_entry(e)
        for cb in list(self.listeners):
            cb(None)

    def add_warning(self, entry: HistoryEntry, text: str, sensitive: bool = False) -> None:
        """``sensitive``: the warning names original values – dropped without store_originals."""
        if sensitive and not self.store_originals:
            return
        with self.lock:
            (entry.sensitive_warnings if sensitive else entry.warnings).append(text)

    def remove(self, entry_id: int) -> None:
        with self.lock:
            self.entries = deque((e for e in self.entries if e.id != entry_id), maxlen=self.entries.maxlen)
        for cb in list(self.listeners):
            cb(None)

    def clear(self) -> None:
        with self.lock:
            self.entries.clear()
        for cb in list(self.listeners):
            cb(None)

    def get(self, entry_id: int) -> HistoryEntry | None:
        for e in self.entries:
            if e.id == entry_id:
                return e
        return None

    def to_list(self) -> list[dict]:
        with self.lock:
            return [e.to_dict() for e in self.entries]

    def load_list(self, items: list[dict]) -> None:
        with self.lock:
            self.entries.clear()
            for d in items[: self.entries.maxlen]:
                e = HistoryEntry.from_dict(d)
                if not self.store_originals:
                    _mask_entry(e)          # entries saved while the setting was still on
                self.entries.append(e)
        for cb in list(self.listeners):
            cb(None)


def _blank(text: str, spans) -> str:
    out, pos = [], 0
    for s, e in sorted(spans):
        if s < pos:
            continue
        out.append(text[pos:s])
        out.append("•" * (e - s))
        pos = e
    out.append(text[pos:])
    return "".join(out)


def _mask_entry(e: HistoryEntry) -> None:
    """Blank the original values, keep the layout. Pseudonymise/anonymise/redact: the originals
    are in the input; revert: they are in the output (the restored values)."""
    e.sensitive_warnings = []
    if e.action == "revert":
        e.output = _blank(e.output, [(r.out_start, r.out_end) for r in e.replacements])
        e.replacements = [Replacement(r.in_start, r.in_end, r.out_start, r.out_end, r.type, r.original,
                                      "•" * max(1, len(r.replacement)), r.detector) for r in e.replacements]
    else:
        e.input = _blank(e.input, [(r.in_start, r.in_end) for r in e.replacements])
        e.replacements = [Replacement(r.in_start, r.in_end, r.out_start, r.out_end, r.type,
                                      "•" * max(1, r.in_end - r.in_start), r.replacement, r.detector)
                          for r in e.replacements]
