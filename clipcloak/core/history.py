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

    def counts(self) -> dict[str, int]:
        c: dict[str, int] = {}
        for r in self.replacements:
            c[r.type] = c.get(r.type, 0) + 1
        return c

    def to_dict(self) -> dict:
        return {"id": self.id, "timestamp": self.timestamp, "action": self.action,
                "source": self.source, "input": self.input, "output": self.output,
                "replacements": [r.to_dict() for r in self.replacements],
                "project": self.project, "warnings": self.warnings}

    @classmethod
    def from_dict(cls, d: dict) -> "HistoryEntry":
        return cls(next(_ids), d.get("timestamp", time.time()), d.get("action", ""),
                   d.get("source", ""), d.get("input", ""), d.get("output", ""),
                   [Replacement.from_dict(r) for r in d.get("replacements", [])],
                   d.get("project", ""), d.get("warnings", []))


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
            inp = result.input
            reps = result.replacements
            if not self.store_originals and result.mode != "revert":
                # keep the layout of the input but blank the detected values
                inp = _mask(result)
                reps = [Replacement(r.in_start, r.in_end, r.out_start, r.out_end, r.type,
                                    "•" * (r.in_end - r.in_start), r.replacement, r.detector)
                        for r in reps]
            e = HistoryEntry(next(_ids), time.time(), result.mode, source, inp, result.output,
                             list(reps), project, list(result.warnings))
            self.entries.appendleft(e)
        for cb in list(self.listeners):
            cb(e)
        return e

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
                self.entries.append(HistoryEntry.from_dict(d))
        for cb in list(self.listeners):
            cb(None)


def _mask(result: Result) -> str:
    text = result.input
    out, pos = [], 0
    for r in sorted(result.replacements, key=lambda r: r.in_start):
        out.append(text[pos:r.in_start])
        out.append("•" * (r.in_end - r.in_start))
        pos = r.in_end
    out.append(text[pos:])
    return "".join(out)
