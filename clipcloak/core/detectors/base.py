"""Detector base class and shared detection context."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..entities import Finding


@dataclass
class DetectorContext:
    known_domains: list = field(default_factory=list)
    custom_terms: list = field(default_factory=list)   # list of dicts
    extra_tlds: set = field(default_factory=set)
    options: dict = field(default_factory=dict)


class Detector:
    id: str = ""
    types: tuple[str, ...] = ()
    default_enabled: bool = True
    priority: int = 50

    def find(self, text: str, ctx: DetectorContext) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError

    def mk(self, start: int, end: int, typ: str, text: str, priority: int | None = None, **meta) -> Finding:
        return Finding(start, end, typ, text[start:end], self.id,
                       self.priority if priority is None else priority, meta)
