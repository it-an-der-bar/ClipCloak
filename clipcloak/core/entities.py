"""Entity types and finding/replacement records."""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from enum import Enum


class EntityType(str, Enum):
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    MAC = "MAC"
    EMAIL = "EMAIL"
    DOMAIN = "DOMAIN"
    HOSTNAME = "HOSTNAME"
    USERNAME = "USERNAME"
    PERSON = "PERSON"
    ORG = "ORG"
    LOCATION = "LOCATION"
    PHONE = "PHONE"
    IBAN = "IBAN"
    CREDIT_CARD = "CREDIT_CARD"
    SID = "SID"
    SECRET = "SECRET"
    PRIVATE_KEY = "PRIVATE_KEY"
    CERTIFICATE = "CERTIFICATE"
    IDENTIFIER = "IDENTIFIER"       # parts of infrastructure names (namespace, release …)
    TRACKING = "TRACKING"           # tracking parameters / redirect wrappers in URLs (removed)
    CUSTOM = "CUSTOM"

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.value


ALL_TYPES = [t.value for t in EntityType]

# Types treated as "critical" by default for the clipboard watcher.
DEFAULT_CRITICAL = ["SECRET", "PRIVATE_KEY", "CREDIT_CARD", "IBAN"]


class Mode(str, Enum):
    REDACT = "redact"
    ANONYMIZE = "anonymize"
    PSEUDONYMIZE = "pseudonymize"
    REVERT = "revert"


@dataclass
class Finding:
    start: int
    end: int
    type: str
    text: str
    detector: str
    priority: int = 50
    meta: dict = field(default_factory=dict)

    @property
    def length(self) -> int:
        return self.end - self.start

    def overlaps(self, other: "Finding") -> bool:
        return self.start < other.end and other.start < self.end


@dataclass
class Replacement:
    """One applied change; offsets refer to the input and the output text."""

    in_start: int
    in_end: int
    out_start: int
    out_end: int
    type: str
    original: str
    replacement: str
    detector: str = ""

    def to_dict(self) -> dict:
        return {
            "in_start": self.in_start, "in_end": self.in_end,
            "out_start": self.out_start, "out_end": self.out_end,
            "type": self.type, "original": self.original,
            "replacement": self.replacement, "detector": self.detector,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Replacement":
        return cls(**{k: d[k] for k in (
            "in_start", "in_end", "out_start", "out_end", "type",
            "original", "replacement")}, detector=d.get("detector", ""))


@dataclass
class Result:
    mode: str
    input: str
    output: str
    replacements: list[Replacement] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.input != self.output

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.replacements:
            out[r.type] = out.get(r.type, 0) + 1
        return out


class IntervalSet:
    """Non-overlapping half-open intervals with O(log n) overlap checks."""

    def __init__(self):
        self.starts: list[int] = []
        self.ends: list[int] = []

    def free(self, start: int, end: int) -> bool:
        i = bisect.bisect_right(self.starts, start)
        if i > 0 and self.ends[i - 1] > start:
            return False
        if i < len(self.starts) and self.starts[i] < end:
            return False
        return True

    def add(self, start: int, end: int) -> None:
        i = bisect.bisect_right(self.starts, start)
        self.starts.insert(i, start)
        self.ends.insert(i, end)


def pick_non_overlapping(ordered: list[Finding]) -> list[Finding]:
    """Greedy selection in the given preference order."""
    taken = IntervalSet()
    accepted: list[Finding] = []
    for f in ordered:
        if f.length <= 0 or not taken.free(f.start, f.end):
            continue
        taken.add(f.start, f.end)
        accepted.append(f)
    accepted.sort(key=lambda f: f.start)
    return accepted


def resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    """Keep non-overlapping findings, preferring priority, then length."""
    return pick_non_overlapping(sorted(findings, key=lambda f: (-f.priority, -f.length, f.start)))


def apply_spans(text: str, spans: list[tuple[int, int, str, str, str, str]]) -> tuple[str, list[Replacement]]:
    """Apply (start, end, replacement, type, original, detector) spans.

    Spans must not overlap. Returns the new text and replacement records.
    """
    spans = sorted(spans, key=lambda s: s[0])
    parts: list[str] = []
    reps: list[Replacement] = []
    pos = 0
    out_len = 0
    for start, end, rep, typ, orig, det in spans:
        chunk = text[pos:start]
        parts.append(chunk)
        out_len += len(chunk)
        parts.append(rep)
        reps.append(Replacement(start, end, out_len, out_len + len(rep), typ, orig, rep, det))
        out_len += len(rep)
        pos = end
    parts.append(text[pos:])
    return "".join(parts), reps
