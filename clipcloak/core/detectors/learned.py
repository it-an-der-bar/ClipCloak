"""Person names learned from e-mail addresses and earlier mappings.

``jonas.hartmann@example.org`` teaches the tokens *Jonas* (first name)
and *Hartmann* (last name). Capitalised occurrences of these tokens in the
same text – or in later texts of the same session/project – are replaced
consistently with the surrogate used for the e-mail address.
"""

from __future__ import annotations

import re

from .. import wordlists
from ..entities import EntityType as T
from ..textutil import WORD_BOUNDARY_L, WORD_BOUNDARY_R
from .base import Detector
from .network import EMAIL_RE


class LearnedNameDetector(Detector):
    id = "learned-names"
    types = (T.PERSON.value,)
    priority = 32

    def __init__(self, vault_getter=None):
        self.vault_getter = vault_getter

    def find(self, text, ctx):
        tokens: dict[str, str] = {}
        v = self.vault_getter() if self.vault_getter else None
        if v is not None:
            for k in v.maps["first"].fwd:
                tokens.setdefault(k, "first")
            for k in v.maps["last"].fwd:
                tokens.setdefault(k, "last")
        for m in EMAIL_RE.finditer(text):
            local = m.group(1)
            if local.lower() in wordlists.FUNCTIONAL_MAILBOXES:
                continue
            parts = [p for p in re.split(r"[._+-]", re.sub(r"\d+$", "", local)) if p]
            if len(parts) < 2 or not all(p.isalpha() for p in parts):
                continue
            for i, p in enumerate(parts):
                tokens.setdefault(p.lower(), "last" if i == len(parts) - 1 else "first")
        skip = wordlists.FUNCTIONAL_MAILBOXES | wordlists.GENERIC_LABELS
        tokens = {k: kind for k, kind in tokens.items() if len(k) >= 3 and k not in skip}
        if not tokens:
            return []
        alt = "|".join(re.escape(k) for k in sorted(tokens, key=len, reverse=True))
        rx = re.compile(WORD_BOUNDARY_L + "(?:" + alt + ")" + WORD_BOUNDARY_R, re.IGNORECASE)
        out = []
        for m in rx.finditer(text):
            w = m.group(0)
            if w.islower():
                continue
            out.append(self.mk(m.start(), m.end(), T.PERSON.value, text, kind=tokens[w.lower()]))
        return out
