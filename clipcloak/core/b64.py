"""Base64: recognise text that is Base64 of readable text, decode and encode.

Only whole contents (or a whole selection) count – a Base64 string inside a sentence is left
alone. Recognised are standard and URL-safe Base64, with or without padding, also wrapped over
several lines (PEM-like blocks). It must decode to readable UTF-8 text; binary data does not count.

``strict`` (the clipboard watcher, which looks at every copy) also needs a length of 12+ characters
(8+ with "=" padding) and ignores hex strings and plain words; the explicit action accepts short
values such as Kubernetes secrets ("YWRtaW4=" -> "admin").
"""

from __future__ import annotations

import base64
import binascii
import re

MIN_LEN = 12            # strict
MIN_LEN_PADDED = 8     # strict, with "=" padding
_STD = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_URL = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", text or "")


def decode(text: str, strict: bool = False) -> str | None:
    """The decoded text, or None if ``text`` is not Base64 of readable text."""
    s = _compact(text)
    if len(s) < 4:
        return None
    if strict:
        if len(s) < (MIN_LEN_PADDED if s.endswith("=") else MIN_LEN):
            return None
        if re.fullmatch(r"[0-9A-Fa-f]+", s) or re.fullmatch(r"[A-Za-z]+", s):
            return None                           # hex, a plain word
    if _STD.match(s):
        alt = base64.b64decode
    elif _URL.match(s):
        alt = base64.urlsafe_b64decode
    else:
        return None
    body = s.rstrip("=")
    if len(body) % 4 == 1:
        return None                               # impossible length
    try:
        raw = alt(body + "=" * (-len(body) % 4))
        out = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not out.strip():
        return None
    printable = sum(1 for c in out if c.isprintable() or c in "\n\r\t")
    if printable / len(out) < 0.95:
        return None
    return out


def encode(text: str, urlsafe: bool = False) -> str:
    raw = (text or "").encode("utf-8")
    return (base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)).decode("ascii")
