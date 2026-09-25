"""Identity data: user paths/accounts, phone numbers, IBAN, cards, SIDs, custom terms."""

from __future__ import annotations

import re

from .. import wordlists
from ..entities import EntityType as T
from ..textutil import WORD_BOUNDARY_L, WORD_BOUNDARY_R, iban_checksum_ok, luhn_ok
from .base import Detector

WIN_PROFILE_RE = re.compile(
    r"(?i)\b[A-Z]:(\\{1,2}|/)(?:Users|Benutzer|Documents and Settings|Dokumente und Einstellungen)\1"
    r"([^\\/:*?\"<>|\r\n\t]{1,64}?)(?=\1|[\"'\s,;)]|$)")
UNIX_HOME_RE = re.compile(r"(?<![\w.~-])/(?:home|Users)/([A-Za-z_][A-Za-z0-9_.-]{0,31})(?=/|[\s\"',;:)]|$)")
TILDE_USER_RE = re.compile(r"(?<![\w/~])~([a-z_][a-z0-9_.-]{1,31})(?=/)")
NT_ACCOUNT_RE = re.compile(r"(?<![\w\\])([A-Z][A-Z0-9-]{1,14})\\([A-Za-z][A-Za-z0-9._-]{1,63})(?![\w\\])")
UPN_SKIP_DOMAINS = {"NT AUTHORITY", "BUILTIN", "NT SERVICE", "WORKGROUP", "IIS APPPOOL",
                    "NT VIRTUAL MACHINE", "WINDOW MANAGER", "FONT DRIVER HOST", "AUTHORITY"}

IBAN_RE = re.compile(r"\b([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?)\b")
IBAN_LEN = {"DE": 22, "AT": 20, "CH": 21, "LI": 21, "NL": 18, "BE": 16, "FR": 27, "IT": 27,
            "ES": 24, "PL": 28, "GB": 22, "LU": 20, "DK": 18, "SE": 24, "NO": 15, "FI": 18,
            "IE": 22, "PT": 25, "CZ": 24, "SK": 24, "HU": 28, "SI": 19, "HR": 21, "RO": 24,
            "BG": 22, "GR": 27, "EE": 20, "LV": 21, "LT": 20, "MT": 31, "CY": 28, "IS": 26,
            "MC": 27, "SM": 27, "TR": 26}
CARD_RE = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
PHONE_INTL_RE = re.compile(
    r"(?<![\w+])(?:\+|00)[1-9]\d{0,2}[ \-/]?(?:\(0\)[ \-/]?)?\(?\d{1,5}\)?(?:[ \-/]?\d{1,8}){1,4}(?![\w])")
PHONE_NAT_RE = re.compile(r"(?<![\w+./:-])(?:\(0\d{1,5}\)|0\d{2,5})(?:[ /\-]\d{2,8}){1,3}(?![\w:/-]|\.\d)")
SID_RE = re.compile(r"\bS-1-5-21-\d{1,10}-\d{1,10}-\d{1,10}(?:-\d{1,10})?\b")
DATE_LIKE = re.compile(r"^\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}$")


class UserPathDetector(Detector):
    id = "userpath"
    types = (T.USERNAME.value,)
    priority = 56

    def find(self, text, ctx):
        out = []
        for m in WIN_PROFILE_RE.finditer(text):
            name = m.group(2).strip()
            if name.lower() in wordlists.SKIP_USERNAMES or not name:
                continue
            s = m.start(2)
            out.append(self.mk(s, s + len(name), T.USERNAME.value, text))
        for rx in (UNIX_HOME_RE, TILDE_USER_RE):
            for m in rx.finditer(text):
                if m.group(1).lower() in wordlists.SKIP_USERNAMES:
                    continue
                out.append(self.mk(m.start(1), m.end(1), T.USERNAME.value, text))
        for m in NT_ACCOUNT_RE.finditer(text):
            dom, user = m.group(1), m.group(2)
            if dom in UPN_SKIP_DOMAINS or re.fullmatch(r"[A-Z]", dom):
                continue
            out.append(self.mk(m.start(1), m.end(1), T.HOSTNAME.value, text, priority=54))
            if user.lower() not in wordlists.SKIP_USERNAMES:
                out.append(self.mk(m.start(2), m.end(2), T.USERNAME.value, text, priority=54))
        return out


class IbanDetector(Detector):
    id = "iban"
    types = (T.IBAN.value,)
    priority = 72

    def find(self, text, ctx):
        out = []
        for m in IBAN_RE.finditer(text):
            raw = m.group(1)
            compact = raw.replace(" ", "")
            exp = IBAN_LEN.get(compact[:2])
            if exp is not None and len(compact) != exp:
                # the greedy regex may have eaten a trailing group; trim
                if len(compact) > exp:
                    cut, n = 0, 0
                    for i, c in enumerate(raw):
                        if c != " ":
                            n += 1
                        if n == exp:
                            cut = i + 1
                            break
                    raw = raw[:cut]
                    compact = raw.replace(" ", "")
                else:
                    continue
            if not (15 <= len(compact) <= 34) or not iban_checksum_ok(compact):
                continue
            s = m.start(1)
            out.append(self.mk(s, s + len(raw), T.IBAN.value, text))
        return out


class CardDetector(Detector):
    id = "creditcard"
    types = (T.CREDIT_CARD.value,)
    priority = 70

    def find(self, text, ctx):
        out = []
        for m in CARD_RE.finditer(text):
            raw = m.group(0)
            digits = re.sub(r"\D", "", raw)
            if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
                continue
            if not re.match(r"^(4|5[1-5]|2[2-7]|3[47]|6011|65|35)", digits):
                continue
            seps = set(re.findall(r"[ -]", raw))
            if len(seps) > 1:
                continue
            if luhn_ok(digits):
                out.append(self.mk(m.start(), m.end(), T.CREDIT_CARD.value, text))
        return out


class PhoneDetector(Detector):
    id = "phone"
    types = (T.PHONE.value,)
    priority = 40

    def find(self, text, ctx):
        out = []
        for rx in (PHONE_INTL_RE, PHONE_NAT_RE):
            for m in rx.finditer(text):
                raw = m.group(0).rstrip(" -/")
                digits = re.sub(r"\D", "", raw)
                if not 7 <= len(digits) <= 15 or DATE_LIKE.match(raw):
                    continue
                out.append(self.mk(m.start(), m.start() + len(raw), T.PHONE.value, text))
        return out


class SidDetector(Detector):
    id = "sid"
    types = (T.SID.value,)
    priority = 70

    def find(self, text, ctx):
        return [self.mk(m.start(), m.end(), T.SID.value, text) for m in SID_RE.finditer(text)]


class CustomTermDetector(Detector):
    """User supplied terms (global list + active project list)."""

    id = "custom"
    types = (T.CUSTOM.value,)
    priority = 75

    def find(self, text, ctx):
        out = []
        for term in ctx.custom_terms:
            value = (term.get("term") or "").strip()
            if not value:
                continue
            flags = 0 if term.get("case_sensitive") else re.IGNORECASE
            if term.get("regex"):
                try:
                    rx = re.compile(value, flags)
                except re.error:
                    continue
            else:
                rx = re.compile(WORD_BOUNDARY_L + re.escape(value) + WORD_BOUNDARY_R, flags)
            as_type = (term.get("type") or "").upper()
            typ = as_type if as_type in T.__members__ else T.CUSTOM.value
            for m in rx.finditer(text):
                if m.end() <= m.start():
                    continue
                out.append(self.mk(m.start(), m.end(), typ, text,
                                   replacement=term.get("replacement") or "",
                                   as_type=as_type))
        return out
