"""Network related detectors: IPs, MACs, e-mail, domains, host names."""

from __future__ import annotations

import ipaddress
import re

from .. import wordlists
from ..entities import EntityType as T
from ..ipmap import is_netmask
from .base import Detector, DetectorContext

_OCT = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4_RE = re.compile(
    r"(?<![\w.])(" + _OCT + r"(?:\." + _OCT + r"){3})(?:/(3[0-2]|[12]?\d))?(?![\w]|\.\d)")
IPV6_RE = re.compile(
    r"(?<![\w:.])((?:[0-9A-Fa-f]{1,4}|:)?(?::[0-9A-Fa-f]{0,4}){2,7}"
    r"(?:(?<=:)(?:\d{1,3}\.){3}\d{1,3})?)(%[\w.-]+)?(?:/(\d{1,3}))?(?![\w:])")
MAC_RE = re.compile(
    r"(?<![\w:.-])([0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\2){4}[0-9A-Fa-f]{2}"
    r"|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![\w:.-])")
EMAIL_RE = re.compile(
    r"(?<![\w.+%-])([A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9_])?)@"
    r"((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63})(?![\w-]|\.[A-Za-z0-9])")
DOMAIN_RE = re.compile(
    r"(?<![\w.-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{0,62})"
    r"(?![\w-]|\.[A-Za-z0-9])")
UNC_RE = re.compile(r"(?<![\w\\])\\\\([A-Za-z0-9][A-Za-z0-9-]{0,62})(?=\\)")
PROMPT_RE = re.compile(
    r"(?<![\w.@+-])([a-z_][a-z0-9_.-]{0,31})@([A-Za-z0-9][A-Za-z0-9-]{0,62})"
    r"(?=:(?:~|/)|\s+[~/]|\s*\]|\s*[$#] )")
USER_AT_IP_RE = re.compile(
    r"(?<![\w.+-])([A-Za-z_][\w.-]{0,31})@(?=(?:\d{1,3}\.){3}\d{1,3}(?!\d))")
URL_USERINFO_BEFORE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s/@]*$")
VERSION_CTX = re.compile(r"(?i)(?<![a-z])(?:version|ver\.?|release|v)\s*[:=]?\s*$")


class IPv4Detector(Detector):
    id = "ipv4"
    types = (T.IPV4.value,)
    priority = 60

    def find(self, text, ctx):
        out = []
        for m in IPV4_RE.finditer(text):
            addr = ipaddress.IPv4Address(m.group(1))
            if m.group(2) is None and is_netmask(addr):
                continue
            if VERSION_CTX.search(text[max(0, m.start() - 12):m.start()]):
                continue
            out.append(self.mk(m.start(), m.end(), T.IPV4.value, text))
        return out


class IPv6Detector(Detector):
    id = "ipv6"
    types = (T.IPV6.value,)
    priority = 61

    def find(self, text, ctx):
        out = []
        for m in IPV6_RE.finditer(text):
            cand = m.group(1)
            if cand.count(":") < 2:
                continue
            try:
                addr = ipaddress.IPv6Address(cand)
            except ValueError:
                continue
            if "::" not in cand and cand.count(":") != 7 and "." not in cand:
                continue
            if not re.search(r"\d", cand) and cand.count(":") < 4:
                continue  # "dead::beef" style identifiers in code
            if addr == ipaddress.IPv6Address("::"):
                continue
            end = m.end(1)
            if m.group(3) is not None and m.group(2) is None:
                end = m.end()
            out.append(self.mk(m.start(1), end, T.IPV6.value, text))
        return out


class MacDetector(Detector):
    id = "mac"
    types = (T.MAC.value,)
    priority = 62

    def find(self, text, ctx):
        return [self.mk(m.start(1), m.end(1), T.MAC.value, text) for m in MAC_RE.finditer(text)]


def _tlds(ctx: DetectorContext) -> set:
    return wordlists.ALL_TLDS | set(t.lower() for t in ctx.extra_tlds)


class EmailDetector(Detector):
    id = "email"
    types = (T.EMAIL.value,)
    priority = 80

    def find(self, text, ctx):
        tlds = _tlds(ctx)
        out = []
        for m in EMAIL_RE.finditer(text):
            tld = m.group(2).rsplit(".", 1)[-1].lower()
            if tld not in tlds:
                continue
            if URL_USERINFO_BEFORE.search(text[max(0, m.start() - 300):m.start()]):
                continue  # scheme://user:password@host is not an e-mail address
            out.append(self.mk(m.start(), m.end(), T.EMAIL.value, text))
        return out


def _in_url_context(text: str, start: int) -> bool:
    before = text[max(0, start - 12):start]
    return before.endswith("://") or before.endswith("@") or before.endswith("//")


class DomainDetector(Detector):
    """Fully qualified host/domain names with heuristics against code."""

    id = "domain"
    types = (T.DOMAIN.value,)
    priority = 50

    def find(self, text, ctx):
        tlds = _tlds(ctx)
        known = [d.lower().strip(".") for d in ctx.known_domains if d]
        out = []
        for m in DOMAIN_RE.finditer(text):
            host = m.group(1)
            labels = host.split(".")
            tld = labels[-1]
            low = host.lower()
            is_known = any(low == d or low.endswith("." + d) for d in known)
            if not is_known:
                if tld.lower() not in tlds or len(labels) < 2:
                    continue
                if not self._plausible(text, m, labels, tld):
                    continue
            out.append(self.mk(m.start(1), m.end(1), T.DOMAIN.value, text, priority=65 if is_known else None))
        return out

    @staticmethod
    def _plausible(text, m, labels, tld) -> bool:
        tl = tld.lower()
        after = text[m.end():m.end() + 1]
        if after == "(":
            return False
        # consistent casing: tld lowercase, or everything uppercase
        if tld != tl:
            if not (tld.isupper() and all(l.upper() == l for l in labels)):
                return False
        if any(re.search(r"[a-z][A-Z]", l) for l in labels):
            return False  # camelCase identifiers
        url_ctx = _in_url_context(text, m.start())
        if tl in wordlists.FILE_EXT_TLDS and not url_ctx:
            return False
        if tl in wordlists.CODEY_TLDS and not url_ctx:
            first = labels[0].lower()
            middle = [l.lower() for l in labels[1:-1]]
            if first in wordlists.CODE_RECEIVERS and (len(labels) == 2 or any(x in wordlists.CODE_RECEIVERS for x in middle)):
                return False
            if after == "=" or text[m.end():m.end() + 2] in (" =", "+="):
                return False
        if all(l.isdigit() for l in labels[:-1]):
            return False
        return True


class HostnameDetector(Detector):
    """Single-label host names in UNC paths and shell prompts."""

    id = "hostname"
    types = (T.HOSTNAME.value, T.USERNAME.value)
    priority = 45

    def find(self, text, ctx):
        out = []
        for m in UNC_RE.finditer(text):
            out.append(self.mk(m.start(1), m.end(1), T.HOSTNAME.value, text))
        for m in PROMPT_RE.finditer(text):
            if m.group(1).lower() not in wordlists.SKIP_USERNAMES:
                out.append(self.mk(m.start(1), m.end(1), T.USERNAME.value, text, priority=55))
            host = m.group(2)
            if host.lower() not in ("localhost",):
                out.append(self.mk(m.start(2), m.end(2), T.HOSTNAME.value, text))
        for m in USER_AT_IP_RE.finditer(text):
            if m.group(1).lower() not in wordlists.SKIP_USERNAMES:
                out.append(self.mk(m.start(1), m.end(1), T.USERNAME.value, text, priority=55))
        return out
