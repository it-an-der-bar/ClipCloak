"""Origin/tracking marks in URLs: utm_*, click ids, share ids, redirect wrappers.

These parameters say where a link came from and often who received it
(``mc_eid``, ``mkt_tok``, ``_hsenc``, the ``data`` part of Outlook Safe Links contains
the recipient's e-mail address). They are removed in every mode; the rest of the
URL is processed as usual.

* tracking parameters → removed together with one ``?``/``&`` so the URL stays valid
* redirect wrappers (Outlook Safe Links, Google /url, Facebook l.php, LinkedIn, Slack,
  YouTube, Steam, DuckDuckGo, Proofpoint URL Defense) → replaced by the real target
* text fragments ``#:~:text=…`` (what you highlighted on the page) → removed
* Amazon ``/ref=…`` path segments → removed
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, unquote, urlsplit

from .. import wordlists
from ..entities import EntityType as T
from .base import Detector

URL_RE = re.compile(r"""https?://[^\s<>"'`]+""", re.IGNORECASE)
TRAILING = ".,;:!?)]}'\""


def _host_matches(host: str, suffixes) -> bool:
    """``example.com`` matches the host and its subdomains; ``google.*`` any TLD."""
    for s in suffixes:
        if s.endswith(".*"):
            if re.search(r"(^|\.)" + re.escape(s[:-2]) + r"\.[a-z]{2,3}(\.[a-z]{2})?$", host):
                return True
        elif host == s or host.endswith("." + s):
            return True
    return False


def _site_params(host: str) -> set[str]:
    out: set[str] = set()
    for suffixes, params in wordlists.TRACKING_SITE_PARAMS:
        if _host_matches(host, suffixes):
            out |= params
    return out


def is_tracking_param(name: str, host: str, extra: set[str] | None = None, site: set[str] | None = None) -> bool:
    low = name.lower()
    if low in wordlists.TRACKING_PARAMS or (extra and low in extra):
        return True
    if any(low.startswith(p) for p in wordlists.TRACKING_PREFIXES):
        return True
    return bool(site) and low in site


def unwrap(url: str) -> str | None:
    """The real target of a known redirect wrapper, or None."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    path = parts.path or ""
    if host.endswith("urldefense.com") and path.startswith("/v3/__"):
        m = re.match(r"/v3/__(.+?)__;", path + ("?" + parts.query if parts.query else ""))
        return m.group(1) if m else None
    if host.endswith("urldefense.proofpoint.com") and path.startswith("/v2/url"):
        q = dict(parse_qsl(parts.query, keep_blank_values=True))
        u = q.get("u")
        if u:
            return unquote(u.replace("-", "%").replace("_", "/"))
        return None
    for host_rx, path_rx, keys in wordlists.REDIRECT_WRAPPERS:
        if re.fullmatch(host_rx, host) and re.match(path_rx, path):
            q = dict(parse_qsl(parts.query, keep_blank_values=True))
            for k in keys:
                target = q.get(k)
                if target and re.match(r"https?://", target, re.IGNORECASE):
                    return target
    return None


class TrackingDetector(Detector):
    id = "tracking"
    types = (T.TRACKING.value,)
    priority = 85            # wins over domains/e-mails inside the removed parts

    def find(self, text, ctx):
        extra = {p.lower() for p in ctx.options.get("tracking_params", ())}
        out = []
        for m in URL_RE.finditer(text):
            url = m.group(0)
            while url and url[-1] in TRAILING:
                if url[-1] == ")" and url.count("(") >= url.count(")"):
                    break
                url = url[:-1]
            start = m.start()
            target = unwrap(url)
            if target:
                out.append(self.mk(start, start + len(url), T.TRACKING.value, text, unwrap=target))
                continue
            out += self._in_url(text, start, url, extra)
        return out

    def _in_url(self, text: str, base: int, url: str, extra: set[str]):
        out = []
        try:
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:
            return out
        site = _site_params(host)
        # Amazon: /ref=xyz path segment
        if _host_matches(host, ("amazon.*",)):
            for rm in re.finditer(r"/ref=[^/?#]*", url):
                out.append(self.mk(base + rm.start(), base + rm.end(), T.TRACKING.value, text))
        q = url.find("?")
        h = url.find("#")
        if q >= 0 and (h < 0 or q < h):
            qend = h if h >= 0 else len(url)
            params, pos = [], q + 1
            for raw in url[q + 1:qend].split("&"):
                params.append((pos, pos + len(raw), raw))
                pos += len(raw) + 1
            drop = [bool(raw) and is_tracking_param(raw.split("=", 1)[0], host, extra, site)
                    for _s, _e, raw in params]
            i, n = 0, len(params)
            while i < n:
                if not drop[i]:
                    i += 1
                    continue
                j = i
                while j + 1 < n and drop[j + 1]:
                    j += 1
                s, e = params[i][0], params[j][1]
                if i == 0 and j == n - 1:
                    s -= 1                    # the whole query: "?" too
                elif i == 0:
                    e += 1                    # "a=1&" … keep the "?" for the rest
                else:
                    s -= 1                    # "&a=1"
                out.append(self.mk(base + s, base + e, T.TRACKING.value, text))
                i = j + 1
        if h >= 0:
            frag = url[h + 1:]
            k = frag.find(":~:")
            if k >= 0:
                s = h if k == 0 else h + 1 + k
                out.append(self.mk(base + s, base + len(url), T.TRACKING.value, text))
        return out
