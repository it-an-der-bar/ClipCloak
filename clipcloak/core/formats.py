"""Rich clipboard formats (HTML) processed with the same engine/vault."""

from __future__ import annotations

import html as htmllib
import re
from typing import Callable

from .entities import Result

TOKEN_RE = re.compile(
    r"<!--.*?-->|<!\[CDATA\[.*?\]\]>|<![^>]*>|<\?.*?\?>|</?[A-Za-z][^<>]*>", re.S)
TAG_NAME_RE = re.compile(r"</?\s*([A-Za-z][A-Za-z0-9:-]*)")
ATTR_RE = re.compile(r"(\b(?:href|title|alt|src|value|data-[\w-]+)\s*=\s*)(\"[^\"]*\"|'[^']*')", re.I)
BLOCK_TAGS = set("""
p div br li ul ol tr td th table h1 h2 h3 h4 h5 h6 pre blockquote section article header
footer hr dd dt dl tbody thead tfoot title body html head option caption figure nav main
aside address center form fieldset legend
""".split())
SKIP_TAGS = {"script", "style"}


def process_html(markup: str, fn: Callable[[str], Result]) -> str:
    """Run ``fn`` over the visible text of ``markup`` and selected attributes.

    Text nodes are concatenated (block elements become newlines) so that
    entities split across inline tags are still found.
    """
    segments: list[list] = []   # [kind, raw, name]
    pos = 0
    for m in TOKEN_RE.finditer(markup):
        if m.start() > pos:
            segments.append(["text", markup[pos:m.start()], ""])
        tag = m.group(0)
        nm = TAG_NAME_RE.match(tag)
        segments.append(["tag", tag, nm.group(1).lower() if nm else ""])
        pos = m.end()
    if pos < len(markup):
        segments.append(["text", markup[pos:], ""])

    stream: list[str] = []
    length = 0
    text_map: list[tuple[int, int, int, str]] = []   # (seg index, start, end, unescaped)
    skip_depth = 0
    for i, (kind, raw, name) in enumerate(segments):
        if kind == "tag":
            if name in SKIP_TAGS:
                skip_depth += -1 if raw.startswith("</") else (0 if raw.endswith("/>") else 1)
                skip_depth = max(skip_depth, 0)
            if name in BLOCK_TAGS:
                stream.append("\n")
                length += 1
            continue
        if skip_depth:
            continue
        u = htmllib.unescape(raw)
        text_map.append((i, length, length + len(u), u))
        stream.append(u)
        length += len(u)

    full = "".join(stream)
    res = fn(full)
    edits: dict[int, list[tuple[int, int, str]]] = {}
    for rep in res.replacements:
        first = True
        for seg_i, s, e, u in text_map:
            if e <= rep.in_start or s >= rep.in_end:
                continue
            ls = max(rep.in_start, s) - s
            le = min(rep.in_end, e) - s
            edits.setdefault(seg_i, []).append((ls, le, rep.replacement if first else ""))
            first = False
    for seg_i, s, e, u in text_map:
        ed = edits.get(seg_i)
        if not ed:
            continue
        ed.sort()
        out, p = [], 0
        for ls, le, txt in ed:
            out.append(u[p:ls])
            out.append(txt)
            p = le
        out.append(u[p:])
        segments[seg_i][1] = htmllib.escape("".join(out), quote=False)

    # attributes (links, titles …)
    for seg in segments:
        if seg[0] != "tag" or seg[2] in SKIP_TAGS:
            continue

        def repl(m):
            quoted = m.group(2)
            q, val = quoted[0], quoted[1:-1]
            r = fn(htmllib.unescape(val))
            if not r.changed:
                return m.group(0)
            return m.group(1) + q + htmllib.escape(r.output, quote=True) + q

        seg[1] = ATTR_RE.sub(repl, seg[1])
    return "".join(seg[1] for seg in segments)


_CF_HTML_HEADER = re.compile(r"^Version:\d[\s\S]*?StartHTML:(-?\d+)[\s\S]*?EndHTML:(-?\d+)", re.I)


def strip_cf_html(data: str) -> str:
    """Strip a Windows CF_HTML header if a platform hands it through verbatim."""
    m = _CF_HTML_HEADER.match(data)
    if not m:
        return data
    start = int(m.group(1))
    if start < 0:
        idx = data.find("<")
        return data[idx:] if idx >= 0 else data
    return data[start:]
