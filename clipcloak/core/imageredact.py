"""Regions to hide in an image, from the plugin's analysis (no Qt here).

The plugin returns faces, QR codes/barcodes and OCR text lines with word boxes.
The OCR text runs through the same detectors as clipboard text (IP, e-mail,
secrets, custom terms, NER …); each finding becomes a box over its characters.
"""

from __future__ import annotations

from dataclasses import dataclass, field

EFFECTS = ("black", "mosaic", "blur")


@dataclass
class Region:
    x: int
    y: int
    w: int
    h: int
    kind: str = "MANUAL"          # FACE | NUDITY | QR_CODE | BARCODE | text finding type (IPV4 …) | MANUAL
    effect: str = "black"
    label: str = ""               # recognised text (shown in the list only, never logged)
    source: str = "manual"        # manual | face | nudity | code | text
    base: tuple | None = None     # detected box before the margin (x, y, w, h); None once edited by hand

    def as_tuple(self) -> tuple[int, int, int, int]:
        return self.x, self.y, self.w, self.h


@dataclass
class ImageSettings:
    faces: bool = True
    text: bool = True
    codes: bool = True
    face_effect: str = "mosaic"
    text_effect: str = "black"
    code_effect: str = "black"
    padding: int = 3
    skip_types: set = field(default_factory=set)
    nudity: bool = True
    nudity_effect: str = "black"
    face_margin: int = 15         # extra margin around faces, % of the larger side of the detected box
    nudity_margin: int = 12

    @classmethod
    def from_config(cls, d: dict) -> "ImageSettings":
        d = d or {}
        eff = lambda k, dflt: d.get(k) if d.get(k) in EFFECTS else dflt  # noqa: E731
        return cls(bool(d.get("faces", True)), bool(d.get("text", True)), bool(d.get("codes", True)),
                   eff("face_effect", "mosaic"), eff("text_effect", "black"), eff("code_effect", "black"),
                   int(d.get("padding", 3) or 0), set(),
                   bool(d.get("nudity", True)), eff("nudity_effect", "black"),
                   _pct(d.get("face_margin", 15)), _pct(d.get("nudity_margin", 12)))


def _pct(v) -> int:
    try:
        return max(0, min(200, int(v)))
    except (TypeError, ValueError):
        return 0


def with_margin(base: tuple, pct: int, min_pad: int, width: int = 0, height: int = 0) -> tuple[int, int, int, int]:
    """``base`` (x, y, w, h) grown by ``pct`` % of its larger side on every side (at least ``min_pad``)."""
    x, y, w, h = base
    pad = max(min_pad, int(round(pct / 100 * max(w, h))))
    return _pad({"x": x, "y": y, "w": w, "h": h}, pad, width, height)


def _pad(box: dict, pad: int, width: int, height: int) -> tuple[int, int, int, int]:
    x = max(0, int(box["x"]) - pad)
    y = max(0, int(box["y"]) - pad)
    x2 = min(width, int(box["x"]) + int(box["w"]) + pad) if width else int(box["x"]) + int(box["w"]) + pad
    y2 = min(height, int(box["y"]) + int(box["h"]) + pad) if height else int(box["y"]) + int(box["h"]) + pad
    return x, y, max(1, x2 - x), max(1, y2 - y)


def span_box(line: dict, s: int, e: int) -> dict:
    """Box of characters s..e of an OCR line: union of the word/character boxes that
    overlap the span, or a proportional slice of the line box if there are none."""
    words = [w for w in line.get("words") or [] if "s" in w and "e" in w]
    hit = [w for w in words if w["s"] < e and w["e"] > s]
    if hit:
        x0 = min(w["x"] for w in hit)
        y0 = min(w["y"] for w in hit)
        x1 = max(w["x"] + w["w"] for w in hit)
        y1 = max(w["y"] + w["h"] for w in hit)
        # a word that is only partly covered (e.g. "IP10.88.10.10") is covered completely
        return {"x": x0, "y": min(y0, line["y"]), "w": x1 - x0, "h": max(y1, line["y"] + line["h"]) - min(y0, line["y"])}
    n = max(1, len(line.get("text") or ""))
    x0 = line["x"] + line["w"] * s / n
    x1 = line["x"] + line["w"] * e / n
    return {"x": int(x0), "y": line["y"], "w": max(1, int(round(x1 - x0))), "h": line["h"]}


def text_regions(lines: list[dict], analyze, settings: ImageSettings, width: int = 0, height: int = 0) -> list[Region]:
    """Run ``analyze(text) -> findings`` over all OCR lines (joined with newlines, so
    key/value context like "password:" works) and map every finding back to boxes."""
    if not lines:
        return []
    starts, parts, pos = [], [], 0
    for ln in lines:
        starts.append(pos)
        parts.append(ln.get("text") or "")
        pos += len(parts[-1]) + 1
    full = "\n".join(parts)
    out: list[Region] = []
    for f in analyze(full):
        if f.type in settings.skip_types:
            continue
        for i, ln in enumerate(lines):
            ls, le = starts[i], starts[i] + len(parts[i])
            s, e = max(f.start, ls), min(f.end, le)
            if s >= e:
                continue
            box = span_box(ln, s - ls, e - ls)
            x, y, w, h = _pad(box, settings.padding, width, height)
            out.append(Region(x, y, w, h, f.type, settings.text_effect, full[s:e], "text"))
    return merge_overlapping(out)


def merge_overlapping(regions: list[Region]) -> list[Region]:
    """Join boxes of the same kind that overlap (e.g. two findings in one word)."""
    out: list[Region] = []
    for r in sorted(regions, key=lambda r: (r.y, r.x)):
        for o in out:
            if o.kind == r.kind and o.effect == r.effect and not (
                    r.x > o.x + o.w or o.x > r.x + r.w or r.y > o.y + o.h or o.y > r.y + r.h):
                x0, y0 = min(o.x, r.x), min(o.y, r.y)
                x1, y1 = max(o.x + o.w, r.x + r.w), max(o.y + o.h, r.y + r.h)
                o.x, o.y, o.w, o.h = x0, y0, x1 - x0, y1 - y0
                if r.label and r.label not in o.label:
                    o.label = (o.label + " " + r.label).strip()
                break
        else:
            out.append(r)
    return out


def face_regions(boxes: list[dict], settings: ImageSettings, width: int = 0, height: int = 0) -> list[Region]:
    out = []
    for b in boxes:
        # faces: a margin so hair/ears/chin are covered too (configurable, "on top")
        base = (int(b["x"]), int(b["y"]), int(b["w"]), int(b["h"]))
        x, y, w, h = with_margin(base, settings.face_margin, settings.padding, width, height)
        out.append(Region(x, y, w, h, "FACE", settings.face_effect, "", "face", base))
    return out


def nudity_regions(boxes: list[dict], settings: ImageSettings, width: int = 0, height: int = 0) -> list[Region]:
    out = []
    for b in boxes:
        base = (int(b["x"]), int(b["y"]), int(b["w"]), int(b["h"]))
        x, y, w, h = with_margin(base, settings.nudity_margin, settings.padding, width, height)
        out.append(Region(x, y, w, h, "NUDITY", settings.nudity_effect, "", "nudity", base))
    return merge_overlapping(out)


def code_regions(boxes: list[dict], settings: ImageSettings, width: int = 0, height: int = 0) -> list[Region]:
    out = []
    for b in boxes:
        x, y, w, h = _pad(b, max(settings.padding, 6), width, height)
        out.append(Region(x, y, w, h, b.get("kind", "QR_CODE"), settings.code_effect, b.get("text", "")[:80], "code"))
    return out
