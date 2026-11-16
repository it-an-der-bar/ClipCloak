"""Redact PDF files for real: the text, image pixels and vector graphics under a box are removed
from the file, not just painted over (no Qt here; uses PyMuPDF).

1. ``extract_text``: the text of every page with the box of every character – also invisible text
   (OCR layers) and text outside the visible page area.
2. The engine's detectors run over this text (``text_regions``); every finding becomes one box per
   line it covers. Images (scans, screenshots) are rendered and handed to an analyser – in the app
   the plugin (faces, QR codes, OCR text) – via ``image_regions``.
3. ``redact``: redaction boxes are applied (text removed, pixels blanked, covered line art removed);
   then everything else that can hold data goes: metadata and XMP, annotations and links, form
   fields, attachments, JavaScript, thumbnails; bookmark titles are redacted like text. The file is
   written anew (no older revision stays inside). ``rasterize`` turns every page into an image.
4. ``verify``: the written file is read again; any redacted text that can still be extracted is
   reported.

Coordinates are PDF points of the page with its rotation removed (``open_pdf`` does that), so text
boxes, rendered pages and redaction boxes all use the same system.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MODES = ("redact", "pseudonymize", "anonymize")
IMAGE_MIN_AREA = 0.01          # images below 1 % of the page are skipped (icons, logos, bullets)
IMAGE_MIN_PIXELS = 48


class PdfError(Exception):
    pass


class PdfPasswordError(PdfError):
    pass


def available() -> bool:
    try:
        _fitz()
        return True
    except ImportError:
        return False


def _fitz():
    try:
        import pymupdf
    except ImportError:                                    # older PyMuPDF releases
        import fitz as pymupdf
    return pymupdf


@dataclass
class PdfRegion:
    page: int
    x0: float
    y0: float
    x1: float
    y1: float
    kind: str = "MANUAL"          # finding type (IPV4, SECRET …), FACE, QR_CODE, MANUAL
    label: str = ""               # the text under the box (for the list and the check after saving)
    source: str = "manual"        # text | image | manual
    start: int = -1               # text regions: the finding in PdfText.text
    end: int = -1
    first: bool = True            # the first box of a finding that spans several lines

    @property
    def rect(self) -> tuple[float, float, float, float]:
        return self.x0, self.y0, self.x1, self.y1


@dataclass
class PdfText:
    text: str
    boxes: list = field(default_factory=list)      # per character: (page, line, x0, y0, x1, y1) or None
    page_starts: list = field(default_factory=list)


@dataclass
class PdfReport:
    pages: int = 0
    regions: int = 0
    counts: dict = field(default_factory=dict)
    images_total: int = 0
    images_analysed: int = 0
    leftovers: list = field(default_factory=list)  # redacted text still found in the result
    warnings: list = field(default_factory=list)
    result: object = None                           # the engine Result (history, mappings)


def open_pdf(path: str, password: str | None = None):
    m = _fitz()
    try:
        doc = m.open(path)
    except Exception as exc:                        # noqa: BLE001 – PyMuPDF raises several types
        raise PdfError(str(exc)) from exc
    if not doc.is_pdf:
        doc.close()
        raise PdfError("not a PDF file")
    if doc.needs_pass and not doc.authenticate(password or ""):
        doc.close()
        raise PdfPasswordError("password required")
    for page in doc:
        if page.rotation:
            page.remove_rotation()                  # one coordinate system for text, images and boxes
    return doc


def _text_flags():
    m = _fitz()
    # ligatures as letters ("fi"), whitespace kept, no clipping to the visible page: text outside it
    # is still in the file and must be found
    return m.TEXT_PRESERVE_WHITESPACE | getattr(m, "TEXT_CID_FOR_UNKNOWN_UNICODE", 0)


def extract_text(doc) -> PdfText:
    parts: list[str] = []
    boxes: list = []
    starts: list[int] = []
    pos = 0
    flags = _text_flags()
    for pno, page in enumerate(doc):
        starts.append(pos)
        line_no = 0
        # no clipping: text outside the visible area (crop box) is still in the file
        for block in page.get_text("rawdict", flags=flags, clip=_fitz().INFINITE_RECT()).get("blocks", []):
            if block.get("type") != 0:
                continue
            for line in block.get("lines", []):
                line_no += 1
                for span in line.get("spans", []):
                    for ch in span.get("chars", []):
                        c = ch.get("c", "")
                        if not c:
                            continue
                        x0, y0, x1, y1 = ch["bbox"]
                        for k in c:
                            parts.append(k)
                            boxes.append((pno, line_no, x0, y0, x1, y1))
                            pos += 1
                parts.append("\n")
                boxes.append(None)
                pos += 1
        parts.append("\n")
        boxes.append(None)
        pos += 1
    return PdfText("".join(parts), boxes, starts)


def text_regions(ptext: PdfText, findings, pad: float = 0.6) -> list[PdfRegion]:
    """One box per line a finding covers (union of its character boxes)."""
    out: list[PdfRegion] = []
    for f in findings:
        groups: dict[tuple[int, int], list] = {}
        order: list[tuple[int, int]] = []
        for i in range(max(0, f.start), min(f.end, len(ptext.boxes))):
            b = ptext.boxes[i]
            if b is None:
                continue
            key = (b[0], b[1])
            if key not in groups:
                groups[key] = [b[2], b[3], b[4], b[5]]
                order.append(key)
            else:
                g = groups[key]
                g[0], g[1], g[2], g[3] = min(g[0], b[2]), min(g[1], b[3]), max(g[2], b[4]), max(g[3], b[5])
        for n, key in enumerate(order):
            x0, y0, x1, y1 = groups[key]
            out.append(PdfRegion(key[0], x0 - pad, y0 - pad, x1 + pad, y1 + pad, f.type,
                                 f.text if n == 0 else "", "text", f.start, f.end, n == 0))
    return out


def analyze_text(doc, analyze, chunk: int = 400_000):
    """(PdfText, findings) – ``analyze(text) -> findings``; very long documents in page-aligned
    chunks (the engine limits the text size)."""
    ptext = extract_text(doc)
    text = ptext.text
    if len(text) <= chunk:
        return ptext, list(analyze(text))
    findings = []
    bounds = ptext.page_starts + [len(text)]
    a = 0
    while a < len(text):
        b = a
        for s in bounds:                            # largest page boundary within the chunk
            if a < s <= a + chunk:
                b = s
        if b == a:
            b = min(len(text), a + chunk)
        for f in analyze(text[a:b]):
            f.start += a
            f.end += a
            findings.append(f)
        a = b
    return ptext, findings


def image_areas(doc) -> list[tuple[int, tuple[float, float, float, float]]]:
    """(page, rect) of every image large enough to hold a face or readable text."""
    out = []
    for pno, page in enumerate(doc):
        pr = page.rect
        page_area = max(1.0, pr.width * pr.height)
        seen = set()
        for info in page.get_image_info():
            x0, y0, x1, y1 = info["bbox"]
            r = _fitz().Rect(x0, y0, x1, y1) & pr
            if r.is_empty:
                continue
            key = tuple(round(v, 1) for v in r)
            if key in seen:
                continue
            seen.add(key)
            if r.width * r.height / page_area < IMAGE_MIN_AREA:
                continue
            if min(info.get("width", 0), info.get("height", 0)) < IMAGE_MIN_PIXELS:
                continue
            out.append((pno, (r.x0, r.y0, r.x1, r.y1)))
    return out


def render_area(doc, pno: int, rect, dpi: int = 150) -> tuple[bytes, int, int]:
    """PNG of an area of a page."""
    m = _fitz()
    pix = doc[pno].get_pixmap(clip=m.Rect(rect), dpi=dpi, alpha=False)
    return pix.tobytes("png"), pix.width, pix.height


def image_regions(doc, analyser, dpi: int = 150, progress=None) -> tuple[list[PdfRegion], int, int]:
    """Run ``analyser(png, width, height) -> [(x, y, w, h, kind, label)]`` (pixels) over every image;
    returns (regions in points, images found, images analysed)."""
    areas = image_areas(doc)
    out: list[PdfRegion] = []
    done = 0
    for i, (pno, rect) in enumerate(areas):
        if progress:
            progress(i + 1, len(areas), pno + 1)
        png, w, h = render_area(doc, pno, rect, dpi)
        boxes = analyser(png, w, h)
        if boxes is None:
            continue
        done += 1
        sx = (rect[2] - rect[0]) / max(1, w)
        sy = (rect[3] - rect[1]) / max(1, h)
        for x, y, bw, bh, kind, label in boxes:
            out.append(PdfRegion(pno, rect[0] + x * sx, rect[1] + y * sy, rect[0] + (x + bw) * sx,
                                 rect[1] + (y + bh) * sy, kind, label, "image"))
    return out, len(areas), done


def replacements_for(result) -> dict[tuple[int, int], str]:
    """Engine result -> {(start, end) of the original: replacement}."""
    return {(r.in_start, r.in_end): r.replacement for r in result.replacements}


def _fit_fontsize(m, text: str, width: float, height: float) -> float:
    fs = max(4.0, min(height * 0.8, 24.0))
    while fs > 4.0 and m.get_text_length(text, fontname="helv", fontsize=fs) > width:
        fs *= 0.9
    return fs


def redact(doc, regions: list[PdfRegion], replacements: dict | None = None, redact_toc=None) -> list[str]:
    """Apply the boxes and remove everything else that can carry data. ``replacements``
    ({(start, end): text}) writes the pseudonym into the first box of a finding (white box, black
    text); without it every box is black. ``redact_toc(title) -> title`` cleans bookmark titles.
    Returns warnings."""
    m = _fitz()
    warnings: list[str] = []
    by_page: dict[int, list[PdfRegion]] = {}
    for r in regions:
        by_page.setdefault(r.page, []).append(r)
    for pno, page in enumerate(doc):
        pr = page.rect
        regs = by_page.get(pno, [])
        crop = None
        if any(not pr.contains(m.Rect(r.rect)) for r in regs) and page.cropbox != page.mediabox:
            # boxes outside the visible area: redact on the whole media box, then restore the crop box
            crop = m.Rect(page.cropbox)
            shift = page.cropbox_position
            page.set_cropbox(page.mediabox)
            regs = [PdfRegion(r.page, r.x0 + shift.x, r.y0 + shift.y, r.x1 + shift.x, r.y1 + shift.y, r.kind, r.label,
                              r.source, r.start, r.end, r.first) for r in regs]
            pr = page.rect
        outside = 0
        for r in regs:
            rect = m.Rect(r.rect)
            if not pr.contains(rect):
                outside += 1
            text = None
            if replacements is not None and r.source == "text":
                text = replacements.get((r.start, r.end), "") if r.first else ""
            if text is None or (replacements is not None and r.source != "text"):
                page.add_redact_annot(rect, fill=(0, 0, 0), cross_out=False)
            elif text:
                fs = _fit_fontsize(m, text, rect.width, rect.height)
                page.add_redact_annot(rect, text=text, fontname="helv", fontsize=fs, fill=(1, 1, 1),
                                      text_color=(0, 0, 0), cross_out=False)
            else:
                page.add_redact_annot(rect, fill=(1, 1, 1), cross_out=False)
        if outside:
            warnings.append(f"page {pno + 1}: {outside} box(es) beyond the page")
        page.apply_redactions(images=m.PDF_REDACT_IMAGE_PIXELS,
                              graphics=getattr(m, "PDF_REDACT_LINE_ART_REMOVE_IF_COVERED", 1),
                              text=m.PDF_REDACT_TEXT_REMOVE)
        if crop is not None:
            page.set_cropbox(crop)
        for annot in list(page.annots() or []):    # comments, highlights, stamps …
            page.delete_annot(annot)
        for w in list(page.widgets() or []):       # form fields (their values)
            page.delete_widget(w)
        for link in list(page.get_links()):
            page.delete_link(link)
    toc = doc.get_toc(simple=False)
    if toc:
        if redact_toc is None:
            doc.set_toc([])
        else:
            doc.set_toc([[e[0], redact_toc(e[1]), e[2]] for e in toc])
    doc.scrub(attached_files=True, clean_pages=True, embedded_files=True, hidden_text=False, javascript=True,
              metadata=True, redactions=False, redact_images=0, remove_links=True, reset_fields=True,
              reset_responses=True, thumbnails=True, xml_metadata=True)
    doc.set_metadata({})
    return warnings


def clean_titles(engine, mode: str, body: str, titles: list[str], limit: int = 1_500_000) -> dict[str, str]:
    """Bookmark titles processed together with the page text, so that what is known from the pages
    (a name learned from an e-mail address, a project term) is found in the titles too."""
    titles = [t for t in dict.fromkeys(titles) if t.strip()]
    if not titles:
        return {}
    sep = "\n\n"
    joined = sep.join(titles)
    if len(body) + len(joined) + 2 > limit:
        return {t: engine.process(t, mode).output for t in titles}
    out = engine.process(body + sep + joined, mode).output
    parts = out.split(sep)                         # titles are single lines: the last blocks are theirs
    if len(parts) < len(titles):
        return {t: engine.process(t, mode).output for t in titles}
    return dict(zip(titles, [x.replace("\n", " ") for x in parts[-len(titles):]], strict=True))


def save(doc, out_path: str, rasterize: bool = False, dpi: int = 150) -> None:
    m = _fitz()
    if rasterize:
        new = m.open()
        for page in doc:
            pix = page.get_pixmap(dpi=dpi, alpha=False)
            np = new.new_page(width=page.rect.width, height=page.rect.height)
            np.insert_image(np.rect, pixmap=pix)
        new.set_metadata({})
        new.save(out_path, garbage=4, deflate=True, clean=True)
        new.close()
        return
    doc.save(out_path, garbage=4, deflate=True, clean=True, encryption=getattr(m, "PDF_ENCRYPT_NONE", 1))


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def verify(out_path: str, labels: list[str]) -> list[str]:
    """Labels (redacted text) that can still be extracted from the written file."""
    doc = open_pdf(out_path)
    try:
        text = _norm(extract_text(doc).text)
    finally:
        doc.close()
    left = []
    for lab in labels:
        n = _norm(lab)
        if len(n) >= 3 and lab not in left and re.search(r"(?<!\w)" + re.escape(n) + r"(?!\w)", text):
            left.append(lab)
    return left


def redact_pdf(src: str, dst: str, engine, mode: str = "redact", rasterize: bool = False, dpi: int = 150,
               analyser=None, password: str | None = None, skip_types=(), progress=None) -> PdfReport:
    """Everything in one go (CLI, tests): detect, redact, save, check."""
    if mode not in MODES:
        raise ValueError(mode)
    rep = PdfReport()
    doc = open_pdf(src, password)
    try:
        rep.pages = doc.page_count
        ptext, findings = analyze_text(doc, engine.analyze)
        findings = [f for f in findings if f.type not in skip_types]
        regions = text_regions(ptext, findings)
        if analyser is not None:
            img, rep.images_total, rep.images_analysed = image_regions(doc, analyser, dpi, progress)
            regions += img
        else:
            rep.images_total = len(image_areas(doc))
        res = engine.process(ptext.text, mode, findings)
        rep.result = res
        reps = replacements_for(res) if mode != "redact" else None
        titles = clean_titles(engine, mode, ptext.text, [e[1] for e in doc.get_toc()])
        rep.warnings += redact(doc, regions, reps, lambda t: titles.get(t, t))
        save(doc, dst, rasterize, dpi)
    finally:
        doc.close()
    rep.regions = len(regions)
    for r in regions:
        if r.first:
            rep.counts[r.kind] = rep.counts.get(r.kind, 0) + 1
    rep.leftovers = verify(dst, [r.label for r in regions if r.source == "text" and r.label])
    return rep
