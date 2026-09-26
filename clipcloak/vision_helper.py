"""Image analysis for the plugin: faces, text with positions (OCR), QR codes and barcodes.

Runs inside the plugin process (``<app>-ner``), which also contains OpenCV, the
YuNet face model and RapidOCR (ONNX), so the main application stays small.
All functions take encoded image bytes (PNG/JPEG …) and return boxes in pixel
coordinates of that image: ``{"x", "y", "w", "h", ...}``.
"""

from __future__ import annotations

import sys
from pathlib import Path

FACE_MODEL = "face_detection_yunet_2023mar.onnx"
_ocr = None


def _data_dir() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "clipcloak" / "plugin_data"
    return Path(__file__).resolve().parent / "plugin_data"


def _quiet(cv2) -> None:
    try:
        cv2.utils.logging.setLogLevel(cv2.utils.logging.LOG_LEVEL_ERROR)
    except AttributeError:
        pass


def _decode(data: bytes):
    import cv2
    import numpy as np
    _quiet(cv2)
    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("cannot decode image")
    return img


def _iou(a, b) -> float:
    ax2, ay2, bx2, by2 = a["x"] + a["w"], a["y"] + a["h"], b["x"] + b["w"], b["y"] + b["h"]
    iw = max(0, min(ax2, bx2) - max(a["x"], b["x"]))
    ih = max(0, min(ay2, by2) - max(a["y"], b["y"]))
    inter = iw * ih
    union = a["w"] * a["h"] + b["w"] * b["h"] - inter
    return inter / union if union else 0.0


# ------------------------------------------------------------------ faces
def faces(data: bytes, score: float = 0.6) -> list[dict]:
    """Faces with YuNet. The model finds faces of about 10–300 px, so large images are
    also searched downscaled; the results are merged."""
    import cv2
    img = _decode(data)
    h, w = img.shape[:2]
    model = str(_data_dir() / FACE_MODEL)
    scales = [1.0]
    longest = max(w, h)
    for target in (1280, 640, 320):
        if longest > target * 1.3:
            scales.append(target / longest)
    found: list[dict] = []
    for s in scales:
        sw, sh = max(1, int(w * s)), max(1, int(h * s))
        im = img if s == 1.0 else cv2.resize(img, (sw, sh), interpolation=cv2.INTER_AREA)
        det = cv2.FaceDetectorYN.create(model, "", (sw, sh), score, 0.3, 5000)
        _ok, res = det.detect(im)
        if res is None:
            continue
        for row in res:
            x, y, fw, fh, conf = float(row[0]), float(row[1]), float(row[2]), float(row[3]), float(row[-1])
            box = {"x": int(max(0, x / s)), "y": int(max(0, y / s)), "w": int(fw / s), "h": int(fh / s),
                   "score": round(conf, 3), "kind": "FACE"}
            box["w"] = min(box["w"], w - box["x"])
            box["h"] = min(box["h"], h - box["y"])
            if box["w"] < 4 or box["h"] < 4:
                continue
            dup = next((f for f in found if _iou(f, box) > 0.3), None)
            if dup is None:
                found.append(box)
            elif box["score"] > dup["score"]:
                found[found.index(dup)] = box
    return found


# ------------------------------------------------------------------ OCR
def _quad_box(q) -> dict:
    xs = [p[0] for p in q]
    ys = [p[1] for p in q]
    x0, y0 = int(min(xs)), int(min(ys))
    return {"x": x0, "y": y0, "w": int(max(xs)) - x0, "h": int(max(ys)) - y0}


def _with_spaces(words: list[dict]) -> tuple[str, list[dict]]:
    """The OCR model often drops spaces; put them back from the gaps between the
    character/word boxes. Returns the text and the words with their offsets (s, e)."""
    widths = sorted(w["w"] / max(1, len(w["text"])) for w in words if w["text"])
    char_w = widths[len(widths) // 2] if widths else 8
    text, out, prev_end = "", [], None
    for w in words:
        if not w["text"]:
            continue
        if prev_end is not None:
            gap = w["x"] - prev_end
            if gap > 0.45 * char_w:
                text += " " * max(1, min(4, round(gap / char_w)))
        s = len(text)
        text += w["text"]
        out.append(dict(w, s=s, e=len(text)))
        prev_end = w["x"] + w["w"]
    return text, out


def ocr(data: bytes) -> list[dict]:
    """Text lines with their box and word/character boxes:
    ``{"text", "x", "y", "w", "h", "score", "words": [{"text", "s", "e", "x", "y", "w", "h"}]}``
    (``s``/``e`` are the offsets of the word in the line text)."""
    global _ocr
    if _ocr is None:
        from rapidocr_onnxruntime import RapidOCR
        _ocr = RapidOCR()
    img = _decode(data)
    res, _elapse = _ocr(img, return_word_box=True)
    lines = []
    for r in res or []:
        quad, text, score = r[0], r[1], r[2]
        line = dict(_quad_box(quad), text=str(text), score=round(float(score), 3), words=[])
        words = []
        if len(r) > 4 and r[3] and r[4]:
            for wbox, wtext in zip(r[3], r[4]):
                try:
                    words.append(dict(_quad_box(wbox), text=str(wtext)))
                except (TypeError, ValueError, IndexError):
                    continue
        if words:
            words.sort(key=lambda w: w["x"])
            line["text"], line["words"] = _with_spaces(words)
        lines.append(line)
    return lines


# ------------------------------------------------------------------ codes
def codes(data: bytes) -> list[dict]:
    """QR codes and barcodes (they often contain URLs, tokens, serial numbers)."""
    import cv2
    img = _decode(data)
    out: list[dict] = []

    def add(points, kind, text=""):
        if points is None:
            return
        for p in points:
            q = [(float(pt[0]), float(pt[1])) for pt in p.reshape(-1, 2)]
            box = dict(_quad_box(q), kind=kind, text=str(text or ""))
            if box["w"] > 3 and box["h"] > 3 and not any(_iou(box, o) > 0.5 for o in out):
                out.append(box)

    try:
        qr = cv2.QRCodeDetector()
        ok, texts, pts, _ = qr.detectAndDecodeMulti(img)
        if ok and pts is not None:
            for t, p in zip(texts, pts):
                add([p], "QR_CODE", t)
    except cv2.error:
        pass
    try:
        bd = cv2.barcode.BarcodeDetector()
        res = bd.detectAndDecodeWithType(img)
        ok, infos, _types, pts = res if len(res) == 4 else (res[0], res[1], None, res[-1])
        if ok and pts is not None:
            for t, p in zip(infos, pts):
                add([p], "BARCODE", t)
    except (cv2.error, AttributeError):
        pass
    return out


def available() -> dict:
    ok = {}
    try:
        import cv2  # noqa: F401
        ok["faces"] = (_data_dir() / FACE_MODEL).is_file()
        ok["codes"] = True
    except ImportError:
        ok["faces"] = ok["codes"] = False
    try:
        import rapidocr_onnxruntime  # noqa: F401
        ok["ocr"] = True
    except ImportError:
        ok["ocr"] = False
    return ok
