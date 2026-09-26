"""Plugin process (optional): names (NER) and image analysis.

Reads JSON lines on stdin and answers one JSON line per request:

  {"id": 1, "text": "...", "lang": "auto|de|en|both"}      -> {"id": 1, "entities": [...]}
  {"id": 2, "op": "faces"|"ocr"|"codes", "image": "<base64 PNG/JPEG>"}
                                                            -> {"id": 2, "boxes": [...]}
  {"id": 3, "op": "info"}                                   -> {"id": 3, "features": {...}}

Built as a separate binary (``<app>-ner``) that contains spaCy and the German and
English models, so the main application stays small. The main application finds
the helper next to its own executable, on the PATH, or via the configured path.
"""

from __future__ import annotations

import json
import re
import sys

_DE = set("der die das und ist nicht mit ein eine einen auf für von zu den dem des im sich auch "
          "wir sie ich es bitte danke hallo grüße gruß werden wurde wird sind oder aber bei aus "
          "nach über unter sehr noch schon wie was wer dass hat haben kann können muss arbeitet "
          "heute morgen gestern kunde server".split())
_EN = set("the and is not with a an on for of to in it we they i you please thanks hello "
          "regards are was were be been or but this that".split())

_models: dict[str, object] = {}


def detect_language(text: str) -> str:
    words = re.findall(r"[a-zäöüß]+", text.lower())
    de = sum(w in _DE for w in words)
    en = sum(w in _EN for w in words)
    return "de" if de >= en else "en"


def load(name: str):
    nlp = _models.get(name)
    if nlp is None:
        import spacy
        # tagger/morphologizer stay on: their part-of-speech tags are used to reject
        # non-names (verbs, nouns, code) that the small models label as entities
        nlp = spacy.load(name, disable=["parser", "lemmatizer"])
        _models[name] = nlp
    return nlp


def analyze(text: str, lang: str, models: dict) -> list[dict]:
    names = {"de": models.get("de") or "de_core_news_sm", "en": models.get("en") or "en_core_web_sm"}
    langs = ["de", "en"] if lang == "both" else [detect_language(text) if lang == "auto" else lang]
    ents: dict[tuple[int, int], dict] = {}
    for lg in langs:
        doc = load(names[lg])(text)
        for e in doc.ents:
            tokens = [{"s": tk.idx, "e": tk.idx + len(tk.text), "pos": tk.pos_, "stop": bool(tk.is_stop)}
                      for tk in e]
            ents.setdefault((e.start_char, e.end_char),
                            {"start": e.start_char, "end": e.end_char, "label": e.label_, "tokens": tokens})
    return [ents[k] for k in sorted(ents)]


INFO = """NER-Plugin / NER plugin

DE: Dieses Programm wird vom Hauptprogramm automatisch im Hintergrund gestartet.
    Es muss nicht von Hand ausgefuehrt werden. Lege es in denselben Ordner wie das
    Hauptprogramm und aktiviere es dort unter Einstellungen > NER-Plugin.

EN: This program is started automatically in the background by the main program.
    There is no need to run it by hand. Put it into the same folder as the main
    program and enable it there under Settings > NER plugin.

Selbsttest / self test ..."""


def interactive() -> int:
    print(INFO, flush=True)
    try:
        for text, lang in (("Jonas Hartmann arbeitet bei der Siemens AG in München.", "de"),
                           ("John Smith works for Microsoft in Seattle.", "en")):
            ents = analyze(text, lang, {})
            print(f"  [{lang}] " + ", ".join(f"{text[e['start']:e['end']]} ({e['label']})" for e in ents), flush=True)
        print("\nOK", flush=True)
        rc = 0
    except Exception as exc:  # show the problem instead of a silent console
        print(f"\nFEHLER / ERROR: {exc}", flush=True)
        rc = 1
    try:
        input("\nEnter zum Beenden / press Enter to close ...")
    except EOFError:
        pass
    return rc


def handle(req: dict) -> dict:
    op = req.get("op") or "ner"
    if op == "ner":
        return {"entities": analyze(req.get("text", ""), req.get("lang", "auto"), req.get("models") or {})}
    from . import vision_helper as vh
    if op == "info":
        return {"features": dict(vh.available(), ner=True)}
    if op in ("faces", "ocr", "codes"):
        import base64
        data = base64.b64decode(req.get("image") or "")
        return {"boxes": getattr(vh, op)(data)}
    raise ValueError(f"unknown op {op!r}")


def selftest() -> int:
    print(json.dumps(analyze("Jonas Hartmann arbeitet bei der Siemens AG in München.", "de", {})))
    print(json.dumps(analyze("John Smith works for Microsoft in Seattle.", "en", {})))
    from . import vision_helper as vh
    feats = vh.available()
    print(json.dumps({"features": feats}))
    import cv2
    import numpy as np
    img = np.full((240, 640, 3), 255, np.uint8)
    cv2.putText(img, "IP 10.88.10.10", (20, 80), cv2.FONT_HERSHEY_SIMPLEX, 1.4, (0, 0, 0), 3)
    qr = cv2.resize(cv2.QRCodeEncoder.create().encode("selftest"), (120, 120), interpolation=cv2.INTER_NEAREST)
    img[110:230, 500:620] = cv2.cvtColor(qr, cv2.COLOR_GRAY2BGR)
    data = cv2.imencode(".png", img)[1].tobytes()
    lines = vh.ocr(data)
    codes = vh.codes(data)
    faces = vh.faces(data)
    print(json.dumps({"ocr": [ln["text"] for ln in lines], "codes": [c["text"] for c in codes], "faces": len(faces)}))
    ok = all(feats.values()) and any("10.88.10.10" in ln["text"] for ln in lines) and \
        any(c["text"] == "selftest" for c in codes)
    print("OK" if ok else "FAILED")
    return 0 if ok else 1


def main() -> int:
    if "--version" in sys.argv:
        import spacy
        print("spacy", spacy.__version__)
        return 0
    if "--selftest" in sys.argv:
        return selftest()
    if sys.stdin is not None and sys.stdin.isatty() and len(sys.argv) == 1:
        return interactive()
    try:
        sys.stdin.reconfigure(encoding="utf-8")
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:  # pragma: no cover
        pass
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = None
        try:
            req = json.loads(line)
            resp = dict(handle(req), id=req.get("id"))
        except Exception as exc:  # report, keep serving
            resp = {"id": req.get("id") if isinstance(req, dict) else None, "error": str(exc)}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
