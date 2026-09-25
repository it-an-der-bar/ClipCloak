"""NER helper process (optional plugin).

Reads JSON lines ``{"id": 1, "text": "...", "lang": "auto|de|en|both"}`` on stdin and
answers ``{"id": 1, "entities": [{"start": 0, "end": 5, "label": "PER"}]}``.

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
        nlp = spacy.load(name, disable=["parser", "lemmatizer", "tagger", "attribute_ruler", "morphologizer"])
        _models[name] = nlp
    return nlp


def analyze(text: str, lang: str, models: dict) -> list[dict]:
    names = {"de": models.get("de") or "de_core_news_sm", "en": models.get("en") or "en_core_web_sm"}
    langs = ["de", "en"] if lang == "both" else [detect_language(text) if lang == "auto" else lang]
    ents: dict[tuple[int, int], str] = {}
    for lg in langs:
        doc = load(names[lg])(text)
        for e in doc.ents:
            ents.setdefault((e.start_char, e.end_char), e.label_)
    return [{"start": s, "end": e, "label": lab} for (s, e), lab in sorted(ents.items())]


def main() -> int:
    if "--version" in sys.argv:
        import spacy
        print("spacy", spacy.__version__)
        return 0
    if "--selftest" in sys.argv:
        print(json.dumps(analyze("Jonas Hartmann arbeitet bei der Siemens AG in München.", "de", {})))
        print(json.dumps(analyze("John Smith works for Microsoft in Seattle.", "en", {})))
        return 0
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
            ents = analyze(req.get("text", ""), req.get("lang", "auto"), req.get("models") or {})
            resp = {"id": req.get("id"), "entities": ents}
        except Exception as exc:  # report, keep serving
            resp = {"id": req.get("id") if isinstance(req, dict) else None, "error": str(exc)}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
