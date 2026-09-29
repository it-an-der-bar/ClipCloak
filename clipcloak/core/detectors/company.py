"""Company names with a legal form: "Kölpertechnis GmbH", "18/3 GmbH",
"Sadisches Blankloppen GmbH & Co. KG", "Bank für Sozialwirtschaft AG", "Contoso Ltd."

The legal form is a reliable anchor – no language model needed. From it the detector walks
back over the words of the name: capitalised words, words with digits or ``/ & - . +``
("18/3", "A&B", "Müller-Lüdenscheidt"), and the small linking words inside a name
("für", "und", "of", "&") when a name word comes before them. It stops at articles,
prepositions, lower-case words, punctuation such as ":" and at a line break, and drops lead
words like "Firma" or "Kunde".
"""

from __future__ import annotations

import re

from .. import wordlists
from ..entities import EntityType as T
from .base import Detector

# longest first: "GmbH & Co. KG" before "GmbH"
LEGAL = [
    r"GmbH\s*&\s*Co\.?\s*KGaA", r"GmbH\s*&\s*Co\.?\s*KG", r"GmbH\s*&\s*Co\.?\s*OHG", r"AG\s*&\s*Co\.?\s*KGaA",
    r"AG\s*&\s*Co\.?\s*KG", r"SE\s*&\s*Co\.?\s*KGaA", r"SE\s*&\s*Co\.?\s*KG",
    r"UG\s*\(haftungsbeschränkt\)\s*&\s*Co\.?\s*KG",
    r"Ltd\.?\s*&\s*Co\.?\s*KG", r"UG\s*\(haftungsbeschränkt\)", r"gGmbH", r"GmbH", r"mbH", r"gAG", r"AG", r"KGaA",
    r"KG", r"OHG", r"GbR", r"PartG\s*mbB", r"PartG", r"UG", r"e\.\s?K\.", r"e\.\s?Kfm\.", r"e\.\s?Kfr\.",
    r"e\.\s?V\.", r"eG", r"SE", r"Ltd\.?", r"Limited", r"LLC", r"L\.L\.C\.", r"LLP", r"PLC", r"plc", r"Inc\.?",
    r"Corp\.?", r"Corporation", r"Co\.,?\s*Ltd\.?", r"S\.A\.S\.?", r"S\.A\.R\.L\.?", r"S\.à\s?r\.l\.", r"SARL", r"SAS",
    r"S\.A\.", r"SA", r"S\.p\.A\.", r"SpA", r"S\.r\.l\.", r"Srl", r"B\.V\.", r"BV", r"N\.V\.", r"NV", r"AB", r"ApS",
    r"A/S", r"AS", r"ASA", r"Oy", r"Oyj", r"Sp\.\s?z\s?o\.\s?o\.", r"s\.r\.o\.", r"a\.s\.", r"Kft\.", r"Zrt\.",
    r"d\.o\.o\.", r"S\.L\.", r"S\.L\.U\.", r"Pty\.?\s*Ltd\.?", r"Pvt\.?\s*Ltd\.?",
]
LEGAL_RE = re.compile(r"(?<![\w&.])(?:" + "|".join(LEGAL) + r")(?![\w])")
# forms that are also ordinary words / abbreviations: only after a clear name
AMBIGUOUS = {"AG", "SE", "SA", "SAS", "AS", "AB", "NV", "BV", "KG", "eG", "Inc", "Corp", "Co"}

TOKEN = re.compile(r"[^\s]+")
LINK_WORDS = {"für", "und", "u.", "&", "+", "of", "and", "the", "de", "la", "du", "van", "von", "zu", "am", "an"}
STOP_WORDS = {
    "der", "die", "das", "den", "dem", "des", "ein", "eine", "einer", "eines", "einem", "einen",
    "bei", "mit", "von", "vom", "zur", "zum", "für", "an", "auf", "aus", "über", "unter", "durch", "gegen", "ohne",
    "und", "oder", "sowie", "wie", "als", "ist", "sind", "war", "wird", "wurde", "hat", "haben",
    "the", "a", "at", "by", "for", "from", "with", "to", "of", "and", "or", "is", "was", "are",
    "ich", "wir", "sie", "er", "es", "ihr", "du", "we", "i", "you", "he", "she", "they", "our", "unsere", "unser",
    "diese", "dieser", "dieses", "jene", "this", "that", "these", "those",
}
LEAD_WORDS = {
    "firma", "fa", "fa.", "unternehmen", "kunde", "kundin", "auftraggeber", "auftraggeberin", "lieferant",
    "lieferantin", "hersteller", "partner", "dienstleister", "arbeitgeber", "company", "customer", "client",
    "vendor", "supplier", "employer", "mandant", "mandantin", "gesellschaft", "rechnung", "angebot", "vertrag",
    "anschrift", "adresse", "absender", "empfänger", "bestellung", "herr", "frau", "hr.", "fr.", "mr.", "ms.",
    "mrs.", "dr.", "kontakt", "ansprechpartner", "ansprechpartnerin", "re", "aw", "fw", "wg", "betreff",
}
MAX_WORDS = 6
OPENING = "(\"'„“‚‘[`*«»"


def _name_word(tok: str) -> bool:
    core = tok.strip("\"'„“”‚‘’()[]`*«»")
    if not core:
        return False
    if core[0].isdigit():
        return bool(re.fullmatch(r"[\w/&.+\-]+", core))            # "18/3", "1&1", "4flow"
    return core[0].isupper() and bool(re.fullmatch(r"[\w/&.+'’\-]+", core))


class CompanyDetector(Detector):
    id = "company"
    types = (T.ORG.value,)
    priority = 58            # above NER/LLM names, below e-mail/domain (a domain in a name stays a domain)

    def find(self, text, ctx):
        out = []
        for m in LEGAL_RE.finditer(text):
            span = self._name_before(text, m.start())
            if span is None:
                continue
            s = span
            form = re.sub(r"[.\s]", "", m.group(0))
            name = text[s:m.start()]
            if form in AMBIGUOUS and not self._clear_name(name):
                continue
            words = [w.strip(OPENING + ")").lower() for w in name.split()]
            if words and all(w in wordlists.PUBLIC_ORGS for w in words):
                continue                                  # "Siemens AG", "Azure SAS": public, no customer data
            end = m.end()
            if text[end:end + 1] == "." and m.group(0)[-1:] != "." and re.match(r"(Ltd|Inc|Corp|Co)$", form):
                end += 1
            out.append(self.mk(s, end, T.ORG.value, text))
        return out

    @staticmethod
    def _clear_name(name: str) -> bool:
        """For "AG", "SE", "KG", "Inc" …: a word with 3+ letters, or letters mixed with digits
        ("4flow", "1&1") – so "5 KG" (kilograms) is no company."""
        for w in name.split():
            letters = sum(c.isalpha() for c in w)
            if letters >= 3 or (letters and any(c.isdigit() for c in w)) or ("&" in w and len(w) > 2):
                return True
        return False

    @staticmethod
    def _name_before(text: str, pos: int) -> int | None:
        """Start of the name that ends right before ``pos`` (only spaces in between), or None."""
        line_start = text.rfind("\n", 0, pos) + 1
        seg = text[line_start:pos]
        if seg and not seg[-1].isspace():
            return None                                   # "…xGmbH": part of a word
        toks = [(line_start + t.start(), t.group(0)) for t in TOKEN.finditer(seg)]
        start = None
        words = 0
        i = len(toks) - 1
        while i >= 0 and words < MAX_WORDS:
            p, tok = toks[i]
            low = tok.lower()
            if tok[-1] in ":;,!?" or (tok[-1] == ")" and tok[0] != "("):
                break
            if LEGAL_RE.fullmatch(tok.rstrip(".,")) or LEGAL_RE.fullmatch(tok):
                break                                     # the legal form of the company before
            if _name_word(tok) and low not in STOP_WORDS:
                opening = tok[0] in OPENING and not (tok[0] == "(" and tok[-1] == ")")
                start = p + (len(tok) - len(tok.lstrip(OPENING)) if opening else 0)
                words += 1
                i -= 1
                if opening:
                    break                                 # "(Kölpertechnis GmbH)": the name starts here
                continue
            # a linking word only inside a name: "Bank für Sozialwirtschaft", "Procter & Gamble"
            if low in LINK_WORDS and start is not None and i > 0 and _name_word(toks[i - 1][1]) \
                    and toks[i - 1][1].lower() not in STOP_WORDS:
                i -= 1
                continue
            break
        if start is None:
            return None
        # drop lead words ("Firma Kölpertechnis GmbH" -> "Kölpertechnis GmbH")
        rest = [(max(p, start), t) for p, t in toks if p + len(t) > start]
        while len(rest) > 1 and rest[0][1].lower().strip(OPENING + ":") in LEAD_WORDS:
            rest = rest[1:]
        return rest[0][0]
