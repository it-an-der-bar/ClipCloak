"""Build the word lists the NER plausibility filter uses (run by hand, the output is committed).

    pip download wordfreq==3.1.1 geonamescache==3.0.2 gender-guesser==0.4.0 --no-deps -d wheels
    python tools/make_wordlists.py wheels/wordfreq-3.1.1-py3-none-any.whl \
                                   wheels/geonamescache-3.0.2-py3-none-any.whl \
                                   wheels/gender_guesser-0.4.0-py2.py3-none-any.whl

clipcloak/resources/wordlists/common.txt.gz
    the most frequent English and German words (lower case). An ORG/LOCATION that the NER
    model found and that consists only of such words ("Roadmap", "Shell-Kommandos",
    "Diagnose-Dateien", "Chain") is an ordinary noun, not a name.
    Data: wordfreq (Robyn Speer), CC BY-SA 4.0 – https://github.com/rspeer/wordfreq
clipcloak/resources/wordlists/places.txt.gz
    place names (whole names, words joined by a space) made only of common words (München,
    Berlin, Essen, Halle, Kassel, "bad tölz" …), so such a LOCATION is kept. Cities with 15,000+
    inhabitants worldwide and 1,000+ in DE/AT/CH, countries, German states.
    Data: GeoNames via geonamescache, CC BY 4.0 – https://www.geonames.org/
clipcloak/resources/wordlists/firstnames.txt.gz
    first names (lower case, without accents), so that a PERSON made only of common words is
    kept when it starts with a first name ("Max Mustermann") and dropped otherwise
    ("Bisherige Läufe"). Data: "nam_dict.txt" by Jörg Michael (via gender-guesser),
    GNU Free Documentation License 1.2+, no invariant sections.
"""

from __future__ import annotations

import gzip
import io
import json
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "clipcloak" / "resources" / "wordlists"
TOP = {"en": 120_000, "de": 120_000}
WORD = re.compile(r"^[a-zäöüßàâçéèêëîïôûùÿñ]{2,}$")

GERMAN_PLACES = """
deutschland österreich schweiz liechtenstein luxemburg frankreich italien spanien portugal niederlande
belgien dänemark schweden norwegen finnland polen tschechien slowakei ungarn slowenien kroatien
griechenland türkei russland ukraine england schottland irland großbritannien amerika kanada china
japan indien europa afrika asien bayern baden württemberg hessen sachsen thüringen brandenburg
niedersachsen nordrhein westfalen rheinland pfalz saarland schleswig holstein mecklenburg vorpommern
hamburg bremen berlin tirol kärnten steiermark vorarlberg salzburg burgenland wien zürich bern basel
genf luzern oberbayern niederbayern oberpfalz franken schwaben allgäu ruhrgebiet
""".split()


def wordfreq_words(whl: Path, lang: str) -> list[str]:
    import msgpack   # dev-time only
    with zipfile.ZipFile(whl) as z:
        raw = z.read(f"wordfreq/data/large_{lang}.msgpack.gz")
    data = msgpack.loads(gzip.decompress(raw), strict_map_key=False)
    out = []
    for bucket in data[1:]:
        for w in bucket:
            if WORD.match(w):
                out.append(w)
                if len(out) >= TOP[lang]:
                    return out
    return out


def geonames(whl: Path) -> set[str]:
    names: set[str] = set()
    with zipfile.ZipFile(whl) as z:
        big = json.loads(z.read("geonamescache/data/cities15000.json"))
        small = json.loads(z.read("geonamescache/data/cities1000.json"))
        countries = json.loads(z.read("geonamescache/data/countries.json"))
    cities = list(big.values()) + [c for c in small.values() if c["countrycode"] in ("DE", "AT", "CH")]
    for c in cities:
        cand = [c["name"]]
        if c["countrycode"] in ("DE", "AT", "CH") or c["population"] >= 500_000:
            cand += c.get("alternatenames") or []     # München, Wien, Mailand …
        names.update(_phrase(n) for n in cand)
    names.update(_phrase(c["name"]) for c in countries.values())
    return {n for n in names if n} | set(GERMAN_PLACES)


def _phrase(name: str) -> str:
    """Whole name, lower case, words joined by one space ("st cloud", "bad tölz"); "" if odd."""
    words = [w for w in re.split(r"[\s\-/.']+", name.lower()) if w]
    return " ".join(words) if words and all(WORD.match(w) for w in words) else ""


def fold(word: str) -> str:
    import unicodedata
    return "".join(c for c in unicodedata.normalize("NFKD", word.lower()) if not unicodedata.combining(c))


def first_names(whl: Path) -> set[str]:
    with zipfile.ZipFile(whl) as z:
        raw = z.read("gender_guesser/data/nam_dict.txt")
    out: set[str] = set()
    for bline in raw.split(b"\n"):
        try:
            line = bline.decode("utf-8")
        except UnicodeDecodeError:
            line = bline.decode("latin-1")
        code = line[:2].strip()
        if not code or code.startswith("#") or code == "=" or code not in ("M", "1M", "?M", "F", "1F", "?F", "?"):
            continue
        for part in re.split(r"[+\s\-]+", line[3:29].strip()):
            w = fold(part)
            if len(w) >= 2 and w.isalpha() and w.isascii():
                out.add(w)
    return out


def main(argv) -> int:
    if len(argv) != 4:
        print(__doc__)
        return 2
    wf, geo, names = Path(argv[1]), Path(argv[2]), Path(argv[3])
    common: set[str] = set()
    for lang in TOP:
        common |= set(wordfreq_words(wf, lang))
    places = {p for p in geonames(geo) if all(w in common for w in p.split())}
    OUT.mkdir(parents=True, exist_ok=True)
    for name, words in (("common.txt.gz", common), ("places.txt.gz", places),
                        ("firstnames.txt.gz", first_names(names))):
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0, compresslevel=9) as gz:
            gz.write("\n".join(sorted(words)).encode("utf-8"))
        (OUT / name).write_bytes(buf.getvalue())
        print(f"{name}: {len(words)} words, {len(buf.getvalue()) / 1024:.0f} KiB")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
