"""Detectors backed by external engines: spaCy NER helper process and an LLM."""

from __future__ import annotations

import json
import logging
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

from ...activity import event
from ...meta import NER_HELPER_NAME
from ..entities import EntityType as T
from .. import wordlists
from ..wordlists import GENERIC_LABELS
from ..textutil import WORD_BOUNDARY_L, WORD_BOUNDARY_R
from .base import Detector

log = logging.getLogger(__name__)

LABEL_MAP = {
    "PER": T.PERSON.value, "PERSON": T.PERSON.value,
    "ORG": T.ORG.value, "NORP": None,
    "LOC": T.LOCATION.value, "GPE": T.LOCATION.value, "FAC": T.LOCATION.value,
}


def occurrences(text: str, needle: str) -> list[tuple[int, int]]:
    rx = re.compile(WORD_BOUNDARY_L + re.escape(needle) + WORD_BOUNDARY_R)
    return [(m.start(), m.end()) for m in rx.finditer(text)]


def find_ner_helper(configured: str = "") -> list[str] | None:
    """Command line to start the NER helper, or ``None`` if unavailable.

    Only fixed places are searched – next to the program (``<app>-ner[.exe]`` or
    ``ner\\<app>-ner.exe`` of the Windows installer), then PATH on Linux/macOS. No wildcard
    names and no PATH search on Windows (it would include the current directory), so a
    file dropped into the download folder is never started by accident.
    """
    win = sys.platform == "win32"
    if configured:
        p = Path(configured).expanduser()
        if p.is_absolute():
            return [str(p)] if p.is_file() else None
        # a relative path would depend on the current directory: only a bare name, looked up in PATH
        bare = "/" not in configured and "\\" not in configured
        found = shutil.which(configured) if bare and not win else None
        return [found] if found else None
    exe = NER_HELPER_NAME + (".exe" if win else "")
    frozen = getattr(sys, "frozen", False)
    base = Path(sys.executable).resolve().parent if frozen else Path(sys.argv[0]).resolve().parent
    for c in (base / exe, base / "ner" / exe):
        if c.is_file():
            return [str(c)]
    if not win:
        found = shutil.which(NER_HELPER_NAME)
        if found:
            return [found]
    if not frozen:
        try:
            import importlib.util
            if importlib.util.find_spec("spacy") is not None:
                return [sys.executable, "-m", __package__.split(".")[0] + ".ner_helper"]
        except (ImportError, ValueError):
            pass
    return None


class NerClient:
    """Talks JSON lines to a long-running helper process."""

    def __init__(self, cmd: list[str], timeout: float = 60):
        self.cmd = cmd
        self.timeout = timeout
        self.proc: subprocess.Popen | None = None
        self._q: queue.Queue = queue.Queue()
        self._lock = threading.Lock()
        self._next = 0

    def _start(self):
        flags = 0x08000000 if sys.platform == "win32" else 0   # CREATE_NO_WINDOW
        # PYINSTALLER_RESET_ENVIRONMENT: the helper is its own frozen program and must
        # not pick up the extraction directory of the (frozen) main application
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYINSTALLER_RESET_ENVIRONMENT="1")
        self.proc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
                                     bufsize=1, creationflags=flags, env=env)
        self._q = queue.Queue()
        event("log.ner_start", cmd=" ".join(self.cmd))
        t = threading.Thread(target=self._reader, args=(self.proc, self._q), daemon=True)
        t.start()

    @staticmethod
    def _reader(proc, q):
        for line in proc.stdout:
            q.put(line)
        q.put(None)

    def request(self, payload: dict, timeout: float | None = None) -> dict:
        timeout = timeout or self.timeout
        with self._lock:
            if self.proc is None or self.proc.poll() is not None:
                self._start()
            self._next += 1
            payload = dict(payload, id=self._next)
            self.proc.stdin.write(json.dumps(payload) + "\n")
            self.proc.stdin.flush()
            while True:
                try:
                    line = self._q.get(timeout=timeout)
                except queue.Empty:
                    self.close()
                    raise TimeoutError("NER helper timeout") from None
                if line is None:
                    self.proc = None
                    raise RuntimeError("NER helper exited")
                try:
                    data = json.loads(line)
                except ValueError:
                    continue
                if data.get("id") == self._next:
                    if data.get("error"):
                        raise RuntimeError(data["error"])
                    return data

    def close(self):
        proc, self.proc = self.proc, None
        if proc is None:
            return
        try:
            if proc.poll() is None:
                proc.stdin.close()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    proc.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired, ValueError):
            pass
        for stream in (proc.stdin, proc.stdout):
            try:
                if stream:
                    stream.close()
            except OSError:
                pass


# --------------------------------------------------------------------------- NER filter
# The small spaCy models label a lot of non-names as entities, especially in code,
# shell scripts and short German/English phrases. Every entity has to pass these checks.
CODE_CHARS = set('=(){}[]$;|<>`*#_\\/":+%~^@')
CODE_WORDS = set("""
if then else elif fi for do done while until case esac in function return echo printf read
local export set unset shift source exit grep sed awk cut tr sort uniq xargs find cat tee
sudo apt yum dnf apk pip npm kubectl docker podman helm git curl wget ssh scp systemctl
journalctl chmod chown mkdir rm cp mv ln def class import from as with try except finally
raise lambda yield pass break continue var let const new public private static void null
none true false nil select where insert update delete create table and or not
""".split())
STOP_WORDS = set("""
der die das den dem des ein eine einen einem einer eines du dein deine deiner deinem deinen
ich mein meine er sie es wir ihr ihre unser unsere euer eure sein seine man und oder aber
nicht kein keine bitte danke hallo alle alles jeder jede mit von zu bei auf aus für im in am
the a an your my his her its our their this that these those you we they he she it and or
but not no please thanks hello all any each with from to at by on in of for
""".split())
LEGAL_FORMS = {"gmbh", "ag", "kg", "ohg", "gbr", "ug", "se", "e.v.", "ev", "eg", "kgaa", "ltd",
               "inc", "llc", "llp", "plc", "corp", "corporation", "co", "sa", "sarl", "sas", "bv",
               "nv", "oy", "ab", "spa", "srl", "gmbh & co. kg"}
_WORD = re.compile(r"[A-Za-zÀ-ɏ][A-Za-zÀ-ɏ'’.\-]*")


def _title(word: str) -> bool:
    return word[:1].isupper() and any(c.islower() for c in word[1:])


# identifiers of code: "ComInterop", "IntPtr", "Int32", "ByRef", "iPhone" is fine (starts lower)
_CAMEL = re.compile(r"[a-zß-ÿ][A-ZÀ-Þ]|^[A-Z]{2,}[a-z]|\d")
_NAME_PREFIX = re.compile(r"^(Mc|Mac|De|Di|Da|Du|La|Le|Van|Von|O')[A-ZÀ-Þ][a-zß-ÿ]+$")
# lines of code / stack traces: "Avalonia.Threading.Dispatcher.Run(", "at System.Dynamic…"
_CODE_LINE = re.compile(r"\b[A-Za-z_]\w*(?:\.[A-Z_]\w*){2,}|^\s*at\s+[\w.$<>`]+\(|\w\(\)|::\w")


def _in_code_context(text: str, s: int, e: int) -> bool:
    before = text[s - 1] if s > 0 else ""
    before2 = text[s - 2] if s > 1 else ""
    after = text[e] if e < len(text) else ""
    after2 = text[e + 1] if e + 1 < len(text) else ""
    if before == "." and before2.isalnum():
        return True                       # Microsoft.CSharp  ->  "CSharp"
    if after == "." and after2.isalpha() and after2.isupper():
        return True                       # "Avalonia".Threading
    if after in "([<" and after:
        return True                       # Method(  Generic<  Array[
    ls = text.rfind("\n", 0, s) + 1
    le = text.find("\n", e)
    return bool(_CODE_LINE.search(text[ls:le if le >= 0 else len(text)]))


def plausible_entity(text: str, s: int, e: int, typ: str, tokens: list | None):
    """Return the (possibly trimmed) span of a believable PERSON/ORG/LOCATION or None."""
    span = text[s:e]
    if len(span.strip()) < 2 or len(span) > 80 or not re.search(r"[A-Za-zÀ-ɏ]", span):
        return None
    if any(c in CODE_CHARS for c in span) or "\n" in span:
        return None
    words = _WORD.findall(span)
    if not words:
        return None
    lower = [w.lower().strip(".") for w in words]
    if all(w in LEGAL_FORMS or w in ("co", "&", "mbh") for w in lower):
        return None                         # "GmbH & Co.": only the legal form, the name is the company detector's
    if any(w in CODE_WORDS for w in lower):
        return None
    if any(_CAMEL.search(w) and not _NAME_PREFIX.match(w) for w in words) \
            and not any(w in LEGAL_FORMS for w in lower):
        return None                         # ComInterop, IntPtr, Int32, ByRef, CancellationToken
    if _in_code_context(text, s, e):
        return None                         # stack traces, namespaces, method calls
    if typ != T.PERSON.value:
        parts = [w for x in lower for w in re.split(r"[/.\-]", x) if w]
        if " ".join(lower) in wordlists.PUBLIC_ORGS or (
                parts and any(w in wordlists.PUBLIC_ORGS for w in parts)
                and all(w in wordlists.PUBLIC_ORGS or w in wordlists.PUBLIC_ORG_EXTRA_WORDS or w == "sas"
                        or re.fullmatch(r"v?\d+(\.\d+)*", w) for w in parts)):
            return None                     # Microsoft, SAP, "Debian GNU/Linux", "Azure SAS" are no personal data
    if span.lower() in GENERIC_LABELS:
        return None
    toks = tokens or []
    pos = [t.get("pos", "") for t in toks]
    stop = [bool(t.get("stop")) for t in toks]

    if typ == T.PERSON.value:
        # a person needs first and last name: leading run of capitalised proper nouns
        if toks:
            run = []
            named = False                     # the run starts with a known first name
            for t, p, st in zip(toks, pos, stop, strict=True):
                w = text[int(t["s"]):int(t["e"])]
                first = w.split("-")[0]
                # the tagger's part of speech is not trusted after a first name: "Anna-Lena Petersen"
                ok = (p == "PROPN" or (named and _title(w)) or (not run and wordlists.is_first_name(first)))
                if ok and not st and _title(w) and w.lower() not in STOP_WORDS:
                    if not run:
                        named = wordlists.is_first_name(first)
                    run.append(t)
                elif w in ("-",) and run:
                    continue
                else:
                    break
            if not run:
                return None
            ps, pe = int(run[0]["s"]), int(run[-1]["e"])
            if not 2 <= len(text[ps:pe].split()) <= 4:   # "RustDesk-Server" is one word
                return None
            if not _person_like(text[ps:pe]):
                return None
            return ps, pe
        if not 2 <= len(words) <= 4 or not all(_title(w) for w in words):
            return None
        if any(w in STOP_WORDS for w in lower):
            return None
        if not _person_like(span):
            return None
        return s, e

    # ORG / LOCATION
    if not _title(words[0]) and not (words[0].isupper() and any(w in LEGAL_FORMS for w in lower)):
        return None                         # lowercase start or ALL-CAPS constant
    if lower[0] in STOP_WORDS or (stop and stop[0]):
        return None                         # "Deine Auswahl", "The …"
    if all(w.isupper() for w in words) and not any(w in LEGAL_FORMS for w in lower):
        return None                         # ACCEPT, ANSWER, VPN …
    if typ == T.LOCATION.value:
        # places are only taken from the gazetteer (GeoNames): the model calls far too many
        # nouns and product names a place ("Kurzbefehle", "Hyprland", "Ollama")
        return (s, e) if _is_place(span) else None
    if any(c in span for c in ",;→…|"):
        return None                         # a list or an arrow, not one name
    if typ == T.ORG.value:
        # "Migration für Northwind Traders": ordinary words before a linking word are no part of it
        link = [i for i, w in enumerate(lower) if w in ("für", "von", "der", "des", "bei", "for", "of", "at")]
        if link and 0 < link[-1] < len(words) - 1 and all(wordlists.is_common_word(w) for w in words[:link[-1]]) \
                and not any(w in LEGAL_FORMS for w in lower[:link[-1]]):
            ns = s + span.find(words[link[-1] + 1], len(" ".join(words[:link[-1] + 1])) - 1)
            return plausible_entity(text, ns, e, typ, None)
    if typ == T.ORG.value and not any(w in LEGAL_FORMS for w in lower):
        if re.search(r"\d|\w\.\w|['’]s\b", span) or lower[0] in MONTHS:
            return None                     # "Python 3.5.x", "Pool.alloc", "Python’s", "March"
        if len(words) == 1 and len(words[0]) <= 3:
            return None                     # "Del", "Esc", "IT"
        if any(w in TECH_WORDS for w in lower):
            return None                     # "Proofpoint URL Defense", "Docker API" – products, not customers
    if typ == T.ORG.value and len(words) >= 2 and _names_place(span):
        return s, e                         # "Stadtwerke Kassel", "Sparkasse Hannover"
    if toks and "PROPN" not in pos and not any(w in LEGAL_FORMS for w in lower):
        return None                         # nouns/verbs the model mislabelled
    if not any(w in LEGAL_FORMS for w in lower) and _only_common_words(span):
        if not _names_place(span):
            return None                     # "Roadmap", "Shell-Kommandos", "Diagnose-Dateien", "Chain"
    return s, e


MONTHS = set("""
january february march april may june july august september october november december
januar februar märz mai juni juli oktober dezember
""".split())
TECH_WORDS = set("""
url uri api apis http https dns tls ssl ssh vpn cli gui sdk ide json yaml xml html css sql rest grpc oauth
stdout stdin stderr saml ldap smtp imap ftp sftp tcp udp ip ipv4 ipv6 dhcp nat vlan wlan lan wan usb pdf csv
exe msi dll gpu cpu linter install
ram ssd hdd os kernel plugin plugins server client cluster container docker image repo git ci cd devops
jwt token tokens
""".split())
_PARTS = re.compile(r"[A-Za-zÀ-ɏß]+")
_LINK_WORDS = {"des", "der", "die", "das", "dem", "den", "von", "vom", "und", "für", "im", "in", "am",
               "the", "of", "and", "for", "on", "at", "to", "a", "an"}


def _only_common_words(span: str) -> bool:
    """Every word (also inside "Release-Binaries") is a frequent English/German word."""
    parts = [p for p in _PARTS.findall(span) if p.lower() not in _LINK_WORDS]
    return bool(parts) and bool(wordlists.common_words()) and all(wordlists.is_common_word(p) for p in parts)


def _person_like(span: str) -> bool:
    """A name made only of ordinary words ("Bisherige Läufe", "Neue Funktionen") needs a first
    name at the start ("Max Mustermann", "Peter Maier"); rare words ("Kölper") pass anyway."""
    parts = _PARTS.findall(span)
    if not parts or not wordlists.common_words():
        return True
    if not all(wordlists.is_common_word(p) for p in parts):
        return True
    return wordlists.is_first_name(parts[0])


def _names_place(span: str) -> bool:
    """An organisation named after its town is specific: "Stadtwerke Kassel" – but not after a
    town that is also an English word ("Root Certificates", "University Press")."""
    places, english = wordlists.place_names(), wordlists.english_words()
    return any(w.lower() in places and w.lower() not in english
               for w in _PARTS.findall(span) if w.lower() not in _LINK_WORDS)


def _is_place(span: str) -> bool:
    words = [w.lower() for w in _PARTS.findall(span)]
    places = wordlists.place_names()
    return " ".join(words) in places or all(w in places for w in words if w not in _LINK_WORDS)


class NerDetector(Detector):
    id = "ner"
    types = (T.PERSON.value, T.ORG.value, T.LOCATION.value)
    default_enabled = False
    priority = 30

    def __init__(self, cmd: list[str] | None, language: str = "auto", types=("PERSON", "ORG"),
                 models: dict | None = None):
        self.client = NerClient(cmd) if cmd else None
        self.language = language
        self.wanted = set(types)
        self.models = models or {}

    def warm_up(self) -> None:
        """Start the helper and load the models before the first real request."""
        if self.client is not None:
            event("log.ner_loading")
            lang = "both" if self.language == "auto" else self.language
            self.client.request({"text": "Hallo Welt. Hello world.", "lang": lang, "models": self.models})

    def find(self, text, ctx):
        if self.client is None:
            raise RuntimeError("NER helper not found")
        t0 = time.monotonic()
        data = self.client.request({"text": text, "lang": self.language, "models": self.models})
        out = []
        for ent in data.get("entities", []):
            typ = LABEL_MAP.get(str(ent.get("label", "")).upper())
            if not typ or typ not in self.wanted:
                continue
            s, e = int(ent["start"]), int(ent["end"])
            if not 0 <= s < e <= len(text):
                continue
            span = plausible_entity(text, s, e, typ, ent.get("tokens"))
            if span is not None:
                out.append(self.mk(span[0], span[1], typ, text))
        event("log.ner_result", n=len(data.get("entities", [])), kept=len(out),
              ms=int((time.monotonic() - t0) * 1000))
        return out


class LlmDetector(Detector):
    id = "llm"
    types = (T.PERSON.value, T.ORG.value, T.LOCATION.value)
    default_enabled = False
    priority = 28

    def __init__(self, client, types=("PERSON", "ORG")):
        self.client = client
        self.wanted = list(types)

    def find(self, text, ctx):
        out = []
        for ent in self.client.detect(text, self.wanted):
            typ = ent["type"] if ent["type"] in T.__members__ else T.CUSTOM.value
            for s, e in occurrences(text, ent["text"]):
                out.append(self.mk(s, e, typ, text))
        return out
