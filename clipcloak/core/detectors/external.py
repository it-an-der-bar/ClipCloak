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
    """Command line to start the NER helper, or ``None`` if unavailable."""
    if configured:
        p = Path(configured).expanduser()
        if p.is_file():
            return [str(p)]
        found = shutil.which(configured)
        if found:
            return [found]
        return None
    exe = NER_HELPER_NAME + (".exe" if sys.platform == "win32" else "")
    candidates = []
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).resolve().parent / exe)
    candidates.append(Path(sys.argv[0]).resolve().parent / exe)
    # Windows installer / ZIP: the NER helper is a folder build of its own in "ner\"
    candidates += [c.parent / "ner" / exe for c in list(candidates)]
    for c in candidates:
        if c.is_file():
            return [str(c)]
    # release downloads carry version/platform in the name: <app>-ner-v1.2.3-linux-x86_64
    for d in {c.parent for c in candidates}:
        hits = sorted(p for p in d.glob(NER_HELPER_NAME + "-*")
                      if p.is_file() and (sys.platform != "win32" or p.suffix.lower() == ".exe"))
        if hits:
            return [str(hits[-1])]
    found = shutil.which(NER_HELPER_NAME)
    if found:
        return [found]
    if not getattr(sys, "frozen", False):
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
                    raise TimeoutError("NER helper timeout")
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
    if any(w in CODE_WORDS for w in lower):
        return None
    if any(_CAMEL.search(w) and not _NAME_PREFIX.match(w) for w in words) \
            and not any(w in LEGAL_FORMS for w in lower):
        return None                         # ComInterop, IntPtr, Int32, ByRef, CancellationToken
    if _in_code_context(text, s, e):
        return None                         # stack traces, namespaces, method calls
    if typ != T.PERSON.value and " ".join(lower) in wordlists.PUBLIC_ORGS:
        return None                         # Microsoft, Google, SAP … are no personal data
    if span.lower() in GENERIC_LABELS:
        return None
    toks = tokens or []
    pos = [t.get("pos", "") for t in toks]
    stop = [bool(t.get("stop")) for t in toks]

    if typ == T.PERSON.value:
        # a person needs first and last name: leading run of capitalised proper nouns
        if toks:
            run = []
            for t, p, st in zip(toks, pos, stop):
                w = text[int(t["s"]):int(t["e"])]
                if p == "PROPN" and not st and _title(w) and w.lower() not in STOP_WORDS:
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
            return ps, pe
        if not 2 <= len(words) <= 4 or not all(_title(w) for w in words):
            return None
        if any(w in STOP_WORDS for w in lower):
            return None
        return s, e

    # ORG / LOCATION
    if not _title(words[0]) and not (words[0].isupper() and any(w in LEGAL_FORMS for w in lower)):
        return None                         # lowercase start or ALL-CAPS constant
    if lower[0] in STOP_WORDS or (stop and stop[0]):
        return None                         # "Deine Auswahl", "The …"
    if all(w.isupper() for w in words) and not any(w in LEGAL_FORMS for w in lower):
        return None                         # ACCEPT, ANSWER, VPN …
    if toks and "PROPN" not in pos and not any(w in LEGAL_FORMS for w in lower):
        return None                         # nouns/verbs the model mislabelled
    return s, e


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
