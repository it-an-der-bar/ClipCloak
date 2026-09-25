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
from pathlib import Path

from ...meta import NER_HELPER_NAME
from ..entities import EntityType as T
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
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        self.proc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
                                     bufsize=1, creationflags=flags, env=env)
        self._q = queue.Queue()
        t = threading.Thread(target=self._reader, args=(self.proc, self._q), daemon=True)
        t.start()

    @staticmethod
    def _reader(proc, q):
        for line in proc.stdout:
            q.put(line)
        q.put(None)

    def request(self, payload: dict) -> dict:
        with self._lock:
            if self.proc is None or self.proc.poll() is not None:
                self._start()
            self._next += 1
            payload = dict(payload, id=self._next)
            self.proc.stdin.write(json.dumps(payload) + "\n")
            self.proc.stdin.flush()
            while True:
                try:
                    line = self._q.get(timeout=self.timeout)
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
            lang = "both" if self.language == "auto" else self.language
            self.client.request({"text": "Hallo Welt. Hello world.", "lang": lang, "models": self.models})

    def find(self, text, ctx):
        if self.client is None:
            raise RuntimeError("NER helper not found")
        data = self.client.request({"text": text, "lang": self.language, "models": self.models})
        out = []
        for ent in data.get("entities", []):
            typ = LABEL_MAP.get(str(ent.get("label", "")).upper())
            if not typ or typ not in self.wanted:
                continue
            s, e = int(ent["start"]), int(ent["end"])
            if 0 <= s < e <= len(text):
                span = text[s:e]
                if len(span.strip()) < 2 or not re.search(r"[A-Za-zÀ-ɏ]", span):
                    continue
                if span.lower() in GENERIC_LABELS or (span.isupper() and len(span) <= 4):
                    continue   # acronyms / IT vocabulary (VPN, DNS, API …) are not names
                out.append(self.mk(s, e, typ, text))
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
