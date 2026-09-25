"""Detection + replacement pipeline and reverse mapping."""

from __future__ import annotations

import ipaddress
import logging
import re
import threading
from dataclasses import dataclass, field

from .detectors import Detector, DetectorContext, builtin_detectors
from .detectors.learned import LearnedNameDetector
from .detectors.network import IPV4_RE, IPV6_RE
from .entities import (EntityType as T, Finding, Mode, Result, apply_spans, pick_non_overlapping,
                       resolve_overlaps)
from .surrogates import PlaceholderFactory, SurrogateFactory, SurrogateSettings
from .vault import Vault

log = logging.getLogger(__name__)

CI_TYPES = {T.DOMAIN.value, T.EMAIL.value, T.HOSTNAME.value, T.USERNAME.value}
_B_L = r"(?:(?<![A-Za-z0-9_À-ɏ])|(?<=\\[nrt]))"
_B_R = r"(?![A-Za-z0-9_À-ɏ])"


@dataclass
class EngineSettings:
    enabled_detectors: set = field(default_factory=lambda: {d.id for d in builtin_detectors() if d.default_enabled} | {"learned-names"})
    disabled_types: set = field(default_factory=set)
    redact_template: str = "[REDACTED]"
    anonymize_style: str = "realistic"          # realistic | placeholder
    placeholder_template: str = "<{type}_{n}>"
    type_modes: dict = field(default_factory=dict)   # TYPE -> redact|anonymize|pseudonymize|keep
    skip_known_surrogates: bool = True
    allow_terms: set = field(default_factory=set)
    surrogate: SurrogateSettings = field(default_factory=SurrogateSettings)
    context: DetectorContext = field(default_factory=DetectorContext)
    max_chars: int = 2_000_000


class Engine:
    def __init__(self, settings: EngineSettings | None = None, vault: Vault | None = None,
                 extra_detectors: list[Detector] | None = None):
        self.settings = settings or EngineSettings()
        self.vault = vault or Vault("session")
        self.anon_vault = Vault("anonymous", reversible=False)
        self.detectors: list[Detector] = builtin_detectors() + [LearnedNameDetector(lambda: self.vault)] \
            + list(extra_detectors or [])
        self.lock = threading.RLock()
        self._revert_cache: tuple[int, object] | None = None
        self._rebuild()

    # ------------------------------------------------------------ setup
    def _rebuild(self) -> None:
        self.pseudo = SurrogateFactory(self.vault, self.settings.surrogate)
        self.anon = SurrogateFactory(self.anon_vault, self.settings.surrogate)
        self.placeholders = PlaceholderFactory(self.anon_vault, self.settings.placeholder_template)
        self._revert_cache = None

    def configure(self, settings: EngineSettings) -> None:
        with self.lock:
            self.settings = settings
            self._rebuild()

    def set_vault(self, vault: Vault) -> None:
        with self.lock:
            self.vault = vault
            self._rebuild()

    def add_detector(self, det: Detector) -> None:
        with self.lock:
            self.detectors = [d for d in self.detectors if d.id != det.id] + [det]

    def reset_anonymous(self) -> None:
        with self.lock:
            self.anon_vault = Vault("anonymous", reversible=False)
            self._rebuild()

    # ------------------------------------------------------------ analysis
    def analyze(self, text: str, warnings: list[str] | None = None) -> list[Finding]:
        s = self.settings
        if len(text) > s.max_chars:
            if warnings is not None:
                warnings.append(f"text too large ({len(text)} chars), skipped")
            return []
        found: list[Finding] = []
        for det in self.detectors:
            if det.id not in s.enabled_detectors:
                continue
            try:
                found.extend(det.find(text, s.context))
            except Exception as exc:  # detector bugs must never break the pipeline
                log.exception("detector %s failed", det.id)
                if warnings is not None:
                    warnings.append(f"detector {det.id}: {exc}")
        allow = {a.lower() for a in s.allow_terms}
        found = [f for f in found
                 if f.type not in s.disabled_types
                 and f.text.strip()
                 and f.text.lower() not in allow
                 and s.type_modes.get(f.type) != "keep"]
        resolved = resolve_overlaps(found)
        if s.skip_known_surrogates:
            ci = {k.lower() for k in self.vault.by_surrogate}
            resolved = [f for f in resolved if not self._looks_pseudonymised(f, ci)]
        return resolved

    def _looks_pseudonymised(self, f: Finding, ci_surrogates: set | None = None) -> bool:
        v = self.vault
        if v.is_surrogate(f.text):
            return True
        if f.type in (T.IPV4.value, T.IPV6.value):
            try:
                addr = ipaddress.ip_address(f.text.split("/")[0])
            except ValueError:
                return False
            return v.in_known_network(addr)
        if f.type in CI_TYPES:
            if ci_surrogates is None:
                ci_surrogates = {k.lower() for k in v.by_surrogate}
            return f.text.lower() in ci_surrogates
        return False

    # ------------------------------------------------------------ processing
    def process(self, text: str, mode: str | Mode, findings: list[Finding] | None = None) -> Result:
        mode = Mode(mode).value
        if mode == Mode.REVERT.value:
            return self.revert(text)
        with self.lock:
            warnings: list[str] = []
            if findings is None:
                findings = self.analyze(text, warnings)
            self.pseudo.set_context(text)
            self.anon.set_context(text)
            spans = []
            for f in findings:
                eff = self.settings.type_modes.get(f.type) or mode
                rep = self._replacement(f, eff)
                if rep is None or rep == f.text:
                    continue
                spans.append((f.start, f.end, rep, f.type, f.text, f.detector))
            out, reps = apply_spans(text, spans)
            return Result(mode, text, out, reps, warnings)

    def _replacement(self, f: Finding, mode: str) -> str | None:
        if mode == Mode.REDACT.value:
            try:
                return self.settings.redact_template.format(type=f.type)
            except (KeyError, IndexError, ValueError):
                return "[REDACTED]"
        if mode == Mode.ANONYMIZE.value:
            if self.settings.anonymize_style == "placeholder":
                return self.placeholders.surrogate(f)
            return self.anon.surrogate(f)
        if mode == Mode.PSEUDONYMIZE.value:
            return self.pseudo.surrogate(f)
        return None

    # ------------------------------------------------------------ revert
    def _revert_patterns(self):
        v = self.vault
        if self._revert_cache and self._revert_cache[0] == v.revision and self._revert_cache[2] is v:
            return self._revert_cache[1]
        exact: dict[str, tuple[str, str]] = {}
        ci: dict[str, tuple[str, str]] = {}
        for (typ, orig), e in v.entries.items():
            if typ in (T.IPV4.value, T.IPV6.value):
                continue
            if typ in CI_TYPES:
                ci[e.surrogate.lower()] = (typ, orig)
            else:
                exact[e.surrogate] = (typ, orig)

        def alt(keys):
            keys = sorted(keys, key=len, reverse=True)
            if not keys:
                return None
            return "|".join(re.escape(k) for k in keys)

        pats = {}
        a = alt(exact.keys())
        if a:
            pats["exact"] = re.compile(_B_L + "(?:" + a + ")" + _B_R)
        a = alt(ci.keys())
        if a:
            pats["ci"] = re.compile(_B_L + "(?:" + a + ")" + _B_R, re.IGNORECASE)
        tokens: dict[str, tuple[str, str]] = {}
        for name, typ in (("words", "WORD"), ("users", T.USERNAME.value), ("first", T.PERSON.value), ("last", T.PERSON.value)):
            for orig, sur in v.maps[name].fwd.items():
                tokens.setdefault(sur, (typ, orig, name))
        a = alt(tokens.keys())
        if a:
            pats["tokens"] = re.compile(_B_L + "(?:" + a + ")" + _B_R, re.IGNORECASE)
        data = (pats, exact, ci, tokens)
        self._revert_cache = (v.revision, data, v)
        return data

    def revert(self, text: str) -> Result:
        from .textutil import transfer_case
        with self.lock:
            pats, exact, ci, tokens = self._revert_patterns()
            cands: list[Finding] = []
            # 1) IP addresses (exact surrogates or inside known surrogate networks)
            for rx in (IPV4_RE, IPV6_RE):
                for m in rx.finditer(text):
                    lit = m.group(0)
                    if rx is IPV6_RE:
                        lit = m.group(1) + (("/" + m.group(3)) if m.group(3) else "")
                        start, end = m.start(1), m.start(1) + len(lit)
                    else:
                        start, end = m.start(), m.end()
                    orig = self._revert_ip(lit)
                    if orig is not None and orig != lit:
                        cands.append(Finding(start, end, T.IPV6.value if ":" in lit else T.IPV4.value,
                                             lit, "revert", 30, {"rep": orig}))
            # 2) exact / case-insensitive entries
            if "exact" in pats:
                for m in pats["exact"].finditer(text):
                    typ, orig = exact[m.group(0)]
                    cands.append(Finding(m.start(), m.end(), typ, m.group(0), "revert", 20, {"rep": orig}))
            if "ci" in pats:
                for m in pats["ci"].finditer(text):
                    typ, orig = ci[m.group(0).lower()]
                    cands.append(Finding(m.start(), m.end(), typ, m.group(0), "revert", 20, {"rep": orig}))
            # 3) tokens from word/name maps
            if "tokens" in pats:
                for m in pats["tokens"].finditer(text):
                    word = m.group(0)
                    typ, orig, name = tokens[word.lower()]
                    if name in ("first", "last") and word.islower():
                        continue  # avoid touching ordinary lowercase words
                    cands.append(Finding(m.start(), m.end(), typ, word, "revert", 10,
                                         {"rep": transfer_case(word, orig)}))
            accepted = pick_non_overlapping(sorted(cands, key=lambda f: (-f.length, -f.priority, f.start)))
            spans = [(f.start, f.end, f.meta["rep"], f.type, f.text, "revert") for f in accepted]
            out, reps = apply_spans(text, spans)
            # replacements in revert: "original" = surrogate found, "replacement" = restored value
            return Result(Mode.REVERT.value, text, out, reps, [])

    def _revert_ip(self, lit: str) -> str | None:
        v = self.vault
        k = v.by_surrogate.get(lit)
        if k is not None:
            return k[1]
        addr_s, _, prefix = lit.partition("/")
        try:
            addr = ipaddress.ip_address(addr_s)
        except ValueError:
            return None
        if not v.in_known_network(addr):
            return None
        ipm = self.pseudo.ip
        if prefix:
            try:
                net = ipaddress.ip_network(lit, strict=False)
            except ValueError:
                return None
            if net.network_address == addr:
                o = ipm.unmap_network(net)
                return None if o is None else f"{o.network_address}/{prefix}"
        o = ipm.unmap_v4(addr) if addr.version == 4 else ipm.unmap_v6(addr)
        if o is None:
            return None
        res = str(o) + (f"/{prefix}" if prefix else "")
        return res.upper() if addr.version == 6 and addr_s != addr_s.lower() else res
