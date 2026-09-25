"""Format-preserving surrogate generation backed by a :class:`Vault`."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from . import wordlists
from .entities import EntityType as T, Finding
from .ipmap import IPMapper
from .textutil import (digits_like, iban_check_digits, keyed_hash, keyed_rng,
                       luhn_complete, pseudo_word, randomize_chars, transfer_case)
from .vault import Vault

_RUNS = re.compile(r"[A-Za-zÀ-ɏ]+|[0-9]+|[^A-Za-z0-9À-ɏ]+")
_NAME_SPLIT = re.compile(r"(\s+|-|,\s*)")
_TITLES = set("dr dr. prof prof. herr frau hr hr. fr fr. mr mr. mrs mrs. ms ms. dipl. ing. mag. von van de der".split())
ORG_GENERIC = set("""
solutions solution consulting services service group holding systems system software
technologies technology tech it bank versicherung stadtwerke klinikum partner partners
international deutschland germany austria europe digital data cloud security
management industries industrie handel logistik bau immobilien energie medien media
networks network labs lab studio agentur agency ventures capital
""".split())


@dataclass
class SurrogateSettings:
    keep_special_hosts: bool = True
    mac_keep_oui: bool = True
    tld_strategy: str = "keep"          # keep | example
    allow_domains: set = field(default_factory=lambda: set(wordlists.DEFAULT_ALLOWLIST_DOMAINS))
    allow_ip_ranges: list = field(default_factory=list)
    generic_labels: set = field(default_factory=lambda: set(wordlists.GENERIC_LABELS))
    custom_replacements: dict = field(default_factory=dict)  # lower term -> replacement
    known_domains: set = field(default_factory=set)
    extra_tlds: set = field(default_factory=set)


def _cc_len(d: str) -> int:
    """Length of the ITU country calling code at the start of ``d``."""
    if not d:
        return 0
    if d[0] in "17":
        return 1
    two = d[:2]
    if two in ("20", "27", "30", "31", "32", "33", "34", "36", "39", "40", "41", "43",
               "44", "45", "46", "47", "48", "49", "51", "52", "53", "54", "55", "56",
               "57", "58", "60", "61", "62", "63", "64", "65", "66", "81", "82", "84",
               "86", "90", "91", "92", "93", "94", "95", "98"):
        return 2
    return 3


class SurrogateFactory:
    def __init__(self, vault: Vault, settings: SurrogateSettings | None = None):
        self.v = vault
        self.s = settings or SurrogateSettings()
        self.ip = IPMapper(vault.key, self.s.keep_special_hosts)
        self.ctx_words: set[str] = set()
        self._allow_nets = []
        for n in self.s.allow_ip_ranges:
            try:
                self._allow_nets.append(ipaddress.ip_network(str(n), strict=False))
            except ValueError:
                pass

    # ------------------------------------------------------------ helpers
    def set_context(self, text: str) -> None:
        self.ctx_words = set(w.lower() for w in re.findall(r"[A-Za-zÀ-ɏ]{3,}", text))

    def _rng(self, *parts):
        return keyed_rng(self.v.key, *parts)

    def _free(self, cand: str) -> bool:
        return cand.lower() not in self.ctx_words

    # ------------------------------------------------------------ dispatcher
    def surrogate(self, f: Finding) -> str | None:
        typ, text = f.type, f.text
        fixed = f.meta.get("replacement")
        if fixed:
            if " " not in fixed and " " not in text:
                fixed = transfer_case(text, fixed)
            if fixed != text:
                self.v.record(typ, text, fixed)
                return fixed
            return None
        existing = self.v.lookup(typ, text)
        if existing is not None:
            self.v.record(typ, text, existing)
            return existing
        fn = {
            T.IPV4.value: self._ip, T.IPV6.value: self._ip, T.MAC.value: self._mac,
            T.EMAIL.value: self._email, T.DOMAIN.value: self._domain_entity,
            T.HOSTNAME.value: self._hostname, T.USERNAME.value: self._username,
            T.PERSON.value: self._person, T.ORG.value: self._org,
            T.LOCATION.value: self._location, T.PHONE.value: self._phone,
            T.IBAN.value: self._iban, T.CREDIT_CARD.value: self._card,
            T.SID.value: self._sid, T.SECRET.value: self._secret,
            T.PRIVATE_KEY.value: self._secret, T.CERTIFICATE.value: self._secret,
            T.CUSTOM.value: self._custom,
        }.get(typ, self._custom)
        out = None
        for attempt in range(8):
            out = fn(f, attempt)
            if out is None or out == text:
                return None
            if not self.v.surrogate_taken(out, typ, text):
                break
        else:
            out = out + "-" + keyed_hash(self.v.key, typ, text)[:4]
        self.v.record(typ, text, out)
        return out

    # ------------------------------------------------------------ word maps
    def word(self, w: str, force_new: bool = False) -> str:
        low = w.lower()
        rep = self.s.custom_replacements.get(low)
        if rep:
            return transfer_case(w, rep) if " " not in rep else rep
        m = self.v.maps["words"]
        s = m.get(low)
        if s is None:
            rng = self._rng("word", low)
            for _ in range(50):
                cand = pseudo_word(rng, len(low))
                if cand != low and not m.taken(cand) and self._free(cand):
                    break
            m.put(low, cand)
            s = cand
        return transfer_case(w, s)

    def _name_token(self, tok: str, kind: str) -> str:
        m = self.v.maps[kind]
        low = tok.lower()
        s = m.get(low)
        if s is None:
            pool = wordlists.FIRST_NAMES if kind == "first" else wordlists.LAST_NAMES
            rng = self._rng("name", kind, low)
            cand = None
            order = pool[:]
            rng.shuffle(order)
            for c in order:
                cl = c.lower()
                if cl != low and not m.taken(cl) and self._free(cl):
                    cand = cl
                    break
            if cand is None:
                cand = pseudo_word(rng, len(low))
            m.put(low, cand)
            s = cand
        return transfer_case(tok, s)

    def user_token(self, u: str) -> str:
        m = self.v.maps["users"]
        low = u.lower()
        s = m.get(low)
        if s is None:
            rng = self._rng("user", low)
            for _ in range(60):
                first = rng.choice(wordlists.FIRST_NAMES).lower()
                last = rng.choice(wordlists.LAST_NAMES).lower()
                style = rng.random()
                cand = first[0] + last if style < 0.6 else first[:1] + last[:6]
                if cand != low and not m.taken(cand) and self._free(cand):
                    break
            m.put(low, cand)
            s = cand
        return transfer_case(u, s)

    # ------------------------------------------------------------ labels/domains
    def label(self, label: str, force: bool) -> str:
        if not force and label.lower() in self.s.generic_labels:
            return label
        runs = _RUNS.findall(label)
        out = list(runs)
        changed = False
        for i, r in enumerate(runs):
            if r[0].isalpha() and len(r) > 2 and r.lower() not in self.s.generic_labels:
                out[i] = self.word(r)
                changed = True
        if force and not changed:
            alpha = [(len(r), i) for i, r in enumerate(runs) if r[0].isalpha()]
            if alpha:
                _, idx = max(alpha)
                out[idx] = self.word(runs[idx])
            else:
                out = [digits_like(label, self._rng("label", label), nonzero_first=False)]
        return "".join(out)

    def suffix_len(self, low: str) -> int:
        labels = low.split(".")
        if len(labels) >= 3 and ".".join(labels[-2:]) in wordlists.MULTI_SUFFIXES:
            return 2
        return 1

    def domain_allowed(self, low: str) -> bool:
        for d in self.s.allow_domains:
            if low == d or low.endswith("." + d):
                return True
        return False

    def domain(self, host: str) -> str | None:
        low = host.lower()
        if self.domain_allowed(low):
            return None
        existing = self.v.lookup(T.DOMAIN.value, host)
        if existing:
            return existing
        labels = host.split(".")
        n = self.suffix_len(low)
        if len(labels) <= n:
            return None
        suffix = labels[-n:]
        reg = labels[-n - 1]
        subs = labels[:-n - 1]
        if self.s.tld_strategy == "example":
            suffix = ["example"]
        new_reg = self.label(reg, force=True)
        new_subs = [self.label(x, force=False) for x in subs]
        out = ".".join(new_subs + [new_reg] + suffix)
        reg_orig = ".".join(labels[-n - 1:])
        reg_new = ".".join([new_reg] + suffix)
        if reg_orig != host and self.v.lookup(T.DOMAIN.value, reg_orig) is None:
            self.v.record(T.DOMAIN.value, reg_orig, reg_new, count=False)
        return out

    def _domain_entity(self, f: Finding, attempt: int = 0):
        return self.domain(f.text)

    def _hostname(self, f: Finding, attempt: int = 0):
        return self.label(f.text, force=True)

    # ------------------------------------------------------------ people
    def user_local(self, local: str) -> str:
        m = re.match(r"^(.*?)(\d*)$", local)
        base, digits = m.group(1), m.group(2)
        parts = re.split(r"([._+-])", base)
        alpha_idx = [i for i, p in enumerate(parts) if p and p[0].isalpha()]
        if len(alpha_idx) >= 2:
            out = list(parts)
            for k, i in enumerate(alpha_idx):
                kind = "last" if k == len(alpha_idx) - 1 else "first"
                out[i] = self._name_token(parts[i], kind) if len(parts[i]) > 1 else parts[i]
            return "".join(out) + digits
        if not base:
            return digits_like(local, self._rng("userdigits", local))
        return self.user_token(base) + digits

    def _username(self, f: Finding, attempt: int = 0):
        if f.text.lower() in wordlists.SKIP_USERNAMES:
            return None
        return self.user_local(f.text)

    def _email(self, f: Finding, attempt: int = 0):
        local, _, dom = f.text.rpartition("@")
        new_dom = self.domain(dom) or dom
        if new_dom != dom and self.v.lookup(T.DOMAIN.value, dom) is None:
            self.v.record(T.DOMAIN.value, dom, new_dom, count=False)
        if local.lower() in wordlists.FUNCTIONAL_MAILBOXES:
            new_local = local
        else:
            new_local = self.user_local(local)
        if new_local == local and new_dom == dom:
            return None
        return f"{new_local}@{new_dom}"

    def person(self, name: str) -> str:
        parts = _NAME_SPLIT.split(name)
        tokens = [(i, p) for i, p in enumerate(parts) if p and p[0].isalpha() and p.lower() not in _TITLES]
        out = list(parts)
        comma = any("," in p for p in parts)
        if len(tokens) == 1:
            i, p = tokens[0]
            if self.v.maps["last"].get(p) is not None:
                out[i] = self._name_token(p, "last")
            elif self.v.maps["first"].get(p) is not None:
                out[i] = self._name_token(p, "first")
            else:
                out[i] = self._name_token(p, "last")
            return "".join(out)
        for k, (i, p) in enumerate(tokens):
            is_last = (k == 0) if comma else (k == len(tokens) - 1)
            out[i] = self._name_token(p, "last" if is_last else "first")
        return "".join(out)

    def _person(self, f: Finding, attempt: int = 0):
        kind = f.meta.get("kind")
        if kind in ("first", "last") and " " not in f.text:
            return self._name_token(f.text, kind)
        return self.person(f.text)

    def _org(self, f: Finding, attempt: int = 0):
        tokens = re.split(r"(\s+|&|,)", f.text)
        out = list(tokens)
        changed = False
        for i, tok in enumerate(tokens):
            core = tok.strip(".,()").lower()
            if not tok or not tok[0].isalpha():
                continue
            if core in wordlists.LEGAL_FORMS or core in ORG_GENERIC or len(core) <= 2:
                continue
            out[i] = self.word(tok)
            changed = True
        if not changed:
            for i, tok in enumerate(tokens):
                if tok and tok[0].isalpha():
                    out[i] = self.word(tok)
                    break
        return "".join(out)

    def _location(self, f: Finding, attempt: int = 0):
        return re.sub(r"[A-Za-zÀ-ɏ]{3,}", lambda m: self.word(m.group(0)), f.text)

    # ------------------------------------------------------------ network
    def _ip_allowed(self, addr) -> bool:
        return any(addr.version == n.version and addr in n for n in self._allow_nets)

    def _ip(self, f: Finding, attempt: int = 0):
        text = f.text
        addr_s, _, prefix = text.partition("/")
        try:
            addr = ipaddress.ip_address(addr_s)
        except ValueError:
            return None
        if self._ip_allowed(addr):
            return None
        mapped = self.ip.map_v4(addr) if addr.version == 4 else self.ip.map_v6(addr)
        if mapped is None:
            return None
        if prefix:
            try:
                net = ipaddress.ip_network(text, strict=False)
            except ValueError:
                return None
            if net.network_address == addr:
                mnet = self.ip.map_network(net)
                if mnet is None:
                    return None
                self.v.add_network(mnet)
                out = f"{mnet.network_address}/{prefix}"
            else:
                self.v.add_network(ipaddress.ip_network(f"{mapped}/{prefix}", strict=False))
                out = f"{mapped}/{prefix}"
        else:
            host_prefix = 24 if addr.version == 4 else 64
            self.v.add_network(ipaddress.ip_network(f"{mapped}/{host_prefix}", strict=False))
            out = str(mapped)
        if addr.version == 6 and addr_s != addr_s.lower():
            out = out.upper()
        return out

    def _mac(self, f: Finding, attempt: int = 0):
        text = f.text
        hexd = re.sub(r"[^0-9A-Fa-f]", "", text)
        if len(hexd) != 12 or hexd.lower() in ("000000000000", "ffffffffffff"):
            return None
        rng = self._rng("mac", hexd.lower(), attempt)
        octets = [int(hexd[i:i + 2], 16) for i in range(0, 12, 2)]
        if self.s.mac_keep_oui:
            new = octets[:3] + [rng.randrange(256) for _ in range(3)]
        else:
            first = (rng.randrange(256) & 0xFC) | (octets[0] & 0x03)
            new = [first] + [rng.randrange(256) for _ in range(5)]
        newhex = "".join(f"{o:02x}" for o in new)
        if hexd.isupper() or (any(c.isalpha() for c in hexd) and hexd == hexd.upper()):
            newhex = newhex.upper()
        out, j = [], 0
        for c in text:
            if c in "0123456789abcdefABCDEF":
                out.append(newhex[j])
                j += 1
            else:
                out.append(c)
        return "".join(out)

    # ------------------------------------------------------------ numbers
    def _phone(self, f: Finding, attempt: int = 0):
        text = f.text
        digits = re.sub(r"\D", "", text)
        rng = self._rng("phone", digits, attempt)
        keep = 0
        if text.startswith("+"):
            keep = 1 + _cc_len(digits)
        elif text.startswith("00"):
            keep = 2 + _cc_len(digits[2:])
        elif text.startswith("0"):
            keep = 1
        # translate "keep" (count of leading digit/plus chars) into a char index
        idx, seen = 0, 0
        while idx < len(text) and seen < keep:
            if text[idx].isdigit() or text[idx] == "+":
                seen += 1
            idx += 1
        # keep a "(0)" trunk marker verbatim
        m = re.search(r"\(0\)", text)
        res = digits_like(text, rng, keep=idx)
        if m:
            res = res[:m.start()] + "(0)" + res[m.end():]
        return res

    def _iban(self, f: Finding, attempt: int = 0):
        text = f.text
        compact = text.replace(" ", "")
        cc, bban = compact[:2].upper(), compact[4:]
        rng = self._rng("iban", compact.upper(), attempt)
        new_bban = randomize_chars(bban, rng, hex_mode=False)
        new = cc + iban_check_digits(cc, new_bban.upper()) + new_bban
        out, j = [], 0
        for c in text:
            if c == " ":
                out.append(" ")
            else:
                out.append(new[j])
                j += 1
        return "".join(out)

    def _card(self, f: Finding, attempt: int = 0):
        text = f.text
        digits = re.sub(r"\D", "", text)
        rng = self._rng("card", digits, attempt)
        body = digits[0] + "".join(rng.choice("0123456789") for _ in range(len(digits) - 2))
        new = body + luhn_complete(body)
        out, j = [], 0
        for c in text:
            if c.isdigit():
                out.append(new[j])
                j += 1
            else:
                out.append(c)
        return "".join(out)

    def _sid(self, f: Finding, attempt: int = 0):
        m = re.match(r"^S-1-5-21-(\d+)-(\d+)-(\d+)(-\d+)?$", f.text)
        if not m:
            return None
        rng = self._rng("sid", m.group(1), m.group(2), m.group(3), attempt)
        parts = [str(rng.randrange(100_000_000, 4_294_967_295)) for _ in range(3)]
        return "S-1-5-21-" + "-".join(parts) + (m.group(4) or "")

    # ------------------------------------------------------------ secrets
    def _secret(self, f: Finding, attempt: int = 0):
        rng = self._rng("secret", f.text, attempt)
        return randomize_chars(f.text, rng, keep_prefix=int(f.meta.get("keep_prefix", 0)))

    # ------------------------------------------------------------ custom
    def _custom(self, f: Finding, attempt: int = 0):
        rep = f.meta.get("replacement")
        if rep:
            return rep
        as_type = (f.meta.get("as_type") or "").upper()
        if as_type == T.PERSON.value:
            return self.person(f.text)
        if as_type == T.ORG.value:
            return self._org(f)
        if as_type == T.DOMAIN.value:
            return self.domain(f.text)
        if as_type == T.USERNAME.value:
            return self.user_local(f.text)
        if as_type in (T.SECRET.value, T.PRIVATE_KEY.value):
            return self._secret(f, attempt)
        if as_type == T.IPV4.value or as_type == T.IPV6.value:
            return self._ip(f)
        return re.sub(r"[A-Za-zÀ-ɏ]{2,}", lambda m: self.word(m.group(0)), f.text) \
            if re.search(r"[A-Za-z]", f.text) else digits_like(f.text, self._rng("custom", f.text))


class PlaceholderFactory:
    """Irreversible ``<TYPE_n>`` placeholders; stores only keyed hashes."""

    def __init__(self, vault: Vault, template: str = "<{type}_{n}>"):
        self.v = vault
        self.template = template

    def surrogate(self, f: Finding) -> str:
        h = keyed_hash(self.v.key, f.type, f.text)
        s = self.v.anon_map.get(h)
        if s is None:
            n = self.v.anon_counters.get(f.type, 0) + 1
            self.v.anon_counters[f.type] = n
            s = self.template.format(type=f.type, n=n)
            self.v.anon_map[h] = s
        return s
