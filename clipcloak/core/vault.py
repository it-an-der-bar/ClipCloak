"""Mapping store (original <-> surrogate) for one session or project."""

from __future__ import annotations

import base64
import ipaddress
import os
import threading
import time
from dataclasses import dataclass, field


@dataclass
class Entry:
    type: str
    original: str
    surrogate: str
    count: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {"type": self.type, "original": self.original, "surrogate": self.surrogate,
                "count": self.count, "first_seen": self.first_seen, "last_seen": self.last_seen}

    @classmethod
    def from_dict(cls, d: dict) -> "Entry":
        return cls(d["type"], d["original"], d["surrogate"], d.get("count", 0),
                   d.get("first_seen", time.time()), d.get("last_seen", time.time()))


class TokenMap:
    """Bidirectional case-insensitive token map (lowercase keys)."""

    def __init__(self):
        self.fwd: dict[str, str] = {}
        self.rev: dict[str, str] = {}

    def get(self, original: str) -> str | None:
        return self.fwd.get(original.lower())

    def original_of(self, surrogate: str) -> str | None:
        return self.rev.get(surrogate.lower())

    def taken(self, surrogate: str) -> bool:
        return surrogate.lower() in self.rev

    def put(self, original: str, surrogate: str) -> None:
        o, s = original.lower(), surrogate.lower()
        old = self.fwd.get(o)
        if old is not None:
            self.rev.pop(old, None)
        self.fwd[o] = s
        self.rev[s] = o

    def remove(self, original: str) -> None:
        s = self.fwd.pop(original.lower(), None)
        if s is not None:
            self.rev.pop(s, None)

    def to_dict(self) -> dict:
        return dict(self.fwd)

    @classmethod
    def from_dict(cls, d: dict) -> "TokenMap":
        m = cls()
        for k, v in (d or {}).items():
            m.put(k, v)
        return m


TOKEN_MAPS = ("words", "first", "last", "users")


class Vault:
    """Holds the secret key and all mappings for one session/project."""

    def __init__(self, name: str = "session", key: bytes | None = None, reversible: bool = True):
        self.name = name
        self.key = key or os.urandom(32)
        self.reversible = reversible
        self.created = time.time()
        self.entries: dict[tuple[str, str], Entry] = {}
        self.by_surrogate: dict[str, tuple[str, str]] = {}
        self.maps: dict[str, TokenMap] = {n: TokenMap() for n in TOKEN_MAPS}
        self.anon_counters: dict[str, int] = {}
        self.anon_map: dict[str, str] = {}
        self.networks: set[str] = set()   # surrogate networks for IP revert
        self.lock = threading.RLock()
        self.revision = 0

    # ------------------------------------------------------------ entries
    def lookup(self, typ: str, original: str) -> str | None:
        e = self.entries.get((typ, original))
        return e.surrogate if e else None

    def surrogate_taken(self, surrogate: str, typ: str, original: str) -> bool:
        k = self.by_surrogate.get(surrogate)
        return k is not None and k != (typ, original)

    def is_surrogate(self, text: str) -> bool:
        return text in self.by_surrogate

    def record(self, typ: str, original: str, surrogate: str, count: bool = True) -> None:
        with self.lock:
            k = (typ, original)
            e = self.entries.get(k)
            if e is None:
                e = Entry(typ, original, surrogate)
                self.entries[k] = e
            elif e.surrogate != surrogate:
                self.by_surrogate.pop(e.surrogate, None)
                e.surrogate = surrogate
            if count:
                e.count += 1
                e.last_seen = time.time()
            self.by_surrogate[surrogate] = k
            self.revision += 1

    def remove(self, typ: str, original: str) -> None:
        with self.lock:
            e = self.entries.pop((typ, original), None)
            if e is not None:
                self.by_surrogate.pop(e.surrogate, None)
                self.revision += 1

    def add_network(self, net) -> None:
        with self.lock:
            self.networks.add(str(net))

    def in_known_network(self, addr) -> bool:
        for n in self.networks:
            try:
                net = ipaddress.ip_network(n)
            except ValueError:
                continue
            if net.version == addr.version and addr in net:
                return True
        return False

    def clear(self) -> None:
        with self.lock:
            self.entries.clear()
            self.by_surrogate.clear()
            self.maps = {n: TokenMap() for n in TOKEN_MAPS}
            self.anon_counters.clear()
            self.anon_map.clear()
            self.networks.clear()
            self.revision += 1

    # ------------------------------------------------------------ export
    def to_dict(self) -> dict:
        with self.lock:
            return {
                "name": self.name,
                "key": base64.b64encode(self.key).decode(),
                "created": self.created,
                "entries": [e.to_dict() for e in self.entries.values()],
                "maps": {n: m.to_dict() for n, m in self.maps.items()},
                "networks": sorted(self.networks),
            }

    @classmethod
    def from_dict(cls, d: dict) -> "Vault":
        v = cls(d.get("name", "project"), base64.b64decode(d["key"]))
        v.created = d.get("created", time.time())
        for ed in d.get("entries", []):
            e = Entry.from_dict(ed)
            v.entries[(e.type, e.original)] = e
            v.by_surrogate[e.surrogate] = (e.type, e.original)
        for n in TOKEN_MAPS:
            v.maps[n] = TokenMap.from_dict(d.get("maps", {}).get(n, {}))
        v.networks = set(d.get("networks", []))
        return v

    def rows(self) -> list[Entry]:
        """All mappings including token maps, for the overview table."""
        with self.lock:
            rows = list(self.entries.values())
            known = {e.original.lower() for e in rows}
            label = {"words": "WORD", "first": "FIRST_NAME", "last": "LAST_NAME", "users": "USER_TOKEN"}
            for n, m in self.maps.items():
                for o, s in m.fwd.items():
                    if o in known:
                        continue   # already listed as a full entry
                    rows.append(Entry(label[n], o, s, 0, self.created, self.created))
            return rows
