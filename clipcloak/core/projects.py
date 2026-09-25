"""Persistent projects: vault + history + project terms, optionally encrypted."""

from __future__ import annotations

import base64
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from .vault import Vault

FORMAT = "clipboard-vault-project"
VERSION = 1
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1


class ProjectError(Exception):
    pass


class WrongPassphrase(ProjectError):
    pass


def slugify(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip()).strip("._")
    return s[:80] or "project"


@dataclass
class Project:
    name: str
    vault: Vault
    history: list = field(default_factory=list)
    terms: list = field(default_factory=list)
    known_domains: list = field(default_factory=list)
    store_history: bool = True
    created: float = field(default_factory=time.time)
    passphrase: str | None = None

    @property
    def encrypted(self) -> bool:
        return bool(self.passphrase)

    def payload(self) -> dict:
        return {"name": self.name, "created": self.created, "vault": self.vault.to_dict(),
                "history": self.history if self.store_history else [],
                "terms": self.terms, "known_domains": self.known_domains,
                "store_history": self.store_history}

    @classmethod
    def from_payload(cls, d: dict, passphrase: str | None) -> "Project":
        v = Vault.from_dict(d["vault"])
        v.name = d.get("name", v.name)
        return cls(d.get("name", "project"), v, d.get("history", []), d.get("terms", []),
                   d.get("known_domains", []), d.get("store_history", True),
                   d.get("created", time.time()), passphrase)


def _derive(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))


def encrypt_payload(payload: dict, passphrase: str) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce = os.urandom(16), os.urandom(12)
    key = _derive(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    ct = AESGCM(key).encrypt(nonce, json.dumps(payload).encode("utf-8"), FORMAT.encode())
    b64 = lambda b: base64.b64encode(b).decode()
    return {"format": FORMAT, "version": VERSION, "encrypted": True,
            "kdf": {"name": "scrypt", "salt": b64(salt), "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
            "cipher": "AES-256-GCM", "nonce": b64(nonce), "ciphertext": b64(ct)}


def decrypt_payload(doc: dict, passphrase: str) -> dict:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    k = doc["kdf"]
    key = _derive(passphrase, base64.b64decode(k["salt"]), int(k["n"]), int(k["r"]), int(k["p"]))
    try:
        pt = AESGCM(key).decrypt(base64.b64decode(doc["nonce"]), base64.b64decode(doc["ciphertext"]),
                                 FORMAT.encode())
    except InvalidTag as exc:
        raise WrongPassphrase("wrong passphrase") from exc
    return json.loads(pt.decode("utf-8"))


@dataclass
class ProjectInfo:
    name: str
    path: Path
    encrypted: bool
    modified: float


class ProjectStore:
    def __init__(self, directory: Path):
        self.dir = Path(directory)

    def path_for(self, name: str) -> Path:
        return self.dir / (slugify(name) + ".json")

    def list(self) -> list[ProjectInfo]:
        out = []
        if not self.dir.exists():
            return out
        for p in sorted(self.dir.glob("*.json")):
            try:
                doc = json.loads(p.read_text("utf-8"))
            except (OSError, ValueError):
                continue
            if doc.get("format") != FORMAT:
                continue
            name = doc.get("name") or (doc.get("data") or {}).get("name") or p.stem
            out.append(ProjectInfo(name, p, bool(doc.get("encrypted")), p.stat().st_mtime))
        return out

    def exists(self, name: str) -> bool:
        return self.path_for(name).exists()

    def create(self, name: str, passphrase: str | None = None) -> Project:
        if self.exists(name):
            raise ProjectError(f"project '{name}' already exists")
        prj = Project(name, Vault(name), passphrase=passphrase or None)
        self.save(prj)
        return prj

    def is_encrypted(self, name: str) -> bool:
        doc = json.loads(self.path_for(name).read_text("utf-8"))
        return bool(doc.get("encrypted"))

    def load(self, name: str, passphrase: str | None = None) -> Project:
        p = self.path_for(name)
        if not p.exists():
            raise ProjectError(f"project '{name}' not found")
        doc = json.loads(p.read_text("utf-8"))
        if doc.get("format") != FORMAT:
            raise ProjectError("not a project file")
        if doc.get("encrypted"):
            if not passphrase:
                raise WrongPassphrase("passphrase required")
            payload = decrypt_payload(doc, passphrase)
        else:
            payload = doc["data"]
        return Project.from_payload(payload, passphrase if doc.get("encrypted") else None)

    def save(self, prj: Project) -> Path:
        self.dir.mkdir(parents=True, exist_ok=True)
        payload = prj.payload()
        if prj.passphrase:
            doc = encrypt_payload(payload, prj.passphrase)
            doc["name"] = prj.name
        else:
            doc = {"format": FORMAT, "version": VERSION, "encrypted": False, "name": prj.name, "data": payload}
        p = self.path_for(prj.name)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, ensure_ascii=False, indent=1), "utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, p)
        return p

    def delete(self, name: str) -> None:
        p = self.path_for(name)
        if p.exists():
            p.unlink()
