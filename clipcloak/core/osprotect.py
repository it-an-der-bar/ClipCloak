"""Encryption bound to the logged-in account, without a passphrase.

Windows: DPAPI (CryptProtectData, user scope). The key can only be unwrapped by
the same Windows account – also after a password change or on another machine
with a roaming profile – but not by other users, backups or a copied disk.

Linux: a random master key in the desktop keyring (Secret Service – GNOME Keyring,
KWallet 5.97+, KeePassXC …), unlocked with the login. Project keys are wrapped with it
(AES-256-GCM). Only the same user in an unlocked session can read them.

Where neither exists (no keyring daemon, headless, macOS) :func:`protector` returns
``None``; projects without a passphrase are then stored as plain JSON with mode 0600 and
the UI says "not encrypted".
"""

from __future__ import annotations

import sys


class Protector:
    """Wraps/unwraps small secrets (data keys) for the current account."""

    name = ""

    def protect(self, data: bytes) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError

    def unprotect(self, data: bytes) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError


class DpapiProtector(Protector):
    name = "dpapi"
    _ENTROPY = b"clipcloak-project-key"
    _UI_FORBIDDEN = 0x1

    def __init__(self):
        import ctypes
        from ctypes import wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

        self._ct = ctypes
        self._Blob = DATA_BLOB
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        pblob = ctypes.POINTER(DATA_BLOB)
        self._protect = crypt32.CryptProtectData
        self._protect.argtypes = [pblob, wintypes.LPCWSTR, pblob, ctypes.c_void_p, ctypes.c_void_p,
                                  wintypes.DWORD, pblob]
        self._protect.restype = wintypes.BOOL
        self._unprotect = crypt32.CryptUnprotectData
        self._unprotect.argtypes = [pblob, ctypes.c_void_p, pblob, ctypes.c_void_p, ctypes.c_void_p,
                                    wintypes.DWORD, pblob]
        self._unprotect.restype = wintypes.BOOL
        self._free = kernel32.LocalFree
        self._free.argtypes = [ctypes.c_void_p]
        self._free.restype = ctypes.c_void_p

    def _blob(self, data: bytes):
        ct = self._ct
        buf = ct.create_string_buffer(data, len(data))
        return self._Blob(len(data), ct.cast(buf, ct.POINTER(ct.c_char))), buf

    def _call(self, fn, data: bytes, *head) -> bytes:
        ct = self._ct
        inp, _keep1 = self._blob(data)
        ent, _keep2 = self._blob(self._ENTROPY)
        out = self._Blob()
        if not fn(ct.byref(inp), *head, ct.byref(ent), None, None, self._UI_FORBIDDEN, ct.byref(out)):
            err = ct.get_last_error()
            raise OSError(err, f"DPAPI error {err}")
        try:
            return ct.string_at(out.pbData, out.cbData)
        finally:
            self._free(ct.cast(out.pbData, ct.c_void_p))

    def protect(self, data: bytes) -> bytes:
        return self._call(self._protect, data, "clipcloak")

    def unprotect(self, data: bytes) -> bytes:
        return self._call(self._unprotect, data, None)


class SecretServiceProtector(Protector):
    """Wraps with a 256-bit master key kept in the Secret Service (the user's keyring)."""

    name = "secret-service"
    ATTRS = {"application": "clipcloak", "purpose": "project-key"}

    def __init__(self):
        import secretstorage                      # jeepney-based, no compiled parts
        try:
            conn = secretstorage.dbus_init()
            coll = secretstorage.get_default_collection(conn)
            if coll.is_locked():
                coll.unlock()                     # the keyring's own prompt; normally unlocked at login
                if coll.is_locked():
                    raise OSError("keyring locked")
            items = list(coll.search_items(self.ATTRS))
            if items:
                key = items[0].get_secret()
            else:
                import os
                key = os.urandom(32)
                coll.create_item("ClipCloak project key", self.ATTRS, key, replace=True)
        except secretstorage.exceptions.SecretStorageException as exc:
            raise OSError(str(exc)) from exc
        if len(key) != 32:
            raise OSError("unexpected key in the keyring")
        self._key = bytes(key)

    def protect(self, data: bytes) -> bytes:
        import os
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = os.urandom(12)
        return nonce + AESGCM(self._key).encrypt(nonce, data, b"clipcloak-project-key")

    def unprotect(self, data: bytes) -> bytes:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        try:
            return AESGCM(self._key).decrypt(data[:12], data[12:], b"clipcloak-project-key")
        except InvalidTag as exc:
            raise OSError("the keyring holds a different key") from exc


_cached: Protector | None | bool = False
_failed_at = 0.0
RETRY_S = 30.0          # the keyring may come up after the program (autostart at login)


def protector() -> Protector | None:
    """The account-bound protector of this platform, or ``None`` (retried every 30 s on Linux)."""
    global _cached, _failed_at
    import time
    if _cached is None and sys.platform.startswith("linux") and time.monotonic() - _failed_at > RETRY_S:
        _cached = False
    if _cached is False:
        _cached = None
        if sys.platform == "win32":
            try:
                _cached = DpapiProtector()
            except (OSError, AttributeError):
                _cached = None
        elif sys.platform.startswith("linux"):
            try:
                _cached = SecretServiceProtector()
            except Exception:                     # noqa: BLE001 - no D-Bus, no keyring, module missing
                _cached = None
                _failed_at = time.monotonic()
    return _cached
