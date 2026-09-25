"""Encryption bound to the logged-in account, without a passphrase.

Windows: DPAPI (CryptProtectData, user scope). The key can only be unwrapped by
the same Windows account – also after a password change or on another machine
with a roaming profile – but not by other users, backups or a copied disk.

Other platforms return ``None`` from :func:`protector`; projects without a
passphrase are then stored as plain JSON with mode 0600.
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


_cached: Protector | None | bool = False


def protector() -> Protector | None:
    """The account-bound protector of this platform, or ``None``."""
    global _cached
    if _cached is False:
        _cached = None
        if sys.platform == "win32":
            try:
                _cached = DpapiProtector()
            except (OSError, AttributeError):
                _cached = None
    return _cached
