"""Windows: who may change a file? (for the machine-wide policy files)

``admin_only_writable(path)`` is True when the owner and every principal that may write,
delete or re-permission ``path`` are SYSTEM, TrustedInstaller, the Administrators group or a
member of it. A file a normal user dropped into %ProgramData% fails this test (that user
owns it or has write access), a file copied there by an administrator passes – also when
the administrator's own account is the owner ("Default owner: object creator").
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes

SYSTEM = "S-1-5-18"
ADMINISTRATORS = "S-1-5-32-544"
TRUSTED_INSTALLER = "S-1-5-80-956008885-3228873120-2519826346-3478906154-2573924823"
OWNER_RIGHTS = "S-1-3-4"
TRUSTED = {SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER}

_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION, _DACL_SECURITY_INFORMATION = 0x1, 0x4
_ACCESS_ALLOWED_ACE_TYPE = 0
_INHERIT_ONLY_ACE = 0x8
# write data / append / delete child / delete / change permissions / take ownership / generic
_WRITE_BITS = 0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000
_SID_TYPE_USER = 1
_LG_INCLUDE_INDIRECT = 1
_MAX_PREFERRED_LENGTH = 0xFFFFFFFF


class _AclSizeInformation(ctypes.Structure):
    _fields_ = [("AceCount", wintypes.DWORD), ("AclBytesInUse", wintypes.DWORD),
                ("AclBytesFree", wintypes.DWORD)]


class _AceHeader(ctypes.Structure):
    _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", wintypes.WORD)]


class _AccessAllowedAce(ctypes.Structure):
    _fields_ = [("Header", _AceHeader), ("Mask", wintypes.DWORD), ("SidStart", wintypes.DWORD)]


def _api():
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    netapi = ctypes.WinDLL("netapi32", use_last_error=True)
    advapi.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int]
    advapi.GetAclInformation.restype = wintypes.BOOL
    advapi.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetAce.restype = wintypes.BOOL
    advapi.LookupAccountSidW.argtypes = [
        wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(ctypes.c_int)]
    advapi.LookupAccountSidW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    netapi.NetUserGetLocalGroups.argtypes = [
        wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
    netapi.NetUserGetLocalGroups.restype = wintypes.DWORD
    netapi.NetApiBufferFree.argtypes = [ctypes.c_void_p]
    netapi.NetApiBufferFree.restype = wintypes.DWORD
    return advapi, kernel, netapi


def _sid_str(advapi, kernel, psid) -> str:
    s = wintypes.LPWSTR()
    if not advapi.ConvertSidToStringSidW(psid, ctypes.byref(s)):
        raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW failed")
    try:
        return s.value or ""
    finally:
        kernel.LocalFree(ctypes.cast(s, ctypes.c_void_p))


def _account(advapi, psid) -> tuple[str, str, int]:
    name = ctypes.create_unicode_buffer(256)
    dom = ctypes.create_unicode_buffer(256)
    n, d, use = wintypes.DWORD(256), wintypes.DWORD(256), ctypes.c_int()
    if not advapi.LookupAccountSidW(None, psid, name, ctypes.byref(n), dom, ctypes.byref(d), ctypes.byref(use)):
        raise OSError(ctypes.get_last_error(), "LookupAccountSidW failed")
    return name.value, dom.value, use.value


def security_info(path) -> tuple[str, list[tuple[int, int, int, str]] | None]:
    """(owner SID, [(ace type, ace flags, access mask, SID)]) – the list is None for a NULL DACL."""
    advapi, kernel, _ = _api()
    owner, dacl, sd = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    rc = advapi.GetNamedSecurityInfoW(str(path), _SE_FILE_OBJECT,
                                      _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
                                      ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(sd))
    if rc != 0:
        raise OSError(rc, "GetNamedSecurityInfoW failed")
    try:
        owner_sid = _sid_str(advapi, kernel, owner)
        if not dacl.value:
            return owner_sid, None
        info = _AclSizeInformation()
        if not advapi.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2):   # AclSizeInformation
            raise OSError(ctypes.get_last_error(), "GetAclInformation failed")
        aces = []
        for i in range(info.AceCount):
            pace = ctypes.c_void_p()
            if not advapi.GetAce(dacl, i, ctypes.byref(pace)):
                raise OSError(ctypes.get_last_error(), "GetAce failed")
            ace = ctypes.cast(pace, ctypes.POINTER(_AccessAllowedAce)).contents
            sid = "" if ace.Header.AceType > 1 else _sid_str(
                advapi, kernel, ctypes.c_void_p(pace.value + _AccessAllowedAce.SidStart.offset))
            aces.append((ace.Header.AceType, ace.Header.AceFlags, ace.Mask, sid))
        return owner_sid, aces
    finally:
        kernel.LocalFree(sd)


_admin_cache: dict[str, bool] = {}


def is_admin_sid(sid: str) -> bool:
    """SYSTEM / TrustedInstaller / Administrators, or a user account in the Administrators group."""
    if sid in TRUSTED:
        return True
    if sid in _admin_cache:
        return _admin_cache[sid]
    advapi, kernel, netapi = _api()
    result = False
    psid, padm = ctypes.c_void_p(), ctypes.c_void_p()
    try:
        if advapi.ConvertStringSidToSidW(sid, ctypes.byref(psid)) and \
                advapi.ConvertStringSidToSidW(ADMINISTRATORS, ctypes.byref(padm)):
            name, dom, use = _account(advapi, psid)
            admins = _account(advapi, padm)[0]          # localised group name ("Administratoren" …)
            if use == _SID_TYPE_USER:
                buf, read, total = ctypes.c_void_p(), wintypes.DWORD(), wintypes.DWORD()
                user = f"{dom}\\{name}" if dom else name
                rc = netapi.NetUserGetLocalGroups(None, user, 0, _LG_INCLUDE_INDIRECT, ctypes.byref(buf),
                                                  _MAX_PREFERRED_LENGTH, ctypes.byref(read), ctypes.byref(total))
                if rc == 0 and buf.value:
                    try:
                        groups = ctypes.cast(buf, ctypes.POINTER(wintypes.LPWSTR * read.value)).contents
                        result = any((g or "").lower() == admins.lower() for g in groups)
                    finally:
                        netapi.NetApiBufferFree(buf)
    except OSError:
        result = False
    finally:
        for p in (psid, padm):
            if p.value:
                kernel.LocalFree(p)
    _admin_cache[sid] = result
    return result


def admin_only_writable(path) -> bool:
    owner, aces = security_info(path)
    if not is_admin_sid(owner) or aces is None:
        return False                          # a user owns it (can re-permission it) / NULL DACL: everyone
    for typ, flags, mask, sid in aces:
        if typ != _ACCESS_ALLOWED_ACE_TYPE or flags & _INHERIT_ONLY_ACE or not mask & _WRITE_BITS:
            continue
        if sid == OWNER_RIGHTS:
            continue                          # the owner, checked above
        if not is_admin_sid(sid):
            return False
    return True
