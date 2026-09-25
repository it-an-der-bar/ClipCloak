"""Global hotkeys: Win32 RegisterHotKey and X11 XGrabKey (ctypes, no extra deps).

Wayland has no API for applications to grab global keys; there the desktop's own
shortcut settings run ``<app> --action <name>`` (see README).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import select
import threading

log = logging.getLogger(__name__)

MODIFIER_NAMES = {"ctrl": "ctrl", "control": "ctrl", "strg": "ctrl", "alt": "alt",
                  "shift": "shift", "umschalt": "shift", "meta": "meta", "win": "meta",
                  "super": "meta", "cmd": "meta"}
NAMED_KEYS = ["Space", "Insert", "Delete", "Home", "End", "PageUp", "PageDown", "Left",
              "Up", "Right", "Down", "Pause", "Print", "Escape", "Tab", "Return", "Backspace"]


class HotkeyError(ValueError):
    pass


def parse_sequence(seq: str) -> tuple[frozenset, str]:
    """"Ctrl+Alt+P" -> (frozenset({'ctrl','alt'}), 'P')"""
    if not seq or not seq.strip():
        raise HotkeyError("empty")
    parts = [p.strip() for p in seq.replace(" ", "").split("+")]
    if seq.strip().endswith("++"):
        parts = parts[:-2] + ["+"]
    mods, key = set(), None
    for p in parts:
        if not p:
            continue
        low = p.lower()
        if low in MODIFIER_NAMES:
            mods.add(MODIFIER_NAMES[low])
        elif key is None:
            key = p
        else:
            raise HotkeyError(f"more than one key in '{seq}'")
    if key is None:
        raise HotkeyError(f"no key in '{seq}'")
    k = key.upper() if len(key) == 1 else key[:1].upper() + key[1:]
    if len(k) == 1 and not (k.isascii() and k.isalnum()):
        raise HotkeyError(f"unsupported key '{key}'")
    if len(k) > 1:
        if k.upper().startswith("F") and k[1:].isdigit() and 1 <= int(k[1:]) <= 24:
            k = "F" + k[1:]
        else:
            match = [n for n in NAMED_KEYS if n.lower() == k.lower()]
            aliases = {"esc": "Escape", "enter": "Return", "del": "Delete", "ins": "Insert",
                       "pgup": "PageUp", "pgdown": "PageDown", "pgdn": "PageDown"}
            if match:
                k = match[0]
            elif k.lower() in aliases:
                k = aliases[k.lower()]
            else:
                raise HotkeyError(f"unsupported key '{key}'")
    if not mods and not k.startswith("F"):
        raise HotkeyError("a modifier (Ctrl/Alt/Shift/Meta) is required")
    return frozenset(mods), k


# --------------------------------------------------------------------- Windows
WIN_VK = {"Space": 0x20, "Insert": 0x2D, "Delete": 0x2E, "Home": 0x24, "End": 0x23,
          "PageUp": 0x21, "PageDown": 0x22, "Left": 0x25, "Up": 0x26, "Right": 0x27,
          "Down": 0x28, "Pause": 0x13, "Print": 0x2C, "Escape": 0x1B, "Tab": 0x09,
          "Return": 0x0D, "Backspace": 0x08}
WIN_MOD = {"alt": 0x1, "ctrl": 0x2, "shift": 0x4, "meta": 0x8}
MOD_NOREPEAT = 0x4000
WM_HOTKEY = 0x0312
WM_QUIT = 0x0012


def win_vk(key: str) -> int:
    if len(key) == 1:
        return ord(key.upper())
    if key.startswith("F") and key[1:].isdigit():
        return 0x70 + int(key[1:]) - 1
    return WIN_VK[key]


class _WinHotkeyThread(threading.Thread):
    def __init__(self, bindings: dict, callback):
        super().__init__(daemon=True, name="hotkeys-win32")
        self.bindings = bindings
        self.callback = callback
        self.errors: dict[str, str] = {}
        self.ready = threading.Event()
        self.thread_id = 0

    def run(self):  # pragma: no cover - Windows only
        from ctypes import wintypes
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        user32.RegisterHotKey.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.UINT, wintypes.UINT]
        user32.RegisterHotKey.restype = wintypes.BOOL
        user32.UnregisterHotKey.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
        user32.GetMessageW.restype = wintypes.BOOL
        user32.PeekMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT,
                                        wintypes.UINT, wintypes.UINT]
        self.thread_id = kernel32.GetCurrentThreadId()
        msg = wintypes.MSG()
        user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 0)   # create the message queue
        ids: dict[int, str] = {}
        for i, (action, (mods, key)) in enumerate(self.bindings.items(), start=1):
            flags = MOD_NOREPEAT
            for m in mods:
                flags |= WIN_MOD[m]
            if user32.RegisterHotKey(None, i, flags, win_vk(key)):
                ids[i] = action
            else:
                self.errors[action] = f"RegisterHotKey failed ({ctypes.get_last_error()}), already in use?"
        self.ready.set()
        while True:
            r = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if r == 0 or r == -1:
                break
            if msg.message == WM_HOTKEY and msg.wParam in ids:
                try:
                    self.callback(ids[msg.wParam])
                except Exception:
                    log.exception("hotkey callback failed")
        for i in ids:
            user32.UnregisterHotKey(None, i)

    def stop(self):  # pragma: no cover - Windows only
        if self.thread_id:
            ctypes.windll.user32.PostThreadMessageW(self.thread_id, WM_QUIT, 0, 0)
        self.join(timeout=2)


# --------------------------------------------------------------------- X11
X_MOD = {"shift": 1, "ctrl": 4, "alt": 8, "meta": 64}
X_IGNORED = [0, 2, 16, 18]          # none, CapsLock, NumLock, both
X_KEYSYM = {"Space": "space", "Insert": "Insert", "Delete": "Delete", "Home": "Home", "End": "End",
            "PageUp": "Prior", "PageDown": "Next", "Left": "Left", "Up": "Up", "Right": "Right",
            "Down": "Down", "Pause": "Pause", "Print": "Print", "Escape": "Escape", "Tab": "Tab",
            "Return": "Return", "Backspace": "BackSpace"}
KEY_PRESS = 2
BAD_ACCESS = 10


class XKeyEvent(ctypes.Structure):
    _fields_ = [("type", ctypes.c_int), ("serial", ctypes.c_ulong), ("send_event", ctypes.c_int),
                ("display", ctypes.c_void_p), ("window", ctypes.c_ulong), ("root", ctypes.c_ulong),
                ("subwindow", ctypes.c_ulong), ("time", ctypes.c_ulong), ("x", ctypes.c_int),
                ("y", ctypes.c_int), ("x_root", ctypes.c_int), ("y_root", ctypes.c_int),
                ("state", ctypes.c_uint), ("keycode", ctypes.c_uint), ("same_screen", ctypes.c_int)]


class XEvent(ctypes.Union):
    _fields_ = [("type", ctypes.c_int), ("xkey", XKeyEvent), ("pad", ctypes.c_long * 24)]


class XErrorEvent(ctypes.Structure):
    _fields_ = [("type", ctypes.c_int), ("display", ctypes.c_void_p), ("resourceid", ctypes.c_ulong),
                ("serial", ctypes.c_ulong), ("error_code", ctypes.c_ubyte),
                ("request_code", ctypes.c_ubyte), ("minor_code", ctypes.c_ubyte)]


_XERR_HANDLER = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(XErrorEvent))


def _load_xlib():
    name = ctypes.util.find_library("X11") or "libX11.so.6"
    x = ctypes.cdll.LoadLibrary(name)
    x.XOpenDisplay.argtypes = [ctypes.c_char_p]
    x.XOpenDisplay.restype = ctypes.c_void_p
    x.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
    x.XDefaultRootWindow.restype = ctypes.c_ulong
    x.XStringToKeysym.argtypes = [ctypes.c_char_p]
    x.XStringToKeysym.restype = ctypes.c_ulong
    x.XKeysymToKeycode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    x.XKeysymToKeycode.restype = ctypes.c_ubyte
    x.XGrabKey.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint, ctypes.c_ulong,
                           ctypes.c_int, ctypes.c_int, ctypes.c_int]
    x.XUngrabKey.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint, ctypes.c_ulong]
    x.XSync.argtypes = [ctypes.c_void_p, ctypes.c_int]
    x.XPending.argtypes = [ctypes.c_void_p]
    x.XNextEvent.argtypes = [ctypes.c_void_p, ctypes.POINTER(XEvent)]
    x.XConnectionNumber.argtypes = [ctypes.c_void_p]
    x.XCloseDisplay.argtypes = [ctypes.c_void_p]
    x.XSetErrorHandler.argtypes = [_XERR_HANDLER]
    x.XSetErrorHandler.restype = ctypes.c_void_p
    x.XInitThreads.restype = ctypes.c_int
    return x


class _X11HotkeyThread(threading.Thread):
    def __init__(self, bindings: dict, callback):
        super().__init__(daemon=True, name="hotkeys-x11")
        self.bindings = bindings
        self.callback = callback
        self.errors: dict[str, str] = {}
        self.ready = threading.Event()
        self._stopping = False
        self._wake_r, self._wake_w = os.pipe()
        self._err = 0

    def run(self):
        try:
            x = _load_xlib()
        except OSError as exc:
            self.errors = {a: f"libX11 not available: {exc}" for a in self.bindings}
            self.ready.set()
            return
        dpy = x.XOpenDisplay(None)
        if not dpy:
            self.errors = {a: "cannot open X display" for a in self.bindings}
            self.ready.set()
            return
        root = x.XDefaultRootWindow(dpy)

        def on_error(_d, ev):
            self._err = ev.contents.error_code
            return 0

        handler = _XERR_HANDLER(on_error)
        keymap: dict[tuple[int, int], str] = {}
        grabbed: list[tuple[int, int]] = []
        for action, (mods, key) in self.bindings.items():
            ks_name = key.lower() if len(key) == 1 else X_KEYSYM.get(key, key)
            keysym = x.XStringToKeysym(ks_name.encode())
            code = x.XKeysymToKeycode(dpy, keysym) if keysym else 0
            if not code:
                self.errors[action] = f"no keycode for {key}"
                continue
            modmask = 0
            for m in mods:
                modmask |= X_MOD[m]
            old = x.XSetErrorHandler(handler)
            self._err = 0
            for extra in X_IGNORED:
                x.XGrabKey(dpy, code, modmask | extra, root, 0, 1, 1)
                grabbed.append((code, modmask | extra))
            x.XSync(dpy, 0)
            x.XSetErrorHandler(ctypes.cast(old, _XERR_HANDLER) if old else _XERR_HANDLER())
            if self._err == BAD_ACCESS:
                self.errors[action] = "key combination already grabbed by another program"
                for extra in X_IGNORED:
                    x.XUngrabKey(dpy, code, modmask | extra, root)
                continue
            keymap[(code, modmask)] = action
        x.XSync(dpy, 0)
        self.ready.set()
        fd = x.XConnectionNumber(dpy)
        ev = XEvent()
        relevant = 1 | 4 | 8 | 64
        try:
            while not self._stopping:
                while x.XPending(dpy):
                    x.XNextEvent(dpy, ctypes.byref(ev))
                    if ev.type == KEY_PRESS:
                        act = keymap.get((ev.xkey.keycode, ev.xkey.state & relevant))
                        if act:
                            try:
                                self.callback(act)
                            except Exception:
                                log.exception("hotkey callback failed")
                if self._stopping:
                    break
                select.select([fd, self._wake_r], [], [], 1.0)
        finally:
            for code, mask in grabbed:
                x.XUngrabKey(dpy, code, mask, root)
            x.XSync(dpy, 0)
            x.XCloseDisplay(dpy)
            os.close(self._wake_r)
            os.close(self._wake_w)

    def stop(self):
        self._stopping = True
        try:
            os.write(self._wake_w, b"x")
        except OSError:
            pass
        self.join(timeout=3)


class HotkeyManager:
    """Registers a set of ``action -> "Ctrl+Alt+P"`` bindings."""

    def __init__(self, callback, backend: str):
        self.callback = callback
        self.backend = backend          # windows | x11 | none
        self._thread = None
        self.errors: dict[str, str] = {}

    @staticmethod
    def backend_for(display: str) -> str:
        if display == "windows":
            return "windows"
        if display == "x11":
            return "x11"
        return "none"

    def register(self, bindings: dict[str, str]) -> dict[str, str]:
        self.unregister()
        parsed, errors = {}, {}
        for action, seq in bindings.items():
            if not seq:
                continue
            try:
                parsed[action] = parse_sequence(seq)
            except HotkeyError as exc:
                errors[action] = str(exc)
        seen: dict = {}
        for action, combo in list(parsed.items()):
            if combo in seen:
                errors[action] = f"same shortcut as '{seen[combo]}'"
                del parsed[action]
            else:
                seen[combo] = action
        if parsed and self.backend in ("windows", "x11"):
            cls = _WinHotkeyThread if self.backend == "windows" else _X11HotkeyThread
            self._thread = cls(parsed, self.callback)
            self._thread.start()
            self._thread.ready.wait(5)
            errors.update(self._thread.errors)
        elif parsed:
            for a in parsed:
                errors[a] = "global shortcuts not supported in this session"
        self.errors = errors
        return errors

    def unregister(self) -> None:
        if self._thread is not None:
            self._thread.stop()
            self._thread = None

