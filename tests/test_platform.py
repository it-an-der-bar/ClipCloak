import ctypes
import ctypes.util
import os
import sys
import time
import unittest

from tests import helpers  # noqa: F401
from clipcloak.platform import session
from clipcloak.platform.hotkeys import HotkeyError, HotkeyManager, parse_sequence, win_vk


class ParseTest(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_sequence("Ctrl+Alt+P"), (frozenset({"ctrl", "alt"}), "P"))
        self.assertEqual(parse_sequence("Strg+Umschalt+u"), (frozenset({"ctrl", "shift"}), "U"))
        self.assertEqual(parse_sequence("Meta+F12"), (frozenset({"meta"}), "F12"))
        self.assertEqual(parse_sequence("F9"), (frozenset(), "F9"))
        self.assertEqual(parse_sequence("Ctrl+Alt+PgDown"), (frozenset({"ctrl", "alt"}), "PageDown"))
        for bad in ("", "P", "Ctrl+Alt", "Ctrl+A+B", "Ctrl+Ä", "Ctrl+F30"):
            with self.assertRaises(HotkeyError, msg=bad):
                parse_sequence(bad)

    def test_win_vk(self):
        self.assertEqual(win_vk("P"), 0x50)
        self.assertEqual(win_vk("F1"), 0x70)
        self.assertEqual(win_vk("F12"), 0x7B)
        self.assertEqual(win_vk("7"), 0x37)
        self.assertEqual(win_vk("Delete"), 0x2E)

    def test_duplicates_and_unsupported(self):
        m = HotkeyManager(lambda a: None, "none")
        errs = m.register({"a": "Ctrl+Alt+P", "b": "Ctrl+Alt+P", "c": "nonsense"})
        self.assertIn("b", errs)
        self.assertIn("c", errs)
        self.assertIn("a", errs)          # backend "none" cannot register anything

    def test_session_detection(self):
        self.assertIn(session.display_server("offscreen"), ("offscreen", "windows", "mac"))
        if sys.platform.startswith("linux"):
            self.assertEqual(session.display_server("wayland"), "wayland")


def _xtest():
    if not os.environ.get("DISPLAY") or not sys.platform.startswith("linux"):
        return None
    try:
        x = ctypes.cdll.LoadLibrary(ctypes.util.find_library("X11") or "libX11.so.6")
        xt = ctypes.cdll.LoadLibrary(ctypes.util.find_library("Xtst") or "libXtst.so.6")
    except OSError:
        return None
    x.XOpenDisplay.restype = ctypes.c_void_p
    x.XOpenDisplay.argtypes = [ctypes.c_char_p]
    x.XStringToKeysym.restype = ctypes.c_ulong
    x.XStringToKeysym.argtypes = [ctypes.c_char_p]
    x.XKeysymToKeycode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    x.XKeysymToKeycode.restype = ctypes.c_ubyte
    x.XFlush.argtypes = [ctypes.c_void_p]
    xt.XTestFakeKeyEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]
    d = x.XOpenDisplay(None)
    if not d:
        return None

    def press(*names):
        codes = [x.XKeysymToKeycode(d, x.XStringToKeysym(n.encode())) for n in names]
        for c in codes:
            xt.XTestFakeKeyEvent(d, c, 1, 0)
        for c in reversed(codes):
            xt.XTestFakeKeyEvent(d, c, 0, 0)
        x.XFlush(d)
    return press


@unittest.skipUnless(_xtest(), "needs an X11 display with XTest")
class X11HotkeyTest(unittest.TestCase):
    def test_grab_and_trigger(self):
        press = _xtest()
        got = []
        m = HotkeyManager(got.append, "x11")
        self.assertEqual(m.register({"pseudonymize": "Ctrl+Alt+P", "revert": "Ctrl+Alt+U"}), {})
        # a second grab of the same combination must be reported as conflict
        m2 = HotkeyManager(got.append, "x11")
        errs = m2.register({"other": "Ctrl+Alt+P"})
        self.assertIn("other", errs)
        m2.unregister()
        press("Control_L", "Alt_L", "p")
        press("Control_L", "Alt_L", "u")
        press("Control_L", "p")                     # not bound
        deadline = time.time() + 3
        while len(got) < 2 and time.time() < deadline:
            time.sleep(0.05)
        m.unregister()
        self.assertEqual(got, ["pseudonymize", "revert"])


if __name__ == "__main__":
    unittest.main()
