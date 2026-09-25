"""CI guard: the pushed tag must match the version in the package.

    python tools/check_version.py v0.1.0
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from clipcloak import __version__  # noqa: E402

tag = sys.argv[1] if len(sys.argv) > 1 else ""
if tag.lstrip("v") != __version__:
    sys.exit(f"tag {tag!r} does not match package version {__version__!r} (clipcloak/__init__.py)")
if not re.fullmatch(r"\d+\.\d+\.\d+([.-]?\w+)?", __version__):
    sys.exit(f"unexpected version format {__version__!r}")
print(f"version {__version__} ok")
