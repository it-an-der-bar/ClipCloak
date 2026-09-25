"""Rename the application in one go.

    python tools/rename_app.py <newname> [DisplayName]

Example:  python tools/rename_app.py safeclip SafeClip

Replaces the technical name (lower case), the display name and the upper-case
form (environment variables) in all text files, renames the Python package,
the entry scripts and the desktop file. Run the test suite afterwards.
Note: the per-user config/data directory follows the name, so existing
settings/projects stay under the old directory name (copy them if needed).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

TEXT_SUFFIXES = {".py", ".md", ".yml", ".yaml", ".toml", ".txt", ".json", ".desktop", ".cfg", ".ini"}
SKIP_DIRS = {".git", "build", "dist", "__pycache__", ".cache", "venv", ".venv"}


def _load_old():
    meta_files = [p for p in ROOT.glob("*/meta.py") if (p.parent / "__init__.py").exists()]
    if len(meta_files) != 1:
        raise SystemExit("cannot find the package (expected exactly one */meta.py)")
    text = meta_files[0].read_text("utf-8")
    old = re.search(r'^APP_NAME = "([^"]+)"', text, re.M).group(1)
    old_disp = re.search(r'^APP_DISPLAY_NAME = "([^"]+)"', text, re.M).group(1)
    return meta_files[0].parent, old, old_disp


def rename(new: str, new_disp: str) -> None:
    pkg, old, old_disp = _load_old()
    if new == old:
        raise SystemExit("new name equals the current name")
    pairs = [(old_disp, new_disp), (old.upper(), new.upper()), (old, new)]
    changed = 0
    for p in ROOT.rglob("*"):
        if not p.is_file() or any(part in SKIP_DIRS for part in p.relative_to(ROOT).parts):
            continue
        if p.name == "LICENSE" or (p.suffix not in TEXT_SUFFIXES and p.name not in (".gitlab-ci.yml", ".gitignore")):
            continue
        try:
            text = p.read_text("utf-8")
        except UnicodeDecodeError:
            continue
        new_text = text
        for a, b in pairs:
            new_text = new_text.replace(a, b)
        if new_text != text:
            p.write_text(new_text, "utf-8")
            changed += 1
    # rename files and the package directory
    for p in list(ROOT.rglob(f"*{old}*")):
        if any(part in SKIP_DIRS for part in p.relative_to(ROOT).parts) or not p.exists():
            continue
        if p.is_file():
            p.rename(p.with_name(p.name.replace(old, new)))
    pkg.rename(pkg.with_name(new))
    print(f"renamed {old} -> {new} ({old_disp} -> {new_disp}), {changed} files updated")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    name = sys.argv[1].strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9_]{1,30}", name):
        sys.exit("the technical name must be lower case letters/digits/underscore, starting with a letter")
    display = sys.argv[2] if len(sys.argv) > 2 else name[:1].upper() + name[1:]
    rename(name, display)
