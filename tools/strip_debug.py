"""Remove debug symbols from compiled Python extensions before PyInstaller runs (Linux CI).

    python tools/strip_debug.py            # current interpreter's site-packages

Why not `pyinstaller --strip`: that strips every bundled library, including the
libraries wheels vendor via auditwheel/patchelf (numpy.libs/libscipy_openblas…).
Stripping those with Debian's binutils corrupts them ("ELF load command
address/offset not page-aligned"). The size gain comes from spaCy/thinc/blis/…
Cython modules, which are plain extensions, so only files that
  * are not in a `*.libs` directory and
  * have no RPATH/RUNPATH (i.e. were not rewritten by patchelf)
are stripped, with --strip-debug only.
"""

import subprocess
import sys
import sysconfig
from pathlib import Path


def has_rpath(path: Path) -> bool:
    out = subprocess.run(["readelf", "-d", str(path)], capture_output=True, text=True).stdout
    return "RPATH" in out or "RUNPATH" in out


def main() -> int:
    roots = {Path(sysconfig.get_paths()[k]) for k in ("platlib", "purelib")}
    before = after = count = skipped = 0
    for root in roots:
        for f in root.rglob("*.so*"):
            if not f.is_file() or f.is_symlink():
                continue
            if any(part.endswith(".libs") for part in f.parts) or has_rpath(f):
                skipped += 1
                continue
            size = f.stat().st_size
            if subprocess.run(["strip", "--strip-debug", str(f)], capture_output=True).returncode != 0:
                skipped += 1
                continue
            before += size
            after += f.stat().st_size
            count += 1
    print(f"stripped {count} files: {before / 1e6:.1f} MB -> {after / 1e6:.1f} MB; left alone: {skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
