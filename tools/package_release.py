"""Bundle the CI binaries into one download per platform.

    python tools/package_release.py v0.1.7 [--dist dist] [--upload]

Creates in <dist>:
  <app>-<tag>-windows-x86_64.zip     <app>.exe + <app>-ner.exe + docs
  <app>-<tag>-linux-x86_64.tar.gz    <app> + <app>-ner + .desktop + icon + docs

A platform is skipped if its main binary is missing; a missing NER helper only
gives a warning (the archive then contains the program alone).

--upload puts the archives into the project's generic package registry
(CI only, uses CI_JOB_TOKEN). The package registry has no 100 MB limit like
job artifacts, so archives of ~150 MB are fine.
"""

import argparse
import os
import sys
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from clipcloak.meta import APP_NAME  # noqa: E402

DOCS = ["README.md", "README.de.md", "LICENSE", "CHANGELOG.md"]


def _entries(dist: Path, tag: str, platform: str):
    """-> list of (source path, name inside archive, executable) or None."""
    ext = ".exe" if platform == "windows" else ""
    suffix = f"{tag}-{platform}-x86_64{ext}"
    main = dist / f"{APP_NAME}-{suffix}"
    if not main.is_file():
        print(f"[{platform}] {main.name} missing - skipped")
        return None
    items = [(main, f"{APP_NAME}{ext}", True)]
    ner = dist / f"{APP_NAME}-ner-{suffix}"
    if ner.is_file():
        items.append((ner, f"{APP_NAME}-ner{ext}", True))
    else:
        print(f"[{platform}] WARNING: {ner.name} missing - archive without NER plugin")
    for doc in DOCS:
        items.append((ROOT / doc, doc, False))
    if platform == "linux":
        items.append((ROOT / "packaging" / "linux" / f"{APP_NAME}.desktop", f"{APP_NAME}.desktop", False))
        items.append((ROOT / APP_NAME / "resources" / "icon.png", f"{APP_NAME}.png", False))
    return items


def make_zip(dist: Path, tag: str) -> Path | None:
    items = _entries(dist, tag, "windows")
    if items is None:
        return None
    top = f"{APP_NAME}-{tag}"
    out = dist / f"{APP_NAME}-{tag}-windows-x86_64.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for src, name, _exe in items:
            zf.write(src, f"{top}/{name}")
    return out


def make_tar(dist: Path, tag: str) -> Path | None:
    items = _entries(dist, tag, "linux")
    if items is None:
        return None
    top = f"{APP_NAME}-{tag}"
    out = dist / f"{APP_NAME}-{tag}-linux-x86_64.tar.gz"
    now = int(time.time())

    def add(tf, name, src=None, mode=0o644, is_dir=False):
        info = tarfile.TarInfo(name)
        info.mtime = now
        info.uname = info.gname = "root"
        if is_dir:
            info.type, info.mode = tarfile.DIRTYPE, 0o755
            tf.addfile(info)
            return
        info.mode = mode
        info.size = src.stat().st_size
        with open(src, "rb") as fh:
            tf.addfile(info, fh)

    with tarfile.open(out, "w:gz", compresslevel=6) as tf:
        add(tf, top, is_dir=True)
        for src, name, exe in items:
            add(tf, f"{top}/{name}", src=src, mode=0o755 if exe else 0o644)
    return out


def upload(path: Path, tag: str) -> str:
    api = os.environ["CI_API_V4_URL"]
    project = os.environ["CI_PROJECT_ID"]
    url = f"{api}/projects/{project}/packages/generic/{APP_NAME}/{tag}/{path.name}"
    with open(path, "rb") as fh:
        req = urllib.request.Request(url, data=fh, method="PUT")
        req.add_header("JOB-TOKEN", os.environ["CI_JOB_TOKEN"])
        req.add_header("Content-Length", str(path.stat().st_size))
        req.add_header("Content-Type", "application/octet-stream")
        with urllib.request.urlopen(req, timeout=600) as resp:
            print(f"uploaded {path.name}: HTTP {resp.status}")
    return url


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tag")
    ap.add_argument("--dist", default="dist")
    ap.add_argument("--upload", action="store_true")
    args = ap.parse_args(argv)
    dist = Path(args.dist)
    made = [p for p in (make_zip(dist, args.tag), make_tar(dist, args.tag)) if p]
    if not made:
        print("nothing to package")
        return 1
    for p in made:
        print(f"{p.name}: {p.stat().st_size / 1e6:.1f} MB")
        if args.upload:
            upload(p, args.tag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
