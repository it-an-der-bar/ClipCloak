"""Bundle the CI builds into one download per platform.

    python tools/package_release.py linux   v0.1.9 [--dist dist] [--upload]
    python tools/package_release.py windows v0.1.9 --app dist/clipcloak [--ner dist/clipcloak-ner]
                                            [--dist dist] [--upload] [--also FILE ...]

linux:   <dist>/<app>-<tag>-linux-x86_64.tar.gz from the single-file builds
         <app>-<tag>-linux-x86_64 and <app>-ner-<tag>-linux-x86_64:
           <app>-<tag>/<app>, <app>-ner, <app>.desktop, <app>.png, examples/, docs   (exec bits kept)
windows: <dist>/<app>-<tag>-windows-x86_64.zip from the folder builds (PyInstaller --onedir):
           <app>-<tag>/<app>.exe + _internal\\      program
           <app>-<tag>/ner/<app>-ner.exe + _internal\\   NER plugin
           <app>-<tag>/policies/                  ADMX/ADML templates, examples/ (policy files, .reg)
           docs

A missing NER build only gives a warning (the archive then holds the program alone).

--upload puts the archives (and the --also files, e.g. the MSI) into the project's
generic package registry (CI only, CI_JOB_TOKEN). Unlike job artifacts it has no
100 MB limit.
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
POLICIES = ROOT / "packaging" / "windows" / "policies"
EXAMPLES = ROOT / "packaging" / "examples"


def make_tar(dist: Path, tag: str) -> Path | None:
    main = dist / f"{APP_NAME}-{tag}-linux-x86_64"
    if not main.is_file():
        print(f"[linux] {main.name} missing - skipped")
        return None
    items = [(main, APP_NAME, True)]
    ner = dist / f"{APP_NAME}-ner-{tag}-linux-x86_64"
    if ner.is_file():
        items.append((ner, f"{APP_NAME}-ner", True))
    else:
        print(f"[linux] WARNING: {ner.name} missing - archive without NER plugin")
    items += [(ROOT / d, d, False) for d in DOCS]
    items.append((ROOT / "packaging" / "linux" / f"{APP_NAME}.desktop", f"{APP_NAME}.desktop", False))
    items.append((ROOT / APP_NAME / "resources" / "icon.png", f"{APP_NAME}.png", False))
    items += [(f, f"examples/{f.name}", False) for f in sorted(EXAMPLES.glob("*.yaml"))]
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
        add(tf, f"{top}/examples", is_dir=True)
        for src, name, exe in items:
            add(tf, f"{top}/{name}", src=src, mode=0o755 if exe else 0o644)
    return out


def _add_tree(zf: zipfile.ZipFile, src: Path, prefix: str) -> int:
    n = 0
    for f in sorted(src.rglob("*")):
        if f.is_file():
            zf.write(f, f"{prefix}/{f.relative_to(src).as_posix()}")
            n += 1
    return n


def make_zip(dist: Path, tag: str, app: Path, ner: Path | None) -> Path | None:
    exe = app / f"{APP_NAME}.exe"
    if not exe.is_file():
        print(f"[windows] {exe} missing - skipped")
        return None
    top = f"{APP_NAME}-{tag}"
    out = dist / f"{APP_NAME}-{tag}-windows-x86_64.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        _add_tree(zf, app, top)
        if ner is not None and (ner / f"{APP_NAME}-ner.exe").is_file():
            _add_tree(zf, ner, f"{top}/ner")
        else:
            print(f"[windows] WARNING: NER build missing ({ner}) - archive without NER plugin")
        if POLICIES.is_dir():
            _add_tree(zf, POLICIES, f"{top}/policies")
        if EXAMPLES.is_dir():
            _add_tree(zf, EXAMPLES, f"{top}/policies/examples")
        for d in DOCS:
            zf.write(ROOT / d, f"{top}/{d}")
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
        with urllib.request.urlopen(req, timeout=1800) as resp:
            print(f"uploaded {path.name}: HTTP {resp.status}")
    return url


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("platform", choices=["linux", "windows"])
    ap.add_argument("tag")
    ap.add_argument("--dist", default="dist")
    ap.add_argument("--app", help="windows: folder build of the program")
    ap.add_argument("--ner", help="windows: folder build of the NER plugin")
    ap.add_argument("--also", nargs="*", default=[], help="further files to upload (e.g. the MSI)")
    ap.add_argument("--upload", action="store_true")
    args = ap.parse_args(argv)
    dist = Path(args.dist)
    if args.platform == "linux":
        made = make_tar(dist, args.tag)
    else:
        if not args.app:
            ap.error("windows needs --app")
        made = make_zip(dist, args.tag, Path(args.app), Path(args.ner) if args.ner else None)
    files = ([made] if made else []) + [Path(p) for p in args.also if Path(p).is_file()]
    if not files:
        print("nothing to package")
        return 1
    for p in files:
        print(f"{p.name}: {p.stat().st_size / 1e6:.1f} MB")
        if args.upload:
            upload(p, args.tag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
