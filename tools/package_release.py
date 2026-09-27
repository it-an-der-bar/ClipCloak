"""Bundle the CI builds into one download per platform.

    python tools/package_release.py linux    v0.1.9 [--dist dist] [--upload]
    python tools/package_release.py windows  v0.1.9 --app dist-portable/clipcloak.exe
                                             [--ner dist-portable/clipcloak-ner.exe]
                                             [--dist dist] [--upload] [--also FILE ...]
    python tools/package_release.py policies v0.1.9 [--dist dist] [--upload]

linux:    <dist>/<app>-<tag>-linux-x86_64.tar.gz from the single-file builds
          <app>-<tag>-linux-x86_64 and <app>-ner-<tag>-linux-x86_64:
            <app>-<tag>/<app>, <app>-ner, <app>.desktop, <app>.png, examples/, docs   (exec bits kept)
windows:  <dist>/<app>-<tag>-windows-x86_64-portable.zip from the single-file builds (--onefile):
            <app>-<tag>/<app>.exe, <app>-ner.exe, docs          – nothing else
          (the MSI keeps the folder builds: no unpacking to %TEMP% at every start)
policies: <dist>/<app>-<tag>-policies.zip for administrators:
            PolicyDefinitions/<app>.admx, PolicyDefinitions/en-US|de-DE/<app>.adml
            examples/ (policy.yaml, defaults.yaml, policy-example.reg), README.txt

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

from clipcloak.meta import APP_DISPLAY_NAME, APP_NAME  # noqa: E402

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
    """Portable: the two single-file EXEs and the docs, no _internal folders."""
    if not app.is_file():
        print(f"[windows] {app} missing - skipped")
        return None
    top = f"{APP_NAME}-{tag}"
    out = dist / f"{APP_NAME}-{tag}-windows-x86_64-portable.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        zf.write(app, f"{top}/{APP_NAME}.exe")
        if ner is not None and ner.is_file():
            zf.write(ner, f"{top}/{APP_NAME}-ner.exe")
        else:
            print(f"[windows] WARNING: NER build missing ({ner}) - archive without NER plugin")
        for d in DOCS:
            zf.write(ROOT / d, f"{top}/{d}")
    return out


POLICY_README = """{app} {tag} - Group Policy templates and example policy files

PolicyDefinitions/   copy into the central store  \\\\<domain>\\SYSVOL\\<domain>\\Policies\\PolicyDefinitions
                     (or C:\\Windows\\PolicyDefinitions on a single machine). The settings then appear under
                     Computer/User Configuration > Policies > Administrative Templates > {name}.
examples/policy.yaml     enforced settings  -> %ProgramData%\\{app}\\policy.yaml   (Linux /etc/{app}/policy.yaml)
examples/defaults.yaml   defaults the user may change -> %ProgramData%\\{app}\\defaults.yaml
examples/policy-example.reg  the same as registry values (HKLM\\SOFTWARE\\Policies\\it-an-der-bar\\{name})

Without GPO (ESET, baramundi, Intune ...): distribute policy.yaml or the registry values.
Details: README.md, section "Deployment (Windows)".

---

{app} {tag} - Gruppenrichtlinien-Vorlagen und Beispiel-Richtliniendateien

PolicyDefinitions/   in den zentralen Speicher kopieren  \\\\<domain>\\SYSVOL\\<domain>\\Policies\\PolicyDefinitions
                     (oder C:\\Windows\\PolicyDefinitions auf einem Einzelrechner). Die Einstellungen stehen dann unter
                     Computer-/Benutzerkonfiguration > Richtlinien > Administrative Vorlagen > {name}.
examples/policy.yaml     erzwungene Einstellungen -> %ProgramData%\\{app}\\policy.yaml   (Linux /etc/{app}/policy.yaml)
examples/defaults.yaml   Vorgaben, die der Benutzer ändern darf -> %ProgramData%\\{app}\\defaults.yaml
examples/policy-example.reg  dasselbe als Registry-Werte (HKLM\\SOFTWARE\\Policies\\it-an-der-bar\\{name})

Ohne GPO (ESET, baramundi, Intune ...): policy.yaml oder die Registry-Werte verteilen.
Details: README.de.md, Abschnitt "Verteilung (Windows)".
"""


def make_policies(dist: Path, tag: str) -> Path | None:
    if not (POLICIES / f"{APP_NAME}.admx").is_file():
        print(f"[policies] {POLICIES} missing - skipped")
        return None
    out = dist / f"{APP_NAME}-{tag}-policies.zip"
    dist.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        _add_tree(zf, POLICIES, "PolicyDefinitions")
        for f in sorted(EXAMPLES.glob("*")):
            if f.is_file():
                zf.write(f, f"examples/{f.name}")
        zf.writestr("README.txt", POLICY_README.format(app=APP_NAME, name=APP_DISPLAY_NAME, tag=tag)
                    .replace("\n", "\r\n"))
        zf.write(ROOT / "LICENSE", "LICENSE")
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
    ap.add_argument("platform", choices=["linux", "windows", "policies"])
    ap.add_argument("tag")
    ap.add_argument("--dist", default="dist")
    ap.add_argument("--app", help="windows: single-file build of the program (.exe)")
    ap.add_argument("--ner", help="windows: single-file build of the NER plugin (.exe)")
    ap.add_argument("--also", nargs="*", default=[], help="further files to upload (e.g. the MSI)")
    ap.add_argument("--upload", action="store_true")
    args = ap.parse_args(argv)
    dist = Path(args.dist)
    if args.platform == "linux":
        made = make_tar(dist, args.tag)
    elif args.platform == "policies":
        made = make_policies(dist, args.tag)
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
