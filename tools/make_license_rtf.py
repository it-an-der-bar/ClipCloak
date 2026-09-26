"""Convert LICENSE (plain text) into the RTF the MSI's license page shows.

    python tools/make_license_rtf.py dist/license.rtf
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def to_rtf(text: str) -> str:
    out = []
    for ch in text:
        if ch in "\\{}":
            out.append("\\" + ch)
        elif ch == "\n":
            out.append("\\par\n")
        elif ch == "\t":
            out.append("\\tab ")
        elif ord(ch) < 128:
            out.append(ch)
        else:
            code = ord(ch)
            if code > 0xFFFF:
                ch = "?"
                code = ord(ch)
            out.append(f"\\u{code if code < 0x8000 else code - 0x10000}?")
    return ("{\\rtf1\\ansi\\ansicpg1252\\deff0{\\fonttbl{\\f0\\fmodern Consolas;}}\n"
            "\\f0\\fs16\n" + "".join(out) + "}\n")


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print(__doc__)
        return 2
    text = (ROOT / "LICENSE").read_text("utf-8").replace("\r\n", "\n")
    Path(argv[0]).parent.mkdir(parents=True, exist_ok=True)
    Path(argv[0]).write_text(to_rtf(text), "ascii")
    return 0


if __name__ == "__main__":
    sys.exit(main())
