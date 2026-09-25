"""Reading and writing text files with their original encoding and line endings."""

from __future__ import annotations

from pathlib import Path

MODE_SUFFIX = {"pseudonymize": "pseudo", "anonymize": "anon", "redact": "redacted", "revert": "restored"}


def read_text_file(path: str | Path) -> tuple[str, str]:
    """Return (text, encoding). Line endings are kept as they are."""
    data = Path(path).read_bytes()
    for enc in ("utf-8-sig" if data.startswith(b"\xef\xbb\xbf") else "utf-8", "cp1252", "latin-1"):
        try:
            return data.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace"), "utf-8"


def write_text_file(path: str | Path, text: str, encoding: str = "utf-8") -> None:
    try:
        data = text.encode(encoding)
    except UnicodeEncodeError:
        data = text.encode("utf-8")
    Path(path).write_bytes(data)


def suggest_output_path(src: str | Path, mode: str) -> str:
    """notes.md + pseudonymize -> notes.pseudo.md (next to the source)."""
    p = Path(src)
    return str(p.with_name(f"{p.stem}.{MODE_SUFFIX.get(mode, mode)}{p.suffix}"))
