"""Shell command context shared by several detectors.

* package manager arguments (``apt install containerd.io``, ``pip install foo.bar``) are
  package names, not domains
* the first word of a command line (``sh deploy/compose/start.sh``) says whether the
  arguments are file paths
"""

from __future__ import annotations

import re

PKG_TOOLS = (r"apt(?:-get)?|aptitude|dnf|yum|microdnf|zypper|apk|pacman|yay|paru|brew|port|snap|flatpak|"
             r"pip3?|pipx|uv\s+pip|conda|mamba|npm|pnpm|yarn|bun|gem|cargo|choco|winget|scoop|"
             r"nix-env|dpkg|rpm|opkg|pkg|emerge|Install-Package|Install-Module")
PKG_VERBS = r"install|add|reinstall|remove|purge|erase|uninstall|upgrade|update|show|info|search|download|-S|-Sy|-Syu|-R|-i|-U|-e"
# sudo/doas/env prefix, the tool, options, a verb; the arguments run to the end of the command
PKG_RE = re.compile(
    r"(?im)^[ \t]*(?:[$#>][ \t]*)?(?:(?:sudo|doas|env|RUN)(?:[ \t]+-\S+)*[ \t]+)*(?:" + PKG_TOOLS + r")"
    r"(?:[ \t]+-{1,2}[\w-]+(?:=\S+)?)*[ \t]+(?:" + PKG_VERBS + r")(?=[ \t]|\\?$)")
CMD_END = re.compile(r"&&|\|\||[;|]|(?<!\\)\n")

FILE_COMMANDS = set("""
sh bash zsh ksh dash fish source . cat less more head tail vi vim nvim nano emacs code
cd ls ll dir cp mv rm rmdir mkdir touch chmod chown chgrp ln stat file find tree du
python python3 py node deno ruby perl php java go make cmake tar zip unzip gzip gunzip
diff git grep rg sed awk sort wc xdg-open open start notepad type copy move del
""".split())


def package_spans(text: str) -> list[tuple[int, int]]:
    """Spans holding the arguments of package manager commands (with ``\\`` continuations)."""
    out = []
    for m in PKG_RE.finditer(text):
        end = m.end()
        e = CMD_END.search(text, end)
        out.append((end, e.start() if e else len(text)))
    return out


def in_spans(pos: int, spans) -> bool:
    return any(s <= pos < e for s, e in spans)


def first_word(text: str, pos: int) -> str:
    """The command word of the line around ``pos`` (after sudo / a prompt)."""
    ls = text.rfind("\n", 0, pos) + 1
    line = text[ls:pos]
    words = re.findall(r"[^\s]+", line)
    while words and (words[0] in ("sudo", "doas", "$", "#", ">", "PS>") or words[0].endswith(("$", "#", ">"))):
        words.pop(0)
    if not words:
        return ""
    w = words[0]
    if w.startswith("./") or w.startswith("/"):
        return "./"
    return w.rsplit("/", 1)[-1].lower()
