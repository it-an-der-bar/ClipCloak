"""Convert the gitleaks rule set into clipcloak/resources/secret_rules.json (run by hand, output committed).

    curl -sSfLO https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
    python tools/make_secret_rules.py gitleaks.toml

gitleaks (Zachary Rice and contributors, MIT license, https://github.com/gitleaks/gitleaks) keeps
~220 rules for credential formats of cloud and SaaS providers. The regexes are Go RE2; this script
turns them into Python ``re`` syntax:

- a flag group in the middle of an expression (``\\b(p8e-(?i)[a-z0-9]{32})``) becomes a scoped group
  up to the end of the enclosing group (``\\b(p8e-(?i:[a-z0-9]{32}))``) – Python only allows global
  flags at the start;
- POSIX classes (``[[:alnum:]]``) and ``\\z`` are rewritten;
- a rule that needs a key before the value ("newrelic_key = NRAK-…") but whose value starts with a
  literal prefix ("NRAK-", "dnkey-", "tfp_") also gets a copy without the key: the prefix and the exact
  length are specific enough, and a token pasted alone is the common case in a clipboard;
- allowlist entries that are concrete example keys (they match the rule itself) are dropped, so that
  the file holds no token-shaped strings; such keys are then simply reported.

Rules without a regex (file names only) are skipped. The output is checked by compiling every
expression.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "clipcloak" / "resources" / "secret_rules.json"


def go_to_py(src: str) -> str:
    src = src.replace("[[:alnum:]]", "[a-zA-Z0-9]").replace("[:alnum:]", "a-zA-Z0-9")
    src = src.replace("[[:alpha:]]", "[a-zA-Z]").replace("[:alpha:]", "a-zA-Z")
    src = src.replace("[[:digit:]]", "[0-9]").replace("[:digit:]", "0-9")
    out: list[str] = []
    extra = [0]                  # scoped flag groups opened at each depth, closed with that depth
    i, in_class = 0, False
    while i < len(src):
        c = src[i]
        if c == "\\":
            nxt = src[i + 1:i + 2]
            out.append("\\Z" if nxt == "z" else c + nxt)
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            elif c == "[":
                c = "\\["           # a literal "[" inside a class (Python warns about nested sets)
            out.append(c)
            i += 1
            continue
        if c == "[":
            in_class = True
            out.append(c)
            if src[i + 1:i + 2] == "^":
                out.append("^")
                i += 1
            if src[i + 1:i + 2] == "]":
                out.append("\\]")
                i += 1
            i += 1
            continue
        m = re.match(r"\(\?([imsU]+)\)", src[i:])
        if m and i > 0:
            out.append(f"(?{m.group(1)}:")
            extra[-1] += 1
            i += m.end()
            continue
        if c == "(":
            extra.append(0)
        elif c == ")":
            out.append(")" * extra.pop())
        out.append(c)
        i += 1
    out.append(")" * extra.pop())
    return "".join(out)


KEY_VALUE = r"""[\x60'"\s=]{0,5}("""
END = r"""(?:[\x60'"\s;]|\\[nr]|$)"""


def standalone(rule: dict) -> dict | None:
    """Copy of a key/value rule that matches the value alone, if the value has a literal prefix."""
    rx = rule["regex"]
    i = rx.find(KEY_VALUE)
    if i < 0 or not rx.endswith(END):
        return None
    body = rx[i + len(KEY_VALUE):-len(END)]
    if not body.endswith(")"):
        return None
    body = body[:-1]
    m = re.match(r"(?:[A-Za-z0-9_]|\\\.|-){3,}", body)
    if not m:
        return None
    prefix = m.group(0).replace("\\", "")
    flags = "(?i:" if rx.startswith("(?i)") else "(?:"
    return {"id": rule["id"] + "-standalone", "regex": r"(?<![\w.-])(" + flags + body + r"))(?![\w.-])",
            "keywords": [prefix.lower()], "entropy": rule["entropy"], "group": 0, "allow": rule["allow"]}


def compiles(rx: str) -> bool:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        try:
            re.compile(rx)
        except (re.error, FutureWarning) as exc:
            print("  not usable:", exc, rx[:80])
            return False
    return True


def main(argv) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    data = tomllib.loads(Path(argv[1]).read_text(encoding="utf-8"))
    glob = data.get("allowlist", {})
    rules = []
    for r in data["rules"]:
        if "regex" not in r:
            continue
        rx = go_to_py(r["regex"])
        if not compiles(rx):
            continue
        own = re.compile(rx)
        allow = []
        for a in r.get("allowlists", []):
            regs = [go_to_py(x) for x in a.get("regexes", [])]
            # concrete example keys: they are a token themselves – leave them out
            regs = [x for x in regs if compiles(x) and not own.search(x.replace("\\", ""))]
            entry = {"target": a.get("regexTarget", "secret"), "regexes": regs,
                     "stopwords": [s.lower() for s in a.get("stopwords", [])],
                     "condition": a.get("condition", "OR")}
            if entry["regexes"] or entry["stopwords"]:
                allow.append(entry)
        rules.append({"id": r["id"], "regex": rx, "keywords": [k.lower() for k in r.get("keywords", [])],
                      "entropy": r.get("entropy", 0), "group": r.get("secretGroup", 0), "allow": allow})
        alone = standalone(rules[-1])
        if alone is not None and compiles(alone["regex"]):
            rules.append(alone)
    out = {
        "source": "gitleaks config/gitleaks.toml (MIT, Copyright (c) 2019 Zachary Rice) – converted by "
                  "tools/make_secret_rules.py",
        "allow_regexes": [x for x in (go_to_py(x) for x in glob.get("regexes", [])) if compiles(x)],
        "stopwords": [s.lower() for s in glob.get("stopwords", [])],
        "rules": rules,
    }
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    derived = sum(r["id"].endswith("-standalone") for r in rules)
    print(f"{OUT.name}: {len(rules) - derived} of {len(data['rules'])} rules, {derived} standalone copies")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
