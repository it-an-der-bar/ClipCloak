"""Public identifiers of keys and certificates (optional, off by default).

Not secret, but they identify a vendor, a server or a person just as well:
.NET ``PublicKeyToken=…`` of own assemblies, certificate thumbprints and serial
numbers, SSH host key fingerprints, GPG key ids/fingerprints.

The well-known tokens of Microsoft/.NET assemblies (System.*, mscorlib …) identify
nobody in particular and are never reported.
"""

from __future__ import annotations

import re

from ..entities import EntityType as T
from .base import Detector

# Microsoft / .NET framework assembly tokens (public, the same on every machine)
WELL_KNOWN_TOKENS = {
    "b77a5c561934e089", "b03f5f7f11d50a3a", "31bf3856ad364e35", "7cec85d7bea7798e",
    "cc7b13ffcd2ddd51", "adb9793829ddae60", "89845dcd8080cc91", "71e9bce111e9429c",
    "30ad4fe6b2a6aeed", "0738eb9f132ed756", "null",
}

_HEXSEQ = r"(?:[0-9A-Fa-f]{2}[:\-]){7,63}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{16,128}"
PATTERNS = [
    re.compile(r"\bPublicKeyToken\s*=\s*(?P<v>[0-9A-Fa-f]{16})\b"),
    re.compile(r"(?i)\b(?:thumbprint|fingerprint|sha-?(?:1|256)\s+fingerprint|fingerprint\s*\(sha-?(?:1|256)\)|"
               r"serial(?:\s*number|no)?|key\s*id|keyid|key\s+fingerprint)\s*[:=]?\s*[\"']?(?P<v>" + _HEXSEQ + r")\b"),
    re.compile(r"(?<![\w/+])SHA256:(?P<v>[A-Za-z0-9+/]{43})(?![\w/+=])"),
    re.compile(r"(?<![\w:])MD5:(?P<v>(?:[0-9a-f]{2}:){15}[0-9a-f]{2})\b"),
    # gpg: "Key fingerprint = 1A2B 3C4D …" and the 40-hex line below pub/sec/sub
    re.compile(r"(?i)\bkey\s+fingerprint\s*=\s*(?P<v>(?:[0-9A-F]{4}\s{1,2}){9}[0-9A-F]{4})\b"),
    re.compile(r"(?m)^(?:pub|sec|sub|ssb)\b[^\n]*\n[ \t]+(?P<v>[0-9A-F]{40})[ \t]*$"),
    # PowerShell "Get-ChildItem Cert:\" table: thumbprint followed by the subject
    re.compile(r"(?m)^[ \t]*(?P<v>[0-9A-F]{40})[ \t]+(?:CN|OU|O|E)="),
]


class FingerprintDetector(Detector):
    id = "fingerprints"
    types = (T.FINGERPRINT.value,)
    default_enabled = False
    priority = 70

    def find(self, text, ctx):
        out, seen = [], set()
        for rx in PATTERNS:
            for m in rx.finditer(text):
                v = m.group("v")
                if v.lower() in WELL_KNOWN_TOKENS or len(set(v.lower()) - set(":- ")) < 3:
                    continue           # Microsoft tokens, 0000…/ffff… placeholders
                span = (m.start("v"), m.end("v"))
                if span in seen:
                    continue
                seen.add(span)
                out.append(self.mk(span[0], span[1], T.FINGERPRINT.value, text))
        return out
