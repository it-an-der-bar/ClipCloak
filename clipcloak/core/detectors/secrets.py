"""Secrets: well-known token formats, PEM blocks, key/value credentials."""

from __future__ import annotations

import math
import re

from .. import wordlists
from ..entities import EntityType as T
from .base import Detector

# (name, regex, length of prefix to keep verbatim or -1 for group-based)
TOKEN_PATTERNS = [
    ("gitlab", r"\bgl(?:pat|dt|rt|ptt|ft|imt|agent|oas|cbt|soat|ffct|sa|wt)-[0-9A-Za-z_\-.]{20,}", None),
    ("github", r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{30,255}\b", 4),
    ("github-fine", r"\bgithub_pat_[0-9A-Za-z_]{22,255}\b", 11),
    ("aws-key-id", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b", 4),
    ("slack", r"\bxox[abposr]-[0-9A-Za-z-]{10,}", 5),
    ("slack-webhook", r"(?<=hooks\.slack\.com/services/)T[0-9A-Za-z]+/B[0-9A-Za-z]+/[0-9A-Za-z]+", 0),
    ("anthropic", r"\bsk-ant-[A-Za-z0-9_\-]{20,}", 7),
    ("openai", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}", 3),
    ("google-api", r"\bAIza[0-9A-Za-z_\-]{35}\b", 4),
    ("stripe", r"\b(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b", 8),
    ("npm", r"\bnpm_[0-9A-Za-z]{36}\b", 4),
    ("pypi", r"\bpypi-[0-9A-Za-z_\-]{50,}", 5),
    ("docker", r"\bdckr_pat_[0-9A-Za-z_\-]{20,}", 9),
    ("vault", r"\bhv[sbr]\.[0-9A-Za-z_\-]{20,}", 4),
    ("huggingface", r"\bhf_[0-9A-Za-z]{30,}\b", 3),
    ("sendgrid", r"\bSG\.[\w-]{22}\.[\w-]{43}\b", 3),
    ("twilio", r"\bSK[0-9a-fA-F]{32}\b", 2),
    ("azure-sas", r"(?<=[?&]sig=)[A-Za-z0-9%+/=]{20,}", 0),
    ("azure-accountkey", r"(?<=AccountKey=)[A-Za-z0-9+/=]{40,}", 0),
]
_TOKEN_RES = [(n, re.compile(p), k) for n, p, k in TOKEN_PATTERNS]

JWT_RE = re.compile(r"\beyJ[0-9A-Za-z_-]{5,}\.eyJ[0-9A-Za-z_-]{5,}\.[0-9A-Za-z_-]{10,}")
PEM_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]{3,40})-----(.*?)-----END \1-----", re.S)
AUTH_HEADER_RE = re.compile(
    r"(?i)\b(?:authorization|proxy-authorization)\s*[:=]\s*[\"']?(?:bearer|basic|token|apikey|digest|negotiate)\s+([A-Za-z0-9._~+/=\-]{8,})")
BEARER_RE = re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=\-]{16,})")
URL_CRED_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]{1,20}://([^\s:/@\"'<>]+):([^\s/@\"'<>]+)@")
CURL_USER_RE = re.compile(r"(?i)\bcurl\b[^\n]*?\s(?:-u|--user)\s+[\"']?([^:\s\"']+):([^\s\"']+)")
MYSQL_RE = re.compile(r"(?i)\b(?:mysql|mysqldump|mariadb|mysqladmin)\b[^\n]*?\s-p([^\s\"'-][^\s\"']*)")
SSHPASS_RE = re.compile(r"(?i)\bsshpass\s+-p\s*[\"']?([^\s\"']+)")
SECURESTRING_RE = re.compile(r"(?i)ConvertTo-SecureString\s+(?:-String\s+)?([\"'])(.+?)\1")
NETRC_RE = re.compile(r"(?im)^\s*machine\s+\S+.*?\bpassword\s+(\S+)")
CLI_FLAG_RE = re.compile(
    r"(?i)(?<![\w-])--(?:password|passwd|pass|pwd|token|secret|api-key|apikey|client-secret|access-key|secret-key)(?:=|\s+)([\"']?)([^\s\"']+)\1")

# key/value forms. group "key" and group "val".
_KEY = r"(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{0,60})"
KV_PATTERNS = [
    # JSON / quoted keys: "password": "value"
    re.compile(r"[\"']" + _KEY + r"[\"']\s*:\s*\"(?P<val>(?:[^\"\\\n]|\\.)*)\""),
    re.compile(r"[\"']" + _KEY + r"[\"']\s*:\s*'(?P<val>(?:[^'\\\n]|\\.)*)'"),
    # XML element <password>value</password>
    re.compile(r"<(?P<key>[A-Za-z_][\w.\-:]{0,60})>(?P<val>[^<\n]{1,512})</(?P=key)>"),
    # XML/HTML attribute password="value"
    re.compile(r"(?<![\w.-])" + _KEY + r"=\"(?P<val>[^\"\n]{1,512})\""),
    # YAML / env / ini / connection strings: key: value, KEY=value, key = 'value'
    re.compile(r"(?m)(?<![\w.\-\"'])" + _KEY +
               r"[ \t]*(?:=|:(?=[ \t]))[ \t]*(?:(?P<q>[\"'])(?P<val>[^\"'\n]{1,512})(?P=q)|(?P<val2>[^\s\"'#,;&]{1,512}))"),
]

SECRET_WORDS = {
    "password", "passwd", "pwd", "pass", "passphrase", "passwort", "kennwort", "secret",
    "secrets", "token", "apikey", "credential", "credentials", "cookie", "authorization",
    "sas", "psk", "otp", "totp", "pin", "privatekey", "secretkey", "accesskey",
}
SECRET_PAIRS = {("api", "key"), ("access", "key"), ("secret", "key"), ("private", "key"),
                ("client", "secret"), ("auth", "token"), ("session", "id"), ("session", "key"),
                ("session", "token"), ("shared", "key"), ("master", "key"), ("encryption", "key"),
                ("signing", "key"), ("account", "key"), ("app", "secret"), ("refresh", "token"),
                ("access", "token"), ("id", "token"), ("bearer", "token"), ("x", "api"),
                ("api", "token"), ("webhook", "secret"), ("pre", "shared")}
NON_SECRET_LAST = {
    "type", "types", "policy", "length", "len", "min", "max", "minlength", "maxlength",
    "expiry", "expires", "expiration", "ttl", "lifetime", "url", "uri", "endpoint", "file",
    "path", "dir", "name", "hint", "prompt", "label", "field", "enabled", "enable", "required",
    "reset", "changed", "rotation", "format", "mode", "algorithm", "alg", "method", "header",
    "env", "var", "count", "age", "regex", "pattern", "strength", "manager", "store",
    "provider", "source", "ref", "reference", "location", "server", "host", "port", "user",
    "username", "login", "id_field", "description", "help", "placeholder", "valid", "validity",
    "auth", "authentication", "limit", "timeout", "interval", "size", "version", "scope",
    "scopes", "audience", "issuer", "prefix", "suffix", "hash_algorithm", "kind", "status",
    "template", "secretref", "secretkeyref", "secretname", "keyref", "selector",
}
AUTH_SCHEMES = {"bearer", "basic", "digest", "negotiate", "ntlm", "token", "apikey", "hoba", "mutual"}
_CAMEL = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")
PLACEHOLDER_RE = re.compile(
    r"^(?:\$\{[^}]*\}|\$\{\{.*\}\}|\{\{.*\}\}|<[^<>]*>|%[^%]*%|\$[A-Za-z_][A-Za-z0-9_]*|"
    r"\*+|x{3,}|X{3,}|\.\.\.|…|!vault.*|ENC\[.*|vault:.*|op://.*|secretref:.*|file:.*|env:.*|"
    r"\[REDACTED[^\]]*\]|<[A-Z_]+_\d+>)$", re.S)


def key_words(key: str) -> list[str]:
    words: list[str] = []
    for part in re.split(r"[_.\-:]+", key):
        words.extend(w.lower() for w in _CAMEL.findall(part))
    return [w for w in words if w]


def is_secret_key(key: str) -> bool:
    words = key_words(key)
    if not words:
        return False
    if "public" in words:
        return False          # PublicKeyToken=…, public_key: – public by definition
    if words[-1] in NON_SECRET_LAST:
        return False
    if any(w in SECRET_WORDS for w in words):
        return True
    joined = "".join(words)
    if joined in SECRET_WORDS:
        return True
    return any((a, b) in SECRET_PAIRS for a, b in zip(words, words[1:]))


def _balanced_len(val: str) -> int:
    """Length of an unquoted value up to the first closing bracket that it did not open."""
    depth = 0
    for i, ch in enumerate(val):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return i
            depth -= 1
    return len(val)


def is_placeholder(val: str) -> bool:
    v = val.strip()
    if len(v) < 2:
        return True
    if v.lower() in wordlists.PLACEHOLDER_SECRETS:
        return True
    return bool(PLACEHOLDER_RE.match(v))


class TokenDetector(Detector):
    id = "tokens"
    types = (T.SECRET.value,)
    priority = 92

    def find(self, text, ctx):
        out = []
        for name, rx, keep in _TOKEN_RES:
            for m in rx.finditer(text):
                s, e = m.start(), m.end()
                val = text[s:e].rstrip(".-")
                e = s + len(val)
                k = keep if keep is not None else (val.index("-") + 1 if "-" in val else 0)
                out.append(self.mk(s, e, T.SECRET.value, text, keep_prefix=k, kind=name))
        for m in JWT_RE.finditer(text):
            header = m.group(0).split(".", 1)[0]
            out.append(self.mk(m.start(), m.end(), T.SECRET.value, text, priority=93,
                               keep_prefix=len(header) + 1, kind="jwt"))
        return out


_EDGE_L = re.compile(r"(?:\s|\\[nr])*")
_EDGE_R = re.compile(r"(?:\s|\\[nr])*$")


class PemDetector(Detector):
    id = "pem"
    types = (T.PRIVATE_KEY.value, T.CERTIFICATE.value)
    priority = 100

    def find(self, text, ctx):
        out = []
        for m in PEM_RE.finditer(text):
            label = m.group(1)
            if "PRIVATE" in label or "SECRET" in label:
                typ = T.PRIVATE_KEY.value
            elif "CERTIFICATE" in label and "REQUEST" not in label:
                typ = T.CERTIFICATE.value
            else:
                continue  # public keys, CSRs: not sensitive by themselves
            body_s, body_e = m.start(2), m.end(2)
            # keep leading/trailing whitespace or escaped newlines of the body
            body = text[body_s:body_e]
            lead = len(_EDGE_L.match(body).group(0))
            trail = len(_EDGE_R.search(body).group(0))
            if body_e - trail <= body_s + lead:
                continue
            out.append(self.mk(body_s + lead, body_e - trail, typ, text))
        return out


class KeyValueSecretDetector(Detector):
    id = "kv-secrets"
    types = (T.SECRET.value,)
    priority = 85

    def find(self, text, ctx):
        out = []
        seen: set[tuple[int, int]] = set()
        for rx in KV_PATTERNS:
            for m in rx.finditer(text):
                vg = "val" if m.groupdict().get("val") is not None else "val2"
                key, val = m.group("key"), m.group(vg)
                if not is_secret_key(key) or is_placeholder(val):
                    continue
                if val.lower() in AUTH_SCHEMES:
                    continue  # "Authorization: Bearer <token>" – the token is found separately
                s, e = m.start(vg), m.end(vg)
                if vg == "val2":
                    e = s + _balanced_len(text[s:e])     # "…7798e]](System…" -> "…7798e"
                # trim YAML/ini trailing spaces
                while e > s and text[e - 1] in " \t":
                    e -= 1
                if (s, e) in seen or e <= s:
                    continue
                seen.add((s, e))
                out.append(self.mk(s, e, T.SECRET.value, text, kind="kv", key=key))
        for m in AUTH_HEADER_RE.finditer(text):
            out.append(self.mk(m.start(1), m.end(1), T.SECRET.value, text, priority=88, kind="auth-header"))
        for m in BEARER_RE.finditer(text):
            out.append(self.mk(m.start(1), m.end(1), T.SECRET.value, text, priority=87, kind="bearer"))
        for m in URL_CRED_RE.finditer(text):
            if not is_placeholder(m.group(2)):
                out.append(self.mk(m.start(2), m.end(2), T.SECRET.value, text, priority=88, kind="url-cred"))
            if m.group(1).lower() not in wordlists.SKIP_USERNAMES and not is_placeholder(m.group(1)):
                out.append(self.mk(m.start(1), m.end(1), T.USERNAME.value, text, priority=86))
        for m in CURL_USER_RE.finditer(text):
            out.append(self.mk(m.start(2), m.end(2), T.SECRET.value, text, priority=88, kind="curl"))
            if m.group(1).lower() not in wordlists.SKIP_USERNAMES:
                out.append(self.mk(m.start(1), m.end(1), T.USERNAME.value, text, priority=86))
        for rx, grp in ((MYSQL_RE, 1), (SSHPASS_RE, 1), (SECURESTRING_RE, 2), (NETRC_RE, 1), (CLI_FLAG_RE, 2)):
            for m in rx.finditer(text):
                if not is_placeholder(m.group(grp)):
                    out.append(self.mk(m.start(grp), m.end(grp), T.SECRET.value, text, priority=88, kind="cli"))
        return out


class EntropyDetector(Detector):
    """Optional: long random-looking strings (off by default)."""

    id = "entropy"
    types = (T.SECRET.value,)
    default_enabled = False
    priority = 35
    RX = re.compile(r"(?<![A-Za-z0-9+/_\-])[A-Za-z0-9+/_\-]{24,}={0,2}(?![A-Za-z0-9+/_\-])")

    def find(self, text, ctx):
        min_entropy = float(ctx.options.get("entropy_threshold", 4.0))
        out = []
        for m in self.RX.finditer(text):
            s = m.group(0)
            if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) in (32, 40, 64):
                continue  # hashes / commit ids
            classes = sum(bool(re.search(p, s)) for p in (r"[a-z]", r"[A-Z]", r"\d"))
            if classes < 3:
                continue
            if _entropy(s) < min_entropy:
                continue
            out.append(self.mk(m.start(), m.end(), T.SECRET.value, text, kind="entropy"))
        return out


def _entropy(s: str) -> float:
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())
