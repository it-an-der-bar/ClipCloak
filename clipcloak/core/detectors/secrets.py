"""Secrets: well-known token formats, PEM blocks, key/value credentials."""

from __future__ import annotations

import math
import re

from .. import b64, wordlists
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
    ("newrelic", r"\bNRAK-[A-Z0-9]{27}\b", 5),
    ("supabase", r"\bsbp_[a-f0-9]{40}\b", 4),
    ("groq", r"\bgsk_[A-Za-z0-9]{52}\b", 4),
    ("airtable-pat", r"\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b", 3),
    ("telegram-bot", r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b", 0),
    ("k3s-token", r"\bK10[a-f0-9]{64}::[^\s:]+:[^\s]{8,}", 3),       # k3s / RKE2 node and join tokens
    ("rancher", r"\btoken-[a-z0-9]{5}:[a-z0-9]{54}\b", 12),
    ("azure-sas", r"(?<=[?&]sig=)[A-Za-z0-9%+/=]{20,}", 0),
    ("azure-accountkey", r"(?<=AccountKey=)[A-Za-z0-9+/=]{40,}", 0),
]
_TOKEN_RES = [(n, re.compile(p), k) for n, p, k in TOKEN_PATTERNS]

# signed, or unsigned ("alg": "none" ends with the dot)
JWT_RE = re.compile(r"\beyJ[0-9A-Za-z_-]{5,}\.eyJ[0-9A-Za-z_-]{5,}\.(?:[0-9A-Za-z_-]{10,}|(?![0-9A-Za-z_-]))")
# one part of a JWT alone: base64url of a JSON object
JWT_PART_RE = re.compile(r"(?<![\w.-])eyJ[0-9A-Za-z_-]{16,}={0,2}(?![\w-])")
JWT_HEADER_KEYS = {"alg", "typ", "kid", "cty", "x5t", "x5t#S256", "x5u", "jku", "jwk", "enc", "zip", "crit", "b64"}
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
    r"(?i)(?<![\w-])--?(?:password|passwd|pass|pwd|token|secret|api-key|apikey|client-secret|access-key|secret-key)(?:=|\s+)([\"']?)([^\s\"']+)\1")

# admin commands and configs: (regex, group of the secret)
CRYPT_HASH_RE = re.compile(
    r"(?<![\w$])(\$(?:1|2[abxy]?|5|6|7|8|9|y|gy|apr1|sha1|md5|argon2i|argon2id|argon2d|scrypt|pbkdf2(?:-sha\d+)?)"
    r"\$[^\s:'\"]{2,}\$[./A-Za-z0-9+=]{8,}(?:\$[./A-Za-z0-9+=]+)?)")
ADMIN_PATTERNS = [
    # Cisco IOS: "password 7 0822…", "secret 5 $1$…", "key-string 7 …"
    (re.compile(r"(?im)^\s*(?:enable\s+|username\s+\S+\s+(?:privilege\s+\d+\s+)?)?"
                r"(?:password|secret|key-string|key)\s+[0-9]\s+(\S{6,})"), 1),
    (re.compile(r"(?i)\bnet\s+user\s+\S+\s+([^\s*/][^\s]*)\s+/(?:add|domain|active|expires)"), 1),
    (re.compile(r"(?i)\bnet\s+use\s+\S+\s+([^\s*/][^\s]*)\s+/user:"), 1),
    (re.compile(r"(?i)\bidentified\s+by\s+'([^'\n]{3,})'"), 1),                                # SQL
    (re.compile(r"(?i)\b(?:create|alter)\s+(?:user|role|login)\b[^\n;]*?\bpassword\s*=?\s*'([^'\n]{3,})'"), 1),
    (re.compile(r"(?i)\bset\s+password\b[^\n;]*?=\s*(?:password\s*\(\s*)?'([^'\n]{3,})'"), 1),
    (re.compile(r"(?im)^\s*(?:requirepass|masterauth)\s+(\S+)"), 1),                         # redis.conf
    (re.compile(r"(?i)\bredis-cli\b[^\n]*?\s-a\s+(\S+)"), 1),
    (re.compile(r"\bldap\w*\b[^\n]*?\s-w\s+(\S+)"), 1),                                  # -W: prompt
    (re.compile(r"(?i)\s-pass(?:in|out)?\s+pass:(\S+)"), 1),                                 # openssl
    (re.compile(r"(?i)\s(?:-U|--user(?:name)?=?)\s*[^\s%]+%(\S+)"), 1),                      # smbclient user%pass
    (re.compile(r"(?i)(?:^|\s)/p(?:assword)?:(\S+)"), 1),                                     # xfreerdp /p:
    (re.compile(r"(?i)\s-pw\s+(\S+)"), 1),                                                   # plink / pscp
    (re.compile(r"(?i)\s-u\s+\S+\s+-p\s+(\S+)"), 1),                                        # psexec, docker login
]

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
               r"[ \t]*(?:=|:(?=[ \t]))[ \t]*"
               r"(?:(?P<q>[\"'])(?P<val>[^\"'\n]{1,512})(?P=q)|(?P<val2>[^\s\"'#,;&](?:[^\s\"',;&]|&(?![\w.\-\[\]]+=)){0,511}))"),
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
    r"\[REDACTED[^\]]*\]|<[A-Z_]+_\d+>|(?:%[sdr]|\{\w*\}|[:@/._\-])+|#[0-9a-fA-F]{3,8}|"
    r"\[\]|\{\}|\(\)|-?\d{1,3}|\{[^{}]*\}|\$?\{\{.*|"
    r"(?i:(?:my|your|the|some|example|dummy|test|fake|user|db|admin)?[_\-]?"
    r"(?:secret|password|passwd|pass|pwd|pw|token|key|apikey|api_key)\d?))$", re.S)


# words that may follow the secret word: "password_value", "secretKeyB64", "token_hash"
SECRET_TAIL = {"value", "val", "string", "str", "plain", "plaintext", "raw", "b64", "base64", "hex", "data",
               "enc", "encrypted", "hash", "hashed", "salt", "secret", "key", "token", "password", "pw", "pass"}


def key_words(key: str) -> list[str]:
    words: list[str] = []
    for part in re.split(r"[_.\-:]+", key):
        words.extend(w.lower() for w in _CAMEL.findall(part))
    words = [w.rstrip("0123456789") or w for w in words]          # "password2", "DB_PASS_1"
    return [w for w in words if w and not w.isdigit()]


def is_secret_key(key: str) -> bool:
    """The key names a secret: the secret word ("password", "api key" …) is at the end, maybe followed
    by a form word ("password_b64"). "token.content", "token_offsets", "password_policy" are no secret."""
    words = key_words(key)
    if not words:
        return False
    if "public" in words:
        return False          # PublicKeyToken=…, public_key: – public by definition
    if words[-1] in NON_SECRET_LAST:
        return False
    end = len(words)
    while end > 1 and words[end - 1] in SECRET_TAIL and not _is_secret_at(words, end - 1):
        end -= 1
    return _is_secret_at(words, end - 1) or "".join(words) in SECRET_WORDS


SECRET_SUFFIXES = ("password", "passwd", "passwort", "kennwort", "secret", "token", "apikey")


def _is_secret_at(words: list[str], i: int) -> bool:
    w = words[i]
    return w in SECRET_WORDS or (i > 0 and (words[i - 1], w) in SECRET_PAIRS) or \
        (len(w) <= 20 and w.endswith(SECRET_SUFFIXES))              # PGPASSWORD, rootpassword


_CODE_MARKERS = re.compile(r"(?m)^\s*(?:def|class|import|from|return|if|elif|for|while|with|function|const|let|var)\b"
                           r"|\bself\.|\bthis\.|=>|;\s*$|\)\s*:\s*$|\):\s*$")


def looks_like_code(text: str) -> bool:
    """Source code (Python, JS, C#…): an unquoted word after "=" is a variable there, never a secret."""
    return len(_CODE_MARKERS.findall(text[:20000])) >= 2


# unquoted values that are code, not a secret: calls, indexing, attribute chains, type annotations
_CODE_VALUE = re.compile(
    r"^(?:[A-Za-z_][\w.]*[(\[]|(?:self|this|cls|os|env|process|config|settings|args|options|opts|kwargs)\."
    r"|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$|(?:str|bytes|int|bool|float|object|Any|Optional|Union|dict|list)\b"
    r"|(?:[A-Z][a-z]+){2,}$|\()")


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


def not_a_secret_value(val: str, code: bool = False) -> bool:
    """Values that name something instead of being a secret: placeholders, resource / secret names
    ("db-credentials", "API-Token"), module paths, short everyday words ("ask", "auto")."""
    if is_placeholder(val):
        return True
    parts = re.split(r"[-_.]", val)
    if len(parts) > 1 and re.fullmatch(r"[A-Za-z][A-Za-z0-9]*(?:[-_.][A-Za-z0-9]+)+", val) and \
            all(p.isdigit() or wordlists.is_common_word(p) for p in parts):
        return True
    if val.isalpha() and wordlists.is_common_word(val) and (len(val) <= 5 or code):
        return True
    return False


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
        jwts = []
        for m in JWT_RE.finditer(text):
            header = m.group(0).split(".", 1)[0]
            jwts.append((m.start(), m.end()))
            out.append(self.mk(m.start(), m.end(), T.SECRET.value, text, priority=93,
                               keep_prefix=len(header) + 1, kind="jwt"))
        for m in JWT_PART_RE.finditer(text):
            if any(a <= m.start() < b for a, b in jwts):
                continue
            claims = _jwt_json(m.group(0))
            if claims is not None and not set(claims) <= JWT_HEADER_KEYS:
                # the payload of a token (sub, email, tenant …) – the header alone is public
                out.append(self.mk(m.start(), m.end(), T.SECRET.value, text, priority=93, kind="jwt-part"))
        return out


def _jwt_json(part: str) -> dict | None:
    import base64
    import json
    body = part.rstrip("=")
    try:
        obj = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except (ValueError, UnicodeDecodeError):
        return None
    return obj if isinstance(obj, dict) and obj else None


# string literals written in pieces: "eyJhbGci…." "eyJzdWIi…." "sig" (Python), "…" + "…" (JS, Java, C#),
# "…" & "…" (VB), '…' . '…' (PHP), '…' || '…' (SQL), with a line break in between
_STR_LIT = re.compile(r"""(?:\b[rRbBuUfF]{1,2})?(["'])((?:(?!\1)[^\\\n]|\\.){4,4000})\1""")
_STR_JOIN = re.compile(r"\s*(?:\+|&\s*_?|\.|\|\||\\)?\s*")


class SplitStringDetector(Detector):
    """Tokens that code splits over several string literals: the pieces are joined, the token
    detectors run on the whole, and every piece that belongs to a token is reported."""

    id = "split-strings"
    types = (T.SECRET.value,)
    priority = 94

    def find(self, text, ctx):
        out = []
        run: list[tuple[int, str]] = []          # (start of the content in text, content)
        last_end = -1
        for m in _STR_LIT.finditer(text):
            body = m.group(2)
            if re.search(r"\s|\\", body):
                self._check(run, text, ctx, out)
                run, last_end = [], -1
                continue
            if run and last_end >= 0 and _STR_JOIN.fullmatch(text[last_end:m.start()]):
                run.append((m.start(2), body))
            else:
                self._check(run, text, ctx, out)
                run = [(m.start(2), body)]
            last_end = m.end()
        self._check(run, text, ctx, out)
        return out

    def _check(self, run, text, ctx, out):
        if len(run) < 2:
            return
        joined = "".join(b for _s, b in run)
        offsets, pos = [], 0
        for start, body in run:
            offsets.append((pos, pos + len(body), start))
            pos += len(body)
        found = []
        found += [f for det in (TokenDetector(), GitleaksDetector()) for f in det.find(joined, ctx)
                  if f.type == T.SECRET.value]
        found += [f for f in RandomTokenDetector().find(joined, ctx, whole_ok=False) if f.type == T.SECRET.value]
        taken: list[tuple[int, int]] = []
        for f in sorted(found, key=lambda f: (-f.priority, f.start)):
            # only what really spans pieces – a token inside one piece is found there anyway
            if sum(1 for fs, fe, _t in offsets if fs < f.end and fe > f.start) < 2:
                continue
            if any(a < f.end and f.start < b for a, b in taken):
                continue                              # the best-known format wins (JWT before a generic rule)
            taken.append((f.start, f.end))
            keep_end = f.start + int(f.meta.get("keep_prefix", 0))
            for fs, fe, tstart in offsets:
                a, b = max(f.start, fs), min(f.end, fe)
                if a >= b:
                    continue
                kept = max(0, min(keep_end, b) - a)
                if kept >= b - a:
                    continue                          # a JWT header: stays
                s = tstart + (a - fs)
                out.append(self.mk(s, tstart + (b - fs), T.SECRET.value, text, keep_prefix=kept,
                                   kind="split-" + str(f.meta.get("kind", ""))))


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
            if re.search(r"[\"'`]|\s=\s", m.group(2)):
                continue  # b"-----BEGIN …-----" … b"-----END …-----": two string constants in code
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

    @staticmethod
    def _code(text: str, kpos: int, key: str, val: str, code: bool) -> bool:
        """``token = self.peek_token()``, ``def f(token: Token)``, ``a, token = result``: code."""
        if _CODE_VALUE.match(val) or val.lower() in key_words(key) or val.lower() == key.lower():
            return True
        if re.fullmatch(r"[A-Za-z_]\w*", val):
            if code:
                return True                           # in source code a literal secret is quoted
            before = text[max(0, kpos - 40):kpos].rstrip(" \t")
            if before.endswith(("(", ",")) or re.search(r"\bdef\s+\w+\($", before):
                return True                           # f(token=token), a, token = … – not f(password=S3cr3t!)
        return False

    @staticmethod
    def _prose(text: str, end: int, val: str) -> bool:
        """"password: The password part of the URL." – a sentence, not a value."""
        rest = text[end:end + 40]
        return bool(re.match(r" +[A-Za-zÄÖÜäöü]{2,} +[A-Za-zÄÖÜäöü]", rest)) and \
            (val.isalpha() and (wordlists.is_common_word(val) or len(val) <= 3))

    @staticmethod
    def _label(key: str, val: str) -> bool:
        """UI texts and descriptions: "project.passphrase": "Passphrase (optional)",
        "TOKEN_DATA": "template data / text"."""
        words = re.findall(r"[^\W\d_]+", val)
        if not words or sum(wordlists.is_common_word(w) for w in words) < 0.6 * len(words):
            return False
        if "." in key and key == key.lower():
            return True                               # i18n / settings key
        return " " in val.strip() and bool(re.search(r"[(){}:?…/]|^[A-ZÄÖÜ]", val.strip()))

    @staticmethod
    def _names_key(key: str, val: str) -> bool:
        """"CHALLENGE_PASSWORD": "challengePassword" – the value is the name of the key."""
        vw = key_words(val)
        return bool(vw) and re.fullmatch(r"[A-Za-z_.\-]+", val) is not None and set(vw) <= set(key_words(key))

    def find(self, text, ctx):
        out = []
        seen: set[tuple[int, int]] = set()
        code = looks_like_code(text)
        for rx in KV_PATTERNS:
            for m in rx.finditer(text):
                vg = "val" if m.groupdict().get("val") is not None else "val2"
                key, val = m.group("key"), m.group(vg)
                s, e = m.start(vg), m.end(vg)
                if vg == "val2":
                    e = s + _balanced_len(text[s:e])     # "…7798e]](System…" -> "…7798e"
                    val = text[s:e]
                if not is_secret_key(key) or is_placeholder(val) or self._names_key(key, val):
                    continue
                if vg == "val" and re.fullmatch(r"[a-z_]+(?:\.[a-z_]+)+", val):
                    continue                          # 'Cookie': 'http.cookies' – a module / setting name
                if not_a_secret_value(val, code) or (vg == "val" and self._label(key, val)):
                    continue                          # existingSecret: db-credentials, "project.passphrase": "…"
                if vg == "val2" and (self._code(text, m.start("key"), key, val, code) or self._prose(text, e, val)):
                    continue
                if val.lower() in AUTH_SCHEMES:
                    continue  # "Authorization: Bearer <token>" – the token is found separately
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
        for m in CRYPT_HASH_RE.finditer(text):
            keep = m.group(1).index("$", 1) + 1                   # "$6$", "$2y$": the algorithm stays
            out.append(self.mk(m.start(1), m.end(1), T.SECRET.value, text, priority=89, kind="password-hash",
                               keep_prefix=keep))
        for rx, grp in ((MYSQL_RE, 1), (SSHPASS_RE, 1), (SECURESTRING_RE, 2), (NETRC_RE, 1), (CLI_FLAG_RE, 2),
                        *ADMIN_PATTERNS):
            for m in rx.finditer(text):
                if not is_placeholder(m.group(grp)) and not m.group(grp).startswith("-"):
                    out.append(self.mk(m.start(grp), m.end(grp), T.SECRET.value, text, priority=88, kind="cli"))
        return out


HEX_RE = re.compile(r"(?<![0-9A-Za-z_\-.])(?:0x)?([0-9a-f]{32,256}|[0-9A-F]{32,256})(?![0-9A-Za-z_\-])")
# hashes and ids that are no secret: "sha256:<hex>", "commit <hex>", "<hex>  file.iso"
HEX_PUBLIC_BEFORE = re.compile(
    r"(?i)(?:(?<![a-z])(?:sha(?:1|224|256|384|512)|md5|blake2b?|digest|etag|integrity|checksum|hash|sha\w*sum|"
    r"commit|revision|rev|tree|parent|merge|object|objectid|build\s*id|layer|image\s*id|container\s*id)"
    r"[\s:=\"'@#]{0,4}|@sha256:|\bcommit\s+)$")


HEX_PUBLIC_SEGMENTS = {"commit", "commits", "blob", "tree", "raw", "blame", "releases", "tag", "tags", "compare",
                       "pull", "sha", "shas", "rev", "revs", "revision", "revisions", "objects", "archive",
                       "changeset", "changesets", "-", "src", "diff", "patch", "build", "builds", "pipelines",
                       "jobs", "runs", "artifacts", "packages", "layers", "blobs", "manifests", "ci"}
HEX_PUBLIC_HOSTS = ("gist.github.com/", "raw.githubusercontent.com/", "gist.githubusercontent.com/")
HASH_NAMED = re.compile(r"(?i)\b(?:sha-?(?:1|224|256|384|512)|md5|blake2[bs]?|sha3-\d+)\b")
SECRET_NEAR = re.compile(r"(?i)secret|token|passw|api.?key|private|hmac")


class HexSecretDetector(Detector):
    """Long hex strings standing alone: API keys, tokens, webhook secrets, private hashes.

    Known public ids (image digests ``sha256:…``, ``commit …``, ``sha256sum`` output) stay.
    """

    id = "hex-strings"
    types = (T.SECRET.value,)
    priority = 34

    def find(self, text, ctx):
        out = []
        code = None
        for m in HEX_RE.finditer(text):
            v = m.group(1)
            if len(set(v.lower())) < 6 or not re.search(r"\d", v) or not re.search(r"[a-fA-F]", v):
                continue                              # 0000…, ffff…, placeholders
            if m.group(0).startswith("0x"):
                code = looks_like_code(text) if code is None else code
                if code:
                    continue                          # a number literal in source code
            if re.match(r"\.[A-Za-z0-9]{1,5}\b", text[m.end():]):
                continue                              # file name: "…/d9b8bc10….ttf"
            if HEX_PUBLIC_BEFORE.search(text[max(0, m.start() - 24):m.start()]):
                continue
            chunk = text[max(text.rfind(" ", 0, m.start()), text.rfind("\n", 0, m.start())) + 1:m.start()]
            if chunk.endswith(("/", "\\")):
                segment = re.split(r"[/\\]", chunk.rstrip("/\\"))[-1].lower()
                if "://" not in chunk or segment in HEX_PUBLIC_SEGMENTS or any(h in chunk for h in HEX_PUBLIC_HOSTS):
                    continue                          # file path, or commit / blob / tree in a URL (not a hook)
            near = text[max(0, m.start() - 60):m.start()]
            if HASH_NAMED.search(near) and not SECRET_NEAR.search(near):
                continue                              # SBOM / lock file: "alg": "SHA-256", "content": "…"
            after = text[m.end():m.end() + 3]
            if re.match(r" [ *]\S", after):
                continue                              # sha256sum / md5sum output: "<hex>  file"
            out.append(self.mk(m.start(1), m.end(1), T.SECRET.value, text, kind="hex"))
        return out


_TOKEN_CAND = re.compile(r"(?<![A-Za-z0-9+/_\-~.])([A-Za-z0-9][A-Za-z0-9+/_\-~.]*[A-Za-z0-9+/_\-]={0,2})"
                         r"(?![A-Za-z0-9+/_\-~=])")
_RUNS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
_TOKEN_PREFIX = re.compile(r"^(?:[A-Za-z][A-Za-z0-9]{0,9}[_\-.]){1,2}(?=[A-Za-z0-9+/])")
# what stands right before a public value: data URIs, SRI / npm integrity hashes, fingerprints,
# SSH public keys
_PUBLIC_BEFORE = re.compile(r"(?i)(?:base64,|\bsha(?:1|256|384|512)[-:]|\bmd5[-:]|\bh1:|"
                            r"\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com)\s+)$")
# URL path segments after which a random value is a credential: webhooks, invite / reset links
URL_SECRET_SEGMENTS = {"hook", "hooks", "webhook", "webhooks", "token", "tokens", "key", "keys", "secret", "secrets",
                       "services", "trigger", "triggers", "apikey", "api-key", "invite", "reset", "callback", "notify"}
PUBLIC_QUERY_PARAMS = {"list", "v", "id", "ids", "playlist", "index", "page", "t", "s", "si", "ref", "gid", "cid",
                       "pid", "vid", "sku", "item", "itemid", "product", "article", "doc", "file", "folder",
                       "path", "sort", "lang", "hl", "gl", "feature", "channel", "user", "u", "tab", "view"}
_URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>`]+")
_URL_SECRET_PATH = re.compile(r"/(?:" + "|".join(sorted(URL_SECRET_SEGMENTS)) + r")/([^?#\s]{16,})", re.I)
_STRONG_SYMBOLS = set("!#$%&*+=?@^~<>()[]{}|;,")
_PASSWORD_SYMBOLS = set("!#$%&*+-=?@^_~.,:;<>()[]{}|/\\")


def randomness(body: str) -> tuple[int, float, float]:
    """(character classes, mean length of letter/digit runs, share of letters in common words).

    Random tokens switch between upper, lower and digits all the time (mean run length ≈ 1.5–2.5)
    and contain no words; identifiers ("InternalFrameTitlePane", "cert-manager-cainjector") are
    long runs of real words.
    """
    classes = bool(re.search("[a-z]", body)) + bool(re.search("[A-Z]", body)) + bool(re.search(r"\d", body))
    runs = _RUNS.findall(body)
    if not runs:
        return classes, 99.0, 1.0
    mean = sum(len(r) for r in runs) / len(runs)
    letters = sum(len(r) for r in runs if not r[0].isdigit()) or 1
    words = sum(len(r) for r in runs if len(r) >= 3 and not r[0].isdigit() and wordlists.is_common_word(r))
    return classes, mean, words / letters


def _pem_in_base64(body: str) -> str | None:
    """None: not base64 of a PEM block. Otherwise the type to report: PRIVATE_KEY, CERTIFICATE or ""
    (public key, certificate request: nothing to report)."""
    if not body.startswith("LS0tLS1"):                # "-----" in base64
        return None
    import base64
    import binascii
    head = body[:96]
    try:
        raw = base64.b64decode(head[:len(head) // 4 * 4])
    except (binascii.Error, ValueError):
        return None
    m = re.match(rb"-----BEGIN ([A-Z0-9 ]{3,40})-----", raw)
    if not m:
        return None
    label = m.group(1).decode()
    if "PRIVATE" in label or "SECRET" in label:
        return T.PRIVATE_KEY.value
    if "CERTIFICATE" in label and "REQUEST" not in label:
        return T.CERTIFICATE.value
    return ""


def _path_part(p: str) -> bool:
    return p.isdigit() or bool(re.fullmatch(r"[0-9a-f]{7,}|[a-z][a-z0-9_.\-]{0,19}", p)) or randomness(p)[2] >= 0.5


def looks_random(body: str, min_len: int = 30) -> bool:
    if len(body) < min_len:
        return False
    if sum(c.isalnum() for c in body) < 0.75 * len(body):
        return False                                   # "8X------…", separators
    classes, mean, wordy = randomness(body)
    has_digit = bool(re.search(r"\d", body))
    if re.fullmatch(r"[0-9a-fA-F]+", re.sub(r"[-_:.]", "", body)):
        return False                                   # hex (also "00-4bf9…-00f0…-01"): the hex detector decides
    if classes == 3:
        return mean <= 3.0 and wordy < 0.35
    if classes == 2 and not has_digit:                 # only letters, mixed case (hf_…)
        return len(body) >= max(min_len, 32) and mean <= 2.2 and wordy < 0.2
    if classes == 2:                                   # lower + digits / upper + digits (base32/36)
        return len(body) >= max(min_len, 40) and mean <= 2.5 and wordy < 0.2
    return False


class RandomTokenDetector(Detector):
    """Tokens of formats no rule knows ("abc_" + 43 characters of URL-safe base64): random
    base62 / base64 of 30+ characters, with or without a short prefix. Needs mixed upper/lower case
    and digits (or 40+ characters of base32/36), no dictionary words and short character runs – so
    identifiers, paths, host names, hashes and ids stay. A value that is the whole clipboard is
    checked with 16+ characters, and a password-like value (with symbols) with 10+.
    """

    id = "random-tokens"
    types = (T.SECRET.value, T.PRIVATE_KEY.value, T.CERTIFICATE.value)
    priority = 36

    def find(self, text, ctx, _depth: int = 0, whole_ok: bool = True):
        out = []
        stripped = text.strip().strip("<>()[]{}\"'`")
        whole = whole_ok and 0 < len(stripped) <= 256 and not re.search(r"\s", stripped)
        for m in _TOKEN_CAND.finditer(text):
            s, e = m.span(1)
            cand = m.group(1).rstrip(".~")
            e = s + len(cand)
            if len(cand) < 16 or re.match(r"0[xX][0-9a-fA-F]+$", cand):
                continue                               # too short, a hex number (0x8CB91E…)
            if text[e:e + 1] == "@":
                continue                               # local part of a mail address / Message-ID
            pm = _TOKEN_PREFIX.match(cand)
            prefix = pm.group(0) if pm and len(cand) - pm.end() >= 16 else ""
            if _PUBLIC_BEFORE.search(text[max(0, s - 40):s] + prefix):
                continue                               # data URI, "sha512-…" integrity, SSH public key
            ws = text.rfind(" ", 0, s)
            chunk_start = max(ws, text.rfind("\n", 0, s), text.rfind("\t", 0, s)) + 1
            chunk = text[chunk_start:s]
            if "://" in chunk or "://" in text[s:s + 12]:
                q = re.search(r"[?&#]([^=&#?]*)=$", chunk)
                if q is None:
                    continue                           # URL path: see _url_paths
                if q.group(1).lower() in PUBLIC_QUERY_PARAMS:
                    continue                           # ?list=…, ?v=…, ?id=…: public ids
            body = cand[len(prefix):]
            parts = [p for p in body.split("/") if p]
            if len(parts) > 1 and sum(_path_part(p) for p in parts) * 2 >= len(parts):
                continue                               # a path (names, hashes between the slashes)
            pem = _pem_in_base64(body)
            if pem is not None:
                if pem:                                # base64 of a PEM block (kubeconfig *-data)
                    out.append(self.mk(s, e, pem, text, kind="base64-pem"))
                continue
            decoded = b64.decode(body, strict=True)
            if decoded is not None and decoded.lstrip().startswith("{") and cand.startswith("eyJ"):
                continue                               # a JWT part: the token detector decides
            if decoded is not None:
                # base64 of text: a secret only if the text holds one ("user:pass", "password: …")
                if _depth < 1 and _secret_in(decoded):
                    out.append(self.mk(s, e, T.SECRET.value, text, kind="base64-secret"))
                continue
            min_len = 16 if whole and cand == stripped else 30
            if not looks_random(body, min_len):
                continue
            out.append(self.mk(s, e, T.SECRET.value, text, keep_prefix=len(prefix), kind="random"))
        self._url_paths(text, out)
        if whole and not any(f.text == stripped for f in out) and self._password_like(stripped):
            s = text.index(stripped)
            out = [self.mk(s, s + len(stripped), T.SECRET.value, text, kind="password")]
        return out

    def _url_paths(self, text: str, out: list) -> None:
        """Webhook, invite and reset links: the random part after "hooks/", "token/" … is the credential."""
        for u in _URL_RE.finditer(text):
            m = _URL_SECRET_PATH.search(u.group(0))
            if not m:
                continue
            val = m.group(1).rstrip("/.,;:)")
            vs = u.start() + m.start(1)
            pm = _TOKEN_PREFIX.match(val)
            prefix = pm.group(0) if pm and len(val) - pm.end() >= 16 else ""
            if looks_random(val[len(prefix):].replace("/", ""), 24) or re.fullmatch(r"[0-9a-fA-F]{32,}", val):
                out.append(self.mk(vs, vs + len(val), T.SECRET.value, text, keep_prefix=len(prefix),
                                   kind="url-secret"))

    @staticmethod
    def _password_like(v: str) -> bool:
        """The whole clipboard is one password-like word: 10–128 characters of letters, digits and
        symbols, three kinds of characters of which one is a symbol, not a path, URL, mail address or
        a word with a year ("Sommer2024!")."""
        if not 10 <= len(v) <= 64 or "://" in v or ";base64," in v or v[0] in "/\\~." or re.match(r"^[A-Za-z]:\\", v):
            return False
        if re.fullmatch(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}", v):
            return False
        if not all(c.isalnum() or c in _PASSWORD_SYMBOLS for c in v) or not any(c in _STRONG_SYMBOLS for c in v):
            return False                               # only "-", "_", ".", ":", "/": a slug, id, date, path
        kinds = sum((any(c.islower() for c in v), any(c.isupper() for c in v), any(c.isdigit() for c in v)))
        if kinds < 2:
            return False
        classes, mean, wordy = randomness(v)
        return wordy < 0.5 and mean <= 3.5


def _secret_in(text: str) -> bool:
    """Decoded base64: basic-auth "user:password", or something the secret detectors find."""
    if re.fullmatch(r"[\w.@\\+\-]{1,64}:[^\s\"{}]{4,}", text.strip()):
        return True                                    # user:password (basic auth, docker "auth")
    from .base import DetectorContext
    ctx = DetectorContext()
    for det in (TokenDetector(), PemDetector(), KeyValueSecretDetector(), GitleaksDetector()):
        if any(f.type in (T.SECRET.value, T.PRIVATE_KEY.value) for f in det.find(text, ctx)):
            return True
    return any(f.type == T.SECRET.value for f in RandomTokenDetector().find(text, ctx, _depth=1))


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


class GitleaksDetector(Detector):
    """The credential formats of the gitleaks rule set (≈ 220 cloud and SaaS providers).

    ``resources/secret_rules.json`` is built from gitleaks' ``gitleaks.toml`` by
    ``tools/make_secret_rules.py``. As in gitleaks, a rule only runs when one of its keywords is in
    the text, the secret must reach the rule's entropy, and the rule's allowlists (example values,
    stopwords) apply.
    """

    id = "gitleaks"
    types = (T.SECRET.value,)
    priority = 90
    _rules: list | None = None
    _global: tuple | None = None

    @classmethod
    def _load(cls):
        if cls._rules is None:
            import json

            from ...paths import resource_path
            try:
                data = json.loads(resource_path("secret_rules.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = {"rules": []}
            rules = []
            for r in data.get("rules", []):
                allow = [(a["target"], [re.compile(x) for x in a["regexes"]], a["stopwords"], a["condition"])
                         for a in r.get("allow", [])]
                rules.append((r["id"], re.compile(r["regex"]), r["keywords"], float(r.get("entropy") or 0),
                              int(r.get("group") or 0), allow))
            cls._global = ([re.compile(x) for x in data.get("allow_regexes", [])], data.get("stopwords", []))
            cls._rules = rules
        return cls._rules

    def find(self, text, ctx):
        rules = self._load()
        g_regexes, g_stop = self._global
        low = text.lower()
        out = []
        for rid, rx, keywords, min_entropy, group, allow in rules:
            if keywords and not any(k in low for k in keywords):
                continue
            for m in rx.finditer(text):
                gi = group or next((i for i in range(1, (rx.groups or 0) + 1) if m.group(i)), 0)
                s, e = m.span(gi)
                if e - s > 2 and text[s] in "\"'`" and text[e - 1] == text[s]:
                    s, e = s + 1, e - 1                   # "…" – the quotes are no part of the secret
                secret = text[s:e]
                if len(secret) < 8 or not_a_secret_value(secret):
                    continue
                if min_entropy and _entropy(secret) < min_entropy:
                    continue
                if rid.startswith("generic") and (not re.search(r"\d", secret) or _CODE_VALUE.match(secret)):
                    continue                          # as gitleaks: a generic secret has a digit; not code
                sl = secret.lower()
                if any(x.search(secret) for x in g_regexes) or any(w in sl for w in g_stop):
                    continue
                if self._allowed(allow, secret, m.group(0), text, s):
                    continue
                keep = next((len(k) for k in keywords if sl.startswith(k) and len(secret) - len(k) >= 8), 0)
                out.append(self.mk(s, e, T.SECRET.value, text, keep_prefix=keep, kind=rid))
        return out

    @staticmethod
    def _allowed(allow, secret, match, text, pos) -> bool:
        for target, regexes, stopwords, condition in allow:
            if target == "match":
                subject = match
            elif target == "line":
                a = text.rfind("\n", 0, pos) + 1
                b = text.find("\n", pos)
                subject = text[a:b if b >= 0 else len(text)]
            else:
                subject = secret
            hits = []
            if regexes:
                hits.append(any(x.search(subject) for x in regexes))
            if stopwords:
                hits.append(any(w in secret.lower() for w in stopwords))
            if hits and (all(hits) if condition == "AND" else any(hits)):
                return True
        return False


def _entropy(s: str) -> float:
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())
