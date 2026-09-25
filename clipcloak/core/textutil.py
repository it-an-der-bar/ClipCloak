"""Small text helpers shared by detectors and surrogate generators."""

from __future__ import annotations

import hashlib
import hmac
import random
import re
import string

from . import wordlists

_UPPER = string.ascii_uppercase
_LOWER = string.ascii_lowercase
_DIGITS = string.digits


def keyed_rng(key: bytes, *parts: str | bytes | int) -> random.Random:
    """Deterministic RNG derived from a secret key and a context."""
    h = hmac.new(key, digestmod=hashlib.sha256)
    for p in parts:
        if isinstance(p, int):
            p = str(p)
        if isinstance(p, str):
            p = p.encode("utf-8")
        h.update(len(p).to_bytes(4, "big"))
        h.update(p)
    return random.Random(int.from_bytes(h.digest(), "big"))


def keyed_hash(key: bytes, *parts: str) -> str:
    h = hmac.new(key, digestmod=hashlib.sha256)
    for p in parts:
        b = p.encode("utf-8")
        h.update(len(b).to_bytes(4, "big"))
        h.update(b)
    return h.hexdigest()


def case_pattern(sample: str) -> str:
    letters = [c for c in sample if c.isalpha()]
    if not letters:
        return "lower"
    if all(c.isupper() for c in letters):
        return "upper" if len(letters) > 1 else "title"
    if all(c.islower() for c in letters):
        return "lower"
    if letters[0].isupper() and all(c.islower() for c in letters[1:]):
        return "title"
    return "mixed"


def apply_case(word: str, pattern: str) -> str:
    if pattern == "upper":
        return word.upper()
    if pattern == "lower":
        return word.lower()
    if pattern == "title":
        return word[:1].upper() + word[1:].lower()
    return word


def transfer_case(sample: str, word: str) -> str:
    """Apply the capitalisation style of ``sample`` to ``word``."""
    pat = case_pattern(sample)
    if pat == "mixed":
        # character-wise where possible, otherwise title case
        out = []
        for i, c in enumerate(word):
            ref = sample[i] if i < len(sample) else sample[-1]
            out.append(c.upper() if ref.isupper() else c.lower())
        return "".join(out)
    return apply_case(word, pat)


def randomize_chars(value: str, rng: random.Random, keep_prefix: int = 0,
                    hex_mode: bool | None = None) -> str:
    """Replace letters/digits by random ones of the same class.

    Punctuation, whitespace and backslash escape sequences (``\\n``) are kept
    so that JSON/YAML escaping and layout stay intact.
    """
    if hex_mode is None:
        core = value[keep_prefix:]
        hex_mode = bool(core) and all(c in string.hexdigits for c in core) and len(core) >= 8
    out = list(value[:keep_prefix])
    i = keep_prefix
    n = len(value)
    while i < n:
        c = value[i]
        if c == "\\" and i + 1 < n:
            out.append(value[i:i + 2])
            i += 2
            continue
        if hex_mode and c in string.hexdigits:
            pool = "0123456789abcdef" if not c.isupper() else "0123456789ABCDEF"
            out.append(rng.choice(pool))
        elif c in _UPPER:
            out.append(rng.choice(_UPPER))
        elif c in _LOWER:
            out.append(rng.choice(_LOWER))
        elif c in _DIGITS:
            out.append(rng.choice(_DIGITS))
        else:
            out.append(c)
        i += 1
    result = "".join(out)
    if result == value and any(ch.isalnum() for ch in value[keep_prefix:]):
        # astronomically unlikely, but never return the input unchanged
        return randomize_chars(value, random.Random(rng.random()), keep_prefix, hex_mode)
    return result


def pseudo_word(rng: random.Random, target_len: int) -> str:
    """Pronounceable lowercase pseudo word of roughly ``target_len`` chars."""
    target_len = max(3, min(target_len, 14))
    word = ""
    while len(word) < target_len - 1:
        word += rng.choice(wordlists.SYLLABLE_ONSETS) + rng.choice(wordlists.SYLLABLE_VOWELS)
    if len(word) < target_len + 2:
        word += rng.choice(wordlists.SYLLABLE_CODAS)
    return word[: target_len + 2]


def digits_like(value: str, rng: random.Random, keep: int = 0, nonzero_first: bool = True) -> str:
    """Replace digits after position ``keep`` with random digits (format kept)."""
    out = []
    first = True
    for i, c in enumerate(value):
        if i < keep or not c.isdigit():
            out.append(c)
            continue
        if first and nonzero_first:
            out.append(rng.choice("123456789"))
        else:
            out.append(rng.choice(_DIGITS))
        first = False
    return "".join(out)


WORD_BOUNDARY_L = r"(?<![A-Za-z0-9_À-ɏ])"
WORD_BOUNDARY_R = r"(?![A-Za-z0-9_À-ɏ])"


def word_regex(term: str, case_sensitive: bool = False) -> re.Pattern:
    flags = 0 if case_sensitive else re.IGNORECASE
    return re.compile(WORD_BOUNDARY_L + re.escape(term) + WORD_BOUNDARY_R, flags)


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def luhn_complete(prefix_digits: str) -> str:
    """Return the check digit making ``prefix_digits + d`` Luhn-valid."""
    for d in "0123456789":
        if luhn_ok(prefix_digits + d):
            return d
    raise ValueError("unreachable")


def iban_checksum_ok(iban: str) -> bool:
    s = iban[4:] + iban[:4]
    num = "".join(str(int(c, 36)) for c in s)
    return int(num) % 97 == 1


def iban_check_digits(country: str, bban: str) -> str:
    s = bban + country + "00"
    num = int("".join(str(int(c, 36)) for c in s))
    return f"{98 - num % 97:02d}"
