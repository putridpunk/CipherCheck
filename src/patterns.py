"""Structural pattern recognition (no dictionary needed)."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from .utils import char_pool

MIN_SEQUENCE = 3
MIN_KEYBOARD = 4


@dataclass(frozen=True)
class Match:
    """A span of the password explained by a pattern.

    `bits` is the estimated cost for an attacker to guess this span.
    Matches never store the matched text, so they are safe to export.
    """

    kind: str
    start: int
    end: int  # exclusive
    bits: float
    leet: bool = False

    @property
    def length(self) -> int:
        return self.end - self.start


def find_sequences(password: str) -> list[Match]:
    """Runs like 123, 987, abc, cba (step of +1 / -1)."""
    out: list[Match] = []
    p = password.lower()
    n = len(p)

    def kind(c: str) -> str:
        return "d" if c.isdigit() else "a" if c.isalpha() else "x"

    i = 0
    while i < n - 1:
        d = ord(p[i + 1]) - ord(p[i])
        if d in (1, -1) and kind(p[i]) == kind(p[i + 1]) != "x":
            j = i + 1
            while j + 1 < n and ord(p[j + 1]) - ord(p[j]) == d and kind(p[j + 1]) == kind(p[i]):
                j += 1
            length = j - i + 1
            if length >= MIN_SEQUENCE:
                base = 10 if kind(p[i]) == "d" else 26
                out.append(Match("sequence", i, j + 1,
                                 math.log2(base) + math.log2(length) + 1))
            i = j
        else:
            i += 1
    return out


def find_repeats(password: str) -> list[Match]:
    """Single-character runs (aaaa) and repeated blocks (abcabc)."""
    out: list[Match] = []
    for m in re.finditer(r"(.)\1{2,}", password, flags=re.DOTALL):
        length = m.end() - m.start()
        out.append(Match("repeat_char", m.start(), m.end(),
                         math.log2(char_pool(m.group(1))) + math.log2(length)))
    for m in re.finditer(r"(.{2,}?)\1+", password, flags=re.DOTALL):
        block = m.group(1)
        if len(set(block)) < 2:
            continue
        count = (m.end() - m.start()) // len(block)
        bits = sum(math.log2(char_pool(c)) for c in block) + math.log2(count)
        out.append(Match("repeat_block", m.start(), m.end(), bits))
    return out


# (row, horizontal offset) of each key on a QWERTY layout.
_ROWS = [("1234567890", 0.0), ("qwertyuiop", 0.5), ("asdfghjkl", 0.75), ("zxcvbnm", 1.25)]
_KEYPOS = {ch: (r, off + c) for r, (keys, off) in enumerate(_ROWS) for c, ch in enumerate(keys)}


def _adjacent(a: str, b: str) -> bool:
    if a == b or a not in _KEYPOS or b not in _KEYPOS:
        return False
    (ra, xa), (rb, xb) = _KEYPOS[a], _KEYPOS[b]
    dy, dx = abs(ra - rb), abs(xa - xb)
    return (dy == 0 and dx == 1) or (dy == 1 and dx < 1)


def find_keyboard(password: str) -> list[Match]:
    """Walks across neighbouring keys (qwerty, asdf, 1qaz...)."""
    out: list[Match] = []
    p = password.lower()
    n = len(p)
    i = 0
    while i < n - 1:
        if _adjacent(p[i], p[i + 1]):
            j = i + 1
            while j + 1 < n and _adjacent(p[j], p[j + 1]):
                j += 1
            length = j - i + 1
            if length >= MIN_KEYBOARD:
                # ~47 start keys, ~4 plausible next keys per step
                out.append(Match("keyboard", i, j + 1, math.log2(47) + (length - 1) * 2))
            i = j
        else:
            i += 1
    return out


def find_years(password: str) -> list[Match]:
    """Four-digit years 1900-2099 (birth years, 'summer2024', ...)."""
    return [Match("year", m.start(), m.end(), math.log2(200))
            for m in re.finditer(r"(?<!\d)(?:19|20)\d{2}(?!\d)", password)]


def find_matches(password: str) -> list[Match]:
    return (find_sequences(password) + find_repeats(password)
            + find_keyboard(password) + find_years(password))


def word_plus_digits(password: str, word_matches: list[Match]) -> bool:
    """True if a dictionary word is followed only by a short digit/symbol tail."""
    if not word_matches:
        return False
    tail = password[max(m.end for m in word_matches):]
    return 0 < len(tail) <= 6 and any(c.isdigit() for c in tail) \
        and all(c.isdigit() or not c.isalnum() for c in tail)
