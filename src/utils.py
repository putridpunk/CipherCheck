"""Shared constants and helpers."""

from __future__ import annotations

import string
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"

LOWER = set(string.ascii_lowercase)
UPPER = set(string.ascii_uppercase)
DIGITS = set(string.digits)
SYMBOLS = set(string.punctuation) | {" "}

# Common "leetspeak" substitutions. '1' is ambiguous (i or l), so two maps exist.
LEET_MAP_A = {"@": "a", "4": "a", "8": "b", "3": "e", "6": "g", "1": "i",
              "!": "i", "0": "o", "5": "s", "$": "s", "7": "t", "+": "t", "2": "z"}
LEET_MAP_B = {**LEET_MAP_A, "1": "l", "!": "l"}


def char_pool(ch: str) -> int:
    """Size of the character class a single character belongs to."""
    if ch in LOWER or ch in UPPER:
        return 26
    if ch in DIGITS:
        return 10
    if ch in SYMBOLS:
        return 33
    return 128  # non-ASCII


def unleet(text: str, table: dict[str, str]) -> str:
    return "".join(table.get(c, c) for c in text.lower())


def humanize_seconds(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = [("year", 31_557_600), ("day", 86_400), ("hour", 3_600),
             ("minute", 60), ("second", 1)]
    if seconds >= 31_557_600 * 1_000_000_000:
        return "more than a billion years"
    for name, size in units:
        if seconds >= size:
            n = int(seconds // size)
            return f"{n:,} {name}{'s' if n != 1 else ''}"
    return "instantly"
