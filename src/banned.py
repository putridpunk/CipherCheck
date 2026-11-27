"""Checks a password against a custom list of banned terms - typically an organisation's
own name, products or other words the bundled 100k-password/8k-word dictionary cannot
know about. Unlike `profile.py` (one person's own facts, checked against one password),
the same banned list applies to every password in a run.
"""

from __future__ import annotations

import re
from pathlib import Path

from .patterns import Match
from .utils import LEET_MAP_A, LEET_MAP_B, unleet

MIN_TERM_LEN = 3
BANNED_BITS = 8.0  # a known organisation-specific term is a small, guessable search space


def _tokens(raw: list[str]) -> list[str]:
    """Split free-form entries into individual words (a multi-word term is matched whole
    *and* word by word, the same way `profile.py` splits names and dates)."""
    out: list[str] = []
    for entry in raw:
        entry = entry.strip()
        if len(entry) >= MIN_TERM_LEN:
            out.append(entry)
        for piece in re.split(r"[\s,;/._-]+", entry):
            piece = piece.strip()
            if len(piece) >= MIN_TERM_LEN and piece != entry:
                out.append(piece)
    return out


def find_matches(password: str, banned: list[str]) -> list[Match]:
    """Spans of `password` that match a banned term (plain or leetspeak-normalised)."""
    terms = {t.lower() for t in _tokens(banned)}
    if not terms or not password:
        return []
    n = len(password)
    out: list[Match] = []
    for i in range(n):
        for j in range(i + MIN_TERM_LEN, n + 1):
            piece = password[i:j]
            candidates = {piece.lower(), unleet(piece, LEET_MAP_A), unleet(piece, LEET_MAP_B)}
            if candidates & terms:
                out.append(Match("banned", i, j, BANNED_BITS))
    return out


def load_file(path: str | Path) -> list[str]:
    """One banned term (a word or a whole phrase, e.g. "Acme Corp") per line; blank lines
    and lines starting with # are ignored."""
    terms: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            terms.append(line)
    return terms
