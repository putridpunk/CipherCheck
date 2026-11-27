"""Checks a password against the user's own personal information.

This is the most realistic attack against one specific person: a name, a birth year, a
pet's name. None of this is ever saved to disk or sent anywhere; the caller (CLI flag or
a GUI field the user fills in for the current session only) supplies the tokens each time.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .patterns import Match
from .utils import LEET_MAP_A, LEET_MAP_B, unleet

MIN_TOKEN_LEN = 2
PERSONAL_BITS = 6.0  # a personal fact is a tiny, highly guessable search space


def _tokens(raw: list[str]) -> list[str]:
    """Split free-form entries (names, dates, "my dog is Rex") into individual words/numbers."""
    out: list[str] = []
    for entry in raw:
        for piece in re.split(r"[\s,;/._-]+", entry.strip()):
            piece = piece.strip()
            if len(piece) >= MIN_TOKEN_LEN:
                out.append(piece)
    return out


def find_matches(password: str, profile: list[str]) -> list[Match]:
    """Spans of `password` that match a personal token (plain or leetspeak-normalised)."""
    tokens = [t.lower() for t in _tokens(profile)]
    if not tokens or not password:
        return []
    n = len(password)
    out: list[Match] = []
    for i in range(n):
        for j in range(i + MIN_TOKEN_LEN, n + 1):
            piece = password[i:j]
            candidates = {piece.lower(), unleet(piece, LEET_MAP_A), unleet(piece, LEET_MAP_B)}
            if candidates & set(tokens):
                out.append(Match("personal", i, j, PERSONAL_BITS))
    return out


def load_profiles_file(path: str | Path) -> dict[str, list[str]]:
    """Load a batch-audit profiles file: a JSON object mapping one account/site label
    (matching a CSV's site/account column) to that one account's own personal terms, e.g.:

    {"alice@example.com": ["Alice", "1990", "Rex"], "bob@example.com": "Bob,1985"}

    Each value may be a single string (comma/space-separated, like the single-password
    --profile flag) or a list of strings. No profile here is ever checked against any
    account other than the one it is listed under.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("a profiles file must contain a single JSON object mapping account -> terms")
    out: dict[str, list[str]] = {}
    for key, value in data.items():
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ValueError(f"the profile for {key!r} must be a string or a list of strings")
        out[str(key)] = value
    return out
