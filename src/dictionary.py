"""Local dictionary checks. Nothing here ever touches the network."""

from __future__ import annotations

import math
from functools import lru_cache
from pathlib import Path

from .patterns import Match
from .utils import DATA_DIR, LEET_MAP_A, LEET_MAP_B, unleet

# A general vocabulary word is assumed to cost ~2^13 guesses (diceware-like).
WORD_BITS = 13.0
MIN_WORD_LEN = 4
MAX_SCAN_LEN = 256


def _read_tokens(path: Path) -> list[str]:
    if not path.exists():
        return []
    tokens: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            tokens.extend(line.split())
    return tokens


class Dictionary:
    def __init__(self, passwords: list[str], words: list[str]):
        self.rank: dict[str, int] = {}
        for i, pw in enumerate(passwords, start=1):
            self.rank.setdefault(pw.lower(), i)
        self.words = {w.lower() for w in words if len(w) >= MIN_WORD_LEN}
        self.max_len = max((len(w) for w in self.words), default=0)

    @classmethod
    def load(cls, data_dir: Path = DATA_DIR) -> "Dictionary":
        return cls(_read_tokens(data_dir / "common_passwords.txt"),
                   _read_tokens(data_dir / "common_words.txt"))

    @staticmethod
    def _candidates(token: str) -> list[tuple[str, bool]]:
        """Plain lowercase form plus leetspeak-normalised forms."""
        plain = token.lower()
        seen = {plain}
        out = [(plain, False)]
        for table in (LEET_MAP_A, LEET_MAP_B):
            cand = unleet(token, table)
            if cand not in seen:
                seen.add(cand)
                out.append((cand, True))
        return out

    def password_rank(self, password: str) -> tuple[int, bool] | None:
        """(rank, used_leet) if the whole password is a known common password."""
        for cand, leet in self._candidates(password):
            if cand in self.rank:
                return self.rank[cand], leet
        return None

    @staticmethod
    def _case_bits(token: str) -> float:
        letters = [c for c in token if c.isalpha()]
        if not letters or token.islower():
            return 0.0
        if token.isupper() or (token[0].isupper() and token[1:].islower()):
            return 1.0
        return math.log2(len(token)) + 1

    def find_matches(self, password: str) -> list[Match]:
        out: list[Match] = []
        n = len(password)

        hit = self.password_rank(password)
        if hit:
            rank, leet = hit
            out.append(Match("common_password", 0, n,
                             math.log2(rank) + 1 + self._case_bits(password), leet))

        if n > MAX_SCAN_LEN or not self.words:
            return out
        for i in range(n):
            for j in range(i + MIN_WORD_LEN, min(n, i + self.max_len) + 1):
                token = password[i:j]
                for cand, leet in self._candidates(token):
                    if cand in self.words:
                        subs = sum(a != b for a, b in zip(token.lower(), cand))
                        out.append(Match("word", i, j,
                                         WORD_BITS + self._case_bits(token) + subs, leet))
                        break
        return out


@lru_cache(maxsize=1)
def default_dictionary() -> Dictionary:
    return Dictionary.load()
