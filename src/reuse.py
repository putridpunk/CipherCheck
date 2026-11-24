"""Detects reuse inside a dataset: identical passwords and near-copies.

"Near-copy" means the same base word once case, digits, symbols and leetspeak are
stripped (Summer2024! and summer2025 share the base "summer"). Only hashes of the
passwords are kept in memory, and only counts leave this module.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict

from .utils import LEET_MAP_A, unleet

MIN_ROOT_LENGTH = 4


_ENDS = re.compile(r"^[^A-Za-z@$]+|[^A-Za-z@$]+$")


def base_word(password: str) -> str:
    """Letters only: digits/symbols at the ends are dropped, inner leetspeak undone."""
    core = _ENDS.sub("", password)
    return "".join(c for c in unleet(core, LEET_MAP_A) if "a" <= c <= "z")


class ReuseTracker:
    def __init__(self) -> None:
        self.total = 0
        self._exact: Counter[int] = Counter()
        self._roots: dict[str, set[int]] = defaultdict(set)

    def add(self, password: str) -> None:
        h = hash(password)
        self.total += 1
        self._exact[h] += 1
        root = base_word(password)
        if len(root) >= MIN_ROOT_LENGTH:
            self._roots[root].add(h)

    def summary(self) -> dict:
        exact = sum(c for c in self._exact.values() if c > 1)
        groups = [hs for hs in self._roots.values() if len(hs) > 1]
        similar = sum(self._exact[h] for hs in groups for h in hs)
        return {"exact_duplicates": exact, "similar_to_another": similar,
                "similar_groups": len(groups)}
