"""Detects reuse inside a dataset: identical passwords and near-copies.

"Near-copy" means the same base word once case, digits, symbols and leetspeak are
stripped (Summer2024! and summer2025 share the base "summer"). Only hashes of the
passwords are kept in memory, and only counts leave this module.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict

from .utils import LEET_MAP_A, unleet

MIN_ROOT_LENGTH = 4


_ENDS = re.compile(r"^[^A-Za-z@$]+|[^A-Za-z@$]+$")


def base_word(password: str) -> str:
    """Letters only: digits/symbols at the ends are dropped, inner leetspeak undone."""
    core = _ENDS.sub("", password)
    return "".join(c for c in unleet(core, LEET_MAP_A) if "a" <= c <= "z")


def stable_hash(text: str) -> int:
    """64-bit hash that is the same in every process (needed to merge worker results)."""
    return int.from_bytes(hashlib.blake2b(text.encode("utf-8", "replace"), digest_size=8).digest(), "big")


class ReuseTracker:
    def __init__(self) -> None:
        self.total = 0
        self._exact: Counter[int] = Counter()
        self._roots: dict[str, set[int]] = defaultdict(set)

    def add(self, password: str) -> None:
        h = stable_hash(password)
        self.total += 1
        self._exact[h] += 1
        root = base_word(password)
        if len(root) >= MIN_ROOT_LENGTH:
            self._roots[root].add(h)

    def merge(self, other: "ReuseTracker") -> None:
        """Fold the counts of another tracker (for example from a worker process) into this one."""
        self.total += other.total
        self._exact.update(other._exact)
        for root, hashes in other._roots.items():
            self._roots[root] |= hashes

    def summary(self) -> dict:
        exact = sum(c for c in self._exact.values() if c > 1)
        groups = [hs for hs in self._roots.values() if len(hs) > 1]
        similar = sum(self._exact[h] for hs in groups for h in hs)
        return {"exact_duplicates": exact, "similar_to_another": similar,
                "similar_groups": len(groups)}
