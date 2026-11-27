"""Detects reuse inside a dataset: identical passwords and near-copies.

"Near-copy" means the same base word once case, digits, symbols and leetspeak are
stripped (Summer2024! and summer2025 share the base "summer"). Only hashes of the
passwords are kept in memory, and only counts (and, if a label column was given,
the non-secret labels themselves) leave this module - never a password.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict

from .utils import LEET_MAP_A, unleet

MIN_ROOT_LENGTH = 4
MAX_LABELS_PER_PASSWORD = 6  # per exact-duplicate group
MAX_SHARED_GROUPS_REPORTED = 15


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
        # Only ever populated when a label (e.g. a site/account name from a CSV
        # import) is given; stays empty, with no extra cost, for plain password lists.
        self._labels: dict[int, list[str]] = defaultdict(list)

    def add(self, password: str, label: str | None = None) -> None:
        h = stable_hash(password)
        self.total += 1
        self._exact[h] += 1
        root = base_word(password)
        if len(root) >= MIN_ROOT_LENGTH:
            self._roots[root].add(h)
        if label:
            labels = self._labels[h]
            if label not in labels and len(labels) < MAX_LABELS_PER_PASSWORD:
                labels.append(label)

    def merge(self, other: "ReuseTracker") -> None:
        """Fold the counts of another tracker (for example from a worker process) into this one."""
        self.total += other.total
        self._exact.update(other._exact)
        for root, hashes in other._roots.items():
            self._roots[root] |= hashes
        for h, labels in other._labels.items():
            cur = self._labels[h]
            for lbl in labels:
                if lbl not in cur and len(cur) < MAX_LABELS_PER_PASSWORD:
                    cur.append(lbl)

    def summary(self) -> dict:
        exact = sum(c for c in self._exact.values() if c > 1)
        groups = [hs for hs in self._roots.values() if len(hs) > 1]
        similar = sum(self._exact[h] for hs in groups for h in hs)
        shared_groups = [(self._exact[h], labels) for h, labels in self._labels.items() if len(labels) > 1]
        shared_groups.sort(key=lambda g: -g[0])
        shared = [{"labels": labels, "count": count}
                 for count, labels in shared_groups[:MAX_SHARED_GROUPS_REPORTED]]
        return {"exact_duplicates": exact, "similar_to_another": similar,
                "similar_groups": len(groups), "shared_accounts": shared}
