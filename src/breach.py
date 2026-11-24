"""Offline check against a list of leaked passwords. Nothing leaves the computer.

data/breached.bin holds the sorted, 6-byte SHA-1 prefixes of the ~1 million most
common leaked passwords (built by tools/build_data.py). A 48-bit prefix makes an
accidental match astronomically unlikely, while keeping the file at 6 MB. It is
not a complete breach database: a password that is not found may still have leaked.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

from .utils import DATA_DIR

PREFIX_BYTES = 6
# Guessing cost used for a leaked password: it is somewhere in the top ~1M.
BREACH_BITS = 20.0


class BreachDB:
    def __init__(self, data: bytes):
        if len(data) % PREFIX_BYTES:
            raise ValueError("corrupt breach index")
        self._data = data
        self.size = len(data) // PREFIX_BYTES

    @classmethod
    def load(cls, path: Path | None = None) -> "BreachDB | None":
        path = path or DATA_DIR / "breached.bin"
        return cls(path.read_bytes()) if path.exists() else None

    def contains(self, password: str) -> bool:
        key = hashlib.sha1(password.encode("utf-8")).digest()[:PREFIX_BYTES]
        data, lo, hi = self._data, 0, self.size
        while lo < hi:
            mid = (lo + hi) // 2
            probe = data[mid * PREFIX_BYTES:(mid + 1) * PREFIX_BYTES]
            if probe < key:
                lo = mid + 1
            elif probe > key:
                hi = mid
            else:
                return True
        return False


@lru_cache(maxsize=1)
def default_breach_db() -> BreachDB | None:
    return BreachDB.load()
