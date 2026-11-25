"""Educational demo: try to match a hash against the bundled 100,000 common passwords.

This only ever "cracks" a hash of one of those well-known passwords, computed with no
salt, exactly as stored in the bundled list. It exists to make a weak, fast hash feel
concrete; it finds nothing for a hash of a real, unique or salted password. Never paste a
hash from a real account here.
"""

from __future__ import annotations

import hashlib
import re
import threading
from collections.abc import Callable
from functools import lru_cache

from .dictionary import _read_tokens
from .utils import DATA_DIR

ALGORITHMS = {"md5": hashlib.md5, "sha1": hashlib.sha1}
HEX_LENGTHS = {32: "md5", 40: "sha1"}
_HEX = re.compile(r"^[0-9a-fA-F]+$")

Progress = Callable[[int, int], None]


@lru_cache(maxsize=1)
def _common_passwords() -> tuple[str, ...]:
    return tuple(_read_tokens(DATA_DIR / "common_passwords.txt"))


def algorithm_for(hash_hex: str) -> str | None:
    """Which algorithm this demo can try for a hash of this shape, or None."""
    s = hash_hex.strip()
    if _HEX.match(s):
        return HEX_LENGTHS.get(len(s))
    return None


def try_crack(hash_hex: str, algo: str, *, cancel: threading.Event | None = None,
             progress: Progress | None = None) -> str | None:
    """The common password that hashes to `hash_hex` with `algo`, or None if not found."""
    target = hash_hex.strip().lower()
    fn = ALGORITHMS.get(algo)
    if fn is None or not target:
        return None
    pool = _common_passwords()
    for i, pw in enumerate(pool):
        if cancel and cancel.is_set():
            return None
        if fn(pw.encode("utf-8", "replace")).hexdigest() == target:
            return pw
        if progress and i % 4000 == 0:
            progress(i, len(pool))
    return None


__all__ = ["try_crack", "algorithm_for", "ALGORITHMS"]
