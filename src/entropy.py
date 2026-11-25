"""Entropy calculations.

Two different numbers are produced and must not be confused:

* theoretical entropy  H = L * log2(R)   -- assumes every character was drawn
  independently and uniformly from a pool of R symbols (true only for
  machine-generated passwords).
* estimated entropy -- the cheapest way an attacker aware of dictionaries,
  keyboard walks, sequences, etc. could construct the password. Computed with
  a minimum-cost cover (dynamic programming) over detected patterns.
"""

from __future__ import annotations

import math
from collections import defaultdict

from .patterns import Match
from .utils import DIGITS, LOWER, SYMBOLS, UPPER, humanize_seconds

OFFLINE_GUESSES_PER_SEC = 1e10       # fast hash (e.g. MD5/NTLM) on a GPU rig
OFFLINE_SLOW_GUESSES_PER_SEC = 1e4   # purpose-built slow hash (e.g. bcrypt/Argon2) on the same rig
ONLINE_GUESSES_PER_SEC = 10          # throttled login endpoint (rate limit / lockout)


def pool_size(password: str) -> int:
    pool = 0
    if any(c in LOWER for c in password):
        pool += 26
    if any(c in UPPER for c in password):
        pool += 26
    if any(c in DIGITS for c in password):
        pool += 10
    if any(c in SYMBOLS for c in password):
        pool += 33
    if any(not c.isascii() for c in password):
        pool += 128
    return pool


def theoretical_entropy(password: str) -> float:
    """H = L * log2(R)."""
    pool = pool_size(password)
    if not password or pool < 2:
        return 0.0
    return len(password) * math.log2(pool)


def estimate_entropy(password: str, matches: list[Match]) -> tuple[float, list[Match]]:
    """Cheapest cover of the password by patterns + brute-forced characters.

    Returns (bits, matches used in the cheapest cover).
    """
    n = len(password)
    if n == 0:
        return 0.0, []
    char_bits = math.log2(max(pool_size(password), 2))
    by_end: dict[int, list[Match]] = defaultdict(list)
    for m in matches:
        by_end[m.end].append(m)

    best = [0.0] + [math.inf] * n
    back: list[Match | None] = [None] * (n + 1)
    for i in range(1, n + 1):
        best[i] = best[i - 1] + char_bits
        for m in by_end[i]:
            cost = best[m.start] + m.bits
            if cost < best[i]:
                best[i], back[i] = cost, m

    used: list[Match] = []
    i = n
    while i > 0:
        step = back[i]
        if step is None:
            i -= 1
        else:
            used.append(step)
            i = step.start
    used.reverse()
    return best[n], used


def crack_time(bits: float) -> dict[str, str]:
    """Average time to guess (half the keyspace) under three attacker models:
    a fast hash (e.g. MD5/NTLM) and a slow, purpose-built hash (e.g. bcrypt/Argon2) cracked
    offline on a GPU rig, and an online login throttled by a rate limit or lockout."""
    guesses = 2 ** max(bits - 1, 0) if bits < 1000 else float("inf")
    return {
        "offline_fast_hash": humanize_seconds(guesses / OFFLINE_GUESSES_PER_SEC),
        "offline_slow_hash": humanize_seconds(guesses / OFFLINE_SLOW_GUESSES_PER_SEC),
        "online_throttled": humanize_seconds(guesses / ONLINE_GUESSES_PER_SEC),
    }
