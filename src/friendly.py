"""Plain-language, translated presentation of an Analysis, for the GUI.

No jargon is shown to the user (no "entropy", "bits", "hash", "dictionary").
All text lives in src/locales/.
"""

from __future__ import annotations

import secrets
import string
from functools import lru_cache
from dataclasses import dataclass, field

from .analyzer import Analysis, analyze
from .dictionary import passphrase_words
from .entropy import OFFLINE_GUESSES_PER_SEC
from .i18n import t, unit

# label -> (level 1..5, colour)
LEVELS = {
    "VERY WEAK": (1, "#ff3b3b"),
    "WEAK": (2, "#ff8c1a"),
    "MODERATE": (3, "#f2e600"),
    "STRONG": (4, "#00ff41"),
    "VERY STRONG": (5, "#7dffb0"),
}
PROBLEM_KINDS = ("common_password", "breached", "word", "sequence", "repeat_char",
                 "repeat_block", "keyboard", "year")
KEY = {"common_password": "common", "breached": "breached", "word": "word", "sequence": "sequence",
       "repeat_char": "repeat_char", "repeat_block": "repeat_block",
       "keyboard": "keyboard", "year": "year"}


@dataclass
class FriendlyReport:
    verdict: str
    color: str
    level: int  # 1..5, for the strength bar
    headline: str
    crack_time: str
    bad: list[str] = field(default_factory=list)
    good: list[str] = field(default_factory=list)
    tips: list[str] = field(default_factory=list)


def duration(seconds: float, lang: str = "en") -> str:
    if seconds < 1:
        return t(lang, "d_less")
    years = seconds / 31_557_600
    if years >= 1_000_000_000:
        return t(lang, "d_billion")
    if years >= 1_000_000:
        return t(lang, "d_millions", n=int(years // 1_000_000))
    for i, size in enumerate((31_557_600, 86_400, 3_600, 60, 1)):
        if seconds >= size:
            n = int(seconds // size)
            return t(lang, "d_about", n=f"{n:,}".replace(",", " "), unit=unit(lang, i, n))
    return t(lang, "d_less")


def explain(a: Analysis, lang: str = "en") -> FriendlyReport:
    level, color = LEVELS[a.label]
    seconds = 2 ** max(a.estimated_bits - 1, 0) / OFFLINE_GUESSES_PER_SEC
    kinds = {m.kind for m in a.matches}

    bad: list[str] = []
    tips: list[str] = []
    if a.length < 8:
        bad.append(t(lang, "too_short"))
        tips.append(t(lang, "t_short"))
    elif a.length < 12:
        bad.append(t(lang, "shortish"))
    for kind in PROBLEM_KINDS:
        if kind in kinds:
            bad.append(t(lang, "p_" + KEY[kind]))
            tips.append(t(lang, "t_" + KEY[kind]))
    if any(m.leet for m in a.matches if m.kind in ("word", "common_password")):
        bad.append(t(lang, "leet"))
        tips.append(t(lang, "t_leet"))
    if a.word_plus_digits:
        bad.append(t(lang, "word_digits"))

    good: list[str] = []
    if a.length >= 12:
        good.append(t(lang, "g_length", n=a.length))
    if a.length and not kinds & {"common_password", "breached"}:
        good.append(t(lang, "g_notcommon"))
    if a.passphrase_words:
        good.append(t(lang, "g_phrase", n=a.passphrase_words))
        if level <= 3:
            tips.append(t(lang, "t_phrase"))
    if not bad and a.length:
        good.append(t(lang, "g_nopatterns"))

    if level <= 3:
        tips.append(t(lang, "t_generate"))
    tips.append(t(lang, "t_unique"))

    return FriendlyReport(t(lang, f"v{level}"), color, level, t(lang, f"h{level}"),
                          duration(seconds, lang), bad, good, list(dict.fromkeys(tips)))


def generate_password(length: int = 16) -> str:
    """Random password with letters, digits and symbols (always one of each)."""
    sets = [string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%&*?-_=+"]
    pool = "".join(sets)
    chars = [secrets.choice(s) for s in sets]
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


SYMBOLS = "!@#$%&*?-_=+"
LEET_SYMBOLS = {"a": "@", "e": "3", "i": "!", "o": "0", "s": "$", "t": "+"}
SANITIZE_KINDS = {"sequence", "repeat_char", "repeat_block", "keyboard", "year"}
TARGET_BITS = 70.0
MIN_LENGTH = 14


def _random_like(ch: str, rnd: secrets.SystemRandom) -> str:
    if ch.isdigit():
        return rnd.choice(string.digits)
    if ch.isalpha():
        return rnd.choice(string.ascii_lowercase if ch.islower() else string.ascii_uppercase)
    return rnd.choice(SYMBOLS)


def strengthen(password: str) -> str:
    """Strong password that stays recognisably similar to `password`.

    Keeps the user's base text, randomises predictable parts (years, sequences,
    repeats, keyboard walks), mixes in some capitals and symbol swaps, then
    appends random characters until the estimated strength is high enough.
    A password that is already strong is returned unchanged.
    """
    if not password:
        return generate_password(16)
    analysis = analyze(password)
    if analysis.label in ("STRONG", "VERY STRONG"):
        return password

    rnd = secrets.SystemRandom()
    chars = list(password)

    # 1. replace predictable spans with random characters of the same kind
    for m in analysis.matches:
        if m.kind in SANITIZE_KINDS:
            for i in range(m.start, m.end):
                chars[i] = _random_like(chars[i], rnd)

    # 2. a couple of capitals and symbol swaps (never touching the first character)
    letters = [i for i, c in enumerate(chars) if i > 0 and c.isalpha()]
    for i in rnd.sample(letters, min(2, len(letters))):
        chars[i] = chars[i].upper() if chars[i].islower() else chars[i]
    swappable = [i for i in letters if chars[i].lower() in LEET_SYMBOLS]
    for i in rnd.sample(swappable, min(2, len(swappable))):
        chars[i] = LEET_SYMBOLS[chars[i].lower()]

    # 3. append random characters (covering every character class) until strong
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits, SYMBOLS]
    pool = "".join(classes)
    result = "".join(chars)
    tail: list[str] = []
    for cls in classes:
        if not any(c in cls for c in result):
            tail.append(rnd.choice(cls))
    result += "".join(tail)
    while len(result) < MIN_LENGTH or analyze(result).estimated_bits < TARGET_BITS:
        result += rnd.choice(pool)
    return result


def generate_passphrase(words: int = 5, separator: str = "-") -> str:
    """Random words from the EFF list (about 12.9 bits each; five words ~ 65 bits)."""
    pool = _generator_pool()
    if not pool:
        raise RuntimeError("passphrase word list is missing")
    return separator.join(secrets.choice(pool) for _ in range(words))


@lru_cache(maxsize=1)
def _generator_pool() -> tuple[str, ...]:
    """EFF words without hyphens, so the words of "a-b-c-d-e" can always be told apart."""
    return tuple(w for w in passphrase_words() if "-" not in w)
