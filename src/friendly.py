"""Plain-language, translated presentation of an Analysis, for the GUI.

No jargon is shown to the user (no "entropy", "bits", "hash", "dictionary").
All text lives in src/locales/.
"""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass, field

from .analyzer import Analysis
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
PROBLEM_KINDS = ("common_password", "word", "sequence", "repeat_char",
                 "repeat_block", "keyboard", "year")
KEY = {"common_password": "common", "word": "word", "sequence": "sequence",
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
    if a.length and "common_password" not in kinds:
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
