"""Combines every module into a single password assessment."""

from __future__ import annotations

from dataclasses import dataclass, field

from . import banned as banned_mod
from . import entropy, patterns
from . import profile as profile_mod
from .breach import BREACH_BITS, BreachDB, default_breach_db
from .dictionary import Dictionary, default_dictionary
from .patterns import Match
from .utils import DIGITS, LOWER, SYMBOLS, UPPER

LABELS = [(28, "VERY WEAK"), (40, "WEAK"), (60, "MODERATE"), (80, "STRONG")]
TOP_LABEL = "VERY STRONG"
LABEL_ORDER = [lbl for _, lbl in LABELS] + [TOP_LABEL]
MIN_RECOMMENDED_LENGTH = 12

PATTERN_TEXT = {
    "sequence": "Contains predictable sequence(s) (e.g. 123, abc)",
    "repeat_char": "Contains repeated characters",
    "repeat_block": "Contains a repeated sequence of characters",
    "keyboard": "Contains keyboard pattern(s) (e.g. qwerty, asdf)",
    "year": "Contains a year-like number",
    "word": "Contains common dictionary word(s)",
    "common_password": "Matches a commonly used password",
    "breached": "Appears in a list of leaked passwords",
    "personal": "Contains your own personal information (name, date, etc.)",
    "banned": "Contains a word your organization has banned (e.g. its name or a product)",
}
PATTERN_ADVICE = {
    "sequence": "Avoid predictable sequences.",
    "repeat_char": "Avoid repeating the same character.",
    "repeat_block": "Avoid repeating blocks of characters.",
    "keyboard": "Avoid keyboard walks such as qwerty or asdf.",
    "year": "Avoid birth years and other dates.",
    "word": "Avoid commonly used words.",
    "common_password": "Never use passwords that appear in breach lists.",
    "breached": "Never reuse a password that has leaked; create a new one.",
    "personal": "Never use names, dates or other facts about yourself; they are the first thing "
                "someone who knows you (or finds you online) will try.",
    "banned": "Never build a password from your organization's name or products; they are the "
              "first thing an attacker who knows where you work will try.",
}


@dataclass
class Finding:
    level: str  # "+" good, "-" weakness, "~" informational
    text: str


@dataclass
class Analysis:
    """Result of auditing one password. Never stores the password itself."""

    length: int
    pool_size: int
    theoretical_bits: float
    estimated_bits: float
    score: int
    label: str
    crack_time: dict[str, str]
    findings: list[Finding] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    matches: list[Match] = field(default_factory=list)
    passphrase_words: int = 0
    word_plus_digits: bool = False

    @property
    def pattern_kinds(self) -> list[str]:
        return sorted({m.kind for m in self.matches if m.kind != "separator"})


def _label(bits: float) -> str:
    for limit, name in LABELS:
        if bits < limit:
            return name
    return TOP_LABEL


def analyze(password: str, dictionary: Dictionary | None = None,
            breach_db: BreachDB | None = None, profile: list[str] | None = None,
            banned: list[str] | None = None) -> Analysis:
    dictionary = dictionary or default_dictionary()
    breach_db = breach_db or default_breach_db()
    n = len(password)
    all_matches = patterns.find_matches(password) + dictionary.find_matches(password)
    if profile:
        all_matches += profile_mod.find_matches(password, profile)
    if banned:
        all_matches += banned_mod.find_matches(password, banned)
    # A lone - _ . or space between two dictionary words is one of ~4 common separators,
    # not a free choice among all symbols (matters for passphrases).
    word_starts = {m.start for m in all_matches if m.kind == "word"}
    word_ends = {m.end for m in all_matches if m.kind == "word"}
    for i, ch in enumerate(password):
        if ch in "-_. " and i in word_ends and i + 1 in word_starts:
            all_matches.append(Match("separator", i, i + 1, 2.0))
    if (password and breach_db and breach_db.contains(password)
            and not any(m.kind == "common_password" for m in all_matches)):
        all_matches.append(Match("breached", 0, n, BREACH_BITS))
    est_bits, used = entropy.estimate_entropy(password, all_matches)
    theo_bits = entropy.theoretical_entropy(password)
    label = _label(est_bits)
    if n < 8 and LABEL_ORDER.index(label) > LABEL_ORDER.index("WEAK"):
        label = "WEAK"  # very short passwords are never better than weak
    if n == 0:
        label = "VERY WEAK"

    findings: list[Finding] = []
    recs: list[str] = []

    # --- length and character classes (informational, not decisive) ---
    if n >= MIN_RECOMMENDED_LENGTH:
        findings.append(Finding("+", f"Length: {n} characters"))
    elif n >= 8:
        findings.append(Finding("~", f"Length: {n} characters (12+ recommended)"))
    else:
        findings.append(Finding("-", f"Length: {n} characters (too short)"))
        recs.append("Use at least 12 characters; length matters more than complexity.")
    for name, charset in (("uppercase", UPPER), ("lowercase", LOWER),
                          ("numeric", DIGITS), ("special", SYMBOLS)):
        has = any(c in charset for c in password)
        findings.append(Finding("+" if has else "~",
                                f"Contains {name} characters" if has
                                else f"No {name} characters"))

    # --- patterns ---
    kinds = {m.kind for m in all_matches}
    for kind in ("common_password", "breached", "personal", "banned", "word", "sequence",
                 "repeat_char", "repeat_block", "keyboard", "year"):
        if kind in kinds:
            findings.append(Finding("-", PATTERN_TEXT[kind]))
            recs.append(PATTERN_ADVICE[kind])
    if any(m.leet for m in all_matches if m.kind in ("word", "common_password")):
        findings.append(Finding("-", "Uses predictable character substitutions (a->@, o->0, ...)"))
        recs.append("Substitutions like a->@ or o->0 are well known to attackers and add almost no strength.")
    wpd = patterns.word_plus_digits(password, [m for m in used if m.kind == "word"])
    if wpd:
        findings.append(Finding("-", "Common word followed by numbers"))
        recs.append("Do not just append digits to a word.")

    words_used = [m for m in used if m.kind == "word"]
    if len(words_used) >= 3 and not (kinds & {"common_password"}):
        findings.append(Finding("+", f"Looks like a passphrase ({len(words_used)} words)"))
        if est_bits < 60:
            recs.append("Add more random words to your passphrase (4-5+ recommended).")

    if LABEL_ORDER.index(label) <= LABEL_ORDER.index("MODERATE"):
        recs.append("Use a longer passphrase of random words, or a password-manager generated password.")
    recs.append("Use a unique password for every account, ideally from a password manager.")

    return Analysis(
        length=n,
        pool_size=entropy.pool_size(password),
        theoretical_bits=round(theo_bits, 1),
        estimated_bits=round(est_bits, 1),
        score=min(100, round(est_bits * 100 / 80)),
        label=label,
        crack_time=entropy.crack_time(est_bits),
        findings=findings,
        recommendations=list(dict.fromkeys(recs)),
        matches=all_matches,
        passphrase_words=len(words_used) if len(words_used) >= 3 and "common_password" not in kinds else 0,
        word_plus_digits=wpd,
    )
