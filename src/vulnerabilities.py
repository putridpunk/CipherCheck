"""Turns an Analysis into categorised weaknesses with explanations and fixes.

Used by the detailed reports. Output never contains any part of the password.
"""

from __future__ import annotations

from dataclasses import dataclass

from .analyzer import Analysis

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass(frozen=True)
class Vulnerability:
    category: str
    severity: str  # critical | high | medium | low
    title: str
    explanation: str
    recommendation: str

    def to_dict(self) -> dict:
        return {"category": self.category, "severity": self.severity, "title": self.title,
                "explanation": self.explanation, "recommendation": self.recommendation}


def assess(a: Analysis) -> list[Vulnerability]:
    kinds = {m.kind for m in a.matches}
    out: list[Vulnerability] = []

    if "common_password" in kinds:
        out.append(Vulnerability(
            "Known / breached passwords", "critical", "Password appears in a common-password list",
            "Attackers try the most popular passwords first, so this one is typically guessed "
            "within the first few attempts, online or offline.",
            "Choose a password that is not on any popular list; use a password manager to generate it."))
    if "breached" in kinds:
        out.append(Vulnerability(
            "Known / breached passwords", "critical", "Password found in a leaked-password list",
            "This exact password is in a collection of leaked passwords that attackers use as a "
            "ready-made guess list; it can be found almost immediately.",
            "Stop using it everywhere and replace it with a new, unique password."))
    if "personal" in kinds:
        out.append(Vulnerability(
            "Personal information", "critical", "Contains your own personal information",
            "Names, dates and other facts about you are the first thing someone who knows you, "
            "or can find you online, will try; they are not secret, whatever their length.",
            "Never build a password from your own name, birth date, pet or similar facts."))
    if "banned" in kinds:
        out.append(Vulnerability(
            "Personal information", "critical", "Contains an organization-banned word",
            "Your organization's name or products are the first thing an attacker who knows "
            "where you work will try; they are not secret, whatever their length.",
            "Never build a password from your organization's name or products."))
    if a.length < 8:
        out.append(Vulnerability(
            "Length", "high", "Password is very short",
            f"At {a.length} characters the search space is small enough to exhaust quickly, "
            "whatever characters are used.",
            "Use at least 12 characters (14+ for important accounts); length adds the most strength."))
    elif a.length < 12:
        out.append(Vulnerability(
            "Length", "medium", "Password is shorter than recommended",
            f"{a.length} characters is borderline against modern offline cracking.",
            "Aim for 12 or more characters, or a passphrase of 4+ random words."))
    if "word" in kinds:
        out.append(Vulnerability(
            "Dictionary words", "high" if a.estimated_bits < 40 else "medium",
            "Contains common words",
            "Cracking tools combine word lists with rules (capitals, digits, suffixes), so words "
            "add much less strength than their length suggests.",
            "Avoid names and everyday words, or combine 4+ unrelated random words."))
    if a.word_plus_digits:
        out.append(Vulnerability(
            "Predictable structure", "medium", "Word followed by digits/symbols",
            "'Word + number' is one of the first mutation rules attackers apply.",
            "Do not just append numbers or punctuation to a word."))
    if kinds & {"sequence", "repeat_char", "repeat_block"}:
        out.append(Vulnerability(
            "Predictable patterns", "medium", "Contains sequences or repetition",
            "Runs such as 123, abc, aaa or abcabc are tested early by pattern-aware attacks and "
            "contribute little unpredictability.",
            "Replace sequences and repetition with unrelated characters."))
    if "keyboard" in kinds:
        out.append(Vulnerability(
            "Predictable patterns", "medium", "Contains keyboard walks",
            "Adjacent-key patterns (qwerty, asdf, 1qaz) are included in standard attack dictionaries.",
            "Avoid following the layout of the keyboard."))
    if "year" in kinds:
        out.append(Vulnerability(
            "Personal information", "low", "Contains a year or date",
            "Birth years and recent years are easy to guess and often discoverable from public information.",
            "Do not use dates of birth, anniversaries or the current year."))
    if any(m.leet for m in a.matches if m.kind in ("word", "common_password")):
        out.append(Vulnerability(
            "Predictable substitutions", "low", "Uses common character substitutions",
            "Swaps such as a->@ and o->0 are built into cracking rule sets and add almost no strength.",
            "Prefer length and randomness over symbol substitutions."))
    return sorted(out, key=lambda v: SEVERITY_ORDER[v.severity])


def risk_level(a: Analysis) -> str:
    return {"VERY WEAK": "Critical", "WEAK": "High", "MODERATE": "Medium",
            "STRONG": "Low", "VERY STRONG": "Low"}[a.label]
