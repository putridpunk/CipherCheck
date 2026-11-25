"""Named password policies: simple pass/fail rules, checked against an Analysis.

No composition rules (forced symbols, mixed case, ...): research (e.g. NIST SP 800-63B)
shows they push people toward predictable patterns instead of real strength. Length,
estimated strength and "is this already known to attackers" are what matters.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .analyzer import Analysis


@dataclass(frozen=True)
class Policy:
    key: str
    min_length: int = 12
    min_bits: float = 40.0
    forbid_common: bool = True
    forbid_breached: bool = True


PRESETS: dict[str, Policy] = {
    "basic": Policy("basic", min_length=8, min_bits=28.0),
    "nist": Policy("nist", min_length=8, min_bits=0.0, forbid_common=True, forbid_breached=True),
    "strong": Policy("strong", min_length=12, min_bits=60.0),
}

REASONS = ("too_short", "weak", "common", "breached")


@dataclass
class PolicyResult:
    passed: bool
    reasons: list[str] = field(default_factory=list)


def evaluate(a: Analysis, policy: Policy) -> PolicyResult:
    reasons: list[str] = []
    if a.length < policy.min_length:
        reasons.append("too_short")
    if a.estimated_bits < policy.min_bits:
        reasons.append("weak")
    kinds = set(a.pattern_kinds)
    if policy.forbid_common and "common_password" in kinds:
        reasons.append("common")
    if policy.forbid_breached and "breached" in kinds:
        reasons.append("breached")
    return PolicyResult(not reasons, reasons)
