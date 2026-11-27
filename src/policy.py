"""Named password policies: simple pass/fail rules, checked against an Analysis.

No composition rules (forced symbols, mixed case, ...): research (e.g. NIST SP 800-63B)
shows they push people toward predictable patterns instead of real strength. Length,
estimated strength and "is this already known to attackers" are what matters.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .analyzer import Analysis, analyze
from .friendly import generate_password


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


def from_dict(data: dict, key: str = "custom") -> Policy:
    """Build a Policy from a plain dict (e.g. loaded from JSON); unknown keys are ignored."""
    return Policy(
        key=str(data.get("key", key)) or key,
        min_length=int(data.get("min_length", 12)),
        min_bits=float(data.get("min_bits", 40.0)),
        forbid_common=bool(data.get("forbid_common", True)),
        forbid_breached=bool(data.get("forbid_breached", True)),
    )


def load_file(path: str | Path) -> Policy:
    """Load a custom policy from a small JSON file, e.g.:

    {"key": "internal", "min_length": 14, "min_bits": 50, "forbid_common": true, "forbid_breached": true}

    Every field is optional; missing ones fall back to the same defaults as `Policy`.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("a policy file must contain a single JSON object")
    return from_dict(data)


def generate_compliant(policy: Policy, max_attempts: int = 20) -> str:
    """A freshly generated, random password guaranteed to satisfy `policy`.

    `generate_password` already mixes every character class, so this normally succeeds on
    the first try; the loop (bounded, never infinite) only matters for an unusually strict
    custom policy that asks for more length or strength than the default 16 characters give.
    """
    length = max(policy.min_length, 16)
    password = ""
    for _ in range(max_attempts):
        password = generate_password(length)
        if evaluate(analyze(password), policy).passed:
            return password
        length += 4
    return password
