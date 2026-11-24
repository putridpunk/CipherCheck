"""Hash-format identification and plain-language security notes.

Only the *shape* of a string is inspected. Nothing is cracked or reversed, and a
match is a hint, never proof of where a hash came from: many algorithms produce
output of the same length, and any string can be made to look like a hash.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .i18n import t

# status: "weak"   fast, unsuitable for password storage
#         "ok"     acceptable when configured with enough work
#         "strong" purpose-built password hash
# salted: True (built in), False (none), None (depends on how it is used)


@dataclass(frozen=True)
class Candidate:
    name: str
    status: str
    salted: bool | None
    detail: str = ""


def _c(name: str, status: str, salted: bool | None, detail: str = "") -> list[Candidate]:
    return [Candidate(name, status, salted, detail)]


# (regex, builder(match) -> candidates). Prefixed formats first: they are unambiguous.
_PREFIXED = [
    (re.compile(r"^\$2([abxy])?\$(\d\d)\$[./A-Za-z0-9]{53}$"),
     lambda m: _c("bcrypt", "strong", True, f"cost={int(m.group(2))}")),
    (re.compile(r"^\$argon2(id|i|d)\$"),
     lambda m: _c(f"Argon2{m.group(1)}", "strong", True)),
    (re.compile(r"^\$(?:scrypt|7)\$"), lambda m: _c("scrypt", "strong", True)),
    (re.compile(r"^\$y\$"), lambda m: _c("yescrypt", "strong", True)),
    (re.compile(r"^\$6\$(?:rounds=(\d+)\$)?"),
     lambda m: _c("SHA-512 crypt", "ok", True, f"rounds={m.group(1)}" if m.group(1) else "")),
    (re.compile(r"^\$5\$(?:rounds=(\d+)\$)?"),
     lambda m: _c("SHA-256 crypt", "ok", True, f"rounds={m.group(1)}" if m.group(1) else "")),
    (re.compile(r"^\$1\$"), lambda m: _c("MD5 crypt", "weak", True)),
    (re.compile(r"^\$apr1\$"), lambda m: _c("Apache MD5 (apr1)", "weak", True)),
    (re.compile(r"^\$[PH]\$"), lambda m: _c("phpass (WordPress/phpBB)", "ok", True)),
    (re.compile(r"^pbkdf2_(sha1|sha256)\$(\d+)\$"),
     lambda m: _c(f"PBKDF2-{m.group(1).upper().replace('SHA', 'SHA-')} (Django)", "ok", True,
                  f"iterations={m.group(2)}")),
    (re.compile(r"^\$pbkdf2-(sha1|sha256|sha512)\$(\d+)\$"),
     lambda m: _c(f"PBKDF2-{m.group(1).upper().replace('SHA', 'SHA-')}", "ok", True,
                  f"iterations={m.group(2)}")),
    (re.compile(r"^\*[0-9A-Fa-f]{40}$"), lambda m: _c("MySQL 4.1+ (double SHA-1)", "weak", False)),
]

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_BY_LENGTH: dict[int, list[Candidate]] = {
    8: [Candidate("CRC32 (a checksum, not a cryptographic hash)", "weak", False)],
    16: [Candidate("MySQL (pre-4.1)", "weak", False),
         Candidate("Half of an MD5 hash", "weak", None)],
    32: [Candidate("MD5", "weak", None), Candidate("NTLM (Windows)", "weak", False),
         Candidate("MD4", "weak", None), Candidate("LM (old Windows)", "weak", False)],
    40: [Candidate("SHA-1", "weak", None), Candidate("RIPEMD-160", "weak", None)],
    56: [Candidate("SHA-224", "weak", None), Candidate("SHA3-224", "weak", None)],
    64: [Candidate("SHA-256", "weak", None), Candidate("SHA3-256", "weak", None),
         Candidate("BLAKE2s", "weak", None)],
    96: [Candidate("SHA-384", "weak", None), Candidate("SHA3-384", "weak", None)],
    128: [Candidate("SHA-512", "weak", None), Candidate("SHA3-512", "weak", None),
          Candidate("Whirlpool", "weak", None), Candidate("BLAKE2b", "weak", None)],
}


def identify(text: str) -> list[Candidate]:
    """Possible formats for `text`, most likely first. Empty list if unrecognised."""
    s = text.strip()
    if not s:
        return []
    for pattern, build in _PREFIXED:
        m = pattern.match(s)
        if m:
            return build(m)
    if _HEX.match(s):
        return list(_BY_LENGTH.get(len(s), []))
    return []


def explain(candidates: list[Candidate], lang: str = "en") -> list[tuple[str, str]]:
    """(style_tag, line) pairs ready to show in a text view."""
    if not candidates:
        return [("bad", t(lang, "hash_unknown")), ("idle", ""), ("idle", t(lang, "hash_note"))]
    lines: list[tuple[str, str]] = [("head", t(lang, "hash_hdr"))]
    if len(candidates) > 1:
        lines.append(("idle", t(lang, "hash_ambig")))
    for c in candidates:
        tag = {"weak": "bad", "ok": "tip", "strong": "good"}[c.status]
        marker = {"weak": "-", "ok": "~", "strong": "+"}[c.status]
        title = f" [{marker}] {c.name}"
        if c.detail:
            title += f"  ({c.detail})"
        lines.append((tag, title))
        lines.append(("idle", "      " + t(lang, "hs_" + c.status)))
        salt = {True: "salt_yes", False: "salt_no", None: "salt_depends"}[c.salted]
        lines.append(("idle", "      " + t(lang, salt)))
    lines += [("idle", ""), ("idle", t(lang, "hash_note"))]
    return lines


def to_text(text: str, lang: str = "en") -> str:
    return "\n".join(line for _, line in explain(identify(text), lang))
