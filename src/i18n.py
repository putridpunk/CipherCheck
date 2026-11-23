"""Tiny translation layer. English is the fallback for any missing key."""

from __future__ import annotations

import os

from .locales import LOCALES

DEFAULT_LANG = "en"
LANGUAGES = {code: mod.NAME for code, mod in LOCALES.items()}


def t(lang: str, key: str, **kw) -> str:
    text = LOCALES.get(lang, LOCALES[DEFAULT_LANG]).STRINGS.get(key)
    if text is None:
        text = LOCALES[DEFAULT_LANG].STRINGS[key]
    return text.format(**kw) if kw else text


def is_rtl(lang: str) -> bool:
    return LOCALES.get(lang, LOCALES[DEFAULT_LANG]).RTL


def unit(lang: str, index: int, n: int) -> str:
    """Name of time unit (0=year,1=day,2=hour,3=minute,4=second) agreeing with n."""
    mod = LOCALES.get(lang, LOCALES[DEFAULT_LANG])
    forms = mod.UNITS[index]
    return forms[min(mod.plural(n), len(forms) - 1)]


def detect_language() -> str:
    """Best guess of the user's language from the operating system."""
    candidates: list[str] = []
    try:  # Windows UI language
        import ctypes
        buf = ctypes.create_unicode_buffer(85)
        if ctypes.windll.kernel32.GetUserDefaultLocaleName(buf, 85):
            candidates.append(buf.value)
    except Exception:
        pass
    candidates += [os.environ.get(v, "") for v in ("LC_ALL", "LC_MESSAGES", "LANG")]
    for c in candidates:
        code = c.lower().replace("_", "-").split("-")[0]
        if code in LOCALES:
            return code
    return DEFAULT_LANG
