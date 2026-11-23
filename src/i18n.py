"""Tiny translation layer. English is the fallback for any missing key."""

from __future__ import annotations

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
