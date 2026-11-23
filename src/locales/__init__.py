"""UI translations. Each module defines NAME, RTL, plural(), UNITS and STRINGS.

Imports are explicit so PyInstaller bundles every language.
"""

from . import ar, de, en, es, fr, ja, pt, ru, zh

# Order shown in the language menu.
LOCALES = {"en": en, "pt": pt, "es": es, "fr": fr, "de": de,
           "ru": ru, "ar": ar, "ja": ja, "zh": zh}
