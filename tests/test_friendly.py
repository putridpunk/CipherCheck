import re
import unittest

from src.analyzer import analyze
from src.friendly import duration, explain, generate_password
from src.i18n import LANGUAGES, t
from src.locales import LOCALES
from src.locales import en as master

PLACEHOLDER = re.compile(r"\{(\w+)\}")


class LocaleTests(unittest.TestCase):
    def test_nine_languages(self):
        self.assertEqual(set(LANGUAGES), {"en", "pt", "es", "fr", "de", "ru", "ar", "ja", "zh"})

    def test_every_locale_has_every_key(self):
        for code, mod in LOCALES.items():
            self.assertEqual(set(mod.STRINGS), set(master.STRINGS), code)

    def test_placeholders_match_english(self):
        for code, mod in LOCALES.items():
            for key, text in mod.STRINGS.items():
                self.assertEqual(set(PLACEHOLDER.findall(text)),
                                 set(PLACEHOLDER.findall(master.STRINGS[key])), f"{code}.{key}")

    def test_units_complete(self):
        for code, mod in LOCALES.items():
            self.assertEqual(len(mod.UNITS), 5, code)
            for n in (1, 2, 5, 11, 21, 100):
                self.assertIsInstance(mod.plural(n), int)
                self.assertLess(mod.plural(n), len(mod.UNITS[0]) + 4)  # sanity
                self.assertLess(min(mod.plural(n), len(mod.UNITS[0]) - 1), len(mod.UNITS[0]))

    def test_unknown_language_falls_back_to_english(self):
        self.assertEqual(t("xx", "copy"), "COPY")


class FriendlyTests(unittest.TestCase):
    def test_verdicts_per_language(self):
        self.assertEqual(explain(analyze("password123"), "pt").verdict, "MUITO FRACA")
        self.assertEqual(explain(analyze("password123"), "en").verdict, "VERY WEAK")
        self.assertEqual(explain(analyze("T7#mQ9!vLp2"), "de").verdict, "STARK")
        self.assertEqual(explain(analyze("T7#mQ9!vLp2"), "ja").verdict, "強い")

    def test_all_languages_render(self):
        for code in LOCALES:
            for pw in ("password123", "P@ssw0rd2024", "T7#mQ9!vLp2", "correct-horse-battery", "a"):
                r = explain(analyze(pw), code)
                self.assertTrue(r.verdict and r.headline and r.crack_time and r.tips, code)

    def test_no_jargon_in_english(self):
        r = explain(analyze("P@ssw0rd123"), "en")
        text = " ".join(r.bad + r.good + r.tips).lower()
        for word in ("entropy", "bits", "hash", "dictionary"):
            self.assertNotIn(word, text)

    def test_password_not_echoed(self):
        pw = "Zq7!unique-Secret-Value"
        for code in LOCALES:
            r = explain(analyze(pw), code)
            self.assertNotIn(pw.lower(), " ".join(r.bad + r.good + r.tips + [r.headline]).lower())

    def test_duration(self):
        self.assertEqual(duration(0.1, "pt"), "menos de 1 segundo")
        self.assertIn("minutos", duration(720, "pt"))
        self.assertIn("minutes", duration(720, "en"))
        self.assertIn("billion", duration(1e30, "en"))
        self.assertEqual(duration(3 * 3600, "ru"), "около 3 часа")
        self.assertEqual(duration(5 * 3600, "ru"), "около 5 часов")
        self.assertEqual(duration(90, "zh"), "大约 1 分钟")

    def test_generator(self):
        pw = generate_password(16)
        self.assertEqual(len(pw), 16)
        self.assertNotEqual(pw, generate_password(16))
        self.assertIn(explain(analyze(pw)).level, (4, 5))


if __name__ == "__main__":
    unittest.main()
