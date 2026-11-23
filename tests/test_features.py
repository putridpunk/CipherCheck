import json
import unittest

from src import hashes, report
from src.analyzer import analyze
from src.i18n import LANGUAGES
from src.main import main
from src.vulnerabilities import assess, risk_level


class HashTests(unittest.TestCase):
    def names(self, s):
        return [c.name for c in hashes.identify(s)]

    def test_md5_is_ambiguous(self):
        names = self.names("5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertIn("MD5", names)
        self.assertIn("NTLM (Windows)", names)
        self.assertGreater(len(names), 1)

    def test_lengths(self):
        self.assertIn("SHA-1", self.names("a" * 40))
        self.assertIn("SHA-256", self.names("b" * 64))
        self.assertIn("SHA-512", self.names("c" * 128))

    def test_bcrypt_is_strong_and_parsed(self):
        (c,) = hashes.identify("$2b$12$" + "a" * 53)
        self.assertEqual((c.name, c.status, c.salted, c.detail), ("bcrypt", "strong", True, "cost=12"))

    def test_other_prefixed_formats(self):
        self.assertEqual(hashes.identify("$argon2id$v=19$m=65536,t=3,p=4$abc$def")[0].name, "Argon2id")
        self.assertEqual(hashes.identify("$6$salt$" + "x" * 86)[0].name, "SHA-512 crypt")
        self.assertEqual(hashes.identify("$1$salt$abcdefghijklmnopqrstuv")[0].status, "weak")
        self.assertEqual(hashes.identify("pbkdf2_sha256$600000$salt$hash")[0].detail, "iterations=600000")

    def test_unrecognised(self):
        for s in ("", "hello world", "zz" * 16, "abc"):
            self.assertEqual(hashes.identify(s), [], s)

    def test_never_claims_origin_and_works_in_every_language(self):
        for lang in LANGUAGES:
            lines = [ln for _, ln in hashes.explain(hashes.identify("a" * 32), lang)]
            self.assertTrue(any(lines), lang)
            self.assertGreater(len(lines), 5, lang)
        self.assertIn("not proof", hashes.to_text("a" * 32))

    def test_cli(self):
        self.assertEqual(main(["--hash", "5f4dcc3b5aa765d61d8327deb882cf99"]), 0)


class VulnerabilityTests(unittest.TestCase):
    def test_common_password_is_critical(self):
        v = assess(analyze("password123"))
        self.assertEqual(v[0].severity, "critical")
        self.assertEqual(risk_level(analyze("password123")), "Critical")

    def test_categories_for_patterns(self):
        cats = {x.category for x in assess(analyze("qwerty1998abc"))}
        self.assertIn("Predictable patterns", cats)
        self.assertIn("Personal information", cats)

    def test_strong_password_has_none(self):
        a = analyze("T7#mQ9!vLp2xK4")
        self.assertEqual(assess(a), [])
        self.assertEqual(risk_level(a), "Low")

    def test_sorted_by_severity(self):
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sev = [order[x.severity] for x in assess(analyze("Password2024"))]
        self.assertEqual(sev, sorted(sev))

    def test_reports_include_vulnerabilities_without_password(self):
        pw = "Summer2024!"
        a = analyze(pw)
        data = json.loads(report.to_json(a))
        self.assertTrue(data["vulnerabilities"])
        self.assertIn("risk_level", data)
        for render in report.RENDERERS.values():
            out = render(a)
            self.assertIn("ulnerabilit", out)
            self.assertNotIn(pw, out)


if __name__ == "__main__":
    unittest.main()
