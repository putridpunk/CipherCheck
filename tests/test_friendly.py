import unittest

from src.analyzer import analyze
from src.friendly import duration_pt, explain, generate_password


class FriendlyTests(unittest.TestCase):
    def test_verdicts_in_portuguese(self):
        self.assertEqual(explain(analyze("password123")).verdict, "MUITO FRACA")
        self.assertEqual(explain(analyze("T7#mQ9!vLp2")).verdict, "FORTE")

    def test_no_jargon(self):
        r = explain(analyze("P@ssw0rd123"))
        text = " ".join(r.bad + r.good + r.tips).lower()
        for word in ("entropy", "entropia", "bits", "hash", "dicionário"):
            self.assertNotIn(word, text)
        self.assertTrue(r.bad and r.tips)

    def test_password_not_echoed(self):
        pw = "Zq7!unique-Secret-Value"
        r = explain(analyze(pw))
        self.assertNotIn(pw.lower(), " ".join(r.bad + r.good + r.tips + [r.headline]).lower())

    def test_duration(self):
        self.assertEqual(duration_pt(0.1), "menos de 1 segundo")
        self.assertIn("minutos", duration_pt(720))
        self.assertIn("mil milhões", duration_pt(1e30))

    def test_generator(self):
        pw = generate_password(16)
        self.assertEqual(len(pw), 16)
        self.assertNotEqual(pw, generate_password(16))
        self.assertIn(explain(analyze(pw)).verdict, ("FORTE", "MUITO FORTE"))


if __name__ == "__main__":
    unittest.main()
