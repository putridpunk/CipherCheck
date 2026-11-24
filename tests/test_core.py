import json
import math
import tempfile
import unittest
from pathlib import Path

from src import entropy, patterns, report
from src.analyzer import analyze
from src.dictionary import Dictionary, default_dictionary
from src.main import main


class EntropyTests(unittest.TestCase):
    def test_theoretical_formula(self):
        # lowercase only: pool 26
        self.assertAlmostEqual(entropy.theoretical_entropy("abcdefgh"), 8 * math.log2(26))
        self.assertEqual(entropy.theoretical_entropy(""), 0.0)

    def test_pool_size(self):
        self.assertEqual(entropy.pool_size("aA1!"), 26 + 26 + 10 + 33)

    def test_estimate_never_exceeds_theoretical(self):
        for pw in ["password123", "T7#mQ9!vLp2", "qwertyuiop", "aaaaaaaa"]:
            bits, _ = entropy.estimate_entropy(pw, patterns.find_matches(pw))
            self.assertLessEqual(bits, entropy.theoretical_entropy(pw) + 1e-9)


class PatternTests(unittest.TestCase):
    def kinds(self, pw):
        return {m.kind for m in patterns.find_matches(pw)}

    def test_sequences(self):
        self.assertIn("sequence", self.kinds("xx123xx"))
        self.assertIn("sequence", self.kinds("cba"))
        self.assertNotIn("sequence", self.kinds("T7#mQ9!vLp2"))

    def test_repeats(self):
        self.assertIn("repeat_char", self.kinds("zzzz"))
        self.assertIn("repeat_block", self.kinds("abcabc"))

    def test_keyboard(self):
        self.assertIn("keyboard", self.kinds("qwerty"))
        self.assertIn("keyboard", self.kinds("asdfgh"))

    def test_year(self):
        self.assertIn("year", self.kinds("summer1999"))


class DictionaryTests(unittest.TestCase):
    d = default_dictionary()

    def test_common_password(self):
        self.assertIsNotNone(self.d.password_rank("password"))
        self.assertIsNotNone(self.d.password_rank("PASSWORD"))

    def test_leet_normalisation(self):
        small = Dictionary(["password"], [])  # tiny list: p@ssw0rd is only reachable via leetspeak
        rank = small.password_rank("p@ssw0rd")
        self.assertEqual(rank, (1, True))

    def test_unknown(self):
        self.assertIsNone(self.d.password_rank("T7#mQ9!vLp2"))


class AnalyzerTests(unittest.TestCase):
    def test_spec_examples(self):
        self.assertEqual(analyze("password123").label, "VERY WEAK")
        # "helloworld" is itself a very common password in the bundled 100k list
        self.assertIn(analyze("HelloWorld").label, ("VERY WEAK", "WEAK"))
        self.assertIn(analyze("T7#mQ9!vLp2").label, ("STRONG", "VERY STRONG"))
        self.assertIn(analyze("correct-horse-battery").label,
                      ("MODERATE", "STRONG", "VERY STRONG"))

    def test_special_chars_do_not_imply_strength(self):
        self.assertEqual(analyze("P@ssw0rd!").label, "VERY WEAK")

    def test_passphrase_detected(self):
        texts = [f.text for f in analyze("correct-horse-battery").findings]
        self.assertTrue(any("passphrase" in t for t in texts))

    def test_short_is_capped(self):
        self.assertIn(analyze("xK9#").label, ("VERY WEAK", "WEAK"))

    def test_empty(self):
        self.assertEqual(analyze("").label, "VERY WEAK")


class ReportTests(unittest.TestCase):
    PW = "Zq7!unique-Secret-Value"

    def test_no_password_leak(self):
        a = analyze(self.PW)
        for render in report.RENDERERS.values():
            out = render(a)
            self.assertNotIn(self.PW, out)
            self.assertNotIn(self.PW.lower(), out.lower())

    def test_json_valid(self):
        data = json.loads(report.to_json(analyze("password123")))
        self.assertEqual(data["assessment"], "VERY WEAK")
        self.assertNotIn("password123", json.dumps(data))
        self.assertTrue(all(set(p) == {"kind", "length"} for p in data["patterns_detected"]))

    def test_write_report_and_bad_format(self):
        a = analyze("abc123")
        with tempfile.TemporaryDirectory() as tmp:
            for ext in ("txt", "json", "html"):
                p = report.write_report(a, Path(tmp) / f"r.{ext}")
                self.assertTrue(p.read_text(encoding="utf-8"))
            with self.assertRaises(ValueError):
                report.write_report(a, Path(tmp) / "r.pdf")


class CliTests(unittest.TestCase):
    def test_batch_aggregate(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "in.txt"
            src.write_text("password\nqwerty\nT7#mQ9!vLp2\n", encoding="utf-8")
            out = Path(tmp) / "agg.json"
            self.assertEqual(main(["-f", str(src), "-r", str(out), "-q"]), 0)
            text = out.read_text(encoding="utf-8")
            self.assertEqual(json.loads(text)["total"], 3)
            self.assertNotIn("secretmarker", text)


if __name__ == "__main__":
    unittest.main()
