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


class BreachTests(unittest.TestCase):
    def test_known_leaked_password_detected(self):
        from src.breach import default_breach_db
        db = default_breach_db()
        self.assertIsNotNone(db)
        self.assertGreater(db.size, 900_000)
        self.assertTrue(db.contains("sunshine99"))
        self.assertFalse(db.contains("Zq7!unique-Secret-Value-never-leaked"))

    def test_breached_kind_and_report(self):
        a = analyze("sunshine99")
        self.assertIn("breached", a.pattern_kinds)
        self.assertEqual(a.label, "VERY WEAK")
        cats = {v.title for v in assess(a)}
        self.assertIn("Password found in a leaked-password list", cats)

    def test_small_custom_index(self):
        import hashlib
        from src.breach import BreachDB, PREFIX_BYTES
        keys = sorted(hashlib.sha1(w.encode()).digest()[:PREFIX_BYTES] for w in ("alpha", "beta", "gamma"))
        db = BreachDB(b"".join(keys))
        self.assertTrue(db.contains("beta"))
        self.assertFalse(db.contains("delta"))
        with self.assertRaises(ValueError):
            BreachDB(b"12345")


class AggregateReportTests(unittest.TestCase):
    def test_all_formats_without_passwords(self):
        import tempfile
        from pathlib import Path
        pws = ["password", "sunshine99", "unique-marker-Zq7!x", "T7#mQ9!vLp2xK4"]
        agg = report.aggregate([analyze(p) for p in pws])
        self.assertEqual(agg["total"], 4)
        self.assertTrue(agg["most_common_problems"])
        with tempfile.TemporaryDirectory() as tmp:
            for ext in ("txt", "json", "html"):
                out = report.write_aggregate(agg, Path(tmp) / f"a.{ext}").read_text(encoding="utf-8")
                self.assertIn("4", out)
                self.assertNotIn("unique-marker", out)
            with self.assertRaises(ValueError):
                report.write_aggregate(agg, Path(tmp) / "a.pdf")


class SettingsTests(unittest.TestCase):
    def test_roundtrip_and_corruption(self):
        import os
        import tempfile
        from pathlib import Path
        from src import settings
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["CIPHERCHECK_CONFIG_DIR"] = tmp
            try:
                self.assertEqual(settings.load(), {})
                self.assertTrue(settings.save(language="de"))
                self.assertEqual(settings.load()["language"], "de")
                (Path(tmp) / "settings.json").write_text("{broken", encoding="utf-8")
                self.assertEqual(settings.load(), {})
            finally:
                del os.environ["CIPHERCHECK_CONFIG_DIR"]


class PassphraseTests(unittest.TestCase):
    def test_generator(self):
        from src.dictionary import passphrase_words
        from src.friendly import generate_passphrase
        self.assertEqual(len(passphrase_words()), 7776)
        p = generate_passphrase(5)
        self.assertEqual(len(p.split("-")), 5)  # the generator never picks hyphenated words
        self.assertNotEqual(p, generate_passphrase(5))
        self.assertTrue(all(w in passphrase_words() for w in p.split("-")))
        self.assertIn(analyze(p).label, ("STRONG", "VERY STRONG"))

    def test_cli(self):
        self.assertEqual(main(["--passphrase"]), 0)
        self.assertEqual(main(["--passphrase", "2"]), 2)


class ReuseTests(unittest.TestCase):
    def test_base_word(self):
        from src.reuse import base_word
        self.assertEqual(base_word("Summer2024!"), base_word("summer2025"))
        self.assertEqual(base_word("P@ssw0rd"), base_word("password1"))

    def test_tracker_counts(self):
        from src.reuse import ReuseTracker
        t = ReuseTracker()
        for pw in ["Summer2024!", "summer2025", "Summer2024!", "Zq7!unique-Secret", "abc"]:
            t.add(pw)
        s = t.summary()
        self.assertEqual(s["exact_duplicates"], 2)
        self.assertEqual(s["similar_to_another"], 3)
        self.assertEqual(s["similar_groups"], 1)

    def test_in_aggregate(self):
        from src.reuse import ReuseTracker
        pws = ["Summer2024!", "summer2025", "Zq7!unique-Secret"]
        t = ReuseTracker()
        for p in pws:
            t.add(p)
        agg = report.aggregate([analyze(p) for p in pws], t.summary())
        self.assertEqual(agg["reuse"]["similar_to_another"], 2)
        self.assertIn("Near-copies", report.aggregate_text(agg))


class CliLanguageTests(unittest.TestCase):
    def test_friendly_output_in_every_language(self):
        for lang in LANGUAGES:
            out = report.to_friendly_text(analyze("Summer2024!"), lang)
            self.assertIn("CIPHERCHECK", out)
            self.assertNotIn("Summer2024!", out)
            self.assertIn("/100", out)

    def test_cli_lang_and_hash(self):
        self.assertEqual(main(["-p", "password", "--lang", "ar", "-q"]), 0)
        self.assertEqual(main(["--hash", "a" * 32, "--lang", "ja"]), 0)

    def test_txt_report_in_language(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            out = report.write_report(analyze("password"), Path(tmp) / "r.txt", lang="pt")
            self.assertIn("MUITO FRACA", out.read_text(encoding="utf-8"))


class AuditFileTests(unittest.TestCase):
    PASSWORDS = (["password", "sunshine99", "Summer2024!", "summer2025", "qwerty", "hello"] * 40
                 + ["Zq7!unique-Secret-Value", "T7#mQ9!vLp2xK4", "correct-horse-battery-staple"] * 10)

    def _file(self, tmp):
        from pathlib import Path
        path = Path(tmp) / "synthetic.txt"
        path.write_text("\n".join(self.PASSWORDS) + "\n", encoding="utf-8")
        return path

    def test_parallel_matches_single_process(self):
        import tempfile
        from src.audit import audit_file
        with tempfile.TemporaryDirectory() as tmp:
            path = self._file(tmp)
            single = audit_file(path, workers=1)
            parallel = audit_file(path, workers=2, chunk_lines=37)
        for key in ("total", "assessment_counts", "pattern_counts", "reuse",
                    "average_estimated_bits", "average_length"):
            self.assertEqual(single[key], parallel[key], key)
        self.assertEqual(single["total"], len(self.PASSWORDS))
        self.assertGreater(single["reuse"]["exact_duplicates"], 0)
        self.assertGreater(single["reuse"]["similar_to_another"], 0)

    def test_progress_and_cancel(self):
        import tempfile
        import threading
        from src.audit import audit_file
        with tempfile.TemporaryDirectory() as tmp:
            path = self._file(tmp)
            calls = []
            audit_file(path, workers=1, chunk_lines=50, progress=lambda n, f: calls.append((n, f)))
            self.assertGreater(len(calls), 3)
            self.assertAlmostEqual(calls[-1][1], 1.0)
            self.assertEqual(calls[-1][0], len(self.PASSWORDS))
            done = threading.Event()
            done.set()
            self.assertIsNone(audit_file(path, workers=1, cancel=done))
            self.assertIsNone(audit_file(path, workers=2, chunk_lines=20, cancel=done))

    def test_missing_file_and_empty_lines(self):
        import tempfile
        from pathlib import Path
        from src.audit import audit_file
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(OSError):
                audit_file(Path(tmp) / "nope.txt")
            empty = Path(tmp) / "empty.txt"
            empty.write_text("\n\n", encoding="utf-8")
            self.assertEqual(audit_file(empty)["total"], 0)

    def test_stable_hash_and_merge(self):
        from src.reuse import ReuseTracker, stable_hash
        self.assertEqual(stable_hash("abc"), stable_hash("abc"))
        a, b = ReuseTracker(), ReuseTracker()
        a.add("Summer2024!")
        b.add("summer2025")
        b.add("Summer2024!")
        a.merge(b)
        s = a.summary()
        self.assertEqual((s["exact_duplicates"], s["similar_to_another"]), (2, 3))

    def test_cli_jobs_option(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = self._file(tmp)
            self.assertEqual(main(["-f", str(path), "-j", "1", "-q"]), 0)


if __name__ == "__main__":
    unittest.main()
