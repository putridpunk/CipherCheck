"""Tests for the five organisation-audit features: delimiter-flexible CSV/TSV import,
banned words, per-account profiles, comparing two files directly, and the remediation
CSV export.
"""

import csv
import json
import os
import sys
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from unittest import mock

from src import banned, profile, report
from src.analyzer import analyze
from src.audit import audit_file
from src.main import main
from src.policy import PRESETS as POLICY_PRESETS


class DelimiterTests(unittest.TestCase):
    PASSWORDS = ["T7#mQ9!vLp2xK4", "correct-horse-battery-staple"] * 5

    def _write(self, tmp, name, delimiter):
        path = Path(tmp) / name
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh, delimiter=delimiter)
            w.writerow(["site", "password"])
            for i, pw in enumerate(self.PASSWORDS):
                w.writerow([f"site{i}.com", pw])
        return path

    def test_semicolon_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "export.csv", ";")
            agg = audit_file(path, workers=1)
        self.assertEqual(agg["total"], len(self.PASSWORDS))

    def test_tab_separated_tsv(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "export.tsv", "\t")
            agg = audit_file(path, workers=1)
        self.assertEqual(agg["total"], len(self.PASSWORDS))

    def test_comma_csv_still_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "export.csv", ",")
            agg = audit_file(path, workers=1)
        self.assertEqual(agg["total"], len(self.PASSWORDS))

    def test_semicolon_detected_even_with_commas_in_a_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "export.csv"
            path.write_text("site;notes;password\nexample.com;foo, bar;T7#mQ9!vLp2xK4\n", encoding="utf-8")
            agg = audit_file(path, workers=1)
        self.assertEqual(agg["total"], 1)


class BannedWordsTests(unittest.TestCase):
    def test_finds_banned_term(self):
        matches = banned.find_matches("Acme2024!", ["Acme"])
        self.assertTrue(any(m.kind == "banned" for m in matches))

    def test_multi_word_term_matched_whole_and_split(self):
        matches_whole = banned.find_matches("AcmeCorp99", ["AcmeCorp"])
        self.assertTrue(matches_whole)
        matches_part = banned.find_matches("Acme99", ["Acme Corp"])
        self.assertTrue(matches_part)

    def test_no_terms_no_matches(self):
        self.assertEqual(banned.find_matches("Acme2024!", []), [])

    def test_analyzer_flags_banned_word(self):
        a = analyze("MyAcmePassword", banned=["Acme"])
        self.assertIn("banned", a.pattern_kinds)

    def test_load_file_ignores_comments_and_blanks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "banned.txt"
            path.write_text("# comment\nAcme\n\nWidgetCo\n", encoding="utf-8")
            terms = banned.load_file(path)
        self.assertEqual(terms, ["Acme", "WidgetCo"])

    def test_audit_file_with_banned_words(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pw.txt"
            path.write_text("Acme2024!\nT7#mQ9!vLp2xK4\n", encoding="utf-8")
            agg = audit_file(path, workers=1, banned=["Acme"])
        self.assertIn("banned", agg["pattern_counts"])

    def test_cli_banned_words_file_single_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "banned.txt"
            path.write_text("Acme\n", encoding="utf-8")
            self.assertEqual(main(["-p", "Acme2024", "--banned-words-file", str(path), "-q"]), 0)

    def test_cli_banned_words_file_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            pw_path = Path(tmp) / "pw.txt"
            pw_path.write_text("Acme2024!\n", encoding="utf-8")
            banned_path = Path(tmp) / "banned.txt"
            banned_path.write_text("Acme\n", encoding="utf-8")
            self.assertEqual(main(["-f", str(pw_path), "--banned-words-file", str(banned_path), "-q"]), 0)


class ProfilesFileTests(unittest.TestCase):
    def test_load_profiles_file_string_and_list_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            path.write_text(json.dumps({"alice@x.com": "Alice,1990", "bob@x.com": ["Bob", "1985"]}),
                            encoding="utf-8")
            profiles = profile.load_profiles_file(path)
        self.assertEqual(profiles["alice@x.com"], ["Alice,1990"])
        self.assertEqual(profiles["bob@x.com"], ["Bob", "1985"])

    def test_load_profiles_file_rejects_non_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            path.write_text("[1, 2]", encoding="utf-8")
            with self.assertRaises(ValueError):
                profile.load_profiles_file(path)

    def test_load_profiles_file_rejects_bad_value_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            path.write_text(json.dumps({"alice@x.com": 123}), encoding="utf-8")
            with self.assertRaises(ValueError):
                profile.load_profiles_file(path)

    def test_audit_file_only_flags_the_matching_account(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "export.csv"
            path.write_text(
                "site,password\nalice.example,RexAlice2010\nbob.example,T7#mQ9!vLp2xK4\n", encoding="utf-8")
            profiles = {"alice.example": ["Rex", "2010"]}
            agg = audit_file(path, workers=1, profiles=profiles)
        labels = {e["label"]: e["kinds"] for e in agg["worst_entries"]}
        self.assertIn("alice.example", labels)
        self.assertIn("personal", labels["alice.example"])
        self.assertNotIn("bob.example", labels)

    def test_cli_profiles_file_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            pw_path = Path(tmp) / "export.csv"
            pw_path.write_text("site,password\nalice.example,RexAlice2010\n", encoding="utf-8")
            prof_path = Path(tmp) / "profiles.json"
            prof_path.write_text(json.dumps({"alice.example": ["Rex", "2010"]}), encoding="utf-8")
            self.assertEqual(main(["-f", str(pw_path), "--profiles-file", str(prof_path), "-q"]), 0)


class CompareWithFileTests(unittest.TestCase):
    def _write(self, tmp, name, rows):
        path = Path(tmp) / name
        path.write_text("\n".join(rows) + "\n", encoding="utf-8")
        return path

    def test_cli_compare_with(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = self._write(tmp, "old.txt", ["password", "qwerty"])
            new = self._write(tmp, "new.txt", ["T7#mQ9!vLp2xK4", "correct-horse-battery-staple"])
            self.assertEqual(main(["-f", str(new), "--compare-with", str(old)]), 0)

    def test_cli_compare_with_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            new = self._write(tmp, "new.txt", ["password"])
            self.assertEqual(main(["-f", str(new), "--compare-with", str(Path(tmp) / "nope.txt"), "-q"]), 2)

    def test_report_compare_text_improved_and_unchanged(self):
        old = report.aggregate([analyze("password"), analyze("qwerty")])
        new = report.aggregate([analyze("T7#mQ9!vLp2xK4"), analyze("correct-horse-battery-staple")])
        self.assertIn("Better", report.compare_text(old, new))
        self.assertIn("change", report.compare_text(old, old))


class RemediationTests(unittest.TestCase):
    def test_remediation_csv_contains_no_old_passwords(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "export.csv"
            path.write_text("site,password\nexample.com,password\nexample.org,qwerty\n", encoding="utf-8")
            agg = audit_file(path, workers=1)
        out = report.remediation_csv(agg, POLICY_PRESETS["strong"])
        self.assertNotIn("password\n", out.split("\n", 1)[1])  # header row only, not a row value
        self.assertIn("example.com", out)
        self.assertIn("example.org", out)
        rows = list(csv.DictReader(out.splitlines()))
        for row in rows:
            self.assertNotEqual(row["suggested_new_password"], "password")
            self.assertNotEqual(row["suggested_new_password"], "qwerty")

    def test_remediation_csv_passwords_satisfy_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "export.csv"
            path.write_text("site,password\nexample.com,password\n", encoding="utf-8")
            agg = audit_file(path, workers=1)
        from src.policy import evaluate
        out = report.remediation_csv(agg, POLICY_PRESETS["strong"])
        rows = list(csv.DictReader(out.splitlines()))
        for row in rows:
            self.assertTrue(evaluate(analyze(row["suggested_new_password"]), POLICY_PRESETS["strong"]).passed)

    def test_remediation_csv_empty_when_no_worst_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "export.csv"
            path.write_text("site,password\nexample.com,T7#mQ9!vLp2xK4\n", encoding="utf-8")
            agg = audit_file(path, workers=1)
        out = report.remediation_csv(agg, POLICY_PRESETS["strong"])
        self.assertEqual(out.strip(), "account,assessment,suggested_new_password")

    def test_cli_remediation(self):
        with tempfile.TemporaryDirectory() as tmp:
            pw_path = Path(tmp) / "export.csv"
            pw_path.write_text("site,password\nexample.com,password\n", encoding="utf-8")
            out_path = Path(tmp) / "remediation.csv"
            self.assertEqual(main(["-f", str(pw_path), "-P", "strong",
                                   "--remediation", str(out_path), "-q"]), 0)
            self.assertIn("example.com", out_path.read_text(encoding="utf-8"))

    def test_cli_remediation_warns_without_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            pw_path = Path(tmp) / "pw.txt"
            pw_path.write_text("password\n", encoding="utf-8")
            out_path = Path(tmp) / "remediation.csv"
            self.assertEqual(main(["-f", str(pw_path), "--remediation", str(out_path), "-q"]), 0)
            self.assertFalse(out_path.exists())


def _root():
    try:
        return tk.Tk()
    except tk.TclError:
        return None


class GuiOrgFeatureTests(unittest.TestCase):
    def setUp(self):
        self.root = None
        if sys.platform == "darwin" and os.environ.get("CI"):
            self.skipTest("GUI smoke test skipped on macOS CI")
        self.root = _root()
        if self.root is None:
            self.skipTest("no display available")
        self.root.withdraw()
        self._cfg = tempfile.TemporaryDirectory()
        os.environ["CIPHERCHECK_CONFIG_DIR"] = self._cfg.name
        from src.gui import App
        self.app = App(self.root)

    def tearDown(self):
        if self.root is not None:
            self.root.destroy()
            os.environ.pop("CIPHERCHECK_CONFIG_DIR", None)
            self._cfg.cleanup()

    def test_load_banned_words_button(self):
        tab = self.app.tabs["audit"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "banned.txt"
            path.write_text("Acme\n", encoding="utf-8")
            with mock.patch("tkinter.filedialog.askopenfilename", return_value=str(path)):
                tab.load_banned_words()
        self.assertEqual(tab._banned_words, ["Acme"])

    def test_load_profiles_button(self):
        tab = self.app.tabs["audit"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            path.write_text(json.dumps({"alice.example": ["Rex"]}), encoding="utf-8")
            with mock.patch("tkinter.filedialog.askopenfilename", return_value=str(path)):
                tab.load_profiles()
        self.assertEqual(tab._profiles, {"alice.example": ["Rex"]})

    def test_compare_with_file_needs_an_audit_first(self):
        tab = self.app.tabs["audit"]
        tab.choose_compare_file()
        self.assertEqual(tab.status.cget("text"), self.app.ui.tr("au_compare_need_first"))

    def test_compare_with_file_does_not_replace_loaded_stats(self):
        tab = self.app.tabs["audit"]
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "first.txt"
            first.write_text("password\n", encoding="utf-8")
            second = Path(tmp) / "second.txt"
            second.write_text("T7#mQ9!vLp2xK4\n", encoding="utf-8")
            tab.start(str(first))
            tab._thread.join(timeout=5)
            tab._poll()
            original_agg = tab._agg
            self.app.ui.lang = "en"  # the system locale may pick another default language
            with mock.patch("tkinter.filedialog.askopenfilename", return_value=str(second)):
                tab.choose_compare_file()
            tab._thread.join(timeout=5)
            tab._poll()
        self.assertIs(tab._agg, original_agg)  # unchanged: compare_only never replaces it
        self.assertIn("Better", tab.compare.cget("text"))

    def test_export_remediation_without_worst_entries_shows_message(self):
        tab = self.app.tabs["audit"]
        tab.export_remediation()
        self.assertEqual(tab.status.cget("text"), self.app.ui.tr("au_no_remediation"))

    def test_export_remediation_writes_file(self):
        tab = self.app.tabs["audit"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "export.csv"
            path.write_text("site,password\nexample.com,password\n", encoding="utf-8")
            tab.start(str(path))
            tab._thread.join(timeout=5)
            tab._poll()
            out_path = Path(tmp) / "remediation.csv"
            with mock.patch("tkinter.filedialog.asksaveasfilename", return_value=str(out_path)):
                tab.export_remediation()
            self.assertTrue(out_path.exists())
            self.assertIn("example.com", out_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
