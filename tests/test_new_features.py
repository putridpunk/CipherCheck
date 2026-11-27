import hashlib
import json
import os
import sys
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from unittest import mock

from src import crack_demo, history, patterns, policy, profile, report, update_check
from src.analyzer import analyze
from src.audit import NoPasswordColumn, audit_file
from src.entropy import crack_time
from src.main import main


class KeyboardLayoutTests(unittest.TestCase):
    def test_azerty_and_qwertz_detected(self):
        self.assertIn("keyboard", {m.kind for m in patterns.find_matches("azer")})
        self.assertIn("keyboard", {m.kind for m in patterns.find_matches("qwer")})

    def test_still_no_false_positive_on_random_text(self):
        self.assertNotIn("keyboard", {m.kind for m in patterns.find_matches("T7#mQ9!vLp2")})


class CrackTimeTests(unittest.TestCase):
    def test_three_models(self):
        t = crack_time(40.0)
        self.assertEqual(set(t), {"offline_fast_hash", "offline_slow_hash", "online_throttled"})

    def test_slow_hash_takes_longer_than_fast_hash(self):
        from src.entropy import OFFLINE_GUESSES_PER_SEC, OFFLINE_SLOW_GUESSES_PER_SEC
        self.assertLess(OFFLINE_SLOW_GUESSES_PER_SEC, OFFLINE_GUESSES_PER_SEC)
        t = crack_time(60.0)
        self.assertNotEqual(t["offline_fast_hash"], t["offline_slow_hash"])


class ProfileTests(unittest.TestCase):
    def test_finds_personal_token(self):
        matches = profile.find_matches("Rex1990!", ["Rex", "1990"])
        self.assertTrue(any(m.kind == "personal" for m in matches))

    def test_no_tokens_no_matches(self):
        self.assertEqual(profile.find_matches("Rex1990!", []), [])

    def test_analyzer_flags_personal_info(self):
        a = analyze("MyDog-Rex-2010", profile=["Rex", "2010"])
        self.assertIn("personal", a.pattern_kinds)
        self.assertTrue(any(f.level == "-" and "personal" in f.text.lower() for f in a.findings))

    def test_leet_personal_token(self):
        matches = profile.find_matches("r3x", ["rex"])
        self.assertTrue(matches)


class PolicyTests(unittest.TestCase):
    def test_strong_password_passes_strong_policy(self):
        result = policy.evaluate(analyze("T7#mQ9!vLp2xK4"), policy.PRESETS["strong"])
        self.assertTrue(result.passed)
        self.assertEqual(result.reasons, [])

    def test_common_password_fails_every_policy(self):
        a = analyze("password")
        for preset in policy.PRESETS.values():
            result = policy.evaluate(a, preset)
            self.assertFalse(result.passed)

    def test_too_short_reason(self):
        result = policy.evaluate(analyze("ab1"), policy.PRESETS["basic"])
        self.assertIn("too_short", result.reasons)


class CustomPolicyTests(unittest.TestCase):
    def test_from_dict_defaults_and_overrides(self):
        pol = policy.from_dict({"min_length": 20, "min_bits": 70, "forbid_common": False})
        self.assertEqual(pol.min_length, 20)
        self.assertEqual(pol.min_bits, 70.0)
        self.assertFalse(pol.forbid_common)
        self.assertTrue(pol.forbid_breached)  # default kept

    def test_load_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps({"key": "internal", "min_length": 16, "min_bits": 55}),
                            encoding="utf-8")
            pol = policy.load_file(path)
            self.assertEqual((pol.key, pol.min_length, pol.min_bits), ("internal", 16, 55.0))

    def test_load_file_rejects_non_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text("[1, 2, 3]", encoding="utf-8")
            with self.assertRaises(ValueError):
                policy.load_file(path)

    def test_load_file_missing(self):
        with self.assertRaises(OSError):
            policy.load_file("/no/such/policy.json")

    def test_generate_compliant_satisfies_preset_policies(self):
        for pol in policy.PRESETS.values():
            pw = policy.generate_compliant(pol)
            self.assertTrue(policy.evaluate(analyze(pw), pol).passed, pol)

    def test_generate_compliant_satisfies_strict_custom_policy(self):
        pol = policy.from_dict({"min_length": 24, "min_bits": 90})
        pw = policy.generate_compliant(pol)
        self.assertTrue(policy.evaluate(analyze(pw), pol).passed)
        self.assertGreaterEqual(len(pw), 24)

    def test_cli_policy_file_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            pw_path = Path(tmp) / "pw.txt"
            pw_path.write_text("password\nT7#mQ9!vLp2xK4\n", encoding="utf-8")
            pol_path = Path(tmp) / "policy.json"
            pol_path.write_text(json.dumps({"min_length": 10, "min_bits": 30}), encoding="utf-8")
            self.assertEqual(main(["-f", str(pw_path), "--policy-file", str(pol_path), "-q"]), 0)

    def test_cli_generate_for_policy(self):
        self.assertEqual(main(["--generate-for-policy", "strong"]), 0)

    def test_cli_generate_for_policy_with_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            pol_path = Path(tmp) / "policy.json"
            pol_path.write_text(json.dumps({"min_length": 18, "min_bits": 60}), encoding="utf-8")
            self.assertEqual(main(["--generate-for-policy", "x", "--policy-file", str(pol_path)]), 0)

    def test_cli_generate_for_policy_unknown_name(self):
        self.assertEqual(main(["--generate-for-policy", "nope"]), 2)


class WeakestEntriesTests(unittest.TestCase):
    def test_friendly_aggregate_includes_worst_and_shared_in_every_language(self):
        from src.i18n import LANGUAGES
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "export.csv"
            path.write_text(
                "site,password\nexample.com,password\nexample.org,password\n", encoding="utf-8")
            agg = audit_file(path, workers=1)
        for lang in LANGUAGES:
            out = report.aggregate_friendly(agg, lang)
            self.assertIn("example.com", out)
            self.assertIn("example.org", out)

    def test_worst_entries_and_shared_accounts_from_csv_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "export.csv"
            path.write_text(
                "site,username,password\n"
                "example.com,bob,password\n"
                "example.org,bob,password\n"
                "bank.com,bob,T7#mQ9!vLp2xK4\n",
                encoding="utf-8")
            agg = audit_file(path, workers=1)
        labels = {e["label"] for e in agg["worst_entries"]}
        self.assertEqual(labels, {"example.com", "example.org"})
        shared = agg["reuse"]["shared_accounts"]
        self.assertEqual(len(shared), 1)
        self.assertEqual(set(shared[0]["labels"]), {"example.com", "example.org"})
        self.assertEqual(shared[0]["count"], 2)

    def test_no_label_column_means_no_worst_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pw.txt"
            path.write_text("password\nT7#mQ9!vLp2xK4\n", encoding="utf-8")
            agg = audit_file(path, workers=1)
        self.assertEqual(agg["worst_entries"], [])
        self.assertEqual(agg["reuse"]["shared_accounts"], [])

    def test_worst_entries_never_include_strong_passwords(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "export.csv"
            path.write_text("site,password\nbank.com,T7#mQ9!vLp2xK4\n", encoding="utf-8")
            agg = audit_file(path, workers=1)
        self.assertEqual(agg["worst_entries"], [])

    def test_worst_entries_bounded_and_rendered(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "export.csv"
            rows = [f"site{i}.com,password" for i in range(50)]
            path.write_text("site,password\n" + "\n".join(rows) + "\n", encoding="utf-8")
            agg = audit_file(path, workers=1)
        from src.audit import MAX_WORST_ENTRIES
        self.assertLessEqual(len(agg["worst_entries"]), MAX_WORST_ENTRIES)
        for ext in ("txt", "json", "html", "csv"):
            with tempfile.TemporaryDirectory() as tmp:
                out = report.write_aggregate(agg, Path(tmp) / f"a.{ext}").read_text(encoding="utf-8")
                self.assertTrue(out)


class AuditHistoryTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["CIPHERCHECK_CONFIG_DIR"] = self._tmp.name

    def tearDown(self):
        os.environ.pop("CIPHERCHECK_CONFIG_DIR", None)
        self._tmp.cleanup()

    def test_record_and_load_roundtrip(self):
        self.assertEqual(history.load(), [])
        history.record(10, 42.5, 20.0)
        hist = history.load()
        self.assertEqual(len(hist), 1)
        self.assertEqual(hist[0]["total"], 10)
        self.assertEqual(hist[0]["average_bits"], 42.5)
        self.assertEqual(hist[0]["weak_percent"], 20.0)
        self.assertIn("at", hist[0])

    def test_bounded_to_max_entries(self):
        for i in range(history.MAX_ENTRIES + 10):
            history.record(1, float(i), 0.0)
        hist = history.load()
        self.assertEqual(len(hist), history.MAX_ENTRIES)
        self.assertEqual(hist[-1]["average_bits"], float(history.MAX_ENTRIES + 9))

    def test_zero_total_not_recorded(self):
        history.record(0, 0.0, 0.0)
        self.assertEqual(history.load(), [])

    def test_clear(self):
        history.record(5, 30.0, 10.0)
        self.assertTrue(history.load())
        history.clear()
        self.assertEqual(history.load(), [])

    def test_corrupted_file_returns_empty(self):
        from src.history import _file
        _file().parent.mkdir(parents=True, exist_ok=True)
        _file().write_text("{not json", encoding="utf-8")
        self.assertEqual(history.load(), [])

    def test_cli_records_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pw.txt"
            path.write_text("password\nT7#mQ9!vLp2xK4\n", encoding="utf-8")
            self.assertEqual(main(["-f", str(path), "-q"]), 0)
        self.assertEqual(len(history.load()), 1)


class CsvAuditTests(unittest.TestCase):
    PASSWORDS = ["T7#mQ9!vLp2xK4", "correct-horse-battery-staple", "Zq7!unique-Secret-Value"] * 10

    def _csv(self, tmp, header="site,username,password"):
        path = Path(tmp) / "export.csv"
        lines = [header] + [f"example.com,user,{pw}" for pw in self.PASSWORDS]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def test_detects_password_column(self):
        with tempfile.TemporaryDirectory() as tmp:
            agg = audit_file(self._csv(tmp), workers=1)
            self.assertEqual(agg["total"], len(self.PASSWORDS))

    def test_detects_login_password_column(self):
        with tempfile.TemporaryDirectory() as tmp:
            agg = audit_file(self._csv(tmp, header="site,username,login_password"), workers=1)
            self.assertEqual(agg["total"], len(self.PASSWORDS))

    def test_no_password_column_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.csv"
            path.write_text("site,username,notes\nexample.com,user,hi\n", encoding="utf-8")
            with self.assertRaises(NoPasswordColumn):
                audit_file(path, workers=1)

    def test_parallel_matches_single_process_for_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._csv(tmp)
            single = audit_file(path, workers=1)
            parallel = audit_file(path, workers=2, chunk_lines=4)
        self.assertEqual(single["total"], parallel["total"])
        self.assertEqual(single["assessment_counts"], parallel["assessment_counts"])


class PolicyAuditTests(unittest.TestCase):
    def test_audit_file_with_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pw.txt"
            path.write_text("password\nT7#mQ9!vLp2xK4\n", encoding="utf-8")
            agg = audit_file(path, workers=1, policy=policy.PRESETS["strong"])
            self.assertIn("policy", agg)
            self.assertEqual(agg["policy"]["passed"], 1)
            self.assertEqual(agg["policy"]["failed"], 1)

    def test_aggregate_renders_policy_in_every_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pw.txt"
            path.write_text("password\nT7#mQ9!vLp2xK4\n", encoding="utf-8")
            agg = audit_file(path, workers=1, policy=policy.PRESETS["strong"])
            for ext in ("txt", "json", "html", "csv"):
                out = report.write_aggregate(agg, Path(tmp) / f"a.{ext}").read_text(encoding="utf-8")
                self.assertTrue(out)
            self.assertIn("csv", report.AGG_RENDERERS)

    def test_cli_policy_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pw.txt"
            path.write_text("password\nT7#mQ9!vLp2xK4\n", encoding="utf-8")
            self.assertEqual(main(["-f", str(path), "-P", "basic", "-q"]), 0)


class CompareAggregatesTests(unittest.TestCase):
    def test_improved(self):
        old = report.aggregate([analyze("password"), analyze("qwerty")])
        new = report.aggregate([analyze("T7#mQ9!vLp2xK4"), analyze("correct-horse-battery-staple")])
        delta = report.compare_aggregates(old, new)
        self.assertTrue(delta["improved"])
        self.assertGreater(delta["delta_average_bits"], 0)

    def test_same_dataset_is_unchanged(self):
        agg = report.aggregate([analyze("password"), analyze("qwerty")])
        delta = report.compare_aggregates(agg, agg)
        self.assertTrue(delta["unchanged"])


class CrackDemoTests(unittest.TestCase):
    def test_algorithm_for_lengths(self):
        self.assertEqual(crack_demo.algorithm_for("a" * 32), "md5")
        self.assertEqual(crack_demo.algorithm_for("a" * 40), "sha1")
        self.assertIsNone(crack_demo.algorithm_for("not a hash"))

    def test_finds_common_password(self):
        import hashlib
        h = hashlib.md5(b"password").hexdigest()
        self.assertEqual(crack_demo.try_crack(h, "md5"), "password")

    def test_does_not_find_unique_password(self):
        import hashlib
        h = hashlib.md5(b"Zq7!unique-Secret-Value-never-common").hexdigest()
        self.assertIsNone(crack_demo.try_crack(h, "md5"))

    def test_cancel_stops_early(self):
        import threading
        done = threading.Event()
        done.set()
        self.assertIsNone(crack_demo.try_crack("a" * 32, "md5", cancel=done))


class UpdateCheckTests(unittest.TestCase):
    def test_parse_version_ordering(self):
        self.assertGreater(update_check._parse_version("1.2.0"), update_check._parse_version("1.1.9"))

    def test_up_to_date_returns_none(self):
        payload = json.dumps({"tag_name": "v0.0.1", "html_url": "https://example.invalid"}).encode()
        resp = mock.MagicMock()
        resp.read.return_value = payload
        resp.__enter__.return_value = resp
        with mock.patch("urllib.request.urlopen", return_value=resp):
            self.assertIsNone(update_check.check_for_update())

    def test_newer_release_detected(self):
        from src import __version__
        newer = f"v{int(__version__.split('.')[0]) + 1}.0.0"
        payload = json.dumps({"tag_name": newer, "html_url": "https://example.invalid/release"}).encode()
        resp = mock.MagicMock()
        resp.read.return_value = payload
        resp.__enter__.return_value = resp
        with mock.patch("urllib.request.urlopen", return_value=resp):
            result = update_check.check_for_update()
        self.assertEqual(result, (newer.lstrip("v"), "https://example.invalid/release"))

    def test_network_failure_raises(self):
        import urllib.error
        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("no network")):
            with self.assertRaises(update_check.UpdateCheckError):
                update_check.check_for_update()

    def test_cli_check_update(self):
        payload = json.dumps({"tag_name": "v0.0.1"}).encode()
        resp = mock.MagicMock()
        resp.read.return_value = payload
        resp.__enter__.return_value = resp
        with mock.patch("urllib.request.urlopen", return_value=resp):
            self.assertEqual(main(["--check-update"]), 0)


class CliProfileTests(unittest.TestCase):
    def test_profile_flag(self):
        self.assertEqual(main(["-p", "Rex1990", "--profile", "Rex,1990", "-q"]), 0)


def _root():
    try:
        return tk.Tk()
    except tk.TclError:
        return None


class GuiNewFeatureTests(unittest.TestCase):
    """Exercises the new widgets through the real app, like test_gui_smoke.py."""

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

    def test_profile_field_flags_personal_info(self):
        tab = self.app.tabs["analyze"]
        tab.profile_var.set("Rex, 2010")
        tab.var.set("MyDog-Rex-2010")
        self.root.update()
        text = tab.text.get("1.0", "end")
        self.assertTrue(text.strip())

    def test_policy_button_cycles(self):
        from src.gui.audit_tab import POLICY_KEYS
        tab = self.app.tabs["audit"]
        first = tab.policy_btn.cget("text")
        tab.cycle_policy()
        self.assertNotEqual(tab.policy_btn.cget("text"), first)
        for _ in range(len(POLICY_KEYS) - 1):
            tab.cycle_policy()
        self.assertEqual(tab.policy_btn.cget("text"), first)  # back to "none" after a full cycle

    def test_hash_crack_button_finds_common_password(self):
        tab = self.app.tabs["hash"]
        tab.var.set(hashlib.md5(b"password").hexdigest())
        self.root.update()
        self.assertEqual(str(tab.crack_btn["state"]), "normal")
        tab.try_crack()
        self.assertIn("password", tab.crack_result.cget("text"))

    def test_hash_crack_disabled_for_non_crackable_input(self):
        tab = self.app.tabs["hash"]
        tab.var.set("not a hash at all")
        self.root.update()
        self.assertEqual(str(tab.crack_btn["state"]), "disabled")

    def test_csv_without_password_column_reports_error(self):
        tab = self.app.tabs["audit"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.csv"
            path.write_text("site,notes\nexample.com,hi\n", encoding="utf-8")
            tab.start(str(path))
            tab._thread.join(timeout=5)
            tab._poll()
        from src.gui.theme import RED
        self.assertEqual(tab.status.cget("fg"), RED)
        self.assertEqual(tab.status.cget("text"), self.app.ui.tr("au_csv_nocolumn"))

    def test_update_check_button_shows_result(self):
        # Patch the high-level function (not urllib.request.urlopen): the check runs in a
        # background thread, so patching only the low-level call risks the mock being undone
        # (at the end of a "with" block in the test thread) before that thread gets to it,
        # letting a real, unbounded network call slip through - this hung Windows CI for 19
        # minutes on the first release attempt, because DNS lookups ignore urlopen's timeout.
        with mock.patch("src.update_check.check_for_update", return_value=None):
            self.app.check_update()
            self.assertIsNotNone(self.app._update_thread)
            self.app._update_thread.join(timeout=5)
            self.assertFalse(self.app._update_thread.is_alive())
            # The background thread (and the mocked call) has already finished; all that is
            # left is for Tk's own 100ms-polling timer to notice and run _update_done.
            import time
            for _ in range(40):
                self.root.update()
                if not self.app._update_checking:
                    break
                time.sleep(0.05)
        self.assertFalse(self.app._update_checking)
        self.assertEqual(self.app.update_status.cget("text"), self.app.ui.tr("upd_latest"))

    def test_load_policy_file_button(self):
        tab = self.app.tabs["audit"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps({"min_length": 10, "min_bits": 20}), encoding="utf-8")
            with mock.patch("tkinter.filedialog.askopenfilename", return_value=str(path)):
                tab.load_policy_file()
        self.assertIsNotNone(tab._custom_policy)
        from src.gui.audit_tab import POLICY_KEYS
        self.assertEqual(POLICY_KEYS[tab._policy_i], "custom")
        self.assertEqual(str(tab.gen_policy_btn["state"]), "normal")

    def test_load_policy_file_bad_json_shows_error(self):
        tab = self.app.tabs["audit"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text("not json", encoding="utf-8")
            with mock.patch("tkinter.filedialog.askopenfilename", return_value=str(path)):
                tab.load_policy_file()
        self.assertIsNone(tab._custom_policy)
        from src.gui.theme import RED
        self.assertEqual(tab.status.cget("fg"), RED)

    def test_generate_for_policy_copies_to_clipboard(self):
        tab = self.app.tabs["audit"]
        tab.cycle_policy()  # none -> basic
        self.assertEqual(str(tab.gen_policy_btn["state"]), "normal")
        tab.generate_for_policy()
        self.root.update()
        pw = self.root.clipboard_get()
        self.assertTrue(pw)
        from src.analyzer import analyze
        from src.policy import PRESETS, evaluate
        self.assertTrue(evaluate(analyze(pw), PRESETS["basic"]).passed)

    def test_generate_for_policy_disabled_when_no_policy(self):
        tab = self.app.tabs["audit"]
        self.assertEqual(str(tab.gen_policy_btn["state"]), "disabled")

    def test_trend_shown_after_second_audit(self):
        tab = self.app.tabs["audit"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pw.txt"
            path.write_text("password\nT7#mQ9!vLp2xK4\n", encoding="utf-8")
            for _ in range(2):
                tab.start(str(path))
                tab._thread.join(timeout=5)
                tab._poll()
        self.assertIn("→", tab.compare.cget("text"))


if __name__ == "__main__":
    unittest.main()
