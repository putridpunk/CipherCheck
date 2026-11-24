"""Builds the real window, flips through every tab and language, then closes it.

Skipped automatically when no display is available (use xvfb on headless Linux).
"""

import os
import sys
import tempfile
import time
import tkinter as tk
import unittest
from pathlib import Path

from src.i18n import LANGUAGES


def _root():
    try:
        return tk.Tk()
    except tk.TclError:
        return None


class GuiSmokeTests(unittest.TestCase):
    def setUp(self):
        self.root = None
        if sys.platform == "darwin" and os.environ.get("CI"):
            # Opening a Tk window on a headless macOS CI runner can hang forever.
            self.skipTest("GUI smoke test skipped on macOS CI")
        self.root = _root()
        if self.root is None:
            self.skipTest("no display available")
        self.root.withdraw()
        self._cfg = tempfile.TemporaryDirectory()  # never touch the user's real settings
        os.environ["CIPHERCHECK_CONFIG_DIR"] = self._cfg.name
        from src.gui import App
        self.app = App(self.root)

    def tearDown(self):
        if self.root is not None:
            self.root.destroy()
            os.environ.pop("CIPHERCHECK_CONFIG_DIR", None)
            self._cfg.cleanup()

    def test_every_language_and_tab(self):
        app = self.app
        app.tabs["analyze"].var.set("Summer2024!qwerty")
        app.tabs["hash"].var.set("5f4dcc3b5aa765d61d8327deb882cf99")
        for code, name in LANGUAGES.items():
            app.on_language(name)
            self.assertEqual(app.ui.lang, code)
            for tab in app.tabs:
                app.show_tab(tab)
                self.root.update()

    def test_font_scale_steps_and_is_remembered(self):
        from src import settings
        base = self.app.ui.size(11)
        self.app.change_font(1)
        self.assertEqual(self.app.ui.scale, 1.15)
        self.assertGreater(self.app.ui.size(11), base)
        self.assertEqual(settings.load()["font_scale"], 1.15)
        for _ in range(5):
            self.app.change_font(-1)  # stops at the smallest step
        self.assertEqual(self.app.ui.scale, 0.9)
        self.root.update()

    def test_shortcuts(self):
        app = self.app
        # Real key events need window focus, which a CI display may not grant; the
        # bindings are checked through their registered callbacks instead.
        self.assertTrue(app.root.bind("<Control-Key-3>"))
        self.assertTrue(app.root.bind("<Control-g>"))
        self.assertTrue(app.root.bind("<Escape>"))
        app.show_tab("hash")
        self.assertEqual(app.current_tab, "hash")
        app.shortcut_generate()
        self.assertEqual(len(app.tabs["analyze"].var.get()), 16)
        app.tabs["analyze"].clear()
        self.assertEqual(app.tabs["analyze"].var.get(), "")

    def test_footer_and_icon(self):
        from src import __version__
        from src.gui.app import ICON
        self.assertTrue(ICON.exists())
        self.assertIn(__version__, self.app.footer.cget("text"))
        self.assertIn("github.com/putridpunk", self.app.footer.cget("text"))

    def test_language_is_remembered(self):
        from src import settings
        self.app.on_language("Deutsch")
        self.assertEqual(settings.load()["language"], "de")

    def test_passphrase_button(self):
        tab = self.app.tabs["analyze"]
        tab.generate_phrase()
        self.assertEqual(len(tab.var.get().split("-")), 5)

    def test_generate_copy_and_clear(self):
        tab = self.app.tabs["analyze"]
        tab.generate()  # empty field: brand-new password
        first = tab.var.get()
        self.assertEqual(len(first), 16)
        tab.var.set("monkey")
        tab.generate()  # similar, stronger version
        self.assertNotEqual(tab.var.get(), "monkey")
        tab.copy()
        self.assertEqual(self.root.clipboard_get(), tab.var.get())

    def test_audit_tab_statistics(self):
        tab = self.app.tabs["audit"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "synthetic.txt"
            path.write_text("password\nsunshine99\nT7#mQ9!vLp2xK4\n", encoding="utf-8")
            tab.start(str(path))
            for _ in range(200):  # the audit runs in a thread; the UI polls for the result
                self.root.update()
                if tab._result is not None and not tab.running:
                    break
                time.sleep(0.05)
            tab._poll()
        self.assertEqual(tab._agg["total"], 3)
        self.assertFalse(tab.running)
        self.root.update()

    def test_audit_cancel_and_missing_file(self):
        tab = self.app.tabs["audit"]
        tab.start(str(Path(tempfile.gettempdir()) / "ciphercheck-does-not-exist.txt"))
        for _ in range(100):
            self.root.update()
            if tab._result is not None and not tab.running:
                break
            time.sleep(0.05)
        tab._poll()
        self.assertEqual(tab._result, ("error", None))
        tab.clear()  # nothing running: just forgets statistics


class GuiDropTests(unittest.TestCase):
    """Drag and drop needs the optional tkinterdnd2 package."""

    def setUp(self):
        try:
            from tkinterdnd2 import TkinterDnD
        except ImportError:
            self.skipTest("tkinterdnd2 is not installed")
        if sys.platform == "darwin" and os.environ.get("CI"):
            self.skipTest("GUI smoke test skipped on macOS CI")
        try:
            self.root = TkinterDnD.Tk()
        except Exception:
            self.skipTest("no display or no tkdnd library available")
        self.root.withdraw()
        self._cfg = tempfile.TemporaryDirectory()
        os.environ["CIPHERCHECK_CONFIG_DIR"] = self._cfg.name
        from src.gui import App
        self.app = App(self.root)

    def tearDown(self):
        self.root.destroy()
        os.environ.pop("CIPHERCHECK_CONFIG_DIR", None)
        self._cfg.cleanup()

    def test_drop_starts_an_audit(self):
        from types import SimpleNamespace
        self.assertTrue(self.app.tabs["audit"].show_drop_hint)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "my passwords.txt"  # a space: Tk wraps such paths in braces
            path.write_text("password\nT7#mQ9!vLp2xK4\n", encoding="utf-8")
            self.app.on_drop(SimpleNamespace(data="{" + str(path).replace("\\", "/") + "}"))
            self.assertEqual(self.app.current_tab, "audit")
            tab = self.app.tabs["audit"]
            for _ in range(200):
                self.root.update()
                if tab._result is not None and not tab.running:
                    break
                time.sleep(0.05)
            tab._poll()
        self.assertEqual(tab._agg["total"], 2)

    def test_drop_of_a_folder_reports_an_error(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as tmp:
            self.app.on_drop(SimpleNamespace(data=tmp.replace("\\", "/")))
        self.assertFalse(self.app.tabs["audit"].running)
        self.assertTrue(self.app.tabs["audit"].status.cget("text"))


if __name__ == "__main__":
    unittest.main()
