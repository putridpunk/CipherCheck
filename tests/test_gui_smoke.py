"""Builds the real window, flips through every tab and language, then closes it.

Skipped automatically when no display is available (use xvfb on headless Linux).
"""

import os
import sys
import tempfile
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
            tab._worker(str(path))
            tab._poll()
        self.assertEqual(tab._agg["total"], 3)
        self.root.update()


if __name__ == "__main__":
    unittest.main()
