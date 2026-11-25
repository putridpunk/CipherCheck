"""HASH tab: identify a hash format and explain its security properties, plus an
educational demo that tries to match an MD5/SHA-1 hash against the 100k common
password list (only ever succeeds on those well-known, unsalted passwords)."""

from __future__ import annotations

import tkinter as tk

from .. import crack_demo, hashes
from .theme import DIM, GREEN, RED
from .widgets import UI


class HashTab:
    def __init__(self, ui: UI, page: tk.Frame):
        self.ui = ui
        self.prompt = ui.label(page, size=11, color=DIM)
        self.prompt.pack(fill="x", padx=30, pady=(10, 4))
        self.var = tk.StringVar()
        self.entry = ui.entry(page, self.var, 12)
        self.entry.pack(fill="x", padx=30, ipady=7)
        self.var.trace_add("write", lambda *_: self.refresh())
        self.text = ui.text_view(page, pady=(14, 8))

        self.crack_warning = ui.label(page, size=9, color=DIM, wraplength=600, justify="center")
        self.crack_warning.pack(pady=(0, 4))
        self.crack_btn = ui.button(page, self.try_crack)
        self.crack_btn.pack(pady=(0, 6))
        self.crack_result = ui.label(page, size=10, wraplength=600, justify="center")
        self.crack_result.pack(pady=(0, 16))

    def focus(self) -> None:
        self.entry.focus_set()

    def clear(self) -> None:
        self.var.set("")

    def apply_language(self) -> None:
        self.prompt.config(text=self.ui.tr("hash_prompt"), anchor="center")
        self.crack_warning.config(text=self.ui.tr("hash_crack_warning"))
        self.crack_btn.config(text=self.ui.tr("hash_crack_btn"))
        self.refresh()

    def _algo(self) -> str | None:
        return crack_demo.algorithm_for(self.var.get().strip())

    def refresh(self) -> None:
        ui, s = self.ui, self.var.get().strip()
        if not s:
            ui.write(self.text, [("idle", ui.tr("hash_empty")), ("idle", ""),
                                 ("idle", ui.tr("hash_note"))])
        else:
            ui.write(self.text, hashes.explain(hashes.identify(s), ui.lang))
        self.crack_result.config(text="")
        self.crack_btn.config(state="normal" if self._algo() else "disabled")

    def try_crack(self) -> None:
        ui, algo = self.ui, self._algo()
        if not algo:
            return
        found = crack_demo.try_crack(self.var.get().strip(), algo)
        if found:
            self.crack_result.config(text=ui.tr("hash_crack_found", pw=found), fg=RED)
        else:
            self.crack_result.config(text=ui.tr("hash_crack_notfound"), fg=GREEN)
