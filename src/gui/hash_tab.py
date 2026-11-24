"""HASH tab: identify a hash format and explain its security properties."""

from __future__ import annotations

import tkinter as tk

from .. import hashes
from .theme import DIM
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
        self.text = ui.text_view(page, pady=(14, 16))

    def focus(self) -> None:
        self.entry.focus_set()

    def apply_language(self) -> None:
        self.prompt.config(text=self.ui.tr("hash_prompt"), anchor="e" if self.ui.rtl else "w")
        self.refresh()

    def refresh(self) -> None:
        ui, s = self.ui, self.var.get().strip()
        if not s:
            ui.write(self.text, [("idle", ui.tr("hash_empty")), ("idle", ""),
                                 ("idle", ui.tr("hash_note"))])
        else:
            ui.write(self.text, hashes.explain(hashes.identify(s), ui.lang))
