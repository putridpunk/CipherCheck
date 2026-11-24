"""Shared widget factory: themed widgets, language, per-script fonts and font scale."""

from __future__ import annotations

import tkinter as tk
from typing import Any

from ..i18n import is_rtl, t
from .theme import BG, DARKER, DIM, GREEN, MONO, PANEL, RED, SCRIPT_FONTS, TIP

TAGS = ("head", "bad", "good", "tip", "idle")
SCALES = (0.9, 1.0, 1.15, 1.3)  # font-size steps (the A- / A+ buttons)


class UI:
    """Holds the current language and font scale and creates widgets that follow them."""

    def __init__(self, root: tk.Tk, lang: str, scale: float = 1.0):
        self.root = root
        self.lang = lang
        self.scale = scale if scale in SCALES else 1.0
        self._fonted: list[tuple[Any, int, bool]] = []
        self._mono: list[tuple[Any, int]] = []
        self._texts: list[tk.Text] = []

    # ----- language and size -----
    def tr(self, key: str, **kw) -> str:
        return t(self.lang, key, **kw)

    @property
    def rtl(self) -> bool:
        return is_rtl(self.lang)

    @property
    def family(self) -> str:
        return SCRIPT_FONTS.get(self.lang, MONO)

    def size(self, base: int) -> int:
        return max(7, round(base * self.scale))

    def step_scale(self, direction: int) -> bool:
        """Move one step up (+1) or down (-1). Returns False at the limits."""
        i = SCALES.index(self.scale) + direction
        if not 0 <= i < len(SCALES):
            return False
        self.scale = SCALES[i]
        return True

    def apply_fonts(self) -> None:
        fam = self.family
        for w, size, bold in self._fonted:
            w.config(font=(fam, self.size(size), "bold" if bold else "normal"))
        for w, size in self._mono:
            w.config(font=(MONO, self.size(size)))
        for tw in self._texts:
            tw.tag_config("head", font=(fam, self.size(10), "bold"))
            for tag in TAGS:
                tw.tag_config(tag, justify="right" if self.rtl else "left")

    def _reg(self, widget: Any, size: int, bold: bool = False) -> None:
        self._fonted.append((widget, size, bold))

    # ----- factories -----
    def label(self, parent, text="", size=11, color=GREEN, bold=False, **kw) -> tk.Label:
        lbl = tk.Label(parent, text=text, bg=PANEL, fg=color, **kw)
        self._reg(lbl, size, bold)
        return lbl

    def button(self, parent, command, width=None, hover=True) -> tk.Button:
        b = tk.Button(parent, command=command, bg=BG, fg=GREEN, relief="flat",
                      cursor="hand2", bd=0, padx=10, pady=6,
                      activebackground=GREEN, activeforeground=BG,
                      highlightbackground=GREEN, highlightthickness=1)
        self._reg(b, 10, True)
        if width:
            b.config(width=width)
        if hover:
            b.bind("<Enter>", lambda e: b.config(bg=GREEN, fg=BG))
            b.bind("<Leave>", lambda e: b.config(bg=BG, fg=GREEN))
        return b

    def entry(self, parent, var: tk.StringVar, size: int, **kw) -> tk.Entry:
        e = tk.Entry(parent, textvariable=var, bg=BG, fg=GREEN,
                     insertbackground=GREEN, relief="flat", highlightthickness=1,
                     highlightbackground=DARKER, highlightcolor=GREEN,
                     selectbackground=GREEN, selectforeground=BG, **kw)
        self._mono.append((e, size))
        e.config(font=(MONO, self.size(size)))
        return e

    def text_view(self, parent, pady=(8, 16)) -> tk.Text:
        frame = tk.Frame(parent, bg=PANEL)
        frame.pack(fill="both", expand=True, padx=30, pady=pady)
        tw = tk.Text(frame, bg=BG, fg=GREEN, relief="flat", wrap="word",
                     highlightthickness=1, highlightbackground=DARKER, padx=12, pady=10,
                     state="disabled", cursor="arrow", spacing1=2, spacing3=2)
        self._reg(tw, 11)
        tw.pack(fill="both", expand=True)
        tw.tag_config("head", foreground=DIM, spacing1=8)
        tw.tag_config("bad", foreground=RED)
        tw.tag_config("good", foreground=GREEN)
        tw.tag_config("tip", foreground=TIP)
        tw.tag_config("idle", foreground=DIM)
        self._texts.append(tw)
        return tw

    @staticmethod
    def write(tw: tk.Text, lines: list[tuple[str, str]]) -> None:
        tw.config(state="normal")
        tw.delete("1.0", "end")
        for tag, line in lines:
            tw.insert("end", line + "\n", tag)
        tw.config(state="disabled")
