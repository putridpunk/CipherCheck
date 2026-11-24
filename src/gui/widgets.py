"""Shared widget factory: themed widgets, language, per-script fonts, font scale and layout."""

from __future__ import annotations

import tkinter as tk
from types import SimpleNamespace
from typing import Any

from ..i18n import is_rtl, t
from .theme import BG, DARKER, DIM, GREEN, MONO, PANEL, RED, SCRIPT_FONTS, TIP

TAGS = ("head", "bad", "good", "tip", "idle")
SCALES = (0.9, 1.0, 1.15, 1.3)  # font-size steps (the A- / A+ buttons)
DEFAULT_WRAP = 600


class ButtonRow:
    """A row of buttons that stacks vertically when they no longer fit side by side."""

    def __init__(self, ui: "UI", parent: Any, pady: Any = 0):
        self.ui = ui
        self.frame = tk.Frame(parent, bg=PANEL)
        self.buttons: list[tk.Button] = []
        self._stacked = False
        self.pady = pady

    def button(self, command, **kw) -> tk.Button:
        b = self.ui.button(self.frame, command, **kw)
        self.buttons.append(b)
        b.pack(side="left", padx=4, pady=2)
        return b

    def relayout(self) -> None:
        needed = sum(b.winfo_reqwidth() + 8 for b in self.buttons)
        stacked = needed > self.ui.wrap_width
        for b in self.buttons:
            b.pack_forget()
            b.pack(side="top" if stacked else "left", padx=4, pady=2)
        self._stacked = stacked


class UI:
    """Holds the current language and font scale and creates widgets that follow them."""

    def __init__(self, root: tk.Tk, lang: str, scale: float = 1.0):
        self.root = root
        self.lang = lang
        self.scale = scale if scale in SCALES else 1.0
        self.wrap_width = DEFAULT_WRAP  # text width available inside the panel
        self.last_dialog: Any = None
        self._fonted: list[tuple[Any, int, bool]] = []
        self._mono: list[tuple[Any, int]] = []
        self._texts: list[tk.Text] = []
        self._wrapped: list[tk.Label] = []
        self._rows: list[ButtonRow] = []

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

    # ----- layout that follows the panel width and the font size -----
    def set_wrap_width(self, width: int) -> None:
        """Wrapped labels always use the width the panel really has (text is never cut off)."""
        self.wrap_width = max(300, width)
        for lbl in self._wrapped:
            lbl.config(wraplength=self.wrap_width)

    def refresh_layout(self) -> None:
        """Re-arrange button rows after a font, language or width change."""
        self.root.update_idletasks()
        for row in self._rows:
            row.relayout()

    # ----- factories -----
    def label(self, parent, text="", size=11, color=GREEN, bold=False, **kw) -> tk.Label:
        wrap = kw.pop("wraplength", None)
        lbl = tk.Label(parent, text=text, bg=PANEL, fg=color, **kw)
        if wrap:  # any wrapped label follows the panel width
            lbl.config(wraplength=self.wrap_width)
            self._wrapped.append(lbl)
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

    def button_row(self, parent, pady: Any = 0) -> ButtonRow:
        row = ButtonRow(self, parent, pady)
        self._rows.append(row)
        return row

    def entry(self, parent, var: tk.StringVar, size: int, **kw) -> tk.Entry:
        e = tk.Entry(parent, textvariable=var, bg=BG, fg=GREEN,
                     insertbackground=GREEN, relief="flat", highlightthickness=1,
                     highlightbackground=DARKER, highlightcolor=GREEN,
                     selectbackground=GREEN, selectforeground=BG, width=8, **kw)
        self._mono.append((e, size))
        e.config(font=(MONO, self.size(size)))
        return e

    def text_view(self, parent, pady=(8, 16)) -> tk.Text:
        frame = tk.Frame(parent, bg=PANEL)
        frame.pack(fill="both", expand=True, padx=30, pady=pady)
        # width=1: the view must never ask for more room than the panel has (it then fills it)
        tw = tk.Text(frame, bg=BG, fg=GREEN, relief="flat", wrap="word", width=1, height=4,
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

    # ----- dialogs -----
    def ask_yes_no(self, message_key: str) -> bool:
        """Matrix-styled yes/no question in the current language. Enter = yes, Esc = no."""
        top = tk.Toplevel(self.root)
        top.title("CipherCheck")
        top.configure(bg=GREEN)
        top.resizable(False, False)
        top.transient(self.root)
        body = tk.Frame(top, bg=PANEL, padx=28, pady=22)
        body.pack(padx=1, pady=1)
        fam = self.family
        msg = tk.Label(body, text=self.tr(message_key), bg=PANEL, fg=GREEN, justify="right" if self.rtl else "center",
                       wraplength=int(380 * max(1.0, self.scale)), font=(fam, self.size(12), "bold"))
        msg.pack(pady=(0, 18))
        result = {"yes": False}

        def finish(answer: bool) -> None:
            result["yes"] = answer
            top.destroy()

        row = tk.Frame(body, bg=PANEL)
        row.pack()
        yes_btn = self.button(row, lambda: finish(True))
        no_btn = self.button(row, lambda: finish(False))
        for b, key in ((yes_btn, "dlg_yes"), (no_btn, "dlg_no")):
            b.config(text=self.tr(key), font=(fam, self.size(10), "bold"), width=8)
            b.pack(side="left", padx=8)
        top.bind("<Return>", lambda e: finish(True))
        top.bind("<Escape>", lambda e: finish(False))
        top.protocol("WM_DELETE_WINDOW", lambda: finish(False))

        top.update_idletasks()  # centre it over the main window
        x = self.root.winfo_rootx() + (self.root.winfo_width() - top.winfo_reqwidth()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - top.winfo_reqheight()) // 2
        top.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self.last_dialog = SimpleNamespace(top=top, yes_btn=yes_btn, no_btn=no_btn, message=msg)
        try:
            top.grab_set()
        except tk.TclError:
            pass  # a window manager that refuses the grab still gets a working dialog
        yes_btn.focus_set()
        self.root.wait_window(top)
        return result["yes"]
