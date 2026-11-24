"""ANALYZE tab: type a password, see a plain-language verdict."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog

from .. import report
from ..analyzer import analyze
from ..friendly import explain, generate_passphrase, generate_password, strengthen
from .theme import DARKER, DIM, PANEL
from .widgets import UI

CLIPBOARD_WIPE_MS = 30_000


class AnalyzeTab:
    def __init__(self, ui: UI, page: tk.Frame):
        self.ui = ui
        self._status_job: str | None = None

        self.prompt = ui.label(page, size=11, color=DIM)
        self.prompt.pack(fill="x", padx=30, pady=(10, 4))
        row = tk.Frame(page, bg=PANEL)
        row.pack(fill="x", padx=30)
        self.var = tk.StringVar()
        self.entry = ui.entry(row, self.var, 16, show="•")
        self.entry.pack(side="left", fill="x", expand=True, ipady=7)
        self.show_btn = ui.button(row, self.toggle_show, width=9)
        self.show_btn.pack(side="left", padx=(8, 0))
        self.var.trace_add("write", lambda *_: self.refresh())

        self.privacy = ui.label(page, size=9, color=DIM, wraplength=600)
        self.privacy.pack(pady=(6, 0))

        gen_row = ui.button_row(page)
        gen_row.frame.pack(pady=(10, 2))
        self.gen_btn = gen_row.button(self.generate)
        self.phrase_btn = gen_row.button(self.generate_phrase)
        act_row = ui.button_row(page)
        act_row.frame.pack()
        self.copy_btn = act_row.button(self.copy)
        self.clear_btn = act_row.button(lambda: self.var.set(""))
        self.save_btn = act_row.button(self.save_report)
        self.status = ui.label(page, size=10, wraplength=600)
        self.status.pack(pady=(4, 0))

        self.verdict = ui.label(page, size=28, bold=True)
        self.verdict.pack(pady=(6, 4))
        self.bar = tk.Canvas(page, width=600, height=16, bg=PANEL, highlightthickness=0)
        self.bar.pack()
        self.headline = ui.label(page, size=12, wraplength=600, justify="center")
        self.headline.pack(pady=(8, 2))
        self.crack = ui.label(page, size=10, color=DIM, wraplength=600, justify="center")
        self.crack.pack()
        self.text = ui.text_view(page, pady=(10, 16))

    def focus(self) -> None:
        self.entry.focus_set()

    def clear(self) -> None:
        self.var.set("")

    def apply_language(self) -> None:
        ui = self.ui
        self.prompt.config(text=ui.tr("prompt"), anchor="center")
        self.privacy.config(text=ui.tr("privacy"))
        self.gen_btn.config(text=ui.tr("gen"))
        self.phrase_btn.config(text=ui.tr("phrase_btn"))
        self.copy_btn.config(text=ui.tr("copy"))
        self.clear_btn.config(text=ui.tr("clear"))
        self.save_btn.config(text=ui.tr("save_report"))
        self._refresh_show_btn()
        self.status.config(text="")
        self.refresh()

    # ----- behaviour -----
    def _refresh_show_btn(self) -> None:
        shown = self.entry.cget("show") == ""
        self.show_btn.config(text=self.ui.tr("hide" if shown else "show"))

    def toggle_show(self) -> None:
        shown = self.entry.cget("show") == ""
        self.entry.config(show="•" if shown else "")
        self._refresh_show_btn()

    def say(self, key: str, **kw) -> None:
        if self._status_job:
            self.ui.root.after_cancel(self._status_job)
        self.status.config(text="> " + self.ui.tr(key, **kw))
        self._status_job = self.ui.root.after(6000, lambda: self.status.config(text=""))

    def generate(self) -> None:
        """Empty field: new strong password. Otherwise: a strong version of the user's."""
        current = self.var.get()
        if not current:
            self.var.set(generate_password(16))
            msg = "st_generated"
        else:
            stronger = strengthen(current)
            if stronger == current:  # already strong: ask before replacing it
                if self.ui.ask_yes_no("dlg_strong"):
                    self.var.set(generate_password(16))
                    msg = "st_generated"
                else:
                    msg = "st_already"
            else:
                self.var.set(stronger)
                msg = "st_similar"
        if self.entry.cget("show") != "":
            self.toggle_show()
        self.say(msg)

    def generate_phrase(self) -> None:
        self.var.set(generate_passphrase(5))
        if self.entry.cget("show") != "":
            self.toggle_show()
        self.say("st_passphrase")

    def copy(self) -> None:
        pw = self.var.get()
        if not pw:
            self.say("st_empty")
            return
        root = self.ui.root
        root.clipboard_clear()
        root.clipboard_append(pw)
        self.say("st_copied")

        def wipe() -> None:
            try:
                if root.clipboard_get() == pw:
                    root.clipboard_clear()
            except tk.TclError:
                pass
        root.after(CLIPBOARD_WIPE_MS, wipe)

    def save_report(self) -> None:
        pw = self.var.get()
        if not pw:
            self.say("st_empty")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".html", initialfile="ciphercheck-report",
            filetypes=[("HTML", "*.html"), ("Text", "*.txt"), ("JSON", "*.json")])
        if not path:
            return
        fmt = Path(path).suffix.lstrip(".").lower()
        try:  # the report never contains the password
            report.write_report(analyze(pw), path, fmt if fmt in report.RENDERERS else "txt")
        except OSError as exc:
            self.status.config(text=f"> {exc}")
            return
        self.say("st_report", path=path)

    # ----- rendering -----
    def _draw_bar(self, level: int, color: str) -> None:
        self.bar.delete("all")
        seg, gap = 28, 2
        for i in range(20):
            self.bar.create_rectangle(i * (seg + gap), 0, i * (seg + gap) + seg, 16,
                                      fill=color if i < level * 4 else DARKER, outline="")

    def refresh(self) -> None:
        ui, pw = self.ui, self.var.get()
        if not pw:
            self.verdict.config(text="—", fg=DIM)
            self._draw_bar(0, DIM)
            self.headline.config(text=ui.tr("idle_headline"), fg=DIM)
            self.crack.config(text="")
            ui.write(self.text, [("idle", ui.tr("idle_1")), ("idle", ""), ("idle", ui.tr("idle_2"))])
            return
        r = explain(analyze(pw), ui.lang)
        self.verdict.config(text=r.verdict, fg=r.color)
        self._draw_bar(r.level, r.color)
        self.headline.config(text=r.headline, fg=r.color)
        self.crack.config(text=ui.tr("crack", time=r.crack_time))
        lines: list[tuple[str, str]] = []
        if r.bad:
            lines += [("head", ui.tr("hdr_bad"))] + [("bad", f" [-] {x}") for x in r.bad]
        if r.good:
            lines += [("head", ui.tr("hdr_good"))] + [("good", f" [+] {x}") for x in r.good]
        if r.tips:
            lines += [("head", ui.tr("hdr_tips"))] + [("tip", f" [>] {x}") for x in r.tips]
        ui.write(self.text, lines)
