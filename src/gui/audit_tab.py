"""AUDIT tab: statistics dashboard for a file of synthetic test passwords."""

from __future__ import annotations

import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog
from types import SimpleNamespace

from .. import report
from ..analyzer import LABEL_ORDER, analyze
from ..friendly import KEY as KIND_KEY
from ..friendly import LEVELS
from ..reuse import ReuseTracker
from .theme import DARKER, GREEN, PANEL, RED
from .widgets import UI


class AuditTab:
    def __init__(self, ui: UI, page: tk.Frame):
        self.ui = ui
        self._agg: dict | None = None
        self._n = 0
        self._result: tuple[str, dict | None] | None = None
        self._thread: threading.Thread | None = None
        self._status_job: str | None = None

        self.intro = ui.label(page, size=10, color="#2f9e4f", wraplength=600, justify="left")
        self.intro.pack(padx=30, pady=(12, 8), fill="x")
        buttons = tk.Frame(page, bg=PANEL)
        buttons.pack()
        self.choose_btn = ui.button(buttons, self.choose_file)
        self.choose_btn.pack(side="left", padx=4)
        self.save_btn = ui.button(buttons, self.save_report)
        self.save_btn.pack(side="left", padx=4)
        self.status = ui.label(page, size=10, wraplength=600)
        self.status.pack(pady=(8, 0))
        self.total = ui.label(page, size=12, bold=True)
        self.total.pack(pady=(4, 4))
        self.chart = tk.Canvas(page, width=600, height=130, bg=PANEL, highlightthickness=0)
        self.chart.pack()
        self.text = ui.text_view(page, pady=(8, 16))

    def focus(self) -> None:
        self.ui.root.focus_set()

    def clear(self) -> None:
        """Escape on this tab: forget the loaded statistics."""
        self._agg = None
        self.status.config(text="")
        self.render()

    def apply_language(self) -> None:
        ui = self.ui
        self.intro.config(text=ui.tr("au_intro"), justify="right" if ui.rtl else "left")
        self.choose_btn.config(text=ui.tr("au_choose"))
        self.save_btn.config(text=ui.tr("save_report"))
        self.render()

    # ----- loading the file (background thread keeps the UI responsive) -----
    def choose_file(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        path = filedialog.askopenfilename(
            filetypes=[("Text", "*.txt *.lst *.csv *.dic"), ("All files", "*.*")])
        if not path:
            return
        self._n, self._result = 0, None
        self._thread = threading.Thread(target=self._worker, args=(path,), daemon=True)
        self._thread.start()
        self._poll()

    def _worker(self, path: str) -> None:
        stats = []
        tracker = ReuseTracker()
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    pw = line.rstrip("\r\n")
                    if not pw:
                        continue
                    a = analyze(pw)  # only aggregate numbers are kept, never the password
                    stats.append(SimpleNamespace(label=a.label, pattern_kinds=a.pattern_kinds,
                                                 estimated_bits=a.estimated_bits, length=a.length))
                    tracker.add(pw)
                    self._n = len(stats)
        except OSError:
            self._result = ("error", None)
            return
        self._result = ("done", report.aggregate(stats, tracker.summary())) if stats else ("empty", None)

    def _poll(self) -> None:
        if self._result is None:
            self.status.config(text=self.ui.tr("au_working", n=self._n), fg=GREEN)
            self.ui.root.after(150, self._poll)
            return
        kind, agg = self._result
        if kind == "done":
            self._agg = agg
            self.status.config(text="")
        else:
            self._agg = None
            self.status.config(text=self.ui.tr("au_error" if kind == "error" else "au_empty"), fg=RED)
        self.render()

    def save_report(self) -> None:
        if not self._agg:
            self.status.config(text=self.ui.tr("au_empty"), fg=RED)
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".html", initialfile="ciphercheck-audit",
            filetypes=[("HTML", "*.html"), ("Text", "*.txt"), ("JSON", "*.json")])
        if not path:
            return
        fmt = Path(path).suffix.lstrip(".").lower()
        try:
            report.write_aggregate(self._agg, path, fmt if fmt in report.AGG_RENDERERS else "txt")
        except OSError as exc:
            self.status.config(text=f"> {exc}", fg=RED)
            return
        self.status.config(text="> " + self.ui.tr("st_report", path=path), fg=GREEN)

    # ----- rendering -----
    def render(self) -> None:
        ui, c, agg = self.ui, self.chart, self._agg
        c.delete("all")
        if not agg:
            self.total.config(text="")
            ui.write(self.text, [])
            return
        total = agg["total"]
        self.total.config(text=ui.tr("au_total", n=f"{total:,}"))
        fam = ui.family
        top = max(agg["assessment_counts"].values()) or 1
        for i, lbl in enumerate(LABEL_ORDER):
            level, color = LEVELS[lbl]
            n = agg["assessment_counts"][lbl]
            y = 4 + i * 25
            c.create_text(0, y + 9, anchor="w", text=ui.tr(f"v{level}"), fill=color,
                          font=(fam, ui.size(10), "bold"))
            width = int(300 * n / top)
            c.create_rectangle(170, y, 170 + max(width, 2 if n else 0), y + 18,
                               fill=color if n else DARKER, outline="")
            c.create_text(170 + width + 8, y + 9, anchor="w", fill=GREEN, font=(fam, ui.size(10)),
                          text=f"{n:,}  ({100 * n / total:.1f}%)")
        lines: list[tuple[str, str]] = []
        reuse = agg.get("reuse", {})
        for key, field in (("au_dupes", "exact_duplicates"), ("au_similar", "similar_to_another")):
            n = reuse.get(field, 0)
            if n:
                lines.append(("bad", " [-] " + ui.tr(key, n=f"{n:,}", pct=f"{100 * n / total:.1f}")))
        if agg["pattern_counts"]:
            lines.append(("head", ui.tr("au_issues")))
            for kind, n in agg["pattern_counts"].items():
                lines.append(("bad", f" [-] {100 * n / total:.0f}%  {ui.tr('p_' + KIND_KEY[kind])}"))
        ui.write(self.text, lines)
