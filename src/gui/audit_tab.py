"""AUDIT tab: statistics dashboard for a file of synthetic test passwords."""

from __future__ import annotations

import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog

from .. import report
from ..analyzer import LABEL_ORDER
from ..audit import audit_file
from ..friendly import KEY as KIND_KEY
from ..friendly import LEVELS
from .theme import DARKER, DIM, GREEN, PANEL, RED
from .widgets import UI

POLL_MS = 120


class AuditTab:
    def __init__(self, ui: UI, page: tk.Frame):
        self.ui = ui
        self.show_drop_hint = False  # set by the app when drag and drop is available
        self._agg: dict | None = None
        self._lines = 0
        self._fraction = 0.0
        self._result: tuple[str, dict | None] | None = None
        self._thread: threading.Thread | None = None
        self._cancel = threading.Event()

        self.intro = ui.label(page, size=10, color=DIM, wraplength=600, justify="center")
        self.intro.pack(padx=30, pady=(12, 4), fill="x")
        self.drop_hint = ui.label(page, size=9, color=DIM, wraplength=600, justify="center")
        self.drop_hint.pack(padx=30, pady=(0, 6), fill="x")
        buttons = ui.button_row(page)
        buttons.frame.pack()
        self.choose_btn = buttons.button(self.choose_file)
        self.cancel_btn = buttons.button(self.cancel)
        self.save_btn = buttons.button(self.save_report)
        self.status = ui.label(page, size=10, wraplength=600)
        self.status.pack(pady=(8, 0))
        self.progress = tk.Canvas(page, width=600, height=8, bg=PANEL, highlightthickness=0)
        self.progress.pack(pady=(2, 0))
        self.total = ui.label(page, size=12, bold=True)
        self.total.pack(pady=(4, 4))
        self.chart = tk.Canvas(page, width=600, height=130, bg=PANEL, highlightthickness=0)
        self.chart.pack()
        self.text = ui.text_view(page, pady=(8, 16))

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def focus(self) -> None:
        self.ui.root.focus_set()

    def clear(self) -> None:
        """Escape on this tab: stop a running audit, or forget the loaded statistics."""
        if self.running:
            self.cancel()
            return
        self._agg = None
        self.status.config(text="")
        self.render()

    def apply_language(self) -> None:
        ui = self.ui
        self.intro.config(text=ui.tr("au_intro"))
        self.drop_hint.config(text=ui.tr("au_drop") if self.show_drop_hint else "")
        self.choose_btn.config(text=ui.tr("au_choose"))
        self.cancel_btn.config(text=ui.tr("au_cancel"))
        self.save_btn.config(text=ui.tr("save_report"))
        self._sync_buttons()
        self.render()

    def _sync_buttons(self) -> None:
        busy = self.running
        self.cancel_btn.config(state="normal" if busy else "disabled")
        self.choose_btn.config(state="disabled" if busy else "normal")

    # ----- running the audit (background thread keeps the window responsive) -----
    def choose_file(self) -> None:
        if self.running:
            return
        path = filedialog.askopenfilename(
            filetypes=[("Text", "*.txt *.lst *.csv *.dic"), ("All files", "*.*")])
        if path:
            self.start(path)

    def start(self, path: str) -> None:
        """Audit `path` (from the file dialog or a dropped file)."""
        if self.running:
            return
        self._lines, self._fraction, self._result = 0, 0.0, None
        self._cancel = threading.Event()
        self._thread = threading.Thread(target=self._worker, args=(path, self._cancel), daemon=True)
        self._thread.start()
        self._sync_buttons()
        self._poll()

    def cancel(self) -> None:
        self._cancel.set()

    def report_error(self) -> None:
        """Something that is not a readable file was dropped or chosen."""
        self.status.config(text=self.ui.tr("au_error"), fg=RED)

    def _on_progress(self, lines: int, fraction: float) -> None:
        self._lines, self._fraction = lines, fraction

    def _worker(self, path: str, cancel: threading.Event) -> None:
        try:
            agg = audit_file(path, progress=self._on_progress, cancel=cancel)
        except OSError:
            self._result = ("error", None)
            return
        if agg is None:
            self._result = ("cancelled", None)
        elif agg["total"] == 0:
            self._result = ("empty", None)
        else:
            self._result = ("done", agg)

    def _poll(self) -> None:
        self._draw_progress(self._fraction if self._result is None else 0.0)
        if self._result is None:
            pct = f"{100 * self._fraction:.0f}"
            self.status.config(text=self.ui.tr("au_working", n=f"{self._lines:,}", pct=pct), fg=GREEN)
            self.ui.root.after(POLL_MS, self._poll)
            return
        kind, agg = self._result
        if kind == "done":
            self._agg = agg
            self.status.config(text="")
        else:
            key = {"error": "au_error", "empty": "au_empty", "cancelled": "au_cancelled"}[kind]
            self.status.config(text=self.ui.tr(key), fg=RED if kind != "cancelled" else DIM)
            if kind != "cancelled":
                self._agg = None
        self._sync_buttons()
        self.render()

    def stop_for_close(self) -> None:
        """Called when the window is closing: stop the audit and give its workers a moment."""
        self._cancel.set()
        if self._thread is not None:
            self._thread.join(timeout=3)

    # ----- report -----
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
    def _draw_progress(self, fraction: float) -> None:
        self.progress.delete("all")
        if fraction > 0:
            self.progress.create_rectangle(0, 0, 600, 8, fill=DARKER, outline="")
            self.progress.create_rectangle(0, 0, int(600 * fraction), 8, fill=GREEN, outline="")

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
