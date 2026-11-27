"""AUDIT tab: statistics dashboard for a file of synthetic test passwords."""

from __future__ import annotations

import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog

from .. import banned as banned_mod
from .. import history, report
from .. import policy as policy_mod
from .. import profile as profile_mod
from ..analyzer import LABEL_ORDER
from ..audit import NoPasswordColumn, audit_file
from ..friendly import KEY as KIND_KEY
from ..friendly import LEVELS
from ..policy import PRESETS as POLICY_PRESETS
from .theme import DARKER, DIM, GREEN, PANEL, RED
from .widgets import UI

POLL_MS = 120
CLIPBOARD_WIPE_MS = 30_000
POLICY_KEYS = ["none", "basic", "nist", "strong", "custom"]


class AuditTab:
    def __init__(self, ui: UI, page: tk.Frame):
        self.ui = ui
        self.show_drop_hint = False  # set by the app when drag and drop is available
        self._agg: dict | None = None
        self._lines = 0
        self._fraction = 0.0
        self._result: tuple[str, dict | None, bool] | None = None
        self._thread: threading.Thread | None = None
        self._cancel = threading.Event()
        self._policy_i = 0  # index into POLICY_KEYS; "none" by default
        self._custom_policy: policy_mod.Policy | None = None
        self._banned_words: list[str] | None = None
        self._profiles: dict[str, list[str]] | None = None
        self._previous_agg: dict | None = None

        self.intro = ui.label(page, size=10, color=DIM, wraplength=600, justify="center")
        self.intro.pack(padx=30, pady=(12, 4), fill="x")
        self.drop_hint = ui.label(page, size=9, color=DIM, wraplength=600, justify="center")
        self.drop_hint.pack(padx=30, pady=(0, 6), fill="x")
        buttons = ui.button_row(page)
        buttons.frame.pack()
        self.choose_btn = buttons.button(self.choose_file)
        self.cancel_btn = buttons.button(self.cancel)
        self.save_btn = buttons.button(self.save_report)
        policy_row = ui.button_row(page)
        policy_row.frame.pack()
        self.policy_btn = policy_row.button(self.cycle_policy)
        self.load_policy_btn = policy_row.button(self.load_policy_file)
        self.gen_policy_btn = policy_row.button(self.generate_for_policy)
        extra_row = ui.button_row(page)
        extra_row.frame.pack()
        self.load_banned_btn = extra_row.button(self.load_banned_words)
        self.load_profiles_btn = extra_row.button(self.load_profiles)
        extra_row2 = ui.button_row(page)
        extra_row2.frame.pack()
        self.compare_file_btn = extra_row2.button(self.choose_compare_file)
        self.remediation_btn = extra_row2.button(self.export_remediation)
        self.status = ui.label(page, size=10, wraplength=600)
        self.status.pack(pady=(8, 0))
        self.compare = ui.label(page, size=9, color=DIM, wraplength=600, justify="center")
        self.compare.pack(pady=(2, 0))
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
        self.compare.config(text="")
        self.render()

    def apply_language(self) -> None:
        ui = self.ui
        self.intro.config(text=ui.tr("au_intro"))
        self.drop_hint.config(text=ui.tr("au_drop") if self.show_drop_hint else "")
        self.choose_btn.config(text=ui.tr("au_choose"))
        self.cancel_btn.config(text=ui.tr("au_cancel"))
        self.save_btn.config(text=ui.tr("save_report"))
        self.load_policy_btn.config(text=ui.tr("au_load_policy"))
        self.gen_policy_btn.config(text=ui.tr("au_gen_policy_btn"))
        self.load_banned_btn.config(text=ui.tr("au_load_banned"))
        self.load_profiles_btn.config(text=ui.tr("au_load_profiles"))
        self.compare_file_btn.config(text=ui.tr("au_compare_file_btn"))
        self.remediation_btn.config(text=ui.tr("au_remediation_btn"))
        self._update_policy_btn()
        self._sync_buttons()
        self.render()

    def _current_policy(self) -> policy_mod.Policy | None:
        key = POLICY_KEYS[self._policy_i]
        return self._custom_policy if key == "custom" else POLICY_PRESETS.get(key)

    def _update_policy_btn(self) -> None:
        key = POLICY_KEYS[self._policy_i]
        self.policy_btn.config(text=self.ui.tr("au_policy_btn", name=self.ui.tr(f"au_policy_{key}")))
        self.gen_policy_btn.config(state="normal" if self._current_policy() else "disabled")

    def cycle_policy(self) -> None:
        if self.running:
            return
        self._policy_i = (self._policy_i + 1) % len(POLICY_KEYS)
        self._update_policy_btn()

    def load_policy_file(self) -> None:
        if self.running:
            return
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            self._custom_policy = policy_mod.load_file(path)
        except (OSError, ValueError) as exc:
            self.status.config(text=f"> {self.ui.tr('au_policy_load_error')} ({exc})", fg=RED)
            return
        self._policy_i = POLICY_KEYS.index("custom")
        self._update_policy_btn()
        self.status.config(text="> " + self.ui.tr("au_policy_loaded"), fg=GREEN)

    def generate_for_policy(self) -> None:
        pol = self._current_policy()
        if pol is None:
            return
        pw = policy_mod.generate_compliant(pol)
        root = self.ui.root
        root.clipboard_clear()
        root.clipboard_append(pw)
        self.status.config(text="> " + self.ui.tr("au_policy_generated"), fg=GREEN)

        def wipe() -> None:
            try:
                if root.clipboard_get() == pw:
                    root.clipboard_clear()
            except tk.TclError:
                pass
        root.after(CLIPBOARD_WIPE_MS, wipe)

    def load_banned_words(self) -> None:
        if self.running:
            return
        path = filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            self._banned_words = banned_mod.load_file(path)
        except OSError as exc:
            self.status.config(text=f"> {self.ui.tr('au_banned_load_error')} ({exc})", fg=RED)
            return
        self.status.config(text="> " + self.ui.tr("au_banned_loaded"), fg=GREEN)

    def load_profiles(self) -> None:
        if self.running:
            return
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            self._profiles = profile_mod.load_profiles_file(path)
        except (OSError, ValueError) as exc:
            self.status.config(text=f"> {self.ui.tr('au_profiles_load_error')} ({exc})", fg=RED)
            return
        self.status.config(text="> " + self.ui.tr("au_profiles_loaded"), fg=GREEN)

    def choose_compare_file(self) -> None:
        if self.running:
            return
        if self._agg is None:
            self.status.config(text=self.ui.tr("au_compare_need_first"), fg=RED)
            return
        path = filedialog.askopenfilename(
            filetypes=[("Text / CSV / TSV", "*.txt *.lst *.csv *.tsv *.dic"), ("All files", "*.*")])
        if path:
            self.start(path, compare_only=True)

    def export_remediation(self) -> None:
        if not self._agg or not self._agg.get("worst_entries"):
            self.status.config(text=self.ui.tr("au_no_remediation"), fg=RED)
            return
        pol = self._current_policy() or POLICY_PRESETS["strong"]
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", initialfile="ciphercheck-remediation", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        try:
            Path(path).write_text(report.remediation_csv(self._agg, pol), encoding="utf-8")
        except OSError as exc:
            self.status.config(text=f"> {exc}", fg=RED)
            return
        self.status.config(text="> " + self.ui.tr("st_report", path=path), fg=GREEN)

    def _sync_buttons(self) -> None:
        busy = self.running
        self.cancel_btn.config(state="normal" if busy else "disabled")
        self.choose_btn.config(state="disabled" if busy else "normal")
        self.policy_btn.config(state="disabled" if busy else "normal")
        self.load_policy_btn.config(state="disabled" if busy else "normal")
        self.gen_policy_btn.config(state="disabled" if busy or not self._current_policy() else "normal")
        self.load_banned_btn.config(state="disabled" if busy else "normal")
        self.load_profiles_btn.config(state="disabled" if busy else "normal")
        self.compare_file_btn.config(state="disabled" if busy else "normal")
        self.remediation_btn.config(state="disabled" if busy else "normal")

    # ----- running the audit (background thread keeps the window responsive) -----
    def choose_file(self) -> None:
        if self.running:
            return
        path = filedialog.askopenfilename(
            filetypes=[("Text / CSV / TSV", "*.txt *.lst *.csv *.tsv *.dic"), ("All files", "*.*")])
        if path:
            self.start(path)

    def start(self, path: str, compare_only: bool = False) -> None:
        """Audit `path` (from the file dialog or a dropped file). `compare_only` audits it
        without replacing the currently shown statistics, just to compare it against them."""
        if self.running:
            return
        self._lines, self._fraction, self._result = 0, 0.0, None
        self._cancel = threading.Event()
        self._thread = threading.Thread(
            target=self._worker, args=(path, self._cancel, compare_only), daemon=True)
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

    def _worker(self, path: str, cancel: threading.Event, compare_only: bool) -> None:
        policy = self._current_policy()
        try:
            agg = audit_file(path, progress=self._on_progress, cancel=cancel, policy=policy,
                             banned=self._banned_words, profiles=self._profiles)
        except NoPasswordColumn:
            self._result = ("csv_error", None, compare_only)
            return
        except OSError:
            self._result = ("error", None, compare_only)
            return
        if agg is None:
            self._result = ("cancelled", None, compare_only)
        elif agg["total"] == 0:
            self._result = ("empty", None, compare_only)
        else:
            self._result = ("done", agg, compare_only)

    def _poll(self) -> None:
        self._draw_progress(self._fraction if self._result is None else 0.0)
        if self._result is None:
            pct = f"{100 * self._fraction:.0f}"
            self.status.config(text=self.ui.tr("au_working", n=f"{self._lines:,}", pct=pct), fg=GREEN)
            self.ui.root.after(POLL_MS, self._poll)
            return
        # `compare_only` travels inside the (immutable, re-readable) result tuple itself,
        # rather than as a separate flag, so handling the same finished result more than
        # once - which cannot happen in the real app, but is how a couple of tests check a
        # fast-finishing audit - stays safe: it always takes the same branch below.
        kind, agg, compare_only = self._result
        if kind == "done":
            assert agg is not None  # only None for "error"/"cancelled"/"empty"/"csv_error"
            if compare_only:
                self.status.config(text="")
                self.compare.config(text=self._compare_text(self._agg, agg))
                self._sync_buttons()
                self.render()
                return
            compare_text = self._compare_text(self._previous_agg, agg)
            self._previous_agg = agg
            self._agg = agg
            self.status.config(text="")
            hist = history.record(agg["total"], agg["average_estimated_bits"], report.weak_percent(agg))
            trend_text = self._trend_text(hist)
            self.compare.config(text="\n".join(t for t in (compare_text, trend_text) if t))
        else:
            key = {"error": "au_error", "empty": "au_empty", "cancelled": "au_cancelled",
                   "csv_error": "au_csv_nocolumn"}[kind]
            self.status.config(text=self.ui.tr(key), fg=RED if kind != "cancelled" else DIM)
            if kind != "cancelled" and not compare_only:
                self._agg = None
        self._sync_buttons()
        self.render()

    def _compare_text(self, old: dict | None, new: dict) -> str:
        ui = self.ui
        if old is None:
            return ""
        delta = report.compare_aggregates(old, new)
        if delta["unchanged"]:
            return ui.tr("au_compare_same")
        bits, pct = delta["delta_average_bits"], delta["delta_weak_percent"]
        key = "au_compare_better" if delta["improved"] else "au_compare_worse"
        return ui.tr(key, bits=f"{abs(bits):.1f}", pct=f"{abs(pct):.1f}")

    def _trend_text(self, hist: list[dict]) -> str:
        recent = hist[-6:]
        if len(recent) < 2:
            return ""
        values = " → ".join(f"{h['average_bits']:.0f}" for h in recent)
        return self.ui.tr("au_trend", n=len(recent), values=values)

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
            filetypes=[("HTML", "*.html"), ("Text", "*.txt"), ("JSON", "*.json"), ("CSV", "*.csv")])
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
        shared = reuse.get("shared_accounts", [])
        if shared:
            lines.append(("head", ui.tr("au_shared")))
            for g in shared:
                lines.append(("bad", " [-] " + " / ".join(g["labels"])))
        worst = agg.get("worst_entries", [])
        if worst:
            lines.append(("head", ui.tr("au_fix_first")))
            for w in worst:
                kinds = [k for k in w["kinds"] if k in KIND_KEY]
                reason = ui.tr("p_" + KIND_KEY[kinds[0]]) if kinds else ""
                lines.append(("bad", f" [-] {w['label']}: {reason}"))
        pol = agg.get("policy")
        if pol:
            lines.append(("head", ui.tr("au_policy_result", name=ui.tr(f"au_policy_{pol['key']}"),
                                        passed=f"{pol['passed']:,}", pct=f"{pol['pass_percent']}")))
            for reason, n in pol.get("reasons", {}).items():
                lines.append(("bad", f" [-] {100 * n / total:.0f}%  {ui.tr('pr_' + reason)}"))
        ui.write(self.text, lines)
