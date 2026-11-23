"""CipherCheck desktop app: Matrix / hacker themed, plain-language, multilingual UI (tkinter).

Three tabs: ANALYZE (one password), AUDIT (statistics dashboard for a file of
synthetic test passwords) and HASH (identify a hash format).
"""

from __future__ import annotations

import random
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog
from types import SimpleNamespace

from . import hashes, report
from .analyzer import LABEL_ORDER, analyze
from .friendly import KEY as KIND_KEY
from .friendly import LEVELS, explain, generate_password, strengthen
from .i18n import LANGUAGES, detect_language, is_rtl, t

BG = "#000000"
PANEL = "#020b04"
GREEN = "#00ff41"
DIM = "#2f9e4f"
DARKER = "#0b3d1a"
MONO = "Consolas"
# Fonts with proper glyph coverage for non-Latin scripts (Windows).
FONT_FAMILY = {"ja": "Yu Gothic UI", "zh": "Microsoft YaHei UI", "ar": "Segoe UI"}

CELL = 18
TRAIL = 16
GLYPHS = [chr(c) for c in range(0xFF66, 0xFF9E)] + list("0123456789")
HEAD_COLOR = "#d6ffe0"
TRAIL_COLORS = [f"#00{int(210 - 195 * k / (TRAIL - 1)):02x}{int(55 - 40 * k / (TRAIL - 1)):02x}"
                for k in range(TRAIL)]
TABS = ("analyze", "audit", "hash")


class MatrixRain:
    """Falling-glyph background drawn on a canvas."""

    def __init__(self, canvas: tk.Canvas):
        self.canvas = canvas
        self.cols = self.rows = 0
        self.state: list[dict] = []
        canvas.bind("<Configure>", self._resize)

    def _new_col(self, spread: bool) -> dict:
        return {"head": random.uniform(-self.rows, self.rows) if spread else random.uniform(-20, 0),
                "speed": random.uniform(0.25, 0.9),
                "chars": [random.choice(GLYPHS) for _ in range(self.rows + TRAIL + 2)]}

    def _resize(self, event: tk.Event) -> None:
        self.cols = event.width // CELL + 1
        self.rows = event.height // CELL + 1
        self.state = [self._new_col(True) for _ in range(self.cols)]

    def tick(self) -> None:
        c = self.canvas
        c.delete("rain")
        for x, col in enumerate(self.state):
            col["head"] += col["speed"]
            if col["head"] - TRAIL > self.rows:
                col.update(self._new_col(False))
            head = int(col["head"])
            for k in range(TRAIL):
                row = head - k
                if 0 <= row < self.rows:
                    if random.random() < 0.04:
                        col["chars"][row] = random.choice(GLYPHS)
                    c.create_text(x * CELL + CELL // 2, row * CELL + CELL // 2,
                                  text=col["chars"][row], tags="rain",
                                  fill=HEAD_COLOR if k == 0 else TRAIL_COLORS[k],
                                  font=("MS Gothic", 12))
        c.after(70, self.tick)


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("CipherCheck")
        root.configure(bg=BG)
        height = min(840, root.winfo_screenheight() - 90)
        root.geometry(f"1000x{height}")
        root.minsize(900, 600)

        self.lang = detect_language()
        self._fonted: list[tuple[tk.Widget, int, bool]] = []
        self._texts: list[tk.Text] = []
        self._status_job: str | None = None
        self._tab = "analyze"
        self._agg: dict | None = None
        self._audit_n = 0
        self._audit_result: tuple[str, dict | None] | None = None

        self.canvas = tk.Canvas(root, bg=BG, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.rain = MatrixRain(self.canvas)
        self.rain.tick()

        self.panel = tk.Frame(root, bg=PANEL, highlightbackground=GREEN, highlightthickness=1)
        self.panel.place(relx=0.5, rely=0.5, anchor="center", width=660, relheight=0.95)
        self._build()
        self._blink = True
        self._blink_title()
        self.apply_language()
        self.show_tab("analyze")

    # ---------- helpers ----------
    def tr(self, key: str, **kw) -> str:
        return t(self.lang, key, **kw)

    def _family(self) -> str:
        return FONT_FAMILY.get(self.lang, MONO)

    def _reg(self, widget: tk.Widget, size: int, bold: bool = False) -> None:
        self._fonted.append((widget, size, bold))

    def _apply_fonts(self) -> None:
        fam = self._family()
        for w, size, bold in self._fonted:
            w.config(font=(fam, size, "bold" if bold else "normal"))
        for tw in self._texts:
            tw.tag_config("head", font=(fam, 10, "bold"))

    def _label(self, parent, text="", size=11, color=GREEN, bold=False, **kw) -> tk.Label:
        lbl = tk.Label(parent, text=text, bg=PANEL, fg=color, **kw)
        self._reg(lbl, size, bold)
        return lbl

    def _button(self, parent, command, width=None, hover=True) -> tk.Button:
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

    def _text_view(self, parent, pady=(8, 16)) -> tk.Text:
        frame = tk.Frame(parent, bg=PANEL)
        frame.pack(fill="both", expand=True, padx=30, pady=pady)
        tw = tk.Text(frame, bg=BG, fg=GREEN, relief="flat", wrap="word",
                     highlightthickness=1, highlightbackground=DARKER, padx=12, pady=10,
                     state="disabled", cursor="arrow", spacing1=2, spacing3=2)
        self._reg(tw, 11)
        tw.pack(fill="both", expand=True)
        tw.tag_config("head", foreground=DIM, spacing1=8)
        tw.tag_config("bad", foreground="#ff6b6b")
        tw.tag_config("good", foreground=GREEN)
        tw.tag_config("tip", foreground="#9dffb5")
        tw.tag_config("idle", foreground=DIM)
        self._texts.append(tw)
        return tw

    @staticmethod
    def _write(tw: tk.Text, lines: list[tuple[str, str]]) -> None:
        tw.config(state="normal")
        tw.delete("1.0", "end")
        for tag, line in lines:
            tw.insert("end", line + "\n", tag)
        tw.config(state="disabled")

    # ---------- layout ----------
    def _build(self) -> None:
        p = self.panel
        self.title = tk.Label(p, text="CIPHERCHECK_", bg=PANEL, fg=GREEN, font=(MONO, 26, "bold"))
        self.title.pack(pady=(34, 0))
        self.subtitle = self._label(p, size=11, color=DIM, wraplength=600)
        self.subtitle.pack()

        bar = tk.Frame(p, bg=PANEL)
        bar.pack(pady=(14, 4))
        self.tab_btns = {}
        for name in TABS:
            b = self._button(bar, lambda n=name: self.show_tab(n), hover=False)
            b.pack(side="left", padx=4)
            self.tab_btns[name] = b

        content = tk.Frame(p, bg=PANEL)
        content.pack(fill="both", expand=True)
        self.pages = {name: tk.Frame(content, bg=PANEL) for name in TABS}
        self._build_analyze(self.pages["analyze"])
        self._build_audit(self.pages["audit"])
        self._build_hash(self.pages["hash"])

        # language selector (top-right corner of the panel)
        self.lang_var = tk.StringVar(value=LANGUAGES[self.lang])
        self.lang_menu = tk.OptionMenu(p, self.lang_var, *LANGUAGES.values(),
                                       command=self.on_language)
        menu_font = ("Segoe UI", 10)
        self.lang_menu.config(bg=BG, fg=GREEN, activebackground=GREEN, activeforeground=BG,
                              relief="flat", bd=0, highlightthickness=1,
                              highlightbackground=GREEN, font=menu_font, cursor="hand2")
        self.lang_menu["menu"].config(bg=BG, fg=GREEN, activebackground=GREEN,
                                      activeforeground=BG, font=menu_font, bd=0)
        self.lang_menu.place(relx=1.0, x=-12, y=10, anchor="ne")

    def _build_analyze(self, page: tk.Frame) -> None:
        self.prompt = self._label(page, size=11, color=DIM)
        self.prompt.pack(fill="x", padx=30, pady=(10, 4))
        row = tk.Frame(page, bg=PANEL)
        row.pack(fill="x", padx=30)
        self.var = tk.StringVar()
        self.entry = tk.Entry(row, textvariable=self.var, show="•", font=(MONO, 16),
                              bg=BG, fg=GREEN, insertbackground=GREEN, relief="flat",
                              highlightthickness=1, highlightbackground=DARKER,
                              highlightcolor=GREEN, selectbackground=GREEN, selectforeground=BG)
        self.entry.pack(side="left", fill="x", expand=True, ipady=7)
        self.show_btn = self._button(row, self.toggle_show, width=9)
        self.show_btn.pack(side="left", padx=(8, 0))
        self.var.trace_add("write", lambda *_: self.update_result())

        self.privacy = self._label(page, size=9, color=DIM, wraplength=600)
        self.privacy.pack(pady=(6, 0))

        buttons = tk.Frame(page, bg=PANEL)
        buttons.pack(pady=(10, 0))
        self.gen_btn = self._button(buttons, self.generate)
        self.gen_btn.grid(row=0, column=0, columnspan=3, pady=(0, 6))
        self.copy_btn = self._button(buttons, self.copy)
        self.clear_btn = self._button(buttons, lambda: self.var.set(""))
        self.save_btn = self._button(buttons, self.save_report)
        for col, b in enumerate((self.copy_btn, self.clear_btn, self.save_btn)):
            b.grid(row=1, column=col, padx=4)
        self.status = self._label(page, size=10, wraplength=600)
        self.status.pack(pady=(4, 0))

        self.verdict = self._label(page, size=28, bold=True)
        self.verdict.pack(pady=(6, 4))
        self.bar = tk.Canvas(page, width=600, height=16, bg=PANEL, highlightthickness=0)
        self.bar.pack()
        self.headline = self._label(page, size=12, wraplength=600, justify="center")
        self.headline.pack(pady=(8, 2))
        self.crack = self._label(page, size=10, color=DIM, wraplength=600, justify="center")
        self.crack.pack()
        self.text = self._text_view(page, pady=(10, 16))

    def _build_audit(self, page: tk.Frame) -> None:
        self.au_intro = self._label(page, size=10, color=DIM, wraplength=600, justify="left")
        self.au_intro.pack(padx=30, pady=(12, 8), fill="x")
        self.au_btn = self._button(page, self.choose_file)
        self.au_btn.pack()
        self.au_status = self._label(page, size=10, wraplength=600)
        self.au_status.pack(pady=(8, 0))
        self.au_total = self._label(page, size=12, bold=True)
        self.au_total.pack(pady=(4, 4))
        self.au_chart = tk.Canvas(page, width=600, height=130, bg=PANEL, highlightthickness=0)
        self.au_chart.pack()
        self.au_text = self._text_view(page, pady=(8, 16))

    def _build_hash(self, page: tk.Frame) -> None:
        self.hash_prompt = self._label(page, size=11, color=DIM)
        self.hash_prompt.pack(fill="x", padx=30, pady=(10, 4))
        self.hash_var = tk.StringVar()
        self.hash_entry = tk.Entry(page, textvariable=self.hash_var, font=(MONO, 12),
                                   bg=BG, fg=GREEN, insertbackground=GREEN, relief="flat",
                                   highlightthickness=1, highlightbackground=DARKER,
                                   highlightcolor=GREEN, selectbackground=GREEN,
                                   selectforeground=BG)
        self.hash_entry.pack(fill="x", padx=30, ipady=7)
        self.hash_var.trace_add("write", lambda *_: self.update_hash())
        self.hash_text = self._text_view(page, pady=(14, 16))

    # ---------- tabs ----------
    def show_tab(self, name: str) -> None:
        self._tab = name
        for page in self.pages.values():
            page.pack_forget()
        self.pages[name].pack(fill="both", expand=True)
        for n, b in self.tab_btns.items():
            on = n == name
            b.config(bg=GREEN if on else BG, fg=BG if on else GREEN)
        {"analyze": self.entry, "hash": self.hash_entry}.get(name, self.root).focus_set()

    # ---------- language ----------
    def on_language(self, name: str) -> None:
        self.lang = next(code for code, n in LANGUAGES.items() if n == name)
        self.apply_language()

    def apply_language(self) -> None:
        rtl = is_rtl(self.lang)
        anchor = "e" if rtl else "w"
        self._apply_fonts()
        self.subtitle.config(text=self.tr("subtitle"))
        for name, b in self.tab_btns.items():
            b.config(text=self.tr("tab_" + name))
        self.prompt.config(text=self.tr("prompt"), anchor=anchor)
        self.hash_prompt.config(text=self.tr("hash_prompt"), anchor=anchor)
        self.privacy.config(text=self.tr("privacy"))
        self.au_intro.config(text=self.tr("au_intro"), justify="right" if rtl else "left")
        self.gen_btn.config(text=self.tr("gen"))
        self.copy_btn.config(text=self.tr("copy"))
        self.clear_btn.config(text=self.tr("clear"))
        self.save_btn.config(text=self.tr("save_report"))
        self.au_btn.config(text=self.tr("au_choose"))
        self._refresh_show_btn()
        for tw in self._texts:
            for tag in ("head", "bad", "good", "tip", "idle"):
                tw.tag_config(tag, justify="right" if rtl else "left")
        self.status.config(text="")
        self.update_result()
        self.update_hash()
        self.render_audit()

    # ---------- analyze tab ----------
    def _blink_title(self) -> None:
        self._blink = not self._blink
        self.title.config(text="CIPHERCHECK" + ("_" if self._blink else " "))
        self.root.after(550, self._blink_title)

    def _refresh_show_btn(self) -> None:
        shown = self.entry.cget("show") == ""
        self.show_btn.config(text=self.tr("hide" if shown else "show"))

    def toggle_show(self) -> None:
        shown = self.entry.cget("show") == ""
        self.entry.config(show="•" if shown else "")
        self._refresh_show_btn()

    def say(self, key: str, **kw) -> None:
        if self._status_job:
            self.root.after_cancel(self._status_job)
        self.status.config(text="> " + self.tr(key, **kw))
        self._status_job = self.root.after(6000, lambda: self.status.config(text=""))

    def generate(self) -> None:
        """Empty field: brand-new strong password. Otherwise: a strong version of the user's."""
        current = self.var.get()
        if not current:
            self.var.set(generate_password(16))
            msg = "st_generated"
        else:
            stronger = strengthen(current)
            msg = "st_already" if stronger == current else "st_similar"
            self.var.set(stronger)
        if self.entry.cget("show") != "":
            self.toggle_show()
        self.say(msg)

    def copy(self) -> None:
        pw = self.var.get()
        if not pw:
            self.say("st_empty")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(pw)
        self.say("st_copied")

        def wipe() -> None:
            try:
                if self.root.clipboard_get() == pw:
                    self.root.clipboard_clear()
            except tk.TclError:
                pass
        self.root.after(30_000, wipe)

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

    def _draw_bar(self, level: int, color: str) -> None:
        self.bar.delete("all")
        seg, gap = 28, 2
        for i in range(20):
            filled = i < level * 4
            self.bar.create_rectangle(i * (seg + gap), 0, i * (seg + gap) + seg, 16,
                                      fill=color if filled else DARKER, outline="")

    def update_result(self) -> None:
        pw = self.var.get()
        if not pw:
            self.verdict.config(text="—", fg=DIM)
            self._draw_bar(0, DIM)
            self.headline.config(text=self.tr("idle_headline"), fg=DIM)
            self.crack.config(text="")
            self._write(self.text, [("idle", self.tr("idle_1")), ("idle", ""),
                                    ("idle", self.tr("idle_2"))])
            return
        r = explain(analyze(pw), self.lang)
        self.verdict.config(text=r.verdict, fg=r.color)
        self._draw_bar(r.level, r.color)
        self.headline.config(text=r.headline, fg=r.color)
        self.crack.config(text=self.tr("crack", time=r.crack_time))
        lines: list[tuple[str, str]] = []
        if r.bad:
            lines += [("head", self.tr("hdr_bad"))] + [("bad", f" [-] {x}") for x in r.bad]
        if r.good:
            lines += [("head", self.tr("hdr_good"))] + [("good", f" [+] {x}") for x in r.good]
        if r.tips:
            lines += [("head", self.tr("hdr_tips"))] + [("tip", f" [>] {x}") for x in r.tips]
        self._write(self.text, lines)

    # ---------- hash tab ----------
    def update_hash(self) -> None:
        s = self.hash_var.get().strip()
        if not s:
            self._write(self.hash_text, [("idle", self.tr("hash_empty")), ("idle", ""),
                                         ("idle", self.tr("hash_note"))])
        else:
            self._write(self.hash_text, hashes.explain(hashes.identify(s), self.lang))

    # ---------- audit tab (statistics dashboard) ----------
    def choose_file(self) -> None:
        if getattr(self, "_audit_thread", None) and self._audit_thread.is_alive():
            return
        path = filedialog.askopenfilename(
            filetypes=[("Text", "*.txt *.lst *.csv *.dic"), ("All files", "*.*")])
        if not path:
            return
        self._audit_n = 0
        self._audit_result = None
        self._audit_thread = threading.Thread(target=self._audit_worker, args=(path,), daemon=True)
        self._audit_thread.start()
        self._poll_audit()

    def _audit_worker(self, path: str) -> None:
        stats = []
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    pw = line.rstrip("\r\n")
                    if not pw:
                        continue
                    a = analyze(pw)  # only aggregate numbers are kept, never the password
                    stats.append(SimpleNamespace(label=a.label, pattern_kinds=a.pattern_kinds,
                                                 estimated_bits=a.estimated_bits, length=a.length))
                    self._audit_n = len(stats)
        except OSError:
            self._audit_result = ("error", None)
            return
        self._audit_result = ("done", report.aggregate(stats)) if stats else ("empty", None)

    def _poll_audit(self) -> None:
        if self._audit_result is None:
            self.au_status.config(text=self.tr("au_working", n=self._audit_n), fg=GREEN)
            self.root.after(150, self._poll_audit)
            return
        kind, agg = self._audit_result
        if kind == "done":
            self._agg = agg
            self.au_status.config(text="")
        else:
            self._agg = None
            self.au_status.config(text=self.tr("au_error" if kind == "error" else "au_empty"),
                                  fg="#ff6b6b")
        self.render_audit()

    def render_audit(self) -> None:
        c = self.au_chart
        c.delete("all")
        agg = self._agg
        if not agg:
            self.au_total.config(text="")
            self._write(self.au_text, [])
            return
        total = agg["total"]
        self.au_total.config(text=self.tr("au_total", n=f"{total:,}"))
        fam = self._family()
        top = max(agg["assessment_counts"].values()) or 1
        for i, lbl in enumerate(LABEL_ORDER):
            level, color = LEVELS[lbl]
            n = agg["assessment_counts"][lbl]
            y = 4 + i * 25
            c.create_text(0, y + 9, anchor="w", text=self.tr(f"v{level}"), fill=color,
                          font=(fam, 10, "bold"))
            width = int(300 * n / top)
            c.create_rectangle(170, y, 170 + max(width, 2 if n else 0), y + 18,
                               fill=color if n else DARKER, outline="")
            c.create_text(170 + width + 8, y + 9, anchor="w", fill=GREEN, font=(fam, 10),
                          text=f"{n:,}  ({100 * n / total:.1f}%)")
        lines: list[tuple[str, str]] = []
        patterns = agg["pattern_counts"]
        if patterns:
            lines.append(("head", self.tr("au_issues")))
            for kind, n in patterns.items():
                text = self.tr("p_" + KIND_KEY[kind])
                lines.append(("bad", f" [-] {100 * n / total:.0f}%  {text}"))
        self._write(self.au_text, lines)


def run() -> None:
    try:  # crisp text on high-DPI Windows screens
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    run()
