"""CipherCheck desktop app: Matrix / hacker themed, plain-language, multilingual UI (tkinter)."""

from __future__ import annotations

import random
import tkinter as tk

from .analyzer import analyze
from .friendly import explain, generate_password
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
        root.geometry("1000x820")
        root.minsize(900, 800)

        self.lang = detect_language()
        self._fonted: list[tuple[tk.Widget, int, bool]] = []
        self._status_job: str | None = None

        self.canvas = tk.Canvas(root, bg=BG, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.rain = MatrixRain(self.canvas)
        self.rain.tick()

        self.panel = tk.Frame(root, bg=PANEL, highlightbackground=GREEN, highlightthickness=1)
        self.panel.place(relx=0.5, rely=0.5, anchor="center", width=660, height=770)
        self._build()
        self._blink = True
        self._blink_title()
        self.apply_language()

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
        self.text.tag_config("head", font=(fam, 10, "bold"))

    def _label(self, text="", size=11, color=GREEN, bold=False, **kw) -> tk.Label:
        lbl = tk.Label(self.panel, text=text, bg=PANEL, fg=color, **kw)
        self._reg(lbl, size, bold)
        return lbl

    def _button(self, parent, command, width=None) -> tk.Button:
        b = tk.Button(parent, command=command, bg=BG, fg=GREEN, relief="flat",
                      cursor="hand2", bd=0, padx=10, pady=6,
                      activebackground=GREEN, activeforeground=BG,
                      highlightbackground=GREEN, highlightthickness=1)
        self._reg(b, 10, True)
        if width:
            b.config(width=width)
        b.bind("<Enter>", lambda e: b.config(bg=GREEN, fg=BG))
        b.bind("<Leave>", lambda e: b.config(bg=BG, fg=GREEN))
        return b

    # ---------- layout ----------
    def _build(self) -> None:
        self.title = tk.Label(self.panel, text="CIPHERCHECK_", bg=PANEL, fg=GREEN,
                              font=(MONO, 26, "bold"))
        self.title.pack(pady=(34, 0))
        self.subtitle = self._label(size=11, color=DIM, wraplength=600)
        self.subtitle.pack()

        self.prompt = self._label(size=11, color=DIM)
        self.prompt.pack(fill="x", padx=30, pady=(18, 4))
        row = tk.Frame(self.panel, bg=PANEL)
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
        self.entry.focus_set()

        self.privacy = self._label(size=9, color=DIM, wraplength=600)
        self.privacy.pack(pady=(6, 0))

        self.verdict = self._label(size=30, bold=True)
        self.verdict.pack(pady=(14, 4))
        self.bar = tk.Canvas(self.panel, width=600, height=16, bg=PANEL, highlightthickness=0)
        self.bar.pack()
        self.headline = self._label(size=12, wraplength=600, justify="center")
        self.headline.pack(pady=(8, 2))
        self.crack = self._label(size=10, color=DIM, wraplength=600, justify="center")
        self.crack.pack()

        frame = tk.Frame(self.panel, bg=PANEL)
        frame.pack(fill="both", expand=True, padx=30, pady=(12, 6))
        self.text = tk.Text(frame, bg=BG, fg=GREEN, relief="flat", wrap="word",
                            highlightthickness=1, highlightbackground=DARKER, padx=12, pady=10,
                            state="disabled", cursor="arrow", spacing1=2, spacing3=2)
        self._reg(self.text, 11)
        self.text.pack(fill="both", expand=True)
        self.text.tag_config("head", foreground=DIM, spacing1=8)
        self.text.tag_config("bad", foreground="#ff6b6b")
        self.text.tag_config("good", foreground=GREEN)
        self.text.tag_config("tip", foreground="#9dffb5")
        self.text.tag_config("idle", foreground=DIM)

        buttons = tk.Frame(self.panel, bg=PANEL)
        buttons.pack(pady=(4, 6))
        self.gen_btn = self._button(buttons, self.generate)
        self.copy_btn = self._button(buttons, self.copy)
        self.clear_btn = self._button(buttons, lambda: self.var.set(""))
        for b in (self.gen_btn, self.copy_btn, self.clear_btn):
            b.pack(side="left", padx=4)

        self.status = self._label(size=10, wraplength=600)
        self.status.pack(pady=(0, 12))

        # language selector (top-right corner of the panel)
        self.lang_var = tk.StringVar(value=LANGUAGES[self.lang])
        self.lang_menu = tk.OptionMenu(self.panel, self.lang_var, *LANGUAGES.values(),
                                       command=self.on_language)
        menu_font = ("Segoe UI", 10)
        self.lang_menu.config(bg=BG, fg=GREEN, activebackground=GREEN, activeforeground=BG,
                              relief="flat", bd=0, highlightthickness=1,
                              highlightbackground=GREEN, font=menu_font, cursor="hand2")
        self.lang_menu["menu"].config(bg=BG, fg=GREEN, activebackground=GREEN,
                                      activeforeground=BG, font=menu_font, bd=0)
        self.lang_menu.place(relx=1.0, x=-12, y=10, anchor="ne")

    # ---------- language ----------
    def set_language(self, code: str) -> None:
        self.lang = code
        self.lang_var.set(LANGUAGES[code])
        self.apply_language()

    def on_language(self, name: str) -> None:
        self.set_language(next(code for code, n in LANGUAGES.items() if n == name))

    def apply_language(self) -> None:
        rtl = is_rtl(self.lang)
        self._apply_fonts()
        self.subtitle.config(text=self.tr("subtitle"))
        self.prompt.config(text=self.tr("prompt"), anchor="e" if rtl else "w")
        self.privacy.config(text=self.tr("privacy"))
        self.gen_btn.config(text=self.tr("gen"))
        self.copy_btn.config(text=self.tr("copy"))
        self.clear_btn.config(text=self.tr("clear"))
        self._refresh_show_btn()
        for tag in ("head", "bad", "good", "tip", "idle"):
            self.text.tag_config(tag, justify="right" if rtl else "left")
        self.status.config(text="")
        self.update_result()

    # ---------- behaviour ----------
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

    def say(self, key: str) -> None:
        if self._status_job:
            self.root.after_cancel(self._status_job)
        self.status.config(text="> " + self.tr(key))
        self._status_job = self.root.after(5000, lambda: self.status.config(text=""))

    def generate(self) -> None:
        self.var.set(generate_password(16))
        if self.entry.cget("show") != "":
            self.toggle_show()
        self.say("st_generated")

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

    def _draw_bar(self, level: int, color: str) -> None:
        self.bar.delete("all")
        seg, gap = 28, 2
        for i in range(20):
            filled = i < level * 4
            self.bar.create_rectangle(i * (seg + gap), 0, i * (seg + gap) + seg, 16,
                                      fill=color if filled else DARKER, outline="")

    def _write(self, lines: list[tuple[str, str]]) -> None:
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        for tag, line in lines:
            self.text.insert("end", line + "\n", tag)
        self.text.config(state="disabled")

    def update_result(self) -> None:
        pw = self.var.get()
        if not pw:
            self.verdict.config(text="—", fg=DIM)
            self._draw_bar(0, DIM)
            self.headline.config(text=self.tr("idle_headline"), fg=DIM)
            self.crack.config(text="")
            self._write([("idle", self.tr("idle_1")), ("idle", ""), ("idle", self.tr("idle_2"))])
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
        self._write(lines)


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
