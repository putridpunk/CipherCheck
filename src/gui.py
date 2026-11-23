"""CipherCheck desktop app: Matrix / hacker themed, plain-language UI (tkinter)."""

from __future__ import annotations

import random
import tkinter as tk

from .analyzer import analyze
from .friendly import explain, generate_password

BG = "#000000"
PANEL = "#020b04"
GREEN = "#00ff41"
DIM = "#2f9e4f"
DARKER = "#0b3d1a"
MONO = "Consolas"

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

        self.canvas = tk.Canvas(root, bg=BG, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.rain = MatrixRain(self.canvas)
        self.rain.tick()

        self.panel = tk.Frame(root, bg=PANEL, highlightbackground=GREEN, highlightthickness=1)
        self.panel.place(relx=0.5, rely=0.5, anchor="center", width=660, height=770)
        self._build()
        self._blink = True
        self._blink_title()
        self.update_result()

    # ---------- layout ----------
    def _label(self, text="", size=11, color=GREEN, bold=False, **kw) -> tk.Label:
        return tk.Label(self.panel, text=text, bg=PANEL, fg=color,
                        font=(MONO, size, "bold" if bold else "normal"), **kw)

    def _button(self, parent, text, command, width=None) -> tk.Button:
        b = tk.Button(parent, text=text, command=command, bg=BG, fg=GREEN, relief="flat",
                      font=(MONO, 11, "bold"), cursor="hand2", bd=0, padx=10, pady=6,
                      activebackground=GREEN, activeforeground=BG,
                      highlightbackground=GREEN, highlightthickness=1)
        if width:
            b.config(width=width)
        b.bind("<Enter>", lambda e: b.config(bg=GREEN, fg=BG))
        b.bind("<Leave>", lambda e: b.config(bg=BG, fg=GREEN))
        return b

    def _build(self) -> None:
        self.title = self._label("CIPHERCHECK_", 26, GREEN, True)
        self.title.pack(pady=(18, 0))
        self._label("> descobre se a tua senha aguenta um hacker", 11, DIM).pack()

        self._label("root@tu:~$ escreve a tua senha", 11, DIM, anchor="w").pack(
            fill="x", padx=30, pady=(18, 4))
        row = tk.Frame(self.panel, bg=PANEL)
        row.pack(fill="x", padx=30)
        self.var = tk.StringVar()
        self.entry = tk.Entry(row, textvariable=self.var, show="•", font=(MONO, 16),
                              bg=BG, fg=GREEN, insertbackground=GREEN, relief="flat",
                              highlightthickness=1, highlightbackground=DARKER,
                              highlightcolor=GREEN, selectbackground=GREEN, selectforeground=BG)
        self.entry.pack(side="left", fill="x", expand=True, ipady=7)
        self.show_btn = self._button(row, "mostrar", self.toggle_show, width=9)
        self.show_btn.pack(side="left", padx=(8, 0))
        self.var.trace_add("write", lambda *_: self.update_result())
        self.entry.focus_set()

        self._label("Fica tudo no teu computador. Nada é enviado nem guardado.",
                    9, DIM).pack(pady=(6, 0))

        self.verdict = self._label("", 30, GREEN, True)
        self.verdict.pack(pady=(14, 4))
        self.bar = tk.Canvas(self.panel, width=600, height=16, bg=PANEL, highlightthickness=0)
        self.bar.pack()
        self.headline = self._label("", 12, GREEN, wraplength=600, justify="center")
        self.headline.pack(pady=(8, 2))
        self.crack = self._label("", 10, DIM, wraplength=600, justify="center")
        self.crack.pack()

        frame = tk.Frame(self.panel, bg=PANEL)
        frame.pack(fill="both", expand=True, padx=30, pady=(12, 6))
        self.text = tk.Text(frame, bg=BG, fg=GREEN, font=(MONO, 11), relief="flat", wrap="word",
                            highlightthickness=1, highlightbackground=DARKER, padx=12, pady=10,
                            state="disabled", cursor="arrow", spacing1=2, spacing3=2)
        self.text.pack(fill="both", expand=True)
        self.text.tag_config("head", foreground=DIM, font=(MONO, 10, "bold"), spacing1=8)
        self.text.tag_config("bad", foreground="#ff6b6b")
        self.text.tag_config("good", foreground=GREEN)
        self.text.tag_config("tip", foreground="#9dffb5")
        self.text.tag_config("idle", foreground=DIM)

        buttons = tk.Frame(self.panel, bg=PANEL)
        buttons.pack(pady=(4, 6))
        self._button(buttons, "GERAR SENHA FORTE", self.generate).pack(side="left", padx=4)
        self._button(buttons, "COPIAR", self.copy).pack(side="left", padx=4)
        self._button(buttons, "LIMPAR", lambda: self.var.set("")).pack(side="left", padx=4)

        self.status = self._label("", 10, GREEN)
        self.status.pack(pady=(0, 12))

    # ---------- behaviour ----------
    def _blink_title(self) -> None:
        self._blink = not self._blink
        self.title.config(text="CIPHERCHECK" + ("_" if self._blink else " "))
        self.root.after(550, self._blink_title)

    def toggle_show(self) -> None:
        hidden = self.entry.cget("show") != ""
        self.entry.config(show="" if hidden else "•")
        self.show_btn.config(text="esconder" if hidden else "mostrar")

    def say(self, msg: str) -> None:
        self.status.config(text="> " + msg)
        self._status_job = self.root.after(5000, lambda: self.status.config(text=""))

    def generate(self) -> None:
        self.var.set(generate_password(16))
        if self.entry.cget("show") != "":
            self.toggle_show()
        self.say("Senha criada! Copia-a e guarda-a num sítio seguro.")

    def copy(self) -> None:
        pw = self.var.get()
        if not pw:
            self.say("Ainda não escreveste nenhuma senha.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(pw)
        self.say("Copiado! Vai ser apagado da área de transferência em 30 segundos.")

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
            self.headline.config(text="Escreve uma senha em cima para começar.", fg=DIM)
            self.crack.config(text="")
            self._write([("idle", "A análise aparece aqui enquanto escreves."),
                         ("idle", ""),
                         ("idle", "Dica: não precisas de usar a tua senha verdadeira."
                                  " Experimenta uma parecida para ver como funciona.")])
            return
        r = explain(analyze(pw))
        self.verdict.config(text=r.verdict, fg=r.color)
        self._draw_bar(r.level, r.color)
        self.headline.config(text=r.headline, fg=r.color)
        self.crack.config(text=f"Um hacker com um computador potente descobria-a em: {r.crack_time}")
        lines: list[tuple[str, str]] = []
        if r.bad:
            lines += [("head", "[ O QUE ESTÁ MAL ]")] + [("bad", f" [-] {t}") for t in r.bad]
        if r.good:
            lines += [("head", "[ O QUE ESTÁ BEM ]")] + [("good", f" [+] {t}") for t in r.good]
        if r.tips:
            lines += [("head", "[ COMO MELHORAR ]")] + [("tip", f" [>] {t}") for t in r.tips]
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
