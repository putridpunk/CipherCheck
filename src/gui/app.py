"""Main window: Matrix background, header, tab bar, language menu."""

from __future__ import annotations

import tkinter as tk

from .. import settings
from ..i18n import LANGUAGES, detect_language
from .analyze_tab import AnalyzeTab
from .audit_tab import AuditTab
from .hash_tab import HashTab
from .rain import MatrixRain
from .theme import BG, DIM, GREEN, MENU_FONT, MONO, PANEL
from .widgets import UI

TAB_CLASSES = {"analyze": AnalyzeTab, "audit": AuditTab, "hash": HashTab}


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("CipherCheck")
        root.configure(bg=BG)
        height = min(840, root.winfo_screenheight() - 90)
        root.geometry(f"1000x{height}")
        root.minsize(900, 600)

        saved = settings.load().get("language")
        self.ui = UI(root, saved if saved in LANGUAGES else detect_language())

        self.canvas = tk.Canvas(root, bg=BG, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.rain = MatrixRain(self.canvas)
        self.rain.tick()

        self.panel = tk.Frame(root, bg=PANEL, highlightbackground=GREEN, highlightthickness=1)
        self.panel.place(relx=0.5, rely=0.5, anchor="center", width=660, relheight=0.95)
        self._build_header()
        self._build_tabs()
        self._build_language_menu()

        self._blink = True
        self._blink_title()
        self.apply_language()
        self.show_tab("analyze")

    def _build_header(self) -> None:
        ui = self.ui
        self.title = tk.Label(self.panel, text="CIPHERCHECK_", bg=PANEL, fg=GREEN,
                              font=(MONO, 26, "bold"))
        self.title.pack(pady=(34, 0))
        self.subtitle = ui.label(self.panel, size=11, color=DIM, wraplength=600)
        self.subtitle.pack()

    def _build_tabs(self) -> None:
        bar = tk.Frame(self.panel, bg=PANEL)
        bar.pack(pady=(14, 4))
        content = tk.Frame(self.panel, bg=PANEL)
        content.pack(fill="both", expand=True)
        self.tab_buttons: dict[str, tk.Button] = {}
        self.pages: dict[str, tk.Frame] = {}
        self.tabs: dict = {}
        for name, cls in TAB_CLASSES.items():
            b = self.ui.button(bar, lambda n=name: self.show_tab(n), hover=False)
            b.pack(side="left", padx=4)
            self.tab_buttons[name] = b
            self.pages[name] = tk.Frame(content, bg=PANEL)
            self.tabs[name] = cls(self.ui, self.pages[name])

    def _build_language_menu(self) -> None:
        self.lang_var = tk.StringVar(value=LANGUAGES[self.ui.lang])
        self.lang_menu = tk.OptionMenu(self.panel, self.lang_var, *LANGUAGES.values(),
                                       command=self.on_language)
        font = (MENU_FONT, 10)
        self.lang_menu.config(bg=BG, fg=GREEN, activebackground=GREEN, activeforeground=BG,
                              relief="flat", bd=0, highlightthickness=1,
                              highlightbackground=GREEN, font=font, cursor="hand2")
        self.lang_menu["menu"].config(bg=BG, fg=GREEN, activebackground=GREEN,
                                      activeforeground=BG, font=font, bd=0)
        self.lang_menu.place(relx=1.0, x=-12, y=10, anchor="ne")

    # ----- behaviour -----
    def show_tab(self, name: str) -> None:
        for page in self.pages.values():
            page.pack_forget()
        self.pages[name].pack(fill="both", expand=True)
        for n, b in self.tab_buttons.items():
            on = n == name
            b.config(bg=GREEN if on else BG, fg=BG if on else GREEN)
        self.tabs[name].focus()

    def on_language(self, name: str) -> None:
        self.ui.lang = next(code for code, n in LANGUAGES.items() if n == name)
        settings.save(language=self.ui.lang)
        self.apply_language()

    def apply_language(self) -> None:
        ui = self.ui
        ui.apply_fonts()
        self.subtitle.config(text=ui.tr("subtitle"))
        for name, b in self.tab_buttons.items():
            b.config(text=ui.tr("tab_" + name))
        for tab in self.tabs.values():
            tab.apply_language()

    def _blink_title(self) -> None:
        self._blink = not self._blink
        self.title.config(text="CIPHERCHECK" + ("_" if self._blink else " "))
        self.root.after(550, self._blink_title)


def run() -> None:
    try:  # crisp text on high-DPI Windows screens
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    root = tk.Tk()
    App(root)
    root.mainloop()
