"""Main window: Matrix background, header, tab bar, language menu, font size, footer."""

from __future__ import annotations

import tkinter as tk
import webbrowser

from .. import __version__, settings
from ..i18n import LANGUAGES, detect_language
from ..utils import ROOT_DIR
from .analyze_tab import AnalyzeTab
from .audit_tab import AuditTab
from .hash_tab import HashTab
from .rain import MatrixRain
from .theme import BG, DIM, GREEN, MENU_FONT, MONO, PANEL
from .widgets import UI

TAB_CLASSES = {"analyze": AnalyzeTab, "audit": AuditTab, "hash": HashTab}
REPO_URL = "https://github.com/putridpunk/CipherCheck"
ICON = ROOT_DIR / "assets" / "ciphercheck.png"


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("CipherCheck")
        root.configure(bg=BG)
        height = min(840, root.winfo_screenheight() - 90)
        root.geometry(f"1000x{height}")
        root.minsize(900, 600)
        self._set_icon()

        prefs = settings.load()
        lang = prefs.get("language")
        self.ui = UI(root, lang if lang in LANGUAGES else detect_language(),
                     prefs.get("font_scale", 1.0))

        self.canvas = tk.Canvas(root, bg=BG, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.rain = MatrixRain(self.canvas)
        self.rain.tick()

        self.panel = tk.Frame(root, bg=PANEL, highlightbackground=GREEN, highlightthickness=1)
        self.panel.place(relx=0.5, rely=0.5, anchor="center", width=660, relheight=0.95)
        self._build_header()
        self._build_tabs()
        self._build_corner_controls()
        self._bind_shortcuts()

        self._blink = True
        self._blink_title()
        self.apply_language()
        self.show_tab("analyze")

    def _set_icon(self) -> None:
        try:
            self._icon = tk.PhotoImage(file=str(ICON))  # keep a reference
            self.root.iconphoto(True, self._icon)
        except tk.TclError:
            pass  # missing icon file must never stop the app

    # ----- layout -----
    def _build_header(self) -> None:
        ui = self.ui
        self.title = tk.Label(self.panel, text="CIPHERCHECK_", bg=PANEL, fg=GREEN,
                              font=(MONO, 26, "bold"))
        self.title.pack(pady=(34, 0))
        self.subtitle = ui.label(self.panel, size=11, color=DIM, wraplength=600)
        self.subtitle.pack()

    def _build_tabs(self) -> None:
        ui = self.ui
        bar = tk.Frame(self.panel, bg=PANEL)
        bar.pack(pady=(14, 4))
        # footer is packed before the content so it always keeps its space
        self.footer = ui.label(self.panel, size=8, color=DIM, cursor="hand2",
                               text=f"CipherCheck v{__version__}  ·  PolyForm Noncommercial 1.0.0  ·  "
                                    "github.com/putridpunk")
        self.footer.pack(side="bottom", pady=(0, 6))
        self.footer.bind("<Button-1>", lambda e: webbrowser.open(REPO_URL))
        content = tk.Frame(self.panel, bg=PANEL)
        content.pack(fill="both", expand=True)
        self.tab_buttons: dict[str, tk.Button] = {}
        self.pages: dict[str, tk.Frame] = {}
        self.tabs: dict = {}
        for name, cls in TAB_CLASSES.items():
            b = ui.button(bar, lambda n=name: self.show_tab(n), hover=False)
            b.pack(side="left", padx=4)
            self.tab_buttons[name] = b
            self.pages[name] = tk.Frame(content, bg=PANEL)
            self.tabs[name] = cls(ui, self.pages[name])

    def _build_corner_controls(self) -> None:
        """Font-size buttons (top-left) and the language menu (top-right)."""
        font = (MENU_FONT, 10, "bold")
        box = tk.Frame(self.panel, bg=PANEL)
        box.place(x=12, y=10)
        for text, step in (("A−", -1), ("A+", 1)):
            b = tk.Button(box, text=text, command=self._font_command(step), bg=BG, fg=GREEN,
                          relief="flat", bd=0, padx=8, pady=3, cursor="hand2", font=font,
                          activebackground=GREEN, activeforeground=BG,
                          highlightbackground=GREEN, highlightthickness=1)
            b.pack(side="left", padx=(0, 4))

        self.lang_var = tk.StringVar(value=LANGUAGES[self.ui.lang])
        self.lang_menu = tk.OptionMenu(self.panel, self.lang_var, *LANGUAGES.values(),
                                       command=self.on_language)  # type: ignore[arg-type]
        menu_font = (MENU_FONT, 10)
        self.lang_menu.config(bg=BG, fg=GREEN, activebackground=GREEN, activeforeground=BG,
                              relief="flat", bd=0, highlightthickness=1,
                              highlightbackground=GREEN, font=menu_font, cursor="hand2")
        self.lang_menu["menu"].config(bg=BG, fg=GREEN, activebackground=GREEN,
                                      activeforeground=BG, font=menu_font, bd=0)
        self.lang_menu.place(relx=1.0, x=-12, y=10, anchor="ne")

    def _bind_shortcuts(self) -> None:
        r = self.root
        for i, name in enumerate(TAB_CLASSES, start=1):
            r.bind(f"<Control-Key-{i}>", self._tab_command(name))
        r.bind("<Control-g>", lambda e: self.shortcut_generate())
        r.bind("<Control-G>", lambda e: self.shortcut_generate())
        r.bind("<Escape>", lambda e: self.tabs[self.current_tab].clear())

    # ----- behaviour -----
    def show_tab(self, name: str) -> None:
        self.current_tab = name
        for page in self.pages.values():
            page.pack_forget()
        self.pages[name].pack(fill="both", expand=True)
        for n, b in self.tab_buttons.items():
            on = n == name
            b.config(bg=GREEN if on else BG, fg=BG if on else GREEN)
        self.tabs[name].focus()

    def _font_command(self, step: int):
        return lambda: self.change_font(step)

    def _tab_command(self, name: str):
        return lambda event: self.show_tab(name)

    def shortcut_generate(self) -> None:
        self.show_tab("analyze")
        self.tabs["analyze"].generate()

    def change_font(self, direction: int) -> None:
        if self.ui.step_scale(direction):
            settings.save(font_scale=self.ui.scale)
            self.apply_language()  # re-applies fonts and redraws

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
