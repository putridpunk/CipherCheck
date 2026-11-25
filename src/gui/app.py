"""Main window: Matrix background, header, tab bar, language menu, font size, footer."""

from __future__ import annotations

import sys
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from typing import Any

from .. import __version__, settings
from ..i18n import LANGUAGES, detect_language
from ..utils import ASSETS_DIR
from .analyze_tab import AnalyzeTab
from .audit_tab import AuditTab
from .hash_tab import HashTab
from .rain import MatrixRain
from .theme import BG, DIM, GREEN, MENU_FONT, MONO, PANEL
from .widgets import UI

TAB_CLASSES = {"analyze": AnalyzeTab, "audit": AuditTab, "hash": HashTab}
REPO_URL = "https://github.com/putridpunk/CipherCheck"
# Named Windows mutex held while the app is open; the installer (AppMutex in installer/ciphercheck.iss)
# uses it to notice a running app instead of failing to replace or delete its files.
INSTANCE_MUTEX = "CipherCheckAppMutex"
_mutex_handle: Any = None
PANEL_WIDTH = 660
PANEL_RELHEIGHT = 0.95
ICON = ASSETS_DIR / "ciphercheck.png"


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("CipherCheck")
        root.configure(bg=BG)
        height = min(840, root.winfo_screenheight() - 90)
        root.geometry(f"1000x{height}")
        root.minsize(900, 600)
        self._set_icon()
        root.protocol("WM_DELETE_WINDOW", self.on_close)

        prefs = settings.load()
        lang = prefs.get("language")
        self.ui = UI(root, lang if lang in LANGUAGES else detect_language(),
                     prefs.get("font_scale", 1.0))

        self.canvas = tk.Canvas(root, bg=BG, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.rain = MatrixRain(self.canvas)
        self.rain.tick()

        self.panel = tk.Frame(root, bg=PANEL, highlightbackground=GREEN, highlightthickness=1)
        self.panel.place(relx=0.5, rely=0.5, anchor="center", width=PANEL_WIDTH, relheight=PANEL_RELHEIGHT)
        self._build_header()
        self._build_tabs()
        self._build_corner_controls()
        self._bind_shortcuts()
        self._enable_drop()

        self._blink = True
        self._blink_title()
        self.apply_language()
        self.show_tab("analyze")
        root.bind("<Configure>", self._on_window_resize)
        self.fit_panel()

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
        bar = ui.button_row(self.panel)
        bar.frame.pack(pady=(14, 4))
        # footer is packed before the content so it always keeps its space; it wraps, never clips
        self.footer = ui.label(self.panel, size=8, color=DIM, cursor="hand2", wraplength=1, justify="center",
                               text=f"CipherCheck v{__version__}  ·  PolyForm Noncommercial 1.0.0  ·  "
                                    "github.com/putridpunk")
        self.footer.pack(side="bottom", pady=(0, 6))
        self.footer.bind("<Button-1>", lambda e: webbrowser.open(REPO_URL))
        self._update_checking = False
        self._update_url: str | None = None
        self._update_thread: threading.Thread | None = None
        self._update_thread_result: tuple[bool, tuple[str, str] | None] | None = None
        self.update_status = ui.label(self.panel, size=8, color=DIM, cursor="hand2",
                                      wraplength=1, justify="center")
        self.update_status.pack(side="bottom", pady=(0, 0))
        self.update_status.bind("<Button-1>", lambda e: self.on_update_click())
        content = tk.Frame(self.panel, bg=PANEL)
        content.pack(fill="both", expand=True)
        self.tab_buttons: dict[str, tk.Button] = {}
        self.pages: dict[str, tk.Frame] = {}
        self.tabs: dict = {}
        for name, cls in TAB_CLASSES.items():
            b = bar.button(self._tab_command(name), hover=False)
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

    def _enable_drop(self) -> None:
        """Let the user drop a password file anywhere on the window (needs the optional
        tkinterdnd2 package; without it the app works exactly the same, minus dropping)."""
        if not hasattr(self.root, "drop_target_register"):
            return
        try:
            from tkinterdnd2 import DND_FILES
            widgets: list[Any] = [self.root, self.canvas, self.panel]  # tkinterdnd2 adds the methods
            for widget in widgets:
                widget.drop_target_register(DND_FILES)
                widget.dnd_bind("<<Drop>>", self.on_drop)
        except Exception:  # missing native library, unsupported platform...
            return
        self.tabs["audit"].show_drop_hint = True

    def on_drop(self, event: Any) -> str:
        """A file was dropped on the window: audit it."""
        audit = self.tabs["audit"]
        self.show_tab("audit")
        paths = [Path(p) for p in self.root.tk.splitlist(event.data)]
        files = [p for p in paths if p.is_file()]
        if files:
            audit.start(str(files[0]))
        else:
            audit.report_error()
        return "copy"

    def _font_command(self, step: int):
        return lambda: self.change_font(step)

    def _tab_command(self, name: str):
        return lambda event=None: self.show_tab(name)

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

    def fit_panel(self) -> None:
        """Make the panel as wide as the font size needs (never wider than the window) and let
        wrapped text and button rows adapt, so nothing is cut off at the sides."""
        wanted = int(PANEL_WIDTH * max(1.0, self.ui.scale))
        width = max(PANEL_WIDTH, min(wanted, self.root.winfo_width() - 30)) if self.root.winfo_width() > 1 else wanted
        self.panel.place_configure(width=width)
        self.ui.set_wrap_width(width - 60)
        self.ui.refresh_layout()
        self._grow_window_if_needed()

    def _grow_window_if_needed(self) -> None:
        """Bigger text needs more room: make the window taller (up to the screen), never shorter."""
        self.root.update_idletasks()
        needed = int(self.panel.winfo_reqheight() / PANEL_RELHEIGHT) + 24
        limit = self.root.winfo_screenheight() - 90
        if self.root.winfo_height() > 1 and needed > self.root.winfo_height():
            self.root.geometry(f"{self.root.winfo_width()}x{min(needed, limit)}")

    def _on_window_resize(self, event: Any) -> None:
        if event.widget is self.root:
            self.fit_panel()

    def on_close(self) -> None:
        self.tabs["audit"].stop_for_close()
        self.root.destroy()

    def apply_language(self) -> None:
        ui = self.ui
        ui.apply_fonts()
        self.subtitle.config(text=ui.tr("subtitle"))
        for name, b in self.tab_buttons.items():
            b.config(text=ui.tr("tab_" + name))
        for tab in self.tabs.values():
            tab.apply_language()
        if not self._update_checking:
            self._update_url = None
            self.update_status.config(text=ui.tr("upd_check"), fg=DIM)
        self.fit_panel()

    def _blink_title(self) -> None:
        self._blink = not self._blink
        self.title.config(text="CIPHERCHECK" + ("_" if self._blink else " "))
        self.root.after(550, self._blink_title)

    # ----- update check (the only network access in the app; only on request) -----
    def on_update_click(self) -> None:
        if self._update_url:
            webbrowser.open(self._update_url)
        elif not self._update_checking:
            self.check_update()

    def check_update(self) -> None:
        self._update_checking = True
        self._update_thread_result = None
        self.update_status.config(text=self.ui.tr("upd_checking"), fg=DIM, cursor="arrow")
        self._update_thread = threading.Thread(target=self._update_worker, daemon=True)
        self._update_thread.start()
        self._poll_update()

    def _update_worker(self) -> None:
        # Runs in a background thread: touches only plain Python state, never Tk,
        # which (like the audit worker thread) is only ever driven from the main thread.
        from .. import update_check
        try:
            self._update_thread_result = (False, update_check.check_for_update())
        except update_check.UpdateCheckError:
            self._update_thread_result = (True, None)

    def _poll_update(self) -> None:
        if self._update_thread is not None and self._update_thread.is_alive():
            self.root.after(100, self._poll_update)
            return
        assert self._update_thread_result is not None
        error, result = self._update_thread_result
        self._update_done(result, error)

    def _update_done(self, result: tuple[str, str] | None, error: bool) -> None:
        self._update_checking = False
        ui = self.ui
        self.update_status.config(cursor="hand2")
        if error:
            self.update_status.config(text=ui.tr("upd_error"), fg=DIM)
        elif result is None:
            self.update_status.config(text=ui.tr("upd_latest"), fg=DIM)
        else:
            version, url = result
            self._update_url = url
            self.update_status.config(text=ui.tr("upd_available", v=version), fg=GREEN)


def hold_instance_mutex() -> None:
    """Windows only: tell the installer/uninstaller that the app is running."""
    global _mutex_handle
    if sys.platform != "win32":
        return
    try:
        import ctypes
        _mutex_handle = ctypes.windll.kernel32.CreateMutexW(None, False, INSTANCE_MUTEX)
    except Exception:
        pass  # purely an aid for the installer; never stop the app over it


def run() -> None:
    if sys.platform == "win32":  # crisp text on high-DPI Windows screens
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    hold_instance_mutex()
    try:  # optional: adds drag-and-drop of files onto the window
        from tkinterdnd2 import TkinterDnD
        root: tk.Tk = TkinterDnD.Tk()
    except Exception:
        root = tk.Tk()
    App(root)
    root.mainloop()
