"""Colours, glyphs and per-platform fonts for the Matrix theme."""

from __future__ import annotations

import sys

BG = "#000000"
PANEL = "#020b04"
GREEN = "#00ff41"
DIM = "#2f9e4f"
DARKER = "#0b3d1a"
RED = "#ff6b6b"
TIP = "#9dffb5"

# Fonts differ per OS; Tk falls back to a default for anything not installed.
if sys.platform == "win32":
    MONO, RAIN_FONT, MENU_FONT = "Consolas", "MS Gothic", "Segoe UI"
    SCRIPT_FONTS = {"ja": "Yu Gothic UI", "zh": "Microsoft YaHei UI", "ar": "Segoe UI"}
elif sys.platform == "darwin":
    MONO, RAIN_FONT, MENU_FONT = "Menlo", "Hiragino Sans", "Helvetica Neue"
    SCRIPT_FONTS = {"ja": "Hiragino Sans", "zh": "PingFang SC", "ar": "Geeza Pro"}
else:
    MONO, RAIN_FONT, MENU_FONT = "DejaVu Sans Mono", "Noto Sans CJK JP", "DejaVu Sans"
    SCRIPT_FONTS = {"ja": "Noto Sans CJK JP", "zh": "Noto Sans CJK SC", "ar": "DejaVu Sans"}

CELL = 18
TRAIL = 16
GLYPHS = [chr(c) for c in range(0xFF66, 0xFF9E)] + list("0123456789")
HEAD_COLOR = "#d6ffe0"
TRAIL_COLORS = [f"#00{int(210 - 195 * k / (TRAIL - 1)):02x}{int(55 - 40 * k / (TRAIL - 1)):02x}"
                for k in range(TRAIL)]
