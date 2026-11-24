"""Falling-glyph Matrix background."""

from __future__ import annotations

import random
import tkinter as tk

from .theme import CELL, GLYPHS, HEAD_COLOR, RAIN_FONT, TRAIL, TRAIL_COLORS


class MatrixRain:
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
                                  font=(RAIN_FONT, 12))
        c.after(70, self.tick)
