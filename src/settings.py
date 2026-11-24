"""Tiny per-user settings file (only the chosen language is stored)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def config_dir() -> Path:
    override = os.environ.get("CIPHERCHECK_CONFIG_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "CipherCheck"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "CipherCheck"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "ciphercheck"


def _file() -> Path:
    return config_dir() / "settings.json"


def load() -> dict:
    try:
        data = json.loads(_file().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save(**values) -> bool:
    """Merge `values` into the settings file. Returns False if it could not be written."""
    data = load()
    data.update(values)
    try:
        _file().parent.mkdir(parents=True, exist_ok=True)
        _file().write_text(json.dumps(data, indent=2), encoding="utf-8")
        return True
    except OSError:
        return False
