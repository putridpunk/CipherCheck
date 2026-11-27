"""A small local history of past audits, so the Audit tab can show a trend over time.

Only aggregate numbers are kept - total count, average estimated strength and the share
of weak passwords - never a password, a filename, an account name or anything else that
could identify what was audited. Stored next to settings.json (see settings.config_dir()).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .settings import config_dir

MAX_ENTRIES = 30


def _file() -> Path:
    return config_dir() / "audit_history.json"


def load() -> list[dict]:
    try:
        data = json.loads(_file().read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def record(total: int, average_bits: float, weak_percent: float) -> list[dict]:
    """Append one entry (bounded to MAX_ENTRIES) and return the updated history.

    Silently does nothing to the file if it cannot be written (e.g. read-only config
    dir); the in-memory list returned is still correct for the caller to display.
    """
    if total <= 0:
        return load()
    history = load()
    history.append({
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total": total,
        "average_bits": round(average_bits, 1),
        "weak_percent": round(weak_percent, 1),
    })
    history = history[-MAX_ENTRIES:]
    try:
        _file().parent.mkdir(parents=True, exist_ok=True)
        _file().write_text(json.dumps(history, indent=2), encoding="utf-8")
    except OSError:
        pass
    return history


def clear() -> None:
    try:
        _file().unlink(missing_ok=True)
    except OSError:
        pass
