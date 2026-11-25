"""Checks GitHub for a newer release. The only network access in the whole app, and only
when the user explicitly asks for it (a button in the GUI or the --check-update CLI flag).

No personal data of any kind is sent: the request carries a generic User-Agent and nothing
else, and goes only to GitHub's public release API for this one repository.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from . import __version__

REPO = "putridpunk/CipherCheck"
API_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_URL = f"https://github.com/{REPO}/releases/latest"


class UpdateCheckError(Exception):
    """Could not reach GitHub or make sense of its answer."""


def _parse_version(v: str) -> tuple[int, ...]:
    parts = tuple(int(p) for p in v.lstrip("v").split(".") if p.isdigit())
    return parts or (0,)


def check_for_update(timeout: float = 5.0) -> tuple[str, str] | None:
    """(latest_version, release_url) if GitHub has a newer tagged release, else None.

    Raises UpdateCheckError on any network or data problem (no internet, GitHub down, ...).
    """
    req = urllib.request.Request(API_URL, headers={"User-Agent": "CipherCheck-update-check"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed https URL)
            data = json.loads(resp.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, ValueError) as exc:
        raise UpdateCheckError(str(exc)) from exc
    tag = str(data.get("tag_name", "")).strip()
    if not tag:
        raise UpdateCheckError("no release information in GitHub's answer")
    if _parse_version(tag) > _parse_version(__version__):
        return tag.lstrip("v"), str(data.get("html_url") or RELEASES_URL)
    return None
