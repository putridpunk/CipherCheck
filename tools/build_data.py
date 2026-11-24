"""Regenerates the bundled datasets in data/ from a frequency-ordered password list.

Usage:
    python tools/build_data.py PATH/TO/xato-net-10-million-passwords-1000000.txt

The source list is SecLists (MIT licence, https://github.com/danielmiessler/SecLists),
ordered from most to least common. Outputs:

* data/common_passwords.txt  top 100,000 entries (rank = line order, used for scoring)
* data/common_words.txt      curated words + frequent purely-alphabetic entries
* data/breached.bin          sorted 6-byte SHA-1 prefixes of all entries (offline leak check)
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"
TOP_PASSWORDS = 100_000
EXTRA_WORDS = 8_000
PREFIX_BYTES = 6
WORD = re.compile(rb"^[a-z]{4,12}$")


def main(source: Path) -> None:
    raw = [ln.rstrip(b"\r\n") for ln in source.read_bytes().splitlines()]
    raw = [ln for ln in raw if ln]

    # 1. password ranking list (plain text, whitespace-free entries only)
    top = [ln.decode("utf-8", "ignore") for ln in raw[:TOP_PASSWORDS] if b" " not in ln]
    header = ("# Most common passwords, most common first (rank = position).\n"
              "# Source: SecLists xato-net-10-million-passwords (MIT), top "
              f"{TOP_PASSWORDS:,}. Regenerate with tools/build_data.py.\n")
    (DATA / "common_passwords.txt").write_text(header + "\n".join(top) + "\n", encoding="utf-8")

    # 2. vocabulary: keep the curated words already in the file, add frequent pure words
    words_path = DATA / "common_words.txt"
    curated: list[str] = []
    if words_path.exists():
        for ln in words_path.read_text(encoding="utf-8").splitlines():
            if ln.strip() and not ln.startswith("#"):
                curated += ln.split()
    seen = {w.lower() for w in curated}
    derived: list[str] = []
    for entry in raw:
        if len(derived) >= EXTRA_WORDS:
            break
        if WORD.match(entry):
            word = entry.decode("ascii")
            if word not in seen:
                seen.add(word)
                derived.append(word)
    lines = [" ".join(curated[i:i + 20]) for i in range(0, len(curated), 20)]
    lines += [" ".join(derived[i:i + 20]) for i in range(0, len(derived), 20)]
    (DATA / "common_words.txt").write_text(
        "# Words used to detect dictionary-based passwords (min 4 letters).\n"
        "# Curated words first, then frequent purely-alphabetic entries from the SecLists list.\n"
        + "\n".join(lines) + "\n", encoding="utf-8")

    # 3. offline breach index: sorted unique SHA-1 prefixes (case-sensitive, exact match)
    prefixes = sorted({hashlib.sha1(ln).digest()[:PREFIX_BYTES] for ln in raw})
    (DATA / "breached.bin").write_bytes(b"".join(prefixes))
    print(f"passwords={len(top):,} words={len(curated) + len(derived):,} breach={len(prefixes):,}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(Path(sys.argv[1]))
