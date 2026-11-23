"""Launcher used for the packaged executable (and `python ciphercheck.py`)."""

import sys

from src.main import main

if __name__ == "__main__":
    interactive = len(sys.argv) == 1
    code = main()
    # Double-clicked .exe: keep the console window open so the result is readable.
    if getattr(sys, "frozen", False) and interactive:
        try:
            input("\nPress Enter to exit...")
        except EOFError:
            pass
    sys.exit(code)
