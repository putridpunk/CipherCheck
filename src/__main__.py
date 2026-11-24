"""`python -m ciphercheck` (installed) or `python -m src` (from a checkout)."""

from .main import main

if __name__ == "__main__":  # the guard matters: worker processes import this module too
    raise SystemExit(main())
