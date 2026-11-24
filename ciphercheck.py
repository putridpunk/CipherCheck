"""CipherCheck desktop app launcher (GUI). The terminal version is ciphercheck_cli.py."""

import multiprocessing

from src.gui import run

if __name__ == "__main__":
    multiprocessing.freeze_support()  # needed so the Audit workers work inside the frozen .exe
    run()
