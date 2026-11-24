"""Cross-platform build of the CipherCheck executables with PyInstaller.

    python build.py            # run the tests, then build
    python build.py --skip-tests

Outputs go to release/ with a per-platform suffix:
    Windows : ciphercheck.exe, ciphercheck-cli.exe          (also copied to the project root)
              (the release workflow also adds ciphercheck-setup.exe, built with Inno Setup)
    Linux   : ciphercheck-linux, ciphercheck-cli-linux, ciphercheck-linux-install.sh
              (the script adds a menu entry and an icon; see packaging/linux/)
    macOS   : ciphercheck-macos.zip (the .app), ciphercheck-cli-macos
PyInstaller does not cross-compile: run this on each OS (the release workflow does).
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RELEASE = ROOT / "release"
DATA = f"src/data{os.pathsep}data"
ASSETS = f"src/assets{os.pathsep}assets"  # window icon is loaded from here at run time
ICONS = {"win32": "src/assets/ciphercheck.ico", "darwin": "src/assets/ciphercheck.icns"}
# Standard-library parts CipherCheck never uses; leaving them out keeps the binaries smaller.
EXCLUDES = ["unittest", "pydoc", "doctest", "sqlite3", "ssl", "xmlrpc", "pdb", "lib2to3"]
CLI_EXCLUDES = ["tkinter", "_tkinter"]  # the terminal tool has no GUI


def run(*cmd: str) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True, cwd=ROOT)


def has_dnd() -> bool:
    try:
        import tkinterdnd2  # noqa: F401
    except ImportError:
        return False
    return True


def cli_icon_skip(cli: bool) -> bool:
    """The terminal tool keeps a plain icon on macOS (no .app bundle to brand)."""
    return cli and sys.platform == "darwin"


def pyinstaller(name: str, script: str, *flags: str, cli: bool = False) -> None:
    excludes = EXCLUDES + (CLI_EXCLUDES if cli else [])
    strip = ["--strip"] if sys.platform.startswith("linux") else []
    icon = ["--icon", ICONS[sys.platform]] if sys.platform in ICONS and not cli_icon_skip(cli) else []
    exclude_flags = [f"--exclude-module={m}" for m in excludes]
    if not cli and has_dnd():  # bundle the native drag-and-drop library into the app
        flags = (*flags, "--collect-all", "tkinterdnd2")
    run(sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--name", name,
        "--add-data", DATA, "--add-data", ASSETS, *icon, *strip, *exclude_flags, *flags, script)


def make_linux_installer() -> Path:
    """Self-contained install script: the app icon is embedded, so only the binary is needed."""
    template = (ROOT / "packaging" / "linux" / "install.sh.in").read_text(encoding="utf-8")
    icon = base64.encodebytes((ROOT / "src" / "assets" / "ciphercheck.png").read_bytes()).decode("ascii")
    target = RELEASE / "ciphercheck-linux-install.sh"
    target.write_text(template.replace("@ICON_B64@", icon.strip()), encoding="utf-8", newline="\n")
    target.chmod(0o755)
    return target


def main() -> None:
    if "--skip-tests" not in sys.argv:
        run(sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", ".")
    shutil.rmtree(RELEASE, ignore_errors=True)
    RELEASE.mkdir()
    dist = ROOT / "dist"

    if sys.platform == "win32":
        pyinstaller("ciphercheck", "ciphercheck.py", "--onefile", "--windowed")
        pyinstaller("ciphercheck-cli", "ciphercheck_cli.py", "--onefile", cli=True)
        for exe in ("ciphercheck.exe", "ciphercheck-cli.exe"):
            shutil.copy2(dist / exe, RELEASE / exe)
            shutil.copy2(dist / exe, ROOT / exe)  # convenient copy in the project root
    elif sys.platform == "darwin":
        # produces ciphercheck.app; the bundle identifier is what macOS uses to recognise the app
        pyinstaller("ciphercheck", "ciphercheck.py", "--windowed",
                    "--osx-bundle-identifier", "io.github.putridpunk.ciphercheck")
        pyinstaller("ciphercheck-cli", "ciphercheck_cli.py", "--onefile", cli=True)
        subprocess.run(["ditto", "-c", "-k", "--keepParent", str(dist / "ciphercheck.app"),
                        str(RELEASE / "ciphercheck-macos.zip")], check=True)
        shutil.copy2(dist / "ciphercheck-cli", RELEASE / "ciphercheck-cli-macos")
    else:
        pyinstaller("ciphercheck", "ciphercheck.py", "--onefile", "--windowed")
        pyinstaller("ciphercheck-cli", "ciphercheck_cli.py", "--onefile", cli=True)
        shutil.copy2(dist / "ciphercheck", RELEASE / "ciphercheck-linux")
        shutil.copy2(dist / "ciphercheck-cli", RELEASE / "ciphercheck-cli-linux")
        make_linux_installer()

    print("\nBuilt:")
    for f in sorted(RELEASE.iterdir()):
        print(f"  {f.relative_to(ROOT)}  ({f.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
