# CipherCheck

A modular password security auditing tool developed in Python. Evaluates password strength through entropy estimation, pattern recognition, dictionary-based detection and security analysis. Features local processing, automated testing and exportable security reports.

Everything runs locally: no network access, no telemetry, and exported reports never contain the password.

## Desktop app (Windows)

**Download:** grab the app (`ciphercheck.exe` on Windows, `ciphercheck-linux`, `ciphercheck-macos.zip`) or the terminal tool (`ciphercheck-cli*`) from the [latest release](https://github.com/putridpunk/CipherCheck/releases/latest). The executables are not code-signed, so Windows SmartScreen / macOS Gatekeeper may warn you the first time (Windows: More info > Run anyway; macOS: right-click > Open). The Linux and macOS builds are produced by CI and have not been tested by hand.

`ciphercheck.exe` opens a Matrix/hacker-themed window in plain language (three tabs: **Analyze** a password, **Audit** a file of synthetic test passwords as a statistics dashboard, **Hash** format identification; 9 languages: English, Português, Español, Français, Deutsch, Русский, العربية, 日本語, 简体中文; pick one from the menu in the top-right corner, the default follows your system language): type a password and instantly see how strong it is, what is wrong, how long a hacker would need, and how to improve it. The generate button turns what you typed into a strong password that still resembles it (or creates a brand-new one if the field is empty), and you can copy it (the clipboard is wiped after 30 s). Everything stays on your computer.

```powershell
.\build.ps1          # Windows: runs the tests, then builds ciphercheck.exe and ciphercheck-cli.exe
python build.py      # any OS: same, output in release/ with a per-OS suffix
.\ciphercheck.exe    # or: python ciphercheck.py
```

The word and password lists are bundled inside the executables; no Python needed.

## Command line

Requires Python 3.10+ and no third-party packages (or use `ciphercheck-cli.exe`).

```powershell
python -m src.main                       # prompts for the password (input hidden)
python -m src.main --stdin               # read one password from stdin
python -m src.main -r report.html        # also export a report (txt / json / html)
python -m src.main -f samples.txt -q -r summary.json   # batch mode: aggregate stats only
python -m src.main --hash 5f4dcc3b5aa765d61d8327deb882cf99   # identify a hash format (never cracks it)
```

`-p/--password` exists but is discouraged (it lands in shell history). Batch mode is meant for **synthetic** test data; it prints only aggregate statistics.

## How it works

| Module | Role |
| --- | --- |
| `src/entropy.py` | Theoretical entropy `H = L·log2(R)` **and** a pattern-aware estimate (minimum-cost cover via dynamic programming), plus crack-time estimates |
| `src/patterns.py` | Sequences, repeated characters/blocks, keyboard walks, years |
| `src/dictionary.py` | Local common-password list, word list, leetspeak normalisation (`p@ssw0rd` → `password`) |
| `src/analyzer.py` | Combines everything into a label, score, findings and recommendations |
| `src/report.py` | TXT / JSON / HTML reports and batch aggregation |
| `src/vulnerabilities.py` | Turns an analysis into categorised weaknesses (severity, why it matters, how to fix) for the detailed reports |
| `src/hashes.py` | Identifies hash formats (MD5, SHA-*, bcrypt, Argon2, ...) and explains their password-storage properties; a format match is a hint, never proof of origin |
| `src/friendly.py` | Plain-language explanations and the password generator used by the app |
| `src/i18n.py`, `src/locales/` | Translations (one file per language; `en.py` is the master, a test checks every locale has the same keys) |
| `src/gui/` | Matrix-themed desktop app (tkinter): `app.py` window and tabs, `analyze_tab.py`, `audit_tab.py`, `hash_tab.py`, `widgets.py` themed widget factory, `rain.py` background, `theme.py` colours and per-OS fonts |
| `src/breach.py` | Offline leaked-password check against `data/breached.bin` (nothing leaves your computer) |
| `src/main.py` | CLI |

Theoretical entropy assumes uniformly random characters, so it overestimates human-chosen passwords (`P@ssw0rd!` has ~59 theoretical bits but is a top-tier guess). The **estimated** figure is what drives the verdict. Special characters are reported but never treated as a strength on their own.

Assessment thresholds (estimated bits): `<28` very weak · `<40` weak · `<60` moderate · `<80` strong · otherwise very strong. Passwords under 8 characters are capped at weak.

## Limits and honesty

- Arabic is shaped and right-aligned correctly, but Tk has no right-to-left paragraph support, so punctuation and the `[-]` markers can sit on the wrong side of a line.
- The language choice is not remembered between launches (it follows the system language).
- The command-line tool and exported reports are English only.

- Bundled data (see `data/README.md`): the 100k most common passwords and an 8k-word vocabulary for scoring, plus an offline index of the ~1M most common leaked passwords. The leak check is not a complete breach database: not being found does not prove a password never leaked.
- Entropy and crack-time numbers are models, not guarantees.
- `correct-horse-battery` scores *moderate*: three common words is only ~50 bits. It is flagged as a passphrase, and four to five random words would reach strong.

## Tests

```powershell
python -m unittest discover -s tests -t .
```

## Continuous integration

`.github/workflows/ci.yml` runs the tests on Linux, Windows and macOS (Python 3.10 and 3.13; the GUI smoke tests run under a virtual display on Linux). `.github/workflows/release.yml` builds the executables on all three systems; pushing a tag such as `v0.3.0` attaches them to a GitHub Release, and running it manually only produces downloadable artifacts.

## Roadmap

1. ~~Foundation, analysis, reporting, hash analysis, audit dashboard, offline leak check, CI~~ (done)
2. Remember the language choice between launches
3. Native-speaker review of the translations
4. Optional C++ analysis engine
