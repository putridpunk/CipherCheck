# CipherCheck

A modular password security auditing tool developed in Python. Evaluates password strength through entropy estimation, pattern recognition, dictionary-based detection and security analysis. Features local processing, automated testing and exportable security reports.

Everything runs locally: no network access, no telemetry, and exported reports never contain the password.

## Desktop app (Windows)

`ciphercheck.exe` opens a Matrix/hacker-themed window in plain Portuguese: type a password and instantly see how strong it is, what is wrong, how long a hacker would need, and how to improve it. It can also generate a strong password and copy it (the clipboard is wiped after 30 s). Everything stays on your computer.

```powershell
.\build.ps1          # runs the tests, then builds ciphercheck.exe (app) and ciphercheck-cli.exe (terminal)
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
| `src/friendly.py` | Plain-language (PT) explanations and the password generator used by the app |
| `src/gui.py` | Matrix-themed desktop app (tkinter) |
| `src/main.py` | CLI |

Theoretical entropy assumes uniformly random characters, so it overestimates human-chosen passwords (`P@ssw0rd!` has ~59 theoretical bits but is a top-tier guess). The **estimated** figure is what drives the verdict. Special characters are reported but never treated as a strength on their own.

Assessment thresholds (estimated bits): `<28` very weak · `<40` weak · `<60` moderate · `<80` strong · otherwise very strong. Passwords under 8 characters are capped at weak.

## Limits and honesty

- Bundled dictionaries are small starter lists in `data/`. Drop in a larger list (e.g. a trimmed SecLists top-100k) for much better coverage; one entry per line/whitespace, most common first.
- Entropy and crack-time numbers are models, not guarantees.
- `correct-horse-battery` scores *moderate*: three common words is only ~50 bits. It is flagged as a passphrase, and four to five random words would reach strong.

## Tests

```powershell
python -m unittest discover -s tests -t .
```

## Roadmap

1. ~~Foundation, analysis, reporting~~ (done)
2. Hash-format identification module
3. Export reports from the app
4. Optional C++ analysis engine
