# CipherCheck

[![CI](https://github.com/putridpunk/CipherCheck/actions/workflows/ci.yml/badge.svg)](https://github.com/putridpunk/CipherCheck/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/putridpunk/CipherCheck)](https://github.com/putridpunk/CipherCheck/releases/latest)
[![Licence: PolyForm Noncommercial](https://img.shields.io/badge/licence-PolyForm%20Noncommercial%201.0.0-blue)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![Offline](https://img.shields.io/badge/network-none-brightgreen)

A modular password security auditing tool developed in Python. Evaluates password strength through entropy estimation, pattern recognition, dictionary-based detection and security analysis. Features local processing, automated testing and exportable security reports.

Everything runs locally: no network access, no telemetry, and exported reports never contain the password.

![The Analyze tab](docs/img/analyze.png)

| Audit: statistics for a file of synthetic passwords | Hash: identify a hash format |
| --- | --- |
| ![The Audit tab](docs/img/audit.png) | ![The Hash tab](docs/img/hash.png) |

## Licence

CipherCheck is **source-available under the [PolyForm Noncommercial License 1.0.0](LICENSE)**, not open source. You may use, study and modify it for personal, educational, research and other noncommercial purposes. **Selling it, offering it as a paid product or service, or otherwise earning income from it requires the author's prior written authorization** - contact the author through [github.com/putridpunk](https://github.com/putridpunk). The bundled datasets keep their own licences (see [`src/data/README.md`](src/data/README.md)). This is not legal advice.

Contributions are welcome: see [`CONTRIBUTING.md`](CONTRIBUTING.md). Found a security problem? Please read [`SECURITY.md`](SECURITY.md) first. What changed in each version: [`CHANGELOG.md`](CHANGELOG.md).

## Desktop app

**Download** from the [latest release](https://github.com/putridpunk/CipherCheck/releases/latest):

| Platform | App | Terminal tool |
| --- | --- | --- |
| Windows | `ciphercheck-setup.exe` (installer) or `ciphercheck.exe` | `ciphercheck-cli.exe` |
| Linux | `ciphercheck-linux` | `ciphercheck-cli-linux` |
| macOS | `ciphercheck-macos.zip` | `ciphercheck-cli-macos` |

The executables are not code-signed, so Windows SmartScreen / macOS Gatekeeper may warn you the first time (Windows: More info > Run anyway; macOS: right-click > Open). The Linux and macOS builds are produced by CI and have not been tested by hand.

**Linux menu entry:** download `ciphercheck-linux-install.sh` next to the binaries and run `bash ciphercheck-linux-install.sh`. It installs for the current user (no root): the app as `~/.local/bin/ciphercheck-gui` with a "CipherCheck" menu entry and icon, and the terminal tool as `ciphercheck`. Remove it again with `--uninstall`.

**With Python (any OS):** every release also has a wheel (`ciphercheck-*.whl`). `pipx install ciphercheck-*.whl` gives you the commands `ciphercheck` (terminal) and `ciphercheck-gui` (app); add `[dnd]` for drag and drop, e.g. `pipx install "ciphercheck-0.6.0-py3-none-any.whl[dnd]"`. From a checkout: `pip install .`.

The app has a Matrix/hacker theme and speaks plain language, in 9 languages (English, Português, Español, Français, Deutsch, Русский, العربية, 日本語, 简体中文). Pick one from the menu in the top-right corner; the choice is remembered, and the first launch follows your system language.

- **Analyze**: type a password and instantly see how strong it is, what is wrong, how long a hacker would need, and how to improve it. *Generate strong password* turns what you typed into a strong password that still resembles it (or creates a brand-new one if the field is empty). *Generate passphrase* makes five random words from the 7,776-word EFF list (about 65 bits, easy to remember). Copying wipes the clipboard after 30 s, and *Save report* exports TXT / JSON / HTML.
- **Audit**: pick a file of **synthetic** test passwords (one per line), or **drag the file onto the window**, and get a statistics dashboard: strength distribution, most common problems, passwords reused and near-copies of each other (`Summer2024!` / `summer2025`). Big files are analysed on all CPU cores (several times faster than one core), with a progress bar and a *Cancel* button. Passwords are never shown or saved; the summary can be exported. Dragging needs the optional `tkinterdnd2` package, which the release executables include.
- **Hash**: paste a hash to see which formats it could be and whether they suit password storage. Only the format is checked; nothing is cracked.

Handy extras: `Ctrl+1/2/3` switch tabs, `Ctrl+G` generates a password, `Esc` clears the current input, and the `A−` / `A+` buttons (top-left) change the text size; both the language and the text size are remembered. The footer shows the version and links to this repository.

```powershell
.\build.ps1          # Windows: runs the tests, then builds ciphercheck.exe and ciphercheck-cli.exe
python build.py      # any OS: same, output in release/ with a per-OS suffix
python ciphercheck.py   # run the app from source
```

The word and password lists are bundled inside the executables; no Python needed.

## Command line

Requires Python 3.10+ and no third-party packages (or use `ciphercheck-cli`).

```powershell
python -m src.main                       # prompts for the password (input hidden)
python -m src.main --stdin               # read one password from stdin
python -m src.main -r report.html        # also export a report (txt / json / html)
python -m src.main -f samples.txt -q -r summary.html   # batch mode: aggregate stats only
python -m src.main -f big.txt -j 4       # ... on 4 worker processes (default: automatic)
python -m src.main --hash 5f4dcc3b5aa765d61d8327deb882cf99   # identify a hash format (never cracks it)
python -m src.main --passphrase          # a random 5-word passphrase (3 to 12 words)
python -m src.main -p "example" --lang pt   # plain-language output in another language
```

`--lang` takes `en pt es fr de ru ar ja zh` and switches terminal output, `--hash` explanations, batch summaries and TXT reports to the same plain language the app uses (JSON and HTML reports stay English). `-p/--password` exists but is discouraged (it lands in shell history). Batch mode is meant for **synthetic** test data; it prints only aggregate statistics.

## How it works

| Module | Role |
| --- | --- |
| `src/entropy.py` | Theoretical entropy `H = L·log2(R)` **and** a pattern-aware estimate (minimum-cost cover via dynamic programming), plus crack-time estimates |
| `src/patterns.py` | Sequences, repeated characters/blocks, keyboard walks, years |
| `src/dictionary.py` | Local common-password list, word lists (incl. the EFF passphrase list), leetspeak normalisation (`p@ssw0rd` → `password`) |
| `src/breach.py` | Offline leaked-password check against `src/data/breached.bin` (nothing leaves your computer) |
| `src/analyzer.py` | Combines everything into a label, score, findings and recommendations |
| `src/reuse.py` | Finds identical passwords and near-copies inside a dataset (only hashes are kept in memory) |
| `src/audit.py` | Audits a whole file on all CPU cores, in chunks, with progress and cancel; only counters come back |
| `src/report.py` | TXT / JSON / HTML reports, batch aggregation and translated plain-language text |
| `src/vulnerabilities.py` | Turns an analysis into categorised weaknesses (severity, why it matters, how to fix) for the detailed reports |
| `src/hashes.py` | Identifies hash formats (MD5, SHA-*, bcrypt, Argon2, ...) and explains their password-storage properties; a format match is a hint, never proof of origin |
| `src/friendly.py` | Plain-language explanations, the password generators and the "similar but strong" password |
| `src/i18n.py`, `src/locales/` | Translations (one file per language; `en.py` is the master, a test checks every locale has the same keys and placeholders) |
| `src/settings.py` | Remembers the chosen language in a small per-user JSON file |
| `src/gui/` | Matrix-themed desktop app (tkinter): `app.py` window and tabs, `analyze_tab.py`, `audit_tab.py`, `hash_tab.py`, `widgets.py` themed widget factory, `rain.py` background, `theme.py` colours and per-OS fonts |
| `src/main.py` | Command line |

Theoretical entropy assumes uniformly random characters, so it overestimates human-chosen passwords (`P@ssw0rd!` has ~59 theoretical bits but is a top-tier guess). The **estimated** figure is what drives the verdict. Special characters are reported but never treated as a strength on their own.

Assessment thresholds (estimated bits): `<28` very weak · `<40` weak · `<60` moderate · `<80` strong · otherwise very strong. Passwords under 8 characters are capped at weak.

## Limits and honesty

- Arabic is shaped and right-aligned correctly, but Tk has no right-to-left paragraph support, so punctuation and the `[-]` markers can sit on the wrong side of a line.
- The translations are not yet reviewed by native speakers (corrections welcome, see `CONTRIBUTING.md`).
- Bundled data (see `src/data/README.md`): the 100k most common passwords and an 8k-word vocabulary for scoring, plus an offline index of the ~1M most common leaked passwords. The leak check is not a complete breach database: not being found does not prove a password never leaked.
- Entropy and crack-time numbers are models, not guarantees.
- `correct-horse-battery` scores *moderate* (~43 bits): three common words are not enough. It is flagged as a passphrase, and five random words reach strong.

## Tests

```powershell
python -m unittest discover -s tests -t .
```

CI also builds the wheel and runs it in a clean environment, and runs `ruff` (rules in `ruff.toml`), `mypy` (`mypy.ini`) and a coverage report that must stay at or above 80% (currently ~88%). To check locally: `pip install ruff mypy coverage`, then `ruff check .`, `mypy` and `coverage run -m unittest discover -s tests -t . && coverage report`. Line endings are normalised to LF by `.gitattributes`.

## Continuous integration

`.github/workflows/ci.yml` runs the tests on Linux, Windows and macOS (Python 3.10 and 3.13; the GUI smoke tests run under a virtual display on Linux). `.github/workflows/release.yml` builds the executables on all three systems, the Windows installer (`installer/ciphercheck.iss`, Inno Setup), the Linux install script and the Python wheel; pushing a tag such as `v0.4.0` attaches them to a GitHub Release, and running it manually only produces downloadable artifacts. Dependabot keeps the GitHub Actions versions current.

## Roadmap

1. ~~Foundation, analysis, reporting, hash analysis, audit dashboard, offline leak check, CI, installer, passphrases, translated CLI~~ (done)
2. Native-speaker review of the translations
3. Code signing for the executables
4. Optional C++ analysis engine
