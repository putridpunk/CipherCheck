# Changelog

All notable changes to CipherCheck. Format based on [Keep a Changelog](https://keepachangelog.com/);
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.7.0] - 2026-11-25

### Added
- **Personal-information check:** an optional field (Analyze tab, `--profile` on the CLI) flags a password built from your own name, birth date, pet, etc. Kept only in memory for the current session; never written to disk.
- **Three crack-time models:** a fast offline hash (e.g. MD5), a slow, purpose-built offline hash (e.g. bcrypt) and a rate-limited online login, instead of just one number.
- **Stronger keyboard-walk detection:** recognises AZERTY and QWERTZ layouts in addition to QWERTY.
- **CSV import for the Audit tab and `-f`:** a password-manager export (Bitwarden, Chrome, 1Password, ...) is read directly; the password column is found automatically from the header.
- **Password policies:** a *Policy* button in the Audit tab (and `-P/--policy` on the CLI) checks every password against a named policy (`basic`, `nist`, `strong`) and reports a pass/fail breakdown, exportable with the rest of the summary.
- **Audit comparison:** after the first audit in a session, each later one is automatically compared with the previous one (strength and the share of weak passwords), so you can see whether things improved.
- **CSV export** for audit summaries, alongside the existing TXT/JSON/HTML.
- **Hash-cracking demo** (Hash tab): an educational "attempt demo crack" button tries an MD5/SHA-1 hash against the bundled 100,000 common passwords. It only ever finds one of those, never a real, unique or salted password.
- **Check for updates:** an on-demand button (and `--check-update` on the CLI) asks GitHub's public release API whether a newer version exists. The only network access anywhere in the app; it never runs on its own.

## [0.6.3] - 2026-11-24

### Fixed
- **Windows uninstaller: "Some elements could not be removed".** Uninstalling while CipherCheck was still open could not delete `ciphercheck.exe` (it was in use). The app now tells the installer that it is running, so the uninstaller (and a later upgrade) asks you to close it first and then removes everything. Versions already installed keep their old uninstaller: close the app before uninstalling them, or install the new version over them first.

### Changed
- Text in the window is now centred (the prompts above the input fields, the Audit tab's intro and hint), while the lists of explanations and the input fields stay left-aligned (right-aligned lists in Arabic).

## [0.6.2] - 2026-11-24

### Fixed
- **Larger text no longer gets cut off at the sides.** With the `A+` button the panel now widens (up to the window), wrapped text follows its real width, rows of buttons stack when they no longer fit, the footer wraps, and the results area can no longer ask for more room than the panel has. At the biggest size the window also grows taller (up to the screen) so the results stay visible. A test checks every language at every text size.

### Added
- **Confirmation when your password is already strong:** pressing "Generate strong password" now asks, in the current language, whether you want a brand-new one (instead of silently keeping it).

## [0.6.1] - 2026-11-24

### Fixed
- **Linux:** the v0.6.0 app binary did not start on Ubuntu 24.04 (`GLIBC_2.42 not found`) because it was built on the newest Ubuntu runner. Linux binaries are now built on Ubuntu 22.04 (glibc 2.35) and run on 22.04 and newer.

### Added
- The release workflow smoke-tests the executables before publishing: the app is started under a virtual display on Linux, and the terminal tool is run on every OS.

## [0.6.0] - 2026-11-24

### Added
- **Large files in the Audit tab and `-f`:** analysed on all CPU cores in chunks (about 3x faster on 4 cores in my test, more on 8+), with a progress bar, a **Cancel** button and a `-j/--jobs` option for the CLI. Results are identical to the single-process run.
- **Drag and drop:** drop a password file anywhere on the window to audit it (optional `tkinterdnd2` package; bundled in the release executables).
- **Python package:** `pyproject.toml`; install the wheel with `pipx install` to get the `ciphercheck` and `ciphercheck-gui` commands. Releases now include the wheel.
- **Linux:** `ciphercheck-linux-install.sh` adds a menu entry and icon (per user, no root) and can uninstall.
- **macOS:** the app now carries a bundle identifier.
- CI builds the wheel and runs it in a clean environment; `ruff`, `mypy` and a coverage report (minimum 80%); README badges.

### Changed
- The bundled data and icons moved from `data/` and `assets/` to `src/data/` and `src/assets/` (they ship inside the package).
- Closing the window stops a running audit and its worker processes.
- The passphrase generator never picks hyphenated words, so the words of `a-b-c-d-e` are always unambiguous.
- `.gitattributes` normalises line endings to LF; small clean-ups found by the new checks.

## [0.5.0] - 2026-11-24

### Added
- Application icon (a green `C_` on a dark tile) for the Windows executables, the installer, the macOS app and the window; regenerate with `tools/make_icon.py`.
- Keyboard shortcuts in the app: `Ctrl+1/2/3` switch tabs, `Ctrl+G` generates a password, `Esc` clears the current input.
- Font-size buttons (`A−` / `A+`); the choice is remembered.
- Footer with the version, the licence and a link to the repository.
- `SECURITY.md` and this changelog.

## [0.4.0] - 2026-11-24

### Added
- **Licence:** PolyForm Noncommercial 1.0.0; commercial use needs the author's written authorization.
- Passphrase generator (EFF large wordlist) in the app and as `--passphrase` in the CLI.
- Audit: identical passwords and near-copies of each other (`reuse.py`).
- CLI `--lang` for plain-language, translated output (passwords, hashes, batch summaries, TXT reports).
- The chosen language is remembered between launches.
- Windows installer (`ciphercheck-setup.exe`, Inno Setup).
- README screenshots, `CONTRIBUTING.md`, issue and pull-request templates, Dependabot.

### Changed
- A separator between two dictionary words is scored as one of a few common separators, so passphrases are no longer overrated.
- Linux binaries are about 40% smaller.

## [0.3.0] - 2026-11-24

### Added
- Bundled data: 100,000 most common passwords, an ~8,000-word vocabulary and an offline index of ~1 million leaked passwords (SecLists, MIT).
- Offline leaked-password check (`breach.py`).
- Audit report export (TXT / JSON / HTML) in the app and the CLI.
- Linux and macOS builds, GitHub Actions CI and release workflows, `build.py`.

### Changed
- The GUI was split into the `src/gui/` package.

### Fixed
- Version string reported `0.1.0`.

## [0.2.0] - 2026-11-23

### Added
- Hash-format identification (app tab and `--hash`).
- Audit dashboard for files of synthetic passwords.
- Detailed vulnerability reports (category, severity, explanation, fix).
- "Generate" creates a strong version of the password you typed.

### Fixed
- `src/report.py` had been git-ignored by mistake.

## [0.1.0] - 2026-11-23

### Added
- First release: entropy estimation, pattern and dictionary detection, plain-language desktop app in 9 languages (Matrix theme), command-line tool, TXT / JSON / HTML reports.

[Unreleased]: https://github.com/putridpunk/CipherCheck/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/putridpunk/CipherCheck/compare/v0.6.3...v0.7.0
[0.6.3]: https://github.com/putridpunk/CipherCheck/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/putridpunk/CipherCheck/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/putridpunk/CipherCheck/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/putridpunk/CipherCheck/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/putridpunk/CipherCheck/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/putridpunk/CipherCheck/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/putridpunk/CipherCheck/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/putridpunk/CipherCheck/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/putridpunk/CipherCheck/releases/tag/v0.1.0
