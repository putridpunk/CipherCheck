# Contributing to CipherCheck

Thanks for your interest! Bug reports, translation fixes and small improvements are welcome.

## Licence of contributions

CipherCheck is released under the [PolyForm Noncommercial License 1.0.0](LICENSE) (see the notice at the top of that file). By submitting a contribution you agree that:

- it is provided under the same licence as the project;
- the licensor may keep distributing it, including with the commercial authorizations that only the licensor can grant.

Please do not contribute code you are not allowed to license this way.

## Getting started

```
python -m unittest discover -s tests -t .      # run the tests (no dependencies needed)
python -m src.main --help                      # command line
python ciphercheck.py                          # desktop app
python build.py                                # build executables (needs: pip install pyinstaller)
```

## Ground rules

- **Privacy first.** The tool must stay offline. Never add network calls, telemetry or logging of passwords. Reports and statistics may contain counts and categories, never password text or fragments. Tests check this - keep them passing.
- **No real data.** Do not commit real passwords, real hashes or personal data (also in screenshots and test fixtures). Use made-up examples.
- **Translations.** Every user-facing string lives in `src/locales/<code>.py`. When you add or change a key, add it to **all nine** languages; `tests/test_friendly.py` fails if keys or `{placeholders}` differ from English. Native-speaker corrections are especially valuable.
- **Tests.** New behaviour needs a test. GUI tests skip themselves when no display is available.
- **Lint and types.** CI runs `ruff check .` and `mypy`, and the test coverage must stay at or above 80%.
- **Keep it small.** Prefer clear, focused pull requests.

## Project layout

See `README.md` and `docs/ARCHITECTURE.md`. Bundled data and its origin are described in `src/data/README.md`.

## Reporting a problem

Use the issue templates. **Never paste a real password** in an issue.
