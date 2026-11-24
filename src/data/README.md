# Bundled data

The data files below are **not** covered by the project licence in `../../LICENSE`; each keeps the licence of its source.

| File | What it is | Licence |
| --- | --- | --- |
| `common_passwords.txt` | The 100,000 most common passwords, most common first (rank = line order). Used to score and to detect common passwords, including leetspeak variants. | MIT (SecLists) |
| `common_words.txt` | Vocabulary used to spot dictionary-based passwords: a curated list plus frequent purely-alphabetic entries from the same source. | MIT (SecLists) |
| `breached.bin` | Offline leak index: the sorted 6-byte SHA-1 prefixes of the ~1,000,000 most common leaked passwords. A password is checked by hashing it locally and binary-searching this file. It is **not** a complete breach database: a password that is not found may still have leaked. | MIT (SecLists) |
| `eff_large_wordlist.txt` | The EFF Large Wordlist (7,776 words) used by the passphrase generator and added to the scoring vocabulary. | CC BY 3.0 US (EFF) |
| `LICENSE-SecLists.txt` | Licence text of SecLists. | |

## Sources and attribution

- [SecLists](https://github.com/danielmiessler/SecLists), `Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt` - MIT licence, Copyright (c) 2018 Daniel Miessler (see `LICENSE-SecLists.txt`).
- *EFF Large Wordlist for Passphrases*, Electronic Frontier Foundation, <https://www.eff.org/dice> - licensed under [Creative Commons Attribution 3.0 United States](https://creativecommons.org/licenses/by/3.0/us/). The dice numbers were removed; the words are unchanged.

## Regenerating

```
python tools/build_data.py path/to/xato-net-10-million-passwords-1000000.txt
```

(`eff_large_wordlist.txt` is the EFF list with the first column removed: `cut -f2 eff_large_wordlist.txt`.)
