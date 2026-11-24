# Bundled data

| File | What it is |
| --- | --- |
| `common_passwords.txt` | The 100,000 most common passwords, most common first (rank = line order). Used to score and to detect common passwords, including leetspeak variants. |
| `common_words.txt` | Vocabulary used to spot dictionary-based passwords: a curated list plus frequent purely-alphabetic entries from the same source. |
| `breached.bin` | Offline leak index: the sorted 6-byte SHA-1 prefixes of the ~1,000,000 most common leaked passwords. A password is checked by hashing it locally and binary-searching this file. It is **not** a complete breach database: a password that is not found may still have leaked. |
| `LICENSE-SecLists.txt` | Licence (MIT) of the source list. |

Source: [SecLists](https://github.com/danielmiessler/SecLists) `Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt` (MIT).

Regenerate with:

```
python tools/build_data.py path/to/xato-net-10-million-passwords-1000000.txt
```
