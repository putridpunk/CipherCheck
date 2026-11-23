# Architecture

```
main.py ──> analyzer.analyze(pw) ──> Analysis ──> report.{to_text,to_json,to_html}
               │
               ├─ patterns.find_matches   (sequence, repeat, keyboard, year)
               ├─ dictionary.find_matches (common password, words, leetspeak)
               └─ entropy.estimate_entropy(pw, matches)
```

## Entropy estimation

Every detector returns `Match(kind, start, end, bits)`: a span of the password and
the estimated cost for an attacker to guess it. `estimate_entropy` finds the cheapest
way to cover the whole password with matches and brute-forced characters
(`best[i] = min(best[i-1] + log2(R), best[m.start] + m.bits)`), so overlapping
detections never double-count.

Costs: dictionary word ~13 bits (+ capitalisation / substitution extras), common
password `log2(rank)+1`, sequence `log2(base)+log2(len)+1`, keyboard walk
`log2(47)+2·(len-1)`, year `log2(200)`.

## Privacy rules

- All lookups are local; no network code exists.
- `Match` stores positions and costs, never the matched text.
- Reports contain length, entropy, pattern kinds/lengths and recommendations only.
  `tests/test_core.py::ReportTests` asserts the password never appears in any format.
