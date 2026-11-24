"""Report generation (text, JSON, HTML) and batch aggregation.

Reports never contain the password or any fragment of it: only lengths,
entropy figures, pattern *kinds* and recommendations.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .analyzer import LABEL_ORDER, PATTERN_ADVICE, PATTERN_TEXT, Analysis
from .i18n import t
from .vulnerabilities import assess, risk_level

BAR = "=" * 36
TITLE = "PASSWORD SECURITY AUDITOR"


def to_dict(a: Analysis) -> dict:
    return {
        "tool": "CipherCheck",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "assessment": a.label,
        "risk_level": risk_level(a),
        "score": a.score,
        "length": a.length,
        "character_pool_size": a.pool_size,
        "entropy": {
            "theoretical_bits": a.theoretical_bits,
            "estimated_bits": a.estimated_bits,
            "note": "Theoretical assumes uniformly random characters; "
                    "estimated accounts for detected human patterns.",
        },
        "estimated_crack_time": a.crack_time,
        "findings": [{"level": f.level, "text": f.text} for f in a.findings],
        "vulnerabilities": [v.to_dict() for v in assess(a)],
        "patterns_detected": [{"kind": m.kind, "length": m.length} for m in a.matches],
        "recommendations": a.recommendations,
    }


def to_text(a: Analysis) -> str:
    lines = [BAR, f"{TITLE:^36}".rstrip(), BAR, "",
             f"Password assessment: {a.label}  (score {a.score}/100)", "",
             "Analysis:"]
    lines += [f"[{f.level}] {f.text}" for f in a.findings]
    vulns = assess(a)
    lines += ["", f"Risk level: {risk_level(a)}", "Vulnerabilities:"]
    if not vulns:
        lines.append("  None found.")
    for v in vulns:
        lines += [f"  [{v.severity.upper()}] {v.category}: {v.title}",
                  f"      Why it matters: {v.explanation}",
                  f"      Fix: {v.recommendation}"]
    lines += ["", "Entropy:",
              f"  Theoretical (random-character model): {a.theoretical_bits} bits",
              f"  Estimated   (pattern-aware):          {a.estimated_bits} bits",
              "", "Estimated time to guess (average):",
              f"  Offline, fast hash : {a.crack_time['offline_fast_hash']}",
              f"  Online, throttled  : {a.crack_time['online_throttled']}",
              "", "Recommendations:"]
    lines += [f"- {r}" for r in a.recommendations]
    lines += ["", BAR]
    return "\n".join(lines)


def to_json(a: Analysis) -> str:
    return json.dumps(to_dict(a), indent=2)


def to_html(a: Analysis) -> str:
    e = html.escape
    d = to_dict(a)
    icon = {"+": "ok", "-": "bad", "~": "info"}
    findings = "\n".join(f'<li class="{icon[f.level]}">{e(f.text)}</li>' for f in a.findings)
    recs = "\n".join(f"<li>{e(r)}</li>" for r in a.recommendations)
    vulns = "\n".join(
        f'<tr><td class="sev {v.severity}">{e(v.severity.upper())}</td><td>{e(v.category)}</td>'
        f'<td><b>{e(v.title)}</b><br>{e(v.explanation)}<br><i>Fix: {e(v.recommendation)}</i></td></tr>'
        for v in assess(a)) or '<tr><td colspan="3">None found.</td></tr>'
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>CipherCheck report</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;color:#222}}
.label{{font-size:2rem;font-weight:700}} .meter{{background:#ddd;border-radius:6px;height:12px}}
.meter div{{background:#2a7;height:12px;border-radius:6px}}
li.ok::marker{{content:"[+] ";color:#2a7}} li.bad::marker{{content:"[-] ";color:#c33}}
li.info::marker{{content:"[~] ";color:#888}} small{{color:#666}}
table{{border-collapse:collapse;width:100%}} td{{border-top:1px solid #ddd;padding:6px;vertical-align:top}}
td.sev{{font-weight:700;white-space:nowrap}} .critical{{color:#b00}} .high{{color:#d60}} .medium{{color:#a80}} .low{{color:#580}}
</style></head><body>
<h1>Password Security Auditor</h1>
<p class="label">{e(a.label)}</p>
<div class="meter"><div style="width:{a.score}%"></div></div>
<p>Score {a.score}/100 &middot; {a.length} characters &middot; Risk level: <b>{e(d['risk_level'])}</b></p>
<h2>Analysis</h2><ul>{findings}</ul>
<h2>Vulnerabilities</h2><table>{vulns}</table>
<h2>Entropy</h2>
<p>Theoretical: <b>{a.theoretical_bits}</b> bits &middot; Estimated: <b>{a.estimated_bits}</b> bits<br>
<small>{e(d['entropy']['note'])}</small></p>
<p>Average time to guess: offline fast hash <b>{e(a.crack_time['offline_fast_hash'])}</b>,
online throttled <b>{e(a.crack_time['online_throttled'])}</b></p>
<h2>Recommendations</h2><ul>{recs}</ul>
<p><small>Generated {e(d['generated_at'])} by CipherCheck {e(__version__)}. The password is not included in this report.</small></p>
</body></html>
"""


RENDERERS = {"txt": to_text, "json": to_json, "html": to_html}


def write_report(a: Analysis, path: str | Path, fmt: str | None = None,
                 lang: str | None = None) -> Path:
    path = Path(path)
    fmt = (fmt or path.suffix.lstrip(".") or "txt").lower()
    if fmt not in RENDERERS:
        raise ValueError(f"Unsupported report format: {fmt!r} (use txt, json or html)")
    text = to_friendly_text(a, lang) if lang and fmt == "txt" else RENDERERS[fmt](a)
    path.write_text(text, encoding="utf-8")
    return path


# ---------- batch / aggregate ----------

def aggregate(analyses: list[Analysis], reuse: dict | None = None) -> dict:
    n = len(analyses)
    labels = Counter(a.label for a in analyses)
    kinds = Counter(k for a in analyses for k in a.pattern_kinds)
    return {
        "tool": "CipherCheck",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total": n,
        "assessment_counts": {lbl: labels.get(lbl, 0) for lbl in LABEL_ORDER},
        "average_estimated_bits": round(sum(a.estimated_bits for a in analyses) / n, 1) if n else 0,
        "average_length": round(sum(a.length for a in analyses) / n, 1) if n else 0,
        "pattern_counts": dict(kinds.most_common()),
        "reuse": reuse or {"exact_duplicates": 0, "similar_to_another": 0, "similar_groups": 0},
        "most_common_problems": [
            {"kind": k, "count": c, "percent": round(100 * c / n, 1),
             "description": PATTERN_TEXT.get(k, k), "recommendation": PATTERN_ADVICE.get(k, "")}
            for k, c in kinds.most_common()] if n else [],
    }


def aggregate_text(agg: dict) -> str:
    lines = [BAR, f"{'BATCH AUDIT SUMMARY':^36}".rstrip(), BAR, "",
             f"Passwords analysed: {agg['total']}",
             f"Average length: {agg['average_length']}",
             f"Average estimated entropy: {agg['average_estimated_bits']} bits", "",
             "Assessments:"]
    for lbl, c in agg["assessment_counts"].items():
        pct = 100 * c / agg["total"] if agg["total"] else 0
        lines.append(f"  {lbl:<12} {c:>6}  ({pct:.1f}%)")
    r, n = agg.get("reuse", {}), agg["total"] or 1
    lines += ["", "Reuse inside the dataset:",
              f"  Passwords used more than once: {r.get('exact_duplicates', 0)} "
              f"({100 * r.get('exact_duplicates', 0) / n:.1f}%)",
              f"  Near-copies of another password (same base word): {r.get('similar_to_another', 0)} "
              f"({100 * r.get('similar_to_another', 0) / n:.1f}%)"]
    lines += ["", "Most common problems (share of passwords):"]
    for p in agg.get("most_common_problems", []):
        lines += [f"  {p['percent']:>5}%  {p['description']}", f"          Fix: {p['recommendation']}"]
    if not agg.get("most_common_problems"):
        lines.append("  none")
    lines += ["", "No passwords are stored in this summary.", BAR]
    return "\n".join(lines)


def aggregate_json(agg: dict) -> str:
    return json.dumps(agg, indent=2)


def aggregate_html(agg: dict) -> str:
    e = html.escape
    total = agg["total"] or 1
    reuse = agg.get("reuse", {})
    colors = {"VERY WEAK": "#c33", "WEAK": "#e80", "MODERATE": "#cb0", "STRONG": "#2a7", "VERY STRONG": "#0a5"}
    bars = "\n".join(
        f'<tr><td>{e(lbl)}</td><td style="width:60%"><div class="bar" style="width:{100 * c / total:.1f}%;'
        f'background:{colors[lbl]}"></div></td><td>{c:,} ({100 * c / total:.1f}%)</td></tr>'
        for lbl, c in agg["assessment_counts"].items())
    probs = "\n".join(
        f"<tr><td>{p['percent']}%</td><td>{e(p['description'])}<br><i>Fix: {e(p['recommendation'])}</i></td></tr>"
        for p in agg.get("most_common_problems", [])) or '<tr><td colspan="2">None found.</td></tr>'
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>CipherCheck audit summary</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;color:#222}}
table{{border-collapse:collapse;width:100%}} td{{border-top:1px solid #ddd;padding:6px;vertical-align:top}}
.bar{{height:14px;border-radius:4px}} small{{color:#666}}
</style></head><body>
<h1>Password audit summary</h1>
<p>{agg['total']:,} passwords analysed &middot; average length {agg['average_length']} &middot;
average estimated entropy {agg['average_estimated_bits']} bits</p>
<h2>Strength distribution</h2><table>{bars}</table>
<h2>Reuse inside the dataset</h2>
<p>Passwords used more than once: <b>{reuse.get('exact_duplicates', 0):,}</b> ({100 * reuse.get('exact_duplicates', 0) / total:.1f}%)<br>
Near-copies of another password (same base word): <b>{reuse.get('similar_to_another', 0):,}</b> ({100 * reuse.get('similar_to_another', 0) / total:.1f}%)</p>
<h2>Most common problems</h2><table>{probs}</table>
<p><small>Generated {e(agg['generated_at'])} by CipherCheck {e(agg['version'])}.
No passwords are stored in this summary.</small></p>
</body></html>
"""


AGG_RENDERERS = {"txt": aggregate_text, "json": aggregate_json, "html": aggregate_html}


def write_aggregate(agg: dict, path: str | Path, fmt: str | None = None,
                    lang: str | None = None) -> Path:
    path = Path(path)
    fmt = (fmt or path.suffix.lstrip(".") or "txt").lower()
    if fmt not in AGG_RENDERERS:
        raise ValueError(f"Unsupported report format: {fmt!r} (use txt, json or html)")
    text = aggregate_friendly(agg, lang) if lang and fmt == "txt" else AGG_RENDERERS[fmt](agg)
    path.write_text(text, encoding="utf-8")
    return path


# ---------- plain-language, translated output (used by --lang) ----------

def to_friendly_text(a: Analysis, lang: str) -> str:
    from .friendly import explain  # local import: friendly depends on analyzer only
    r = explain(a, lang)
    lines = [BAR, f"{'CIPHERCHECK':^36}".rstrip(), BAR, "",
             f"{r.verdict}  ({a.score}/100)", r.headline, t(lang, "crack", time=r.crack_time)]
    for hdr, items, mark in (("hdr_bad", r.bad, "-"), ("hdr_good", r.good, "+"), ("hdr_tips", r.tips, ">")):
        if items:
            lines += ["", t(lang, hdr)] + [f" [{mark}] {x}" for x in items]
    lines += ["", BAR]
    return "\n".join(lines)


def aggregate_friendly(agg: dict, lang: str) -> str:
    from .friendly import KEY, LEVELS
    total = agg["total"] or 1
    lines = [BAR, f"{'CIPHERCHECK':^36}".rstrip(), BAR, "", t(lang, "au_total", n=f"{agg['total']:,}"), ""]
    for lbl in LABEL_ORDER:
        level, _ = LEVELS[lbl]
        n = agg["assessment_counts"][lbl]
        lines.append(f"  {t(lang, f'v{level}'):<18} {'#' * round(30 * n / total):<30} {n:,} ({100 * n / total:.1f}%)")
    reuse = agg.get("reuse", {})
    reuse_lines = [" [-] " + t(lang, key, n=f"{reuse.get(field, 0):,}",
                               pct=f"{100 * reuse.get(field, 0) / total:.1f}")
                   for key, field in (("au_dupes", "exact_duplicates"),
                                      ("au_similar", "similar_to_another"))
                   if reuse.get(field, 0)]
    if reuse_lines:
        lines += [""] + reuse_lines
    if agg["pattern_counts"]:
        lines += ["", t(lang, "au_issues")]
        lines += [f" [-] {100 * n / total:.0f}%  {t(lang, 'p_' + KEY[k])}" for k, n in agg["pattern_counts"].items()]
    lines += ["", BAR]
    return "\n".join(lines)
