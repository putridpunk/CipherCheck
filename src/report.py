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
from .analyzer import LABEL_ORDER, Analysis
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


def write_report(a: Analysis, path: str | Path, fmt: str | None = None) -> Path:
    path = Path(path)
    fmt = (fmt or path.suffix.lstrip(".") or "txt").lower()
    if fmt not in RENDERERS:
        raise ValueError(f"Unsupported report format: {fmt!r} (use txt, json or html)")
    path.write_text(RENDERERS[fmt](a), encoding="utf-8")
    return path


# ---------- batch / aggregate ----------

def aggregate(analyses: list[Analysis]) -> dict:
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
    lines += ["", "Patterns found (number of passwords):"]
    lines += [f"  {k:<16} {v}" for k, v in agg["pattern_counts"].items()] or ["  none"]
    lines += ["", "No passwords are stored in this summary.", BAR]
    return "\n".join(lines)
